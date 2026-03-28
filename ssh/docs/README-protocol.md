# qsh/qshd Protocol

## Overview

qsh is an interactive remote shell over QUIC (UDP) with TLS 1.3 mutual
authentication. The client certificate CN carries the username. After
the handshake, a PTY-backed bash session is relayed over a QUIC
bidirectional stream.

## Handshake Flow

### 1. Client to Server: Initial packet

*Encrypted with Initial keys (derived from DCID, publicly known)*

The first UDP datagram. A QUIC long-header packet containing a TLS 1.3
ClientHello:

- QUIC version (v1)
- Random Destination Connection ID (DCID) -- the client generates one
- Client's Source Connection ID (SCID)
- CRYPTO frame carrying the ClientHello (cipher suites, key shares,
  ALPN "qsh", transport params)
- Padded to at least 1200 bytes (QUIC amplification attack mitigation)

Initial keys are derived from the DCID using a well-known salt, so this
encryption provides **obfuscation, not confidentiality**. Anyone who sees
the DCID can derive the same keys. It exists to prevent middlebox
interference, not eavesdropping.

The server validates this with `ngtcp2_accept()`.

### 2. Server to Client: Initial + Handshake packets

*Initial portion: obfuscated (same as above);
Handshake portion: encrypted with handshake keys (confidential)*

The server responds with multiple messages in one or two UDP datagrams:

- **Initial** (obfuscated): ServerHello (with key share, selected cipher)
- **Handshake** (encrypted with handshake traffic keys):
  EncryptedExtensions, CertificateRequest, server Certificate,
  CertificateVerify, Finished

After the ServerHello, both sides perform ECDHE key agreement and derive
handshake traffic keys. Everything from EncryptedExtensions onward is
**truly encrypted** -- an eavesdropper cannot read it. The server's
certificate and identity are protected.

### 3. Client to Server: Handshake packet

*Encrypted with handshake keys (confidential)*

The client responds at the handshake encryption level:

- Client Certificate (X.509v3 with username in the CN)
- CertificateVerify (proves the client owns the private key)
- Finished

All of this is encrypted with handshake keys. An eavesdropper cannot see
the client certificate or username. The server verifies the client cert
against the CA, extracts the CN (e.g. `ubuntu`), and the handshake is
complete. **This is where qshd forks a child process for the session.**

### 4. Post-fork: Application data on QUIC streams

*Encrypted with application traffic keys (confidential, forward-secret)*

Both sides derive application traffic keys from the master secret. These
keys provide **forward secrecy** -- even if the server's long-term
private key is later compromised, captured traffic cannot be decrypted.

## Encryption Summary

| Phase | Encryption | Confidential? |
|-------|-----------|---------------|
| Initial (ClientHello, ServerHello) | Initial keys from DCID | No -- obfuscation only |
| Handshake (certs, verify, finished) | Handshake traffic keys | **Yes** |
| Application data (shell I/O) | Application traffic keys | **Yes + forward secret** |

## Stream Protocol

After the handshake, the client opens QUIC bidirectional streams. The
first byte of each stream indicates its type:

### Data Stream (0x01) -- Shell I/O

```
Byte 0:      0x01 (stream type)
Bytes 1-2:   terminal rows (uint16, big-endian)
Bytes 3-4:   terminal columns (uint16, big-endian)
Bytes 5+:    raw bidirectional shell I/O (no framing)
```

The server allocates a PTY with the given dimensions, spawns
`/bin/bash --login`, and sets environment variables from the client
certificate:

- `TERM=xterm-256color`
- `USER=<cert CN>`
- `LOGNAME=<cert CN>`
- `HOME=/home/<cert CN>` (if it exists)

Data flows bidirectionally with no further framing:

- Client stdin bytes are written to the PTY master
- PTY master output is sent back on the same stream

When the shell exits, the server sends FIN on the stream. The client
restores the terminal and disconnects.

### Resize Stream (0x02) -- Window Size Change

```
Byte 0:      0x02 (stream type)
Bytes 1-2:   new rows (uint16, big-endian)
Bytes 3-4:   new columns (uint16, big-endian)
[FIN]
```

Sent by the client on SIGWINCH. Each resize opens a new stream. The
server applies the new size with `ioctl(TIOCSWINSZ)` on the PTY master,
which automatically delivers SIGWINCH to the foreground process group.

## Server Architecture

```
                   +------------------+
   UDP :2222 ----->|  Parent process  |
                   |  - accept loop   |
                   |  - handshake     |
                   |  - verify cert   |
                   +--------+---------+
                            | fork()
                   +--------+---------+
                   |  Child process   |
                   |  - connected UDP |
                   |  - PTY + bash    |
                   |  - stream relay  |
                   +------------------+
```

1. Parent receives Initial packet, validates with `ngtcp2_accept()`
2. Parent completes the full QUIC/TLS 1.3 handshake (no fork yet)
3. Parent verifies client certificate, extracts username from CN
4. Parent forks; child `connect()`s the UDP socket to the client
5. Parent closes the old socket, creates a fresh listen socket
6. Child runs the PTY session loop until disconnect or shell exit

Completing the handshake before forking eliminates races from Initial
packet retransmissions.

### UDP Packet Routing to Forked Processes

After forking, the child calls `connect(fd, client_addr)` on the
inherited UDP socket. An unconnected UDP socket receives packets from
any source. A connected UDP socket receives only from the specific
address it was connected to. When both are bound to the same port (via
`SO_REUSEADDR`), the kernel uses longest-match -- the connected socket
is more specific, so it wins:

```
Parent:   bind(:2222)                    -> receives from anyone (new clients)
Child 1:  bind(:2222) + connect(client1) -> receives only from client1
Child 2:  bind(:2222) + connect(client2) -> receives only from client2
```

In practice, the parent gives up its socket after forking -- it closes
the fd and creates a fresh one:

1. Parent has `fd` bound to `:2222`, receives Initial from client
2. Parent completes handshake on `fd`
3. Fork -- child inherits `fd`
4. Child: `connect(fd, client_addr)` -- `fd` is now dedicated to this
   client
5. Parent: `close(fd)`, creates new socket, binds to `:2222` again

There is a brief window between the fork and step 5 where no socket is
listening for new clients. Any new Initials arriving in that window are
lost, but QUIC clients retransmit so they connect on the next attempt.

### What happens if two Hello messages arrive at once?

The parent processes them sequentially. It is single-threaded:

```
recvfrom -> ngtcp2_accept -> server_setup -> handshake -> fork -> close fd -> new socket -> recvfrom
```

The second Initial sits in the kernel's UDP receive buffer until the
parent finishes with the first one, creates its new listen socket, and
calls `recvfrom` again. UDP sockets have a receive buffer (typically
128KB-256KB on Linux), so packets queue up rather than being lost.

The only risk is if the handshake takes so long that the second client
times out. A TLS 1.3 handshake is ~1 RTT (a few milliseconds on a LAN,
maybe 100ms intercontinental), so in practice a second client waits at
most that long. If hundreds of simultaneous new connections arrived, it
could bottleneck -- but that is not the use case for a shell server.
Sequential accept is fine -- OpenSSH does the same thing.

### When Hello is received, does the code connect() to complete the handshake?

No. The parent never calls `connect()`. It stays unconnected during the
entire handshake so it can receive packets from any address:

1. Parent receives Initial via `recvfrom` (which provides the client's
   address)
2. Parent calls `server_setup` -- creates the ngtcp2 connection and
   records the client address in `srv.remote_addr`
3. Parent runs the handshake loop -- `send_packets` uses
   `sendto(fd, ..., &srv.remote_addr)` to reply to the specific client,
   while `recv_packets` uses `recvfrom` with `MSG_DONTWAIT` to read
   responses
4. Handshake completes, certificate verified
5. **Now** fork
6. **Child** calls `connect(fd, client_addr)` -- locks the socket to
   this client
7. **Parent** closes `fd`, creates a new unconnected socket

`sendto` with the stored address directs packets to the right client
during the handshake -- no `connect()` needed. The `connect()` only
happens after the fork, in the child, for the long-running session.

## Certificates

All certificates are ECC (P-256), X.509v3, signed by a shared CA:

- **CA**: `certs/ca-cert.pem` -- shared trust anchor
- **Server**: `certs/server-cert.pem` -- CN is the hostname,
  SAN includes DNS + IP entries
- **Client**: `certs/client-cert.pem` -- CN is the username,
  must include extensions (basicConstraints, keyUsage) to be v3

wolfSSL requires peer certificates to be X.509v3. A v1 certificate
(no extensions) will be rejected with `ASN_VERSION_E`.

Generate all certificates:

```
./make-certs.sh [hostname] [username]
```

## Cryptographic Algorithms

- Key exchange: ECDHE with P-256 (from TLS 1.3 key share)
- Signature: ECDSA with SHA-256 (certificate and CertificateVerify)
- AEAD: AES-128-GCM or AES-256-GCM (negotiated in TLS 1.3)
- HKDF: SHA-256 or SHA-384 (key derivation)
- QUIC header protection: AES-ECB

## Security Analysis

### Initial Packet Encryption

The first packet (ClientHello) is encrypted with keys derived via HKDF
from the Destination Connection ID (DCID) and a salt hardcoded in the
QUIC RFC. This is symmetric AES-128-GCM encryption -- no public key
crypto at this stage. Anyone who reads the DCID off the wire can derive
the same key and decrypt it. This provides **obfuscation** (to prevent
middlebox interference), not confidentiality.

No RSA is used anywhere in qsh. All certificates and key exchange use
ECC (P-256/ECDSA/ECDHE).

### Man-in-the-Middle Protection

A passive eavesdropper can decrypt the Initial packets (ClientHello,
ServerHello) since the DCID-derived keys are public knowledge. However,
the ClientHello and ServerHello contain ECDHE public key shares. Both
sides combine them to derive handshake keys that only they know. A man
in the middle can see both public shares but cannot compute the shared
secret -- that is the discrete log problem that ECC security is based on.

An active MITM could try to intercept and substitute their own key
shares, but then they cannot produce valid CertificateVerify signatures
for the real certificates. The handshake fails.

Defense in depth:

1. **Initial** -- no protection from MITM (obfuscation only)
2. **ECDHE key agreement** -- passive attacker defeated (cannot derive
   handshake keys)
3. **Server CertificateVerify** -- active MITM defeated (cannot forge
   the server's signature)
4. **Client CertificateVerify** -- mutual authentication (server knows
   who is connecting)

### Role of TLS 1.3

QUIC does not have its own key exchange or authentication. TLS 1.3
runs inside QUIC packets -- the handshake messages (ClientHello,
ServerHello, Certificate, etc.) are carried in QUIC CRYPTO frames
rather than TLS records:

```
UDP -> QUIC packet layer -> TLS 1.3 handshake in CRYPTO frames
                         -> encrypted data in STREAM frames
```

TLS 1.3 handles key exchange, authentication, key derivation, and
cipher negotiation. QUIC handles packet framing, encryption with the
derived keys, reliability (replacing TCP), multiplexed streams, and
congestion control.

wolfSSL is the TLS 1.3 implementation. ngtcp2 is the QUIC
implementation. They communicate through `WOLFSSL_QUIC_METHOD`
callbacks -- wolfSSL derives the keys, ngtcp2 uses them to
encrypt/decrypt packets.

### Replay Attack Protection

TLS 1.3 has multiple layers of replay protection:

- **Handshake replay**: The ClientHello contains a 32-byte random
  nonce, the ServerHello another. These feed into ECDHE key derivation,
  so every handshake produces unique keys. Replaying an old ClientHello
  gets a different ServerHello -- the attacker cannot complete the
  handshake without the client's ECDHE private key.

- **Data replay**: Every QUIC packet has a strictly increasing packet
  number. ngtcp2 rejects duplicates. AEAD (AES-GCM) binds the packet
  number into the authentication tag, so replayed packets cannot be
  renumbered either -- the tag check fails.

- **Connection replay**: Even replaying a full captured handshake fails
  because the server generates a fresh ECDHE key pair each time, the
  CertificateVerify signature covers the full transcript including both
  randoms, and the Finished message is a MAC over the entire transcript.

qsh does not use TLS 1.3 0-RTT session resumption, which is the one
TLS 1.3 feature vulnerable to replay.

### Stolen Client Key

If an attacker obtains the client's private key (`client-key.pem`),
they can connect as that user. This is equivalent to stealing an SSH
private key.

Mitigations:

- **Encrypt the key file** with a passphrase
- **File permissions** (`chmod 600`)
- **Hardware tokens** (store the key on a YubiKey/TPM so it cannot be
  copied)
- **Revocation** -- regenerate the CA and all certificates, or
  implement CRL/OCSP support

Advantages over SSH password authentication: there is no password to
phish or brute force. The attacker needs the actual key file. And
unlike SSH `authorized_keys` scattered across every server, qsh uses
a CA model -- revoke at one place (the CA) rather than updating every
server.

**Forward secrecy** helps with one scenario: if the key is stolen
*after* a session ended, previously captured traffic **cannot** be
decrypted. The ECDHE ephemeral keys are gone. The attacker can only
impersonate the user going forward, not read past sessions.

### Trust Model: CA vs SSH

The server does not store client public keys. It only has the CA
certificate (`ca-cert.pem`). During the handshake, the client sends
its certificate and the server verifies the CA's signature on it in
real time. If the signature is valid, the client is trusted.

This differs from SSH, where the server stores each user's public key
in `~/.ssh/authorized_keys`:

| | SSH | qsh |
|---|---|---|
| Server stores | each user's public key | CA cert only |
| Add a user | edit `authorized_keys` on every server | sign a cert with the CA |
| Revoke a user | remove key from every server | revoke at the CA (CRL/OCSP) |

### Key Distribution

A new user receives three files:

- `client-cert.pem` -- their certificate (public key + username CN,
  signed by the CA)
- `client-key.pem` -- their private key
- `ca-cert.pem` -- the CA cert (to verify the server)

The private key should never leave the user's machine. The secure
workflow is:

1. **User** generates a key pair and CSR on their own machine:
   ```
   openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
       -keyout my-key.pem -out my.csr -nodes -subj "/CN=alice"
   ```
2. **User** sends only the CSR to the administrator (no private key)
3. **Admin** signs it with the CA key:
   ```
   cat > client-ext.cnf <<EOF
   basicConstraints = CA:FALSE
   keyUsage = digitalSignature
   EOF

   openssl x509 -req -in my.csr -CA ca-cert.pem -CAkey ca-key.pem \
       -CAcreateserial -out alice-cert.pem -days 365 \
       -extfile client-ext.cnf
   ```
4. **Admin** sends back `alice-cert.pem` + `ca-cert.pem`

The private key is generated on and never leaves the user's machine.
The current `make-certs.sh` takes a shortcut by generating everything
in one place, which is fine for single-user or development use.

### CA Key Security

The client never receives `ca-key.pem`. That is the CA's **private**
key -- whoever has it can sign new certificates and create new users.
It must stay with the administrator.

What each party holds:

| File | Admin | Server | Client |
|------|-------|--------|--------|
| `ca-key.pem` (CA private key) | **yes** | no | no |
| `ca-cert.pem` (CA public cert) | yes | yes | yes |
| `server-key.pem` (server private key) | yes | **yes** | no |
| `server-cert.pem` (server public cert) | yes | yes | no |
| `client-key.pem` (client private key) | no* | no | **yes** |
| `client-cert.pem` (client public cert) | no* | no | yes |

\* With the secure CSR workflow, the admin never sees the client's
private key. With the `make-certs.sh` shortcut, the admin generates
it and must transfer it securely.

If `ca-key.pem` is compromised, the attacker can issue certificates
for any username. Protect it accordingly -- keep it offline, encrypted,
or in a hardware security module.
