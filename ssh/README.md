# qsh -- QUIC Shell

An interactive remote shell over QUIC with TLS 1.3 mutual authentication.
Like SSH, but built on UDP/QUIC using [ngtcp2](https://github.com/ngtcp2/ngtcp2)
and [wolfSSL](https://github.com/wolfSSL/wolfssl).

## Features

- Full PTY support -- run vi, htop, or any interactive program
- Mutual TLS authentication using X.509v3 certificates
- Username embedded in the client certificate CN (no password auth)
- Multi-client support via fork-per-connection
- Window resize (SIGWINCH) forwarding
- Certificate revocation via filesystem-based CRL
- Forward-secret encryption (ECDHE + AES-GCM)
- Single UDP port, no TCP required

## Directory Layout

```
ssh/
  qsh/          Client source and Makefile
  qshd/         Server (daemon) source and Makefile
  certs/        Generated certificates (gitignored)
  crl/          Revoked certificate serials (touch to revoke)
  tools/        Build scripts for wolfSSL and ngtcp2
  docs/         Protocol documentation and notes
  make-certs.sh Certificate generation script
```

## Prerequisites

- wolfSSL built with QUIC support
- ngtcp2 built with wolfSSL crypto backend
- Linux (uses forkpty, PTY ioctls)

Build scripts are provided in `tools/`:

```bash
# Build and install wolfSSL
./tools/build-wolfssl.sh

# Build and install ngtcp2
./tools/build-ngtcp2.sh
```

## Generating Certificates

```bash
./make-certs.sh [hostname] [username]
```

Defaults: hostname=`factsorlie.com`, username=`$USER`.

This creates:

| File | Purpose |
|------|---------|
| `certs/ca-cert.pem` | CA certificate (shared trust anchor) |
| `certs/ca-key.pem` | CA private key (admin only -- keep secure) |
| `certs/server-cert.pem` | Server certificate |
| `certs/server-key.pem` | Server private key |
| `certs/client-cert.pem` | Client certificate (CN = username) |
| `certs/client-key.pem` | Client private key |

Client certificates must be X.509v3 (with extensions). wolfSSL rejects
v1 certificates for peer verification.

### Adding Users

The quick way -- use the `add-user.sh` script:

```bash
# Add alice (identity only -- HOME defaults to /home/alice)
./tools/add-user.sh alice

# Add alice with access to the ubuntu account (/home/ubuntu)
./tools/add-user.sh alice ubuntu

# Add bob with access to the ubuntu account
./tools/add-user.sh bob ubuntu
```

The certificate CN is the user's identity (shown in logs, set as USER).
The optional second argument becomes the certificate OU, which tells
qshd which unix account (HOME directory) to use. If omitted, the CN
is used for both.

Output files:

- `alice-cert.pem` -- signed client certificate
- `alice-key.pem` -- client private key

Give the user these three files:

1. `alice-cert.pem` -> install as `~/ssh/certs/client-cert.pem`
2. `alice-key.pem` -> install as `~/ssh/certs/client-key.pem`
3. `certs/ca-cert.pem` -> install as `~/ssh/certs/ca-cert.pem`

The script prints the certificate serial number for easy revocation.

### Adding Users (Manual / Secure Way)

If the user should generate their own private key (recommended for
production), have them create a CSR on their machine:

```bash
# On the user's machine:
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout my-key.pem -out my.csr -nodes -subj "/CN=alice/OU=ubuntu"

# Send my.csr to the admin (NOT the private key)
```

```bash
# Admin signs it:
openssl x509 -req -in my.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem \
    -CAcreateserial -out alice-cert.pem -days 365 -extfile client-ext.cnf

# Send alice-cert.pem + certs/ca-cert.pem back to the user
```

The `client-ext.cnf` file contains the required X.509v3 extensions:

```
basicConstraints = CA:FALSE
keyUsage = digitalSignature
```

Without these extensions, openssl creates a v1 certificate which
wolfSSL will reject.

## Building

```bash
cd qshd && make
cd qsh  && make
```

The qsh client is statically linked for easy deployment to other machines.

## Usage

### Server

```bash
./qshd [port]        # default: 2222
```

The server listens on a single UDP port. Certificates are loaded from
`~/ssh/certs/`. The CRL directory is `~/ssh/crl/`.

### Client

```bash
./qsh --host=<hostname> [--port=2222]
```

The username is read from the client certificate CN. To override:

```bash
./qsh --host=<user>:<hostname> --port=2222
```

Client certificates and keys are loaded from `~/ssh/certs/`.

### Example Session

```
$ ./qsh --host=factsorlie.com
qsh: connecting to ubuntu@factsorlie.com:2222 via QUIC...
qsh: connected (TLS 1.3 / QUIC)
ubuntu@factsorlie:~$ whoami
ubuntu
ubuntu@factsorlie:~$ exit
qsh: disconnected
```

## Certificate Revocation

Revocation uses a simple filesystem check. Each revoked certificate is
identified by its serial number as a file in `~/ssh/crl/`:

```bash
# Get the serial
openssl x509 -in certs/client-cert.pem -serial -noout
# serial=785B7E89317A993E409C43EB05142D7B0B6F7DB2

# Revoke
touch ~/ssh/crl/785B7E89317A993E409C43EB05142D7B0B6F7DB2

# Unrevoke
rm ~/ssh/crl/785B7E89317A993E409C43EB05142D7B0B6F7DB2

# List revoked
ls ~/ssh/crl/
```

The server checks the CRL after the TLS handshake completes. If the
certificate is revoked, the server sends a QUIC CONNECTION_CLOSE with
reason "certificate revoked" and the client exits immediately.

## Documentation

See `docs/` for detailed documentation:

- [README-protocol.md](docs/README-protocol.md) -- Complete protocol
  specification including handshake flow, encryption levels, stream
  protocol, server architecture, security analysis, and trust model
- [README-der.md](docs/README-der.md) -- DER encoding notes
- [README-flexi-cert.md](docs/README-flexi-cert.md) -- Flexible
  certificate topics

## Security

- All traffic after the initial ClientHello/ServerHello is encrypted
  with keys derived from ECDHE key agreement
- Application data uses forward-secret keys -- compromising the server's
  long-term key cannot decrypt past sessions
- Mutual TLS: both client and server present certificates signed by the
  shared CA
- No passwords, no key files on the server -- authentication is purely
  certificate-based with a CA trust model
- See [docs/README-protocol.md](docs/README-protocol.md) for full
  security analysis
