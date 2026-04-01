# What is QUIC?

QUIC is a transport protocol (like TCP) that runs over UDP. It was originally developed by Google and is now standardized as RFC 9000.

## Key differences from TCP

- **Encryption built-in** — TLS 1.3 is part of the protocol, not layered on top. Even most header fields are encrypted.
- **Faster connection setup** — handshake and encryption are combined into 1 round-trip (vs TCP's 2-3 with TLS). Repeat connections can do 0-RTT.
- **Multiplexed streams** — multiple independent streams over one connection, without head-of-line blocking (where one lost packet stalls everything behind it, as in TCP).
- **Connection migration** — connections are identified by IDs, not IP:port tuples, so they survive network changes (e.g. switching from Wi-Fi to cellular).
- **Runs over UDP** — allows deployment without waiting for middleboxes (firewalls, NATs) to support a new protocol.

HTTP/3 is the most well-known user of QUIC. In this project, qsh/qshd use it as a transport for an encrypted remote shell — essentially SSH-like functionality over QUIC instead of TCP.
