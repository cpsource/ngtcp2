#!/bin/bash
#
# make-certs.sh — Generate CA, server, and client certificates for qsh/qshd
#
# Creates:
#   certs/ca-cert.pem        CA certificate (shared)
#   certs/ca-key.pem         CA private key (keep secure)
#   certs/server-cert.pem    Server certificate (for qshd)
#   certs/server-key.pem     Server private key (for qshd)
#   certs/client-cert.pem    Client certificate (for qsh)
#   certs/client-key.pem     Client private key (for qsh)
#
# The client certificate CN is set to the username, which qshd uses
# to identify the connecting user (like an SSH authorized key).
#
# Usage:
#   ./make-certs.sh [hostname] [username]
#   hostname defaults to factsorlie.com
#   username defaults to the current $USER

set -e

DAYS=365
CURVE=P-256
DIR="$(dirname "$0")/certs"
HOSTNAME="${1:-factsorlie.com}"
USERNAME="${2:-$USER}"

mkdir -p "$DIR"

echo "=== Generating qsh certificates ==="
echo "    Output:   $DIR"
echo "    Hostname: $HOSTNAME"
echo "    Username: $USERNAME"
echo "    Curve:    $CURVE"
echo "    Validity: $DAYS days"
echo

# ---- CA ----
echo "[1/3] Creating CA..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:$CURVE \
    -keyout "$DIR/ca-key.pem" \
    -out "$DIR/ca-cert.pem" \
    -days $DAYS -nodes \
    -subj "/CN=qsh-ca" \
    2>/dev/null

# ---- Server ----
echo "[2/3] Creating server certificate (CN=$HOSTNAME)..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:$CURVE \
    -keyout "$DIR/server-key.pem" \
    -out "$DIR/server.csr" \
    -nodes \
    -subj "/CN=$HOSTNAME" \
    2>/dev/null

# Add SAN for both hostname and localhost
cat > "$DIR/server-ext.cnf" <<EOF
subjectAltName = DNS:$HOSTNAME, DNS:localhost, IP:127.0.0.1
EOF

openssl x509 -req \
    -in "$DIR/server.csr" \
    -CA "$DIR/ca-cert.pem" \
    -CAkey "$DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$DIR/server-cert.pem" \
    -days $DAYS \
    -extfile "$DIR/server-ext.cnf" \
    2>/dev/null

# ---- Client ----
echo "[3/3] Creating client certificate (CN=$USERNAME)..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:$CURVE \
    -keyout "$DIR/client-key.pem" \
    -out "$DIR/client.csr" \
    -nodes \
    -subj "/CN=$USERNAME" \
    2>/dev/null

# Client cert needs extensions to be X.509v3 (wolfSSL requires v3 for peer certs)
cat > "$DIR/client-ext.cnf" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature
EOF

openssl x509 -req \
    -in "$DIR/client.csr" \
    -CA "$DIR/ca-cert.pem" \
    -CAkey "$DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$DIR/client-cert.pem" \
    -days $DAYS \
    -extfile "$DIR/client-ext.cnf" \
    2>/dev/null

# ---- Cleanup ----
rm -f "$DIR"/*.csr "$DIR"/*.cnf "$DIR"/*.srl

# ---- Permissions ----
chmod 600 "$DIR"/*-key.pem
chmod 644 "$DIR"/*-cert.pem

echo
echo "=== Done ==="
echo
echo "  Server (qshd):"
echo "    cert:  $DIR/server-cert.pem"
echo "    key:   $DIR/server-key.pem"
echo "    ca:    $DIR/ca-cert.pem  (to verify clients)"
echo
echo "  Client (qsh):"
echo "    cert:  $DIR/client-cert.pem  (CN=$USERNAME)"
echo "    key:   $DIR/client-key.pem"
echo "    ca:    $DIR/ca-cert.pem  (to verify server)"
echo
echo "  The username '$USERNAME' is embedded in the client certificate CN."
echo "  qshd will use it to set USER/LOGNAME in the shell session."
echo
echo "  To add another user:"
echo "    openssl req -newkey ec -pkeyopt ec_paramgen_curve:$CURVE \\"
echo "        -keyout alice-key.pem -out alice.csr -nodes \\"
echo "        -subj \"/CN=alice\""
echo "    openssl x509 -req -in alice.csr \\"
echo "        -CA $DIR/ca-cert.pem -CAkey $DIR/ca-key.pem \\"
echo "        -CAcreateserial -out alice-cert.pem -days $DAYS"
echo "    # Then give alice-cert.pem + alice-key.pem + ca-cert.pem to the user"
