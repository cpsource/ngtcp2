#!/bin/bash
#
# add-user.sh — Generate a signed client certificate for a new user
#
# Usage:
#   ./tools/add-user.sh <username> [account]
#
#   username   The user's identity (becomes the certificate CN)
#   account    Optional unix account to log into (becomes the certificate OU)
#              If omitted, the CN is used for HOME/chdir on the server.
#
# Output:
#   <username>-cert.pem   Signed client certificate
#   <username>-key.pem    Client private key
#
# The user needs these files plus certs/ca-cert.pem to connect.
#
# Examples:
#   ./tools/add-user.sh alice              # CN=alice, no OU
#   ./tools/add-user.sh alice ubuntu       # CN=alice, OU=ubuntu
#   ./tools/add-user.sh bob ubuntu         # CN=bob, OU=ubuntu

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SSH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CERT_DIR="$SSH_DIR/certs"
EXT_FILE="$SSH_DIR/client-ext.cnf"
CURVE=P-256
DAYS=365

USERNAME="${1:-}"
ACCOUNT="${2:-}"

if [ -z "$USERNAME" ]; then
    echo "Usage: $0 <username> [account]"
    echo ""
    echo "  username   User identity (certificate CN)"
    echo "  account    Unix account (certificate OU, optional)"
    exit 1
fi

# Check prerequisites
if [ ! -f "$CERT_DIR/ca-cert.pem" ] || [ ! -f "$CERT_DIR/ca-key.pem" ]; then
    echo "Error: CA certificate not found. Run make-certs.sh first."
    exit 1
fi

if [ ! -f "$EXT_FILE" ]; then
    echo "Error: $EXT_FILE not found."
    exit 1
fi

# Build subject line
SUBJECT="/CN=$USERNAME"
if [ -n "$ACCOUNT" ]; then
    SUBJECT="$SUBJECT/OU=$ACCOUNT"
fi

OUTDIR="$CERT_DIR"
KEY_OUT="$OUTDIR/${USERNAME}-key.pem"
CERT_OUT="$OUTDIR/${USERNAME}-cert.pem"
CSR_TMP="$OUTDIR/${USERNAME}.csr"

# Check for existing files
if [ -f "$KEY_OUT" ] || [ -f "$CERT_OUT" ]; then
    echo "Error: $KEY_OUT or $CERT_OUT already exists."
    echo "Remove them first if you want to regenerate."
    exit 1
fi

echo "=== Creating certificate for $USERNAME ==="
echo "    Subject: $SUBJECT"
echo "    Curve:   $CURVE"
echo "    Validity: $DAYS days"
echo ""

# Generate key and CSR
echo "[1/2] Generating key and CSR..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:$CURVE \
    -keyout "$KEY_OUT" \
    -out "$CSR_TMP" \
    -nodes \
    -subj "$SUBJECT" \
    2>/dev/null

# Sign with CA
echo "[2/2] Signing with CA..."
openssl x509 -req \
    -in "$CSR_TMP" \
    -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_OUT" \
    -days $DAYS \
    -extfile "$EXT_FILE" \
    2>/dev/null

# Cleanup
rm -f "$CSR_TMP" "$CERT_DIR/ca-cert.srl"

# Permissions
chmod 600 "$KEY_OUT"
chmod 644 "$CERT_OUT"

# Show serial for revocation reference
SERIAL=$(openssl x509 -in "$CERT_OUT" -serial -noout | cut -d= -f2)

echo ""
echo "=== Done ==="
echo ""
echo "  Files created:"
echo "    cert:  $CERT_OUT"
echo "    key:   $KEY_OUT"
echo ""
echo "  Serial: $SERIAL"
echo "  To revoke: touch $SSH_DIR/crl/$SERIAL"
echo ""
echo "  Give the user these three files:"
echo "    1. $CERT_OUT          -> ~/ssh/certs/client-cert.pem"
echo "    2. $KEY_OUT           -> ~/ssh/certs/client-key.pem"
echo "    3. $CERT_DIR/ca-cert.pem  -> ~/ssh/certs/ca-cert.pem"
