#!/bin/bash
set -e

cd "$(dirname "$0")"

CERT_DIR="./certs"
DAYS_VALID=365

if [ ! -d "$CERT_DIR" ]; then
    mkdir -p "$CERT_DIR"
    echo "Created $CERT_DIR directory"
fi

if [ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/key.pem" ]; then
    echo "Certificate files already exist in $CERT_DIR"
    read -p "Overwrite? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

echo "Generating self-signed TLS certificate for $DAYS_VALID days..."
openssl req -x509 -newkey rsa:4096 \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days $DAYS_VALID \
    -nodes \
    -subj "/C=US/ST=State/L=City/O=Subrosa/CN=Subrosa.local"

chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem"

echo "✓ Certificate generated successfully"
echo "  Private key: $CERT_DIR/key.pem"
echo "  Certificate: $CERT_DIR/cert.pem"
echo ""
echo "Certificate fingerprint (SHA256):"
openssl x509 -in "$CERT_DIR/cert.pem" -noout -fingerprint -sha256
