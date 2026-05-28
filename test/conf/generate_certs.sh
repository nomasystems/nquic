#!/usr/bin/env bash
#
# generate_certs.sh
#
# Generates a self-signed ECDSA private key and certificate for local
# QUIC testing (TLS 1.3 with prime256v1).
#
# The repository does NOT ship a committed key/cert; the material is
# regenerated on demand by the test harness and by this script.
#
# Usage:
#   ./generate_certs.sh              # writes server.{key,pem} next to this script
#   ./generate_certs.sh /some/dir    # writes server.{key,pem} to /some/dir

set -euo pipefail

if [[ $# -ge 1 ]]; then
    DIR="$1"
else
    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
fi

mkdir -p "$DIR"
KEY_FILE="$DIR/server.key"
CERT_FILE="$DIR/server.pem"

if [[ -f "$KEY_FILE" && -f "$CERT_FILE" ]]; then
    echo "test certificate already present at $DIR, nothing to do"
    exit 0
fi

if ! command -v openssl &> /dev/null; then
    echo "Error: openssl not found in PATH." >&2
    exit 1
fi

echo "generating test certificate in $DIR"

# EC P-256 private key
openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_FILE"
chmod 600 "$KEY_FILE"

# Self-signed certificate, 10 years so CI doesn't silently break.
# SAN covers localhost + loopback for tools that pin the name.
openssl req -new -x509 -days 3650 -nodes \
    -key "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

echo "wrote: $KEY_FILE"
echo "wrote: $CERT_FILE"
