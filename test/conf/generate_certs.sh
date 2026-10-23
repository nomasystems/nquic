#!/usr/bin/env bash
#
# generate_certs.sh
#
# Generates self-signed private keys and certificates for local QUIC
# testing (TLS 1.3):
#
#   server.{key,pem}      ECDSA prime256v1, ~600 B certificate
#   server_rsa.{key,pem}  RSA-2048, ~1.3 KB certificate
#
# The RSA pair exists so that the server handshake flight exceeds a
# 1200-byte datagram and exercises CRYPTO fragmentation.
#
# The repository does NOT ship committed keys/certs; the material is
# regenerated on demand by the test harness and by this script.
#
# Usage:
#   ./generate_certs.sh              # writes into the directory of this script
#   ./generate_certs.sh /some/dir    # writes into /some/dir

set -euo pipefail

if [[ $# -ge 1 ]]; then
    DIR="$1"
else
    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
fi

mkdir -p "$DIR"

if ! command -v openssl &> /dev/null; then
    echo "Error: openssl not found in PATH." >&2
    exit 1
fi

# Self-signed certificate, 10 years so CI doesn't silently break.
# SAN covers localhost + loopback for tools that pin the name.
sign_cert() {
    local key_file="$1" cert_file="$2"
    openssl req -new -x509 -days 3650 -nodes \
        -key "$key_file" \
        -out "$cert_file" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    echo "wrote: $key_file"
    echo "wrote: $cert_file"
}

EC_KEY="$DIR/server.key"
EC_CERT="$DIR/server.pem"
if [[ -f "$EC_KEY" && -f "$EC_CERT" ]]; then
    echo "ECDSA test certificate already present at $DIR, nothing to do"
else
    echo "generating ECDSA test certificate in $DIR"
    openssl ecparam -name prime256v1 -genkey -noout -out "$EC_KEY"
    chmod 600 "$EC_KEY"
    sign_cert "$EC_KEY" "$EC_CERT"
fi

RSA_KEY="$DIR/server_rsa.key"
RSA_CERT="$DIR/server_rsa.pem"
if [[ -f "$RSA_KEY" && -f "$RSA_CERT" ]]; then
    echo "RSA test certificate already present at $DIR, nothing to do"
else
    echo "generating RSA-2048 test certificate in $DIR"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RSA_KEY" 2>/dev/null
    chmod 600 "$RSA_KEY"
    sign_cert "$RSA_KEY" "$RSA_CERT"
fi
