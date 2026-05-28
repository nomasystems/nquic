#!/bin/bash

# run_endpoint.sh - Docker entrypoint for quic-interop-runner
#
# Environment variables (set by quic-interop-runner):
#   ROLE          - "server" or "client"
#   TESTCASE      - test name (handshake, transfer, multiconnect, etc.)
#   REQUESTS      - space-separated URLs to fetch (client only)
#   SSLKEYLOGFILE - path to write TLS key log
#   QLOGDIR       - path to write qlog files
#   DOWNLOADS     - directory to save downloaded files (client only)
#
# quic-interop-runner supported test cases:
#   handshake (H)    - TLS 1.3 handshake completes
#   transfer (D)     - Bidirectional data transfer
#   multiconnect (M) - Multiple sequential connections
#   retry (S)        - Retry token validation
#   resumption (R)   - TLS session resumption
#   zerortt (Z)      - 0-RTT early data
#   chacha20 (C)     - ChaCha20-Poly1305 cipher
#   keyupdate (U)    - Key update after transfer
#
# Exit codes:
#   0   - Test passed
#   1   - Test failed
#   127 - Unsupported test case (skipped by runner)

set -e

ROLE="${ROLE:-server}"
TESTCASE="${TESTCASE:-handshake}"
PORT="${PORT:-443}"
WWWDIR="${WWWDIR:-/www}"

# Supported test cases (exit 127 for unsupported)
case "$TESTCASE" in
    handshake|transfer|multiconnect|retry|chacha20|keyupdate|resumption|zerortt)
        ;;
    *)
        echo "Unknown test case: $TESTCASE"
        exit 127
        ;;
esac

# Wait for network simulator if present (quic-interop-runner injects this)
if command -v wait-for-it &>/dev/null; then
    wait-for-it sim:57832 -s -t 30 2>/dev/null || true
elif [ -f "/wait-for-it.sh" ]; then
    /wait-for-it.sh sim:57832 -s -t 30 2>/dev/null || true
fi

cd /app

# Build -pa arguments. interop_client/server live under test/interop;
# the ctx owner-loop driver (nquic_ctx_driver) under test/support.
PA_ARGS=""
for dir in _build/interop/lib/*/ebin; do
    [ -d "$dir" ] && PA_ARGS="$PA_ARGS -pa $dir"
done
for dir in _build/interop/lib/*/test/interop _build/interop/lib/*/test/support; do
    [ -d "$dir" ] && PA_ARGS="$PA_ARGS -pa $dir"
done

case "$ROLE" in
    server)
        echo "nquic server: port=$PORT www=$WWWDIR testcase=$TESTCASE"
        exec erl -noshell -name nquic_server@127.0.0.1 \
            $PA_ARGS \
            -eval "interop_server:start($PORT, \"$WWWDIR\")"
        ;;
    client)
        # Parse REQUESTS into individual URL paths
        # Format: "https://server:port/path1 https://server:port/path2"
        HOST=""
        PATHS=""
        for URL in $REQUESTS; do
            PARSED_HOST=$(echo "$URL" | sed -E 's|https?://([^:/]+).*|\1|')
            PARSED_PORT=$(echo "$URL" | sed -E 's|https?://[^:]+:([0-9]+).*|\1|')
            PARSED_PATH=$(echo "$URL" | sed -E 's|https?://[^/]+(/.*)|\1|')
            HOST="$PARSED_HOST"
            PORT="$PARSED_PORT"
            PATHS="$PATHS \"$PARSED_PATH\""
        done

        if [ -z "$HOST" ]; then
            echo "No REQUESTS provided"
            exit 1
        fi

        DOWNLOAD_DIR="${DOWNLOADS:-/downloads}"
        mkdir -p "$DOWNLOAD_DIR"

        echo "nquic client: host=$HOST port=$PORT testcase=$TESTCASE"

        EVAL="
            Paths = [${PATHS}],
            Code = interop_client:run_endpoint(\"$HOST\", $PORT, Paths, \"$DOWNLOAD_DIR\", \"$TESTCASE\"),
            init:stop(Code)
        "

        exec erl -noshell -name nquic_client@127.0.0.1 \
            $PA_ARGS \
            -eval "$EVAL"
        ;;
    *)
        echo "Unknown ROLE: $ROLE"
        exit 1
        ;;
esac
