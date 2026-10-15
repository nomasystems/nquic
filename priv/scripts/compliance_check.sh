#!/usr/bin/env bash

# compliance_check.sh
#
# Runs QUIC compliance tools against the local nquic server.
#
# Tool: h3spec - QUIC transport error handling validation
#
# The suite runs once per server certificate:
#
#   ecdsa  test/conf/server.pem      flight fits one 1200-byte datagram
#   rsa    test/conf/server_rsa.pem  flight exceeds 1200 bytes, so the
#                                    handshake CRYPTO fragmentation path
#                                    (budgeted off the peer's advertised
#                                    max_udp_payload_size) is exercised
#
# For interop testing against real implementations, use quic-interop-runner
# which tests against aioquic, quiche, ngtcp2, etc.
# See: CLAUDE.md for compliance testing details
#
# Requirements:
# - h3spec Docker image (run `make h3spec-docker`)
# - nquic built (`rebar3 as interop compile`)
# - test certificates (`make test-certs`)
#
# COMPLIANCE_CERTS="ecdsa rsa" selects the certificates (default: both).

set -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$DIR/../.."
LOG_DIR="$PROJECT_ROOT/test/compliance_logs"
CONF_DIR="$PROJECT_ROOT/test/conf"
export PORT=4433
export WWWDIR="$PROJECT_ROOT/test/interop/www"

H3SPEC_IMAGE="${H3SPEC_IMAGE:-nquic-h3spec:0.1.12}"
read -r -a CERT_LABELS <<< "${COMPLIANCE_CERTS:-ecdsa rsa}"

mkdir -p "$LOG_DIR"

echo "==========================================="
echo "   nquic Compliance Verification Suite"
echo "==========================================="
echo ""
echo "Target: RFC 9000 (QUIC Transport)"
echo "        RFC 9001 (QUIC TLS)"
echo "        RFC 9002 (Loss Detection)"
echo ""
echo "Note: HTTP/3 (RFC 9114) is out of scope"
echo "Logs: $LOG_DIR"

# Kill any lingering interop server from a previous run
pkill -f "nquic_interop@" 2>/dev/null || true
pkill -f "nquic_compliance_server@" 2>/dev/null || true
sleep 1

SERVER_PID=""

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

cleanup() {
    echo ""
    echo "[*] Shutting down..."
    stop_server
}
trap cleanup EXIT

cert_file() { case "$1" in ecdsa) echo "$CONF_DIR/server.pem" ;; rsa) echo "$CONF_DIR/server_rsa.pem" ;; esac; }
key_file()  { case "$1" in ecdsa) echo "$CONF_DIR/server.key" ;; rsa) echo "$CONF_DIR/server_rsa.key" ;; esac; }

# 1. Ensure h3spec Docker image and certificates are available
echo ""
if ! command -v docker > /dev/null 2>&1; then
    echo "Error: docker not found in PATH (required to run h3spec)"
    exit 1
fi
if ! docker image inspect "$H3SPEC_IMAGE" > /dev/null 2>&1; then
    echo "Error: h3spec image '$H3SPEC_IMAGE' not found"
    echo "Run: make h3spec-docker"
    exit 1
fi
echo "[*] h3spec image: $H3SPEC_IMAGE"
for label in "${CERT_LABELS[@]}"; do
    if [ ! -f "$(cert_file "$label")" ] || [ ! -f "$(key_file "$label")" ]; then
        echo "Error: $label test certificate not found in $CONF_DIR"
        echo "Run: make test-certs"
        exit 1
    fi
done

# 2. Build the server once
echo ""
cd "$PROJECT_ROOT"
rebar3 as interop compile

# start_server LABEL: launch the interop server with the certificate for LABEL.
start_server() {
    local label="$1"
    echo ""
    echo "[*] Starting nquic interop server ($label certificate)..."
    tail -f /dev/null | \
    NQUIC_CERTFILE="$(cert_file "$label")" NQUIC_KEYFILE="$(key_file "$label")" \
    rebar3 as interop shell \| rebar3 as interop shell \
        --name "nquic_interop_$$@127.0.0.1" \
        --eval 'interop_server:start()' > "$LOG_DIR/server_$label.log" 2>&1 &
    SERVER_PID=$!

    echo "[*] Waiting 5s for server initialization..."
    sleep 5

    if ! ps -p "$SERVER_PID" > /dev/null; then
        echo "Error: Server failed to start. Check $LOG_DIR/server_$label.log"
        exit 1
    fi
    echo "[*] Server running (PID: $SERVER_PID)"
}

# Parse results (only QUIC tests, not HTTP/3).
# h3spec marks passes with `[v]` and failures with `[x]` at end of line.
# Note: `grep -c` with no matches prints "0" and exits 1, so `|| echo 0`
# would double-print. Use `|| true` and let grep's stdout ("0") stand.
quic_section() { sed -n '/^QUIC servers/,/^HTTP\/3 servers/{/^HTTP\/3 servers/d;p;}' "$1"; }

# run_h3spec LABEL: one full h3spec pass; records PASS_<label> and TOTAL_<label>.
run_h3spec() {
    local label="$1" log="$LOG_DIR/h3spec_$label.log"
    start_server "$label"
    echo ""
    echo "==========================================="
    echo ">>> h3spec: QUIC Transport Error Handling ($label certificate)"
    echo "==========================================="
    docker run --rm --network host "$H3SPEC_IMAGE" 127.0.0.1 "$PORT" -n -t 3000 \
        2>&1 | tee "$log"
    stop_server
    eval "PASS_$label=\$(quic_section \"$log\" | grep -c '\[v\]\$' || true)"
    eval "TOTAL_$label=\$(quic_section \"$log\" | grep -cE '\[[vx]\]\$' || true)"
}

# 3. Run h3spec once per certificate
for label in "${CERT_LABELS[@]}"; do
    run_h3spec "$label"
done

# 4. Summary
echo ""
echo "==========================================="
echo "        COMPLIANCE SUMMARY"
echo "==========================================="
echo ""
echo "RFC 9000/9001/9002 (QUIC Transport + TLS)"
echo "─────────────────────────────────────────"
STATUS=0
for label in "${CERT_LABELS[@]}"; do
    pass="PASS_$label"; total="TOTAL_$label"
    printf "h3spec (%-5s cert):  %d/%d QUIC transport tests\n" "$label" "${!pass}" "${!total}"
    if [ "${!pass}" -ne "${!total}" ] || [ "${!total}" -eq 0 ]; then
        STATUS=1
    fi
done
echo "─────────────────────────────────────────"

if [ "$STATUS" -eq 0 ]; then
    echo "Status: COMPLIANT"
    echo ""
    echo "HTTP/3 failures are expected - out of scope"
    exit 0
else
    echo "Status: ISSUES FOUND"
    exit 1
fi
