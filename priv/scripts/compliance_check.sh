#!/usr/bin/env bash

# compliance_check.sh
#
# Runs QUIC compliance tools against the local nquic server.
#
# Tool: h3spec - QUIC transport error handling validation
#
# For interop testing against real implementations, use quic-interop-runner
# which tests against aioquic, quiche, ngtcp2, etc.
# See: CLAUDE.md for compliance testing details
#
# Requirements:
# - h3spec Docker image (run `make h3spec-docker`)
# - nquic built (`rebar3 as interop compile`)

set -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$DIR/../.."
LOG_DIR="$PROJECT_ROOT/test/compliance_logs"
export PORT=4433
export WWWDIR="$PROJECT_ROOT/test/interop/www"

H3SPEC_IMAGE="${H3SPEC_IMAGE:-nquic-h3spec:0.1.12}"

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

# Cleanup function
cleanup() {
    echo ""
    echo "[*] Shutting down..."
    if [ -n "${SERVER_PID:-}" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT


# 1. Ensure h3spec Docker image is available
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

# 2. Start Server
echo ""
echo "[*] Starting nquic interop server..."
cd "$PROJECT_ROOT"

rebar3 as interop compile

tail -f /dev/null | rebar3 as interop shell \
    --name "nquic_interop_$$@127.0.0.1" \
    --eval 'interop_server:start()' > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

echo "[*] Waiting 5s for server initialization..."
sleep 5

if ! ps -p "$SERVER_PID" > /dev/null; then
    echo "Error: Server failed to start. Check $LOG_DIR/server.log"
    exit 1
fi

echo "[*] Server running (PID: $SERVER_PID)"

# 3. Run h3spec
echo ""
echo "==========================================="
echo ">>> h3spec: QUIC Transport Error Handling"
echo "==========================================="

docker run --rm --network host "$H3SPEC_IMAGE" 127.0.0.1 "$PORT" -n -t 3000 \
    2>&1 | tee "$LOG_DIR/h3spec.log"

# Parse results (only QUIC tests, not HTTP/3).
# h3spec marks passes with `[v]` and failures with `[x]` at end of line.
# Note: `grep -c` with no matches prints "0" and exits 1, so `|| echo 0`
# would double-print. Use `|| true` and let grep's stdout ("0") stand.
quic_section() { sed -n '/^QUIC servers/,/^HTTP\/3 servers/{/^HTTP\/3 servers/d;p;}' "$LOG_DIR/h3spec.log"; }
H3SPEC_QUIC_PASS=$(quic_section | grep -c '\[v\]$' || true)
H3SPEC_QUIC_TOTAL=$(quic_section | grep -cE '\[[vx]\]$' || true)

# 4. Summary
echo ""
echo "==========================================="
echo "        COMPLIANCE SUMMARY"
echo "==========================================="
echo ""
echo "RFC 9000/9001/9002 (QUIC Transport + TLS)"
echo "─────────────────────────────────────────"
printf "h3spec:  %d/%d QUIC transport tests\n" "$H3SPEC_QUIC_PASS" "$H3SPEC_QUIC_TOTAL"
echo "─────────────────────────────────────────"

if [ "$H3SPEC_QUIC_PASS" -eq "$H3SPEC_QUIC_TOTAL" ] && [ "$H3SPEC_QUIC_TOTAL" -gt 0 ]; then
    echo "Status: COMPLIANT"
    echo ""
    echo "HTTP/3 failures are expected - out of scope"
    exit 0
else
    echo "Status: ISSUES FOUND"
    exit 1
fi
