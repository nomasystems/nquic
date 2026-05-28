#!/usr/bin/env bash

# compliance_interop.sh
#
# Structured RFC compliance test suite for nquic.
# Tests specific RFC 9000/9001/9002 requirements against Docker images
# of reference QUIC implementations.
#
# Usage:
#   ./priv/scripts/compliance_interop.sh                # All implementations
#   ./priv/scripts/compliance_interop.sh aioquic        # Single implementation
#   ./priv/scripts/compliance_interop.sh ngtcp2
#   ./priv/scripts/compliance_interop.sh picoquic
#   ./priv/scripts/compliance_interop.sh self           # Self-test (no Docker)
#
# Docker images:
#   aiortc/aioquic-qns:latest
#   ghcr.io/ngtcp2/ngtcp2-interop:latest
#   privateoctopus/picoquic:latest

set -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$DIR/../.."
LOG_DIR="$PROJECT_ROOT/test/compliance_logs/compliance"
CERT_DIR="$PROJECT_ROOT/test/conf"
WWW_DIR="$PROJECT_ROOT/test/interop/www"
export PORT=4433
REBAR="${PROJECT_ROOT}/rebar3"

# Docker image map
declare -A DOCKER_IMAGES
DOCKER_IMAGES[aioquic]="aiortc/aioquic-qns:latest"
DOCKER_IMAGES[ngtcp2]="ghcr.io/ngtcp2/ngtcp2-interop:latest"
DOCKER_IMAGES[picoquic]="privateoctopus/picoquic:latest"

# Test definitions
# Format: test_name:description:erlang_function
TESTS=(
    "handshake:TLS 1.3 handshake + transport params:test_handshake"
    "transfer:Stream data transfer (small file):test_transfer"
    "multiconnect:5 sequential connections:test_multiconnect"
    "version_negotiation:VN packet for bad version:test_version_negotiation"
    "connection_close:Clean shutdown with NO_ERROR:test_connection_close"
    "stream_fin:FIN handling (half-close):test_stream_fin"
)

# Parse arguments
IMPL="${1:-all}"

mkdir -p "$LOG_DIR"

# Kill any leftover nodes from previous runs
pkill -f "nquic_compliance_server@" 2>/dev/null || true
pkill -f "nquic_ct_.*@" 2>/dev/null || true
sleep 1

# Start a dummy "sim" listener on port 57832.
# quic-interop-runner images wait for this before starting their client.
start_sim_listener() {
    if [ -n "${SIM_PID:-}" ]; then
        return
    fi
    if command -v socat &>/dev/null; then
        socat TCP-LISTEN:57832,fork,reuseaddr /dev/null &
    elif command -v ncat &>/dev/null; then
        ncat -lk 57832 > /dev/null 2>&1 &
    else
        echo "Warning: neither socat nor ncat found, Docker clients may hang"
        return
    fi
    SIM_PID=$!
}

# Cleanup function
cleanup() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "${SIM_PID:-}" ]; then
        kill -TERM "$SIM_PID" 2>/dev/null || true
        wait "$SIM_PID" 2>/dev/null || true
    fi
    docker rm -f nquic-compliance-server 2>/dev/null || true
    docker rm -f nquic-compliance-client 2>/dev/null || true
}
trap cleanup EXIT

echo "==========================================="
echo "   nquic RFC Compliance Test Suite"
echo "==========================================="
echo ""
echo "Tests:"
for t in "${TESTS[@]}"; do
    IFS=':' read -r name desc _func <<< "$t"
    printf "  %-22s %s\n" "$name" "$desc"
done
echo ""
echo "Logs: $LOG_DIR"
echo ""

# Build nquic (interop profile)
echo "[*] Building nquic..."
cd "$PROJECT_ROOT"
if ! rebar3 as interop compile > "$LOG_DIR/compile.log" 2>&1; then
    echo "    Build failed (see $LOG_DIR/compile.log)"
    exit 1
fi
echo "    Build complete"
echo ""

# ============================================================
# Run a single test against a target (self or Docker)
# Uses rebar3 as interop shell --eval to get correct code paths.
# ============================================================
run_test() {
    local TEST_NAME="$1"
    local TEST_FUNC="$2"
    local HOST="$3"
    local TEST_PORT="$4"
    local IMPL_NAME="$5"

    local LOG_FILE="$LOG_DIR/${IMPL_NAME}_${TEST_NAME}.log"
    local NODE_NAME="nquic_ct_${IMPL_NAME}_${TEST_NAME}_$$@127.0.0.1"

    # Build eval string based on test function
    local EVAL=""
    case "$TEST_FUNC" in
        test_handshake)
            EVAL="case compliance_tests:test_handshake(\"$HOST\", $TEST_PORT) of ok -> halt(0); {error, R} -> io:format(\"FAIL: ~p~n\", [R]), halt(1) end"
            ;;
        test_transfer)
            EVAL="case compliance_tests:test_transfer(\"$HOST\", $TEST_PORT, \"/small.txt\") of ok -> halt(0); {error, R} -> io:format(\"FAIL: ~p~n\", [R]), halt(1) end"
            ;;
        test_multiconnect)
            EVAL="case compliance_tests:test_multiconnect(\"$HOST\", $TEST_PORT) of ok -> halt(0); {error, R} -> io:format(\"FAIL: ~p~n\", [R]), halt(1) end"
            ;;
        test_version_negotiation)
            EVAL="case compliance_tests:test_version_negotiation(\"$HOST\", $TEST_PORT) of ok -> halt(0); {error, R} -> io:format(\"FAIL: ~p~n\", [R]), halt(1) end"
            ;;
        test_connection_close)
            EVAL="case compliance_tests:test_connection_close(\"$HOST\", $TEST_PORT) of ok -> halt(0); {error, R} -> io:format(\"FAIL: ~p~n\", [R]), halt(1) end"
            ;;
        test_stream_fin)
            EVAL="case compliance_tests:test_stream_fin(\"$HOST\", $TEST_PORT) of ok -> halt(0); {error, R} -> io:format(\"FAIL: ~p~n\", [R]), halt(1) end"
            ;;
        *)
            echo "      Unknown test function: $TEST_FUNC"
            return 1
            ;;
    esac

    rebar3 as interop shell --name "$NODE_NAME" --eval "$EVAL" > "$LOG_FILE" 2>&1
    return $?
}

# ============================================================
# Start nquic server for testing
# ============================================================
start_nquic_server() {
    local SERVER_PORT="$1"
    local LOG_FILE="$LOG_DIR/nquic_server.log"

    export PORT="$SERVER_PORT"
    export WWWDIR="$WWW_DIR"

    # tail -f keeps stdin open so rebar3 shell doesn't exit on EOF
    tail -f /dev/null | rebar3 as interop shell \
        --name "nquic_compliance_server_$$@127.0.0.1" \
        --eval 'interop_server:start()' > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    sleep 3

    if ! ps -p "$SERVER_PID" > /dev/null 2>&1; then
        echo "    Server failed to start (see $LOG_FILE)"
        unset SERVER_PID
        return 1
    fi
    return 0
}

stop_nquic_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        unset SERVER_PID
    fi
}

# ============================================================
# Start Docker server for testing
# ============================================================
start_docker_server() {
    local IMPL_NAME="$1"
    local IMAGE="${DOCKER_IMAGES[$IMPL_NAME]}"
    local SERVER_PORT="$2"

    local DOCKER_LOGS="/tmp/nquic-compliance-logs"
    mkdir -p "$DOCKER_LOGS" "$DOCKER_LOGS/qlog"

    docker rm -f nquic-compliance-server 2>/dev/null || true
    docker run -d --rm --name nquic-compliance-server \
        --network host \
        --add-host sim:127.0.0.1 \
        -v "$CERT_DIR/server.key:/certs/priv.key:ro" \
        -v "$CERT_DIR/server.pem:/certs/cert.pem:ro" \
        -v "$WWW_DIR:/www:ro" \
        -v "$DOCKER_LOGS:/logs" \
        -e ROLE=server \
        -e TESTCASE=transfer \
        -e PORT="$SERVER_PORT" \
        -e QLOGDIR=/logs/qlog \
        -e SSLKEYLOGFILE=/logs/keys.log \
        "$IMAGE" > "$LOG_DIR/${IMPL_NAME}_docker_server.log" 2>&1

    sleep 3

    if ! docker ps --format '{{.Names}}' | grep -q nquic-compliance-server; then
        echo "    Docker server failed to start"
        return 1
    fi
    return 0
}

stop_docker_server() {
    docker rm -f nquic-compliance-server 2>/dev/null || true
}

# ============================================================
# Run all tests against a target
# ============================================================
run_test_suite() {
    local IMPL_NAME="$1"
    local HOST="$2"
    local TEST_PORT="$3"
    local DIRECTION="$4"

    local PASS=0
    local FAIL=0
    local SKIP=0

    for t in "${TESTS[@]}"; do
        IFS=':' read -r name desc func <<< "$t"
        printf "    %-22s " "$name"

        if run_test "$name" "$func" "$HOST" "$TEST_PORT" "${IMPL_NAME}_${DIRECTION}"; then
            echo "PASS"
            PASS=$((PASS + 1))
        else
            EXIT_CODE=$?
            if [ "$EXIT_CODE" -eq 127 ]; then
                echo "SKIP"
                SKIP=$((SKIP + 1))
            else
                echo "FAIL"
                FAIL=$((FAIL + 1))
            fi
        fi
    done

    printf "\n    Results: %d PASS, %d FAIL, %d SKIP\n\n" "$PASS" "$FAIL" "$SKIP"
    [ "$FAIL" -eq 0 ]
}

# ============================================================
# Self-interop compliance
# ============================================================
run_self_compliance() {
    echo "==========================================="
    echo "   Self-Compliance (nquic client -> nquic server)"
    echo "==========================================="
    echo ""

    echo "[*] Starting nquic server on port $PORT..."
    if ! start_nquic_server "$PORT"; then
        return 1
    fi
    echo "    Server running (PID: $SERVER_PID)"
    echo ""

    run_test_suite "self" "127.0.0.1" "$PORT" "client_to_server"
    local RESULT=$?

    stop_nquic_server
    return $RESULT
}

# ============================================================
# Docker-based compliance
# ============================================================
run_docker_compliance() {
    local IMPL_NAME="$1"
    local IMAGE="${DOCKER_IMAGES[$IMPL_NAME]}"

    echo "==========================================="
    echo "   $IMPL_NAME Compliance Tests"
    echo "==========================================="
    echo ""

    # Pull image
    echo "[*] Pulling $IMAGE..."
    if ! docker pull "$IMAGE" > "$LOG_DIR/${IMPL_NAME}_pull.log" 2>&1; then
        echo "    Failed to pull image (is Docker running?)"
        return 1
    fi
    echo "    Image ready"
    echo ""

    local TOTAL_PASS=0
    local TOTAL_FAIL=0

    # Direction A: nquic client -> Docker server
    echo "--- nquic client -> $IMPL_NAME server ---"
    echo ""
    if start_docker_server "$IMPL_NAME" "$PORT"; then
        if run_test_suite "$IMPL_NAME" "127.0.0.1" "$PORT" "nquic_to_docker"; then
            TOTAL_PASS=$((TOTAL_PASS + 1))
        else
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
        fi
        stop_docker_server
    else
        echo "    Skipping (server failed to start)"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi

    # Direction B: Docker client -> nquic server
    echo "--- $IMPL_NAME client -> nquic server ---"
    echo ""
    echo "[*] Starting nquic server on port $PORT..."
    if start_nquic_server "$PORT"; then
        echo "    Server running"
        echo ""

        # Run Docker client for handshake + transfer tests
        local B_PASS=0
        local B_FAIL=0
        local B_DOCKER_LOGS="/tmp/nquic-compliance-logs"
        mkdir -p "$B_DOCKER_LOGS" "$B_DOCKER_LOGS/qlog" "/tmp/compliance-downloads"

        start_sim_listener

        for TESTCASE in handshake transfer; do
            printf "    %-22s " "$TESTCASE"
            docker rm -f nquic-compliance-client 2>/dev/null || true
            docker run --rm --name nquic-compliance-client \
                --network host \
                --add-host sim:127.0.0.1 \
                -v "/tmp/compliance-downloads:/downloads" \
                -v "$B_DOCKER_LOGS:/logs" \
                -e ROLE=client \
                -e TESTCASE="$TESTCASE" \
                -e REQUESTS="https://127.0.0.1:$PORT/small.txt" \
                -e QLOGDIR=/logs/qlog \
                -e SSLKEYLOGFILE=/logs/keys.log \
                "$IMAGE" > "$LOG_DIR/${IMPL_NAME}_${TESTCASE}_client.log" 2>&1
            if [ $? -eq 0 ]; then
                echo "PASS"
                B_PASS=$((B_PASS + 1))
            else
                echo "FAIL"
                B_FAIL=$((B_FAIL + 1))
            fi
        done

        printf "\n    Results: %d PASS, %d FAIL\n\n" "$B_PASS" "$B_FAIL"
        [ "$B_FAIL" -eq 0 ] && TOTAL_PASS=$((TOTAL_PASS + 1)) || TOTAL_FAIL=$((TOTAL_FAIL + 1))

        stop_nquic_server
    else
        echo "    Skipping (nquic server failed to start)"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi

    echo "==========================================="
    printf "  $IMPL_NAME: %d suite(s) PASS, %d suite(s) FAIL\n" "$TOTAL_PASS" "$TOTAL_FAIL"
    echo "==========================================="
    echo ""

    [ "$TOTAL_FAIL" -eq 0 ]
}

# ============================================================
# Main dispatch
# ============================================================

GRAND_PASS=0
GRAND_FAIL=0

case "$IMPL" in
    self)
        run_self_compliance && GRAND_PASS=$((GRAND_PASS + 1)) || GRAND_FAIL=$((GRAND_FAIL + 1))
        ;;
    aioquic|ngtcp2|picoquic)
        run_self_compliance && GRAND_PASS=$((GRAND_PASS + 1)) || GRAND_FAIL=$((GRAND_FAIL + 1))
        run_docker_compliance "$IMPL" && GRAND_PASS=$((GRAND_PASS + 1)) || GRAND_FAIL=$((GRAND_FAIL + 1))
        ;;
    all)
        run_self_compliance && GRAND_PASS=$((GRAND_PASS + 1)) || GRAND_FAIL=$((GRAND_FAIL + 1))
        for impl in aioquic ngtcp2 picoquic; do
            run_docker_compliance "$impl" && GRAND_PASS=$((GRAND_PASS + 1)) || GRAND_FAIL=$((GRAND_FAIL + 1))
        done
        ;;
    *)
        echo "Unknown implementation: $IMPL"
        echo "Supported: self, aioquic, ngtcp2, picoquic, all"
        exit 1
        ;;
esac

echo ""
echo "==========================================="
echo "     COMPLIANCE SUITE SUMMARY"
echo "==========================================="
printf "  Suites: %d PASS, %d FAIL\n" "$GRAND_PASS" "$GRAND_FAIL"
echo "==========================================="

[ "$GRAND_FAIL" -eq 0 ]
