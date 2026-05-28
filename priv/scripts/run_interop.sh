#!/usr/bin/env bash

# run_interop.sh
#
# Run interoperability tests for nquic using Docker images.
#
# Usage:
#   ./priv/scripts/run_interop.sh                # Self-interop (nquic vs nquic)
#   ./priv/scripts/run_interop.sh ngtcp2         # Docker-based vs ngtcp2
#   ./priv/scripts/run_interop.sh picoquic       # Docker-based vs picoquic
#   ./priv/scripts/run_interop.sh all            # All implementations
#
# Docker images (quic-interop-runner standard):
#   ghcr.io/ngtcp2/ngtcp2-interop:latest
#   privateoctopus/picoquic:latest
#
# Note: aioquic-qns image is not usable standalone (broken entrypoint,
# aioquic not installed). Use the full quic-interop-runner for aioquic.

set -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$DIR/../.."
LOG_DIR="$PROJECT_ROOT/test/compliance_logs/interop"
CERT_DIR="$PROJECT_ROOT/test/conf"
WWW_DIR="$PROJECT_ROOT/test/interop/www"
PORT=4433

# Docker image map
declare -A DOCKER_IMAGES
DOCKER_IMAGES[ngtcp2]="ghcr.io/ngtcp2/ngtcp2-interop:latest"
DOCKER_IMAGES[picoquic]="privateoctopus/picoquic:latest"

# Parse arguments
IMPL="${1:-all}"

mkdir -p "$LOG_DIR"

# Kill any leftover Erlang nodes from previous runs
kill_leftover_nodes() {
    pkill -f "nquic_server@127.0.0.1" 2>/dev/null || true
    pkill -f "nquic_server_ext@127.0.0.1" 2>/dev/null || true
    pkill -f "nquic_client" 2>/dev/null || true
    sleep 1
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
    docker rm -f nquic-interop-server 2>/dev/null || true
    docker rm -f nquic-interop-client 2>/dev/null || true
}
trap cleanup EXIT

# Start a dummy "sim" listener on port 57832.
# quic-interop-runner images (ngtcp2, picoquic) wait for this service
# before starting their client. Providing it lets them proceed immediately.
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

kill_leftover_nodes

echo "==========================================="
echo "   nquic Interoperability Test Suite"
echo "==========================================="
echo ""
echo "Logs: $LOG_DIR"
echo ""

# Build nquic (interop profile)
echo "[*] Building nquic..."
cd "$PROJECT_ROOT"
if ! rebar3 as interop compile > "$LOG_DIR/compile.log" 2>&1; then
    echo "    Build failed (see $LOG_DIR/compile.log)"
    cat "$LOG_DIR/compile.log"
    exit 1
fi
echo "    Build complete"
echo ""

# ============================================================
# Self-interop test
# ============================================================
run_self_interop() {
    echo "==========================================="
    echo "   Self-Interop Tests (nquic vs nquic)"
    echo "==========================================="
    echo ""

    local PASS=0
    local FAIL=0

    # Start nquic server (tail -f keeps stdin open so rebar3 shell doesn't exit)
    echo "[*] Starting nquic server on port $PORT..."
    export PORT WWWDIR="$WWW_DIR"
    tail -f /dev/null | rebar3 as interop shell \
        --name "nquic_server@127.0.0.1" \
        --eval 'interop_server:start()' > "$LOG_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 3

    if ! ps -p "$SERVER_PID" > /dev/null 2>&1; then
        echo "    Server failed to start!"
        cat "$LOG_DIR/server.log"
        return 1
    fi
    echo "    Server running (PID: $SERVER_PID)"
    echo ""

    # Test 1: Handshake
    # nquic:connect uses start_link, so any async statem exit would
    # kill the shell eval process before it can print PASS/FAIL. Wrap
    # the test in a spawn+monitor so the eval reports the actual result.
    # Pipe `tail -f /dev/null` into rebar3 to keep stdin open: without
    # it, the shell halts on stdin-EOF the moment the eval submits its
    # expression, which is before the monitor receive can fire.
    echo ">>> Test 1: Handshake"
    echo "-------------------------------------------"
    tail -f /dev/null | rebar3 as interop shell \
        --name "nquic_client_1_$$@127.0.0.1" \
        --eval "P = self(), Pid = spawn(fun() -> process_flag(trap_exit, true), R = interop_client:test_handshake(\"127.0.0.1\", $PORT), P ! {res, R} end), Ref = erlang:monitor(process, Pid), receive {res, ok} -> io:format(\"PASS~n\"), init:stop(0); {res, {error, Rsn}} -> io:format(\"FAIL: ~p~n\", [Rsn]), init:stop(1); {'DOWN', Ref, _, _, Reason} -> io:format(\"FAIL: crashed ~p~n\", [Reason]), init:stop(1) after 30000 -> io:format(\"FAIL: timeout~n\"), init:stop(1) end" \
        2>&1 | tee "$LOG_DIR/self_handshake.log"
    # Both exit code and PASS marker must line up: a silent crash
    # (eval killed by a linked process) can leave exit 0 with no output.
    if grep -q '^PASS$' "$LOG_DIR/self_handshake.log"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
    echo ""

    # Test 2: Data Transfer
    echo ">>> Test 2: Data Transfer"
    echo "-------------------------------------------"
    tail -f /dev/null | rebar3 as interop shell \
        --name "nquic_client_2_$$@127.0.0.1" \
        --eval "P = self(), Pid = spawn(fun() -> process_flag(trap_exit, true), R = interop_client:test_transfer(\"127.0.0.1\", $PORT), P ! {res, R} end), Ref = erlang:monitor(process, Pid), receive {res, ok} -> io:format(\"PASS~n\"), init:stop(0); {res, {error, Rsn}} -> io:format(\"FAIL: ~p~n\", [Rsn]), init:stop(1); {'DOWN', Ref, _, _, Reason} -> io:format(\"FAIL: crashed ~p~n\", [Reason]), init:stop(1) after 30000 -> io:format(\"FAIL: timeout~n\"), init:stop(1) end" \
        2>&1 | tee "$LOG_DIR/self_transfer.log"
    if grep -q '^PASS$' "$LOG_DIR/self_transfer.log"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
    echo ""

    # Stop server
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    unset SERVER_PID
    sleep 1

    echo "==========================================="
    echo "     SELF-INTEROP SUMMARY"
    echo "==========================================="
    printf "Total: %d PASS, %d FAIL\n" "$PASS" "$FAIL"
    echo "==========================================="
    echo ""

    [ "$FAIL" -eq 0 ]
}

# ============================================================
# Docker-based interop test
# ============================================================
run_docker_interop() {
    local IMPL_NAME="$1"
    local IMAGE="${DOCKER_IMAGES[$IMPL_NAME]}"

    echo "==========================================="
    echo "   $IMPL_NAME Interop Tests (Docker)"
    echo "==========================================="
    echo ""

    local PASS=0
    local FAIL=0
    local DOCKER_LOGS="/tmp/nquic-interop-logs"
    mkdir -p "$DOCKER_LOGS" "$DOCKER_LOGS/qlog" "/tmp/interop-downloads"

    # Ensure sim listener is running (ngtcp2/picoquic need it)
    start_sim_listener

    # Pull the image if needed
    echo "[*] Pulling $IMAGE..."
    if ! docker pull "$IMAGE" > "$LOG_DIR/${IMPL_NAME}_pull.log" 2>&1; then
        echo "    Failed to pull $IMAGE"
        echo "    (Is Docker running? Do you have internet access?)"
        return 1
    fi
    echo "    Image ready"
    echo ""

    # ----------------------------------------------------------
    # Test A: nquic client -> Docker server
    # ----------------------------------------------------------
    echo ">>> Test A: nquic client -> $IMPL_NAME server"
    echo "-------------------------------------------"

    # Kill leftover nodes before starting Docker server
    kill_leftover_nodes

    docker rm -f nquic-interop-server 2>/dev/null || true
    docker run -d --rm --name nquic-interop-server \
        --network host \
        --add-host sim:127.0.0.1 \
        -v "$CERT_DIR/server.key:/certs/priv.key:ro" \
        -v "$CERT_DIR/server.pem:/certs/cert.pem:ro" \
        -v "$WWW_DIR:/www:ro" \
        -v "$DOCKER_LOGS:/logs" \
        -e ROLE=server \
        -e TESTCASE=handshake \
        -e QLOGDIR=/logs/qlog \
        -e SSLKEYLOGFILE=/logs/keys.log \
        "$IMAGE" > "$LOG_DIR/${IMPL_NAME}_docker_server.log" 2>&1

    sleep 5

    # Verify the Docker server is still running
    if ! docker ps --format '{{.Names}}' | grep -q nquic-interop-server; then
        echo "    Docker server exited prematurely"
        echo "    Log:"
        docker logs nquic-interop-server 2>&1 | tail -5 || true
        FAIL=$((FAIL + 1))
        echo "    Result: FAIL"
    else
        # Connect nquic client to Docker server on port 443 (Docker has root)
        tail -f /dev/null | rebar3 as interop shell \
            --name "nquic_client_a_$$@127.0.0.1" \
            --eval "P = self(), Pid = spawn(fun() -> process_flag(trap_exit, true), R = interop_client:test_handshake(\"127.0.0.1\", 443), P ! {res, R} end), Ref = erlang:monitor(process, Pid), receive {res, ok} -> io:format(\"PASS~n\"), init:stop(0); {res, {error, Rsn}} -> io:format(\"FAIL: ~p~n\", [Rsn]), init:stop(1); {'DOWN', Ref, _, _, Reason} -> io:format(\"FAIL: crashed ~p~n\", [Reason]), init:stop(1) after 30000 -> io:format(\"FAIL: timeout~n\"), init:stop(1) end" \
            2>&1 | tee "$LOG_DIR/${IMPL_NAME}_test_a.log"

        if grep -q '^PASS$' "$LOG_DIR/${IMPL_NAME}_test_a.log"; then
            PASS=$((PASS + 1))
            echo "    Result: PASS"
        else
            FAIL=$((FAIL + 1))
            echo "    Result: FAIL"
        fi
    fi

    docker rm -f nquic-interop-server 2>/dev/null || true
    echo ""

    # ----------------------------------------------------------
    # Test B: Docker client -> nquic server
    # ----------------------------------------------------------
    echo ">>> Test B: $IMPL_NAME client -> nquic server"
    echo "-------------------------------------------"

    # Start nquic server on port 4433 (tail -f keeps stdin open)
    export PORT WWWDIR="$WWW_DIR"
    tail -f /dev/null | rebar3 as interop shell \
        --name "nquic_server_ext_$$@127.0.0.1" \
        --eval 'interop_server:start()' > "$LOG_DIR/${IMPL_NAME}_nquic_server.log" 2>&1 &
    SERVER_PID=$!
    sleep 3

    if ! ps -p "$SERVER_PID" > /dev/null 2>&1; then
        echo "    Server failed to start!"
        cat "$LOG_DIR/${IMPL_NAME}_nquic_server.log"
        FAIL=$((FAIL + 1))
    else
        docker rm -f nquic-interop-client 2>/dev/null || true
        docker run --rm --name nquic-interop-client \
            --network host \
            --add-host sim:127.0.0.1 \
            -v "/tmp/interop-downloads:/downloads" \
            -v "$DOCKER_LOGS:/logs" \
            -e ROLE=client \
            -e TESTCASE=handshake \
            -e REQUESTS="https://127.0.0.1:$PORT/small.txt" \
            -e QLOGDIR=/logs/qlog \
            -e SSLKEYLOGFILE=/logs/keys.log \
            "$IMAGE" > "$LOG_DIR/${IMPL_NAME}_test_b.log" 2>&1
        DOCKER_EXIT=$?

        if [ "$DOCKER_EXIT" -eq 0 ]; then
            PASS=$((PASS + 1))
            echo "    Result: PASS"
        else
            FAIL=$((FAIL + 1))
            echo "    Result: FAIL (exit code: $DOCKER_EXIT)"
            echo "    Log:"
            tail -10 "$LOG_DIR/${IMPL_NAME}_test_b.log" 2>/dev/null || true
        fi
    fi

    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    unset SERVER_PID
    echo ""

    # Summary
    echo "==========================================="
    echo "     $IMPL_NAME INTEROP SUMMARY"
    echo "==========================================="
    printf "Total: %d PASS, %d FAIL\n" "$PASS" "$FAIL"
    echo "==========================================="
    echo ""

    [ "$FAIL" -eq 0 ]
}

# ============================================================
# Main dispatch
# ============================================================

TOTAL_PASS=0
TOTAL_FAIL=0

case "$IMPL" in
    "")
        run_self_interop
        ;;
    all)
        run_self_interop && TOTAL_PASS=$((TOTAL_PASS + 1)) || TOTAL_FAIL=$((TOTAL_FAIL + 1))
        for impl in ngtcp2 picoquic; do
            run_docker_interop "$impl" && TOTAL_PASS=$((TOTAL_PASS + 1)) || TOTAL_FAIL=$((TOTAL_FAIL + 1))
        done
        echo ""
        echo "==========================================="
        echo "     FULL INTEROP SUMMARY"
        echo "==========================================="
        printf "Implementation suites: %d PASS, %d FAIL\n" "$TOTAL_PASS" "$TOTAL_FAIL"
        echo "==========================================="
        [ "$TOTAL_FAIL" -eq 0 ]
        ;;
    ngtcp2|picoquic)
        run_docker_interop "$IMPL"
        ;;
    aioquic)
        echo "aioquic-qns image is not usable standalone."
        echo "Use the full quic-interop-runner for aioquic testing."
        echo "See: https://github.com/quic-interop/quic-interop-runner"
        exit 1
        ;;
    *)
        echo "Unknown implementation: $IMPL"
        echo "Supported: ngtcp2, picoquic, all"
        exit 1
        ;;
esac
