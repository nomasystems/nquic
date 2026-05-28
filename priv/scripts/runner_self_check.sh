#!/usr/bin/env bash

# runner_self_check.sh
#
# Local, Docker-free verification of every TESTCASE that
# `priv/interop/run_endpoint.sh` accepts. For each testcase we:
#
#   1. Start an nquic interop server with `TESTCASE=<name>` so that
#      `interop_server:apply_testcase_opts/2` configures the server-side
#      knobs (e.g. retry=true, cipher_suites=[chacha20_poly1305]).
#   2. Drive `interop_client:run_endpoint/5` against it (the same
#      Erlang function `run_endpoint.sh` calls), so the client-side
#      wiring (cipher list, key update trigger, session-cache
#      resumption) is exercised end-to-end.
#   3. Capture the client exit code and report PASS/FAIL.
#
# This is not a substitute for the official quic-interop-runner; it
# does not inspect qlog or pcap, so it cannot prove that, e.g., a Retry
# packet was actually emitted. It does prove that the handler the
# runner invokes produces a successful end-to-end exchange.
#
# Usage:
#   ./priv/scripts/runner_self_check.sh                  # all testcases
#   ./priv/scripts/runner_self_check.sh retry resumption # just these

set -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$DIR/../.."
LOG_DIR="$PROJECT_ROOT/test/compliance_logs/runner_self"
WWW_DIR="$PROJECT_ROOT/test/interop/www"
PORT_BASE=44330

mkdir -p "$LOG_DIR"

# Default test matrix: every TESTCASE that run_endpoint.sh accepts as
# supported. Keep this list in sync with the case statement in
# priv/interop/run_endpoint.sh.
ALL_TESTS=(handshake transfer multiconnect retry chacha20 keyupdate resumption zerortt)

if [ $# -gt 0 ]; then
    TESTS=("$@")
else
    TESTS=("${ALL_TESTS[@]}")
fi

cd "$PROJECT_ROOT"

echo "[*] Building nquic (interop profile)..."
if ! rebar3 as interop compile > "$LOG_DIR/compile.log" 2>&1; then
    echo "    Build failed (see $LOG_DIR/compile.log)"
    exit 1
fi

# Per-testcase resources. The server is restarted each time so its
# TESTCASE-driven opts apply.
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    pkill -f "nquic_runner_self_(srv|cli)_" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

start_server() {
    local TC="$1"
    local SERVER_PORT="$2"
    local LOG_FILE="$LOG_DIR/server_${TC}.log"

    # `tail -f /dev/null` keeps stdin open so the rebar3 shell doesn't
    # exit on EOF; without it, the listener `accept_loop` recursion
    # never gets a chance to run before the shell tears down.
    tail -f /dev/null | \
    PORT="$SERVER_PORT" \
    WWWDIR="$WWW_DIR" \
    TESTCASE="$TC" \
    rebar3 as interop shell \
        --name "nquic_runner_self_srv_${TC}_$$@127.0.0.1" \
        --eval 'interop_server:start()' \
        > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!

    # Poll for "Listening" line; bail out after ~10 s.
    for _ in $(seq 1 100); do
        if grep -q "Listening on" "$LOG_FILE" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "    server died before listening (see $LOG_FILE)"
            SERVER_PID=""
            return 1
        fi
        sleep 0.1
    done
    echo "    server did not become ready within 10 s (see $LOG_FILE)"
    return 1
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

# Pick the request set for a testcase. Resumption needs >=2 URLs so the
# second connection can prove ticket reuse; multiconnect benefits from
# more than one path so the loop has something to do per iteration.
paths_for() {
    local TC="$1"
    case "$TC" in
        resumption|multiconnect)
            # Resumption needs >= 2 connections so the second one can
            # prove the cached ticket is reused. medium.bin (1 MB)
            # exercises the per-stream send-side buffering + cwnd-aware
            # drain path; a small.txt by itself does not.
            echo '"/small.txt", "/medium.bin"'
            ;;
        transfer)
            # The bulk-transfer testcase fetches a single object;
            # use medium.bin so the harness exercises STREAM-frame
            # splitting and ACK-driven re-flush.
            echo '"/medium.bin"'
            ;;
        *)
            echo '"/small.txt"'
            ;;
    esac
}

run_client() {
    local TC="$1"
    local SERVER_PORT="$2"
    local LOG_FILE="$LOG_DIR/client_${TC}.log"
    local DOWNLOADS_DIR="$LOG_DIR/downloads_${TC}"

    rm -rf "$DOWNLOADS_DIR"
    mkdir -p "$DOWNLOADS_DIR"

    local PATHS
    PATHS=$(paths_for "$TC")

    # Build the -pa argument list once; interop_client/server live
    # under test/interop and the ctx owner-loop driver under
    # test/support in the interop profile.
    local PA_ARGS=""
    for d in "$PROJECT_ROOT"/_build/interop/lib/*/ebin; do
        [ -d "$d" ] && PA_ARGS="$PA_ARGS -pa $d"
    done
    for d in "$PROJECT_ROOT"/_build/interop/lib/*/test/interop \
             "$PROJECT_ROOT"/_build/interop/lib/*/test/support; do
        [ -d "$d" ] && PA_ARGS="$PA_ARGS -pa $d"
    done

    # Use plain `erl -noshell` rather than `rebar3 shell --eval` so the
    # `halt(Code)` exit code actually reaches the script. rebar3 wraps
    # the shell and always exits 0, which would mask every failure.
    local EVAL="
        Paths = [${PATHS}],
        Code = interop_client:run_endpoint(
            \"127.0.0.1\", ${SERVER_PORT}, Paths, \"${DOWNLOADS_DIR}\", \"${TC}\"
        ),
        halt(Code)
    "

    erl -noshell \
        -name "nquic_runner_self_cli_${TC}_$$@127.0.0.1" \
        $PA_ARGS \
        -eval "$EVAL" \
        > "$LOG_FILE" 2>&1
    return $?
}

PASS=0
FAIL=0

echo ""
echo "==========================================="
echo "   run_endpoint.sh testcase self-check"
echo "==========================================="
echo ""

i=0
for TC in "${TESTS[@]}"; do
    i=$((i + 1))
    TEST_PORT=$((PORT_BASE + i))
    printf "  %-15s " "$TC"

    if ! start_server "$TC" "$TEST_PORT"; then
        echo "FAIL (server)"
        FAIL=$((FAIL + 1))
        continue
    fi

    if run_client "$TC" "$TEST_PORT"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (see $LOG_DIR/client_${TC}.log)"
        FAIL=$((FAIL + 1))
    fi

    stop_server
done

echo ""
echo "Results: $PASS PASS, $FAIL FAIL"
echo "Logs:    $LOG_DIR"

[ "$FAIL" -eq 0 ]
