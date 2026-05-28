#!/usr/bin/env bash

# run_interop_runner.sh
#
# Local validation with the official quic-interop-runner.
# This script clones the runner, builds the nquic Docker image,
# and runs the test matrix.
#
# Prerequisites:
#   - Docker
#   - The nquic Docker image built (make docker-build)
#
# Usage:
#   ./scripts/run_interop_runner.sh                    # handshake + transfer
#   ./scripts/run_interop_runner.sh -t handshake       # specific test
#   ./scripts/run_interop_runner.sh -c aioquic         # specific client
#   ./scripts/run_interop_runner.sh -s aioquic         # specific server

set -eu

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$DIR/../.."
RUNNER_DIR="$PROJECT_ROOT/.interop-runner"
IMAGE="ghcr.io/nomasystems/nquic-interop:latest"

# Default test cases
TESTS="handshake,transfer,multiconnect"
CLIENT=""
SERVER=""

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -t|--tests) TESTS="$2"; shift 2 ;;
        -c|--client) CLIENT="$2"; shift 2 ;;
        -s|--server) SERVER="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -t, --tests TESTS   Comma-separated test cases (default: handshake,transfer,multiconnect)"
            echo "  -c, --client IMPL   Client implementation to test against (default: nquic)"
            echo "  -s, --server IMPL   Server implementation to test against (default: nquic)"
            echo "  -h, --help          Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                                    # nquic vs nquic"
            echo "  $0 -s nquic -c aioquic                # aioquic client vs nquic server"
            echo "  $0 -s aioquic -c nquic                # nquic client vs aioquic server"
            echo "  $0 -t handshake -c aioquic -s nquic   # specific test"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "==========================================="
echo "   quic-interop-runner Validation"
echo "==========================================="
echo ""

# Step 1: Build nquic Docker image
echo "[*] Building nquic Docker image..."
cd "$PROJECT_ROOT"
docker build -t "$IMAGE" -f priv/interop/Dockerfile . > /dev/null 2>&1
echo "    Image: $IMAGE"
echo ""

# Step 2: Clone/update quic-interop-runner
if [ -d "$RUNNER_DIR" ]; then
    echo "[*] Updating quic-interop-runner..."
    cd "$RUNNER_DIR"
    git pull --quiet || true
else
    echo "[*] Cloning quic-interop-runner..."
    git clone https://github.com/quic-interop/quic-interop-runner "$RUNNER_DIR"
    cd "$RUNNER_DIR"
fi
echo ""

# Step 3: Install runner dependencies
if [ ! -d "$RUNNER_DIR/venv" ]; then
    echo "[*] Setting up Python environment..."
    python3 -m venv "$RUNNER_DIR/venv"
    "$RUNNER_DIR/venv/bin/pip" install -r requirements.txt > /dev/null 2>&1
fi
echo ""

# Step 4: Run tests
echo "[*] Running interop tests..."
echo "    Tests: $TESTS"

# Build the command
CMD="$RUNNER_DIR/venv/bin/python3 $RUNNER_DIR/run.py -t $TESTS"

# Add nquic as an implementation
CMD="$CMD -r nquic=$IMAGE"

if [ -n "$CLIENT" ] && [ -n "$SERVER" ]; then
    CMD="$CMD -s $SERVER -c $CLIENT"
elif [ -n "$CLIENT" ]; then
    CMD="$CMD -s nquic -c $CLIENT"
elif [ -n "$SERVER" ]; then
    CMD="$CMD -s $SERVER -c nquic"
else
    # Default: nquic as both client and server
    CMD="$CMD -s nquic -c nquic"
fi

echo "    Command: $CMD"
echo ""

$CMD

echo ""
echo "Done. Results are in $RUNNER_DIR/results/"
