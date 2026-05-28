PROJECT = nquic
REBAR = rebar3
ERLC := erlc
INCLUDE := include
H3SPEC_VERSION := 0.1.12
H3SPEC_IMAGE := nquic-h3spec:$(H3SPEC_VERSION)
H3SPEC_DOCKERFILE := priv/scripts/Dockerfile.h3spec

.PHONY: all compile test clean check compliance compliance-interop interop interop-server runner-check binopt cover docker-build doc h3spec-docker help test-certs interop-fixtures

all: compile

help:
	@echo "nquic - QUIC transport library for Erlang/OTP"
	@echo ""
	@echo "Targets:"
	@echo "  compile       Build the project"
	@echo "  test          Run all tests with coverage"
	@echo "  check         Format check + xref + dialyzer + hank"
	@echo "  clean         Remove build artifacts"
	@echo ""
	@echo "Quality / analysis:"
	@echo "  cover                Run tests with coverage report"
	@echo "  binopt               Analyze binary optimization opportunities"
	@echo ""
	@echo "Interop testing:"
	@echo "  compliance-interop  Run RFC compliance interop tests"
	@echo "  interop             Run interop tests (IMPL=aioquic|ngtcp2|picoquic|all)"
	@echo "  runner-check        Self-check run_endpoint.sh testcases (TESTS=\"retry chacha20 ...\")"
	@echo "  docker-build        Build nquic Docker image for interop runner"

compile:
	$(REBAR) compile

check:
	$(REBAR) check

clean:
	$(REBAR) clean

cover:
	$(REBAR) ct --cover
	$(REBAR) cover --verbose

doc:
	$(REBAR) ex_doc

# Binary optimization analysis (bin_opt_info per src file).
binopt:
	@for f in src/*.erl; do \
		$(ERLC) +bin_opt_info -I $(INCLUDE) -o /tmp "$$f" 2>&1 | grep -E "^src/"; \
	done
	@rm -f /tmp/nquic*.beam

# Regenerate the local test certificate (idempotent; no-op if present).
test-certs:
	./test/conf/generate_certs.sh

# Regenerate interop test fixtures that are excluded from git / hex.
interop-fixtures:
	mkdir -p test/interop/www
	@[ -f test/interop/www/medium.bin ] || \
		(echo "generating test/interop/www/medium.bin (1 MB)"; \
		 dd if=/dev/zero of=test/interop/www/medium.bin bs=1M count=1 status=none)
	@[ -f test/interop/www/large.bin ] || \
		(echo "generating test/interop/www/large.bin (10 MB)"; \
		 dd if=/dev/zero of=test/interop/www/large.bin bs=1M count=10 status=none)

test: test-certs
	$(REBAR) test

# RFC compliance interop tests
compliance: h3spec-docker compliance-interop
	H3SPEC_IMAGE=$(H3SPEC_IMAGE) ./priv/scripts/compliance_check.sh

# Build the h3spec runner image (idempotent; skips if already present).
h3spec-docker:
	@if docker image inspect $(H3SPEC_IMAGE) > /dev/null 2>&1; then \
		exit 0; \
	fi; \
	echo "Building $(H3SPEC_IMAGE) from $(H3SPEC_DOCKERFILE)..."; \
	docker build \
		--build-arg H3SPEC_VERSION=$(H3SPEC_VERSION) \
		-t $(H3SPEC_IMAGE) \
		-f $(H3SPEC_DOCKERFILE) \
		priv/scripts

compliance-interop: test-certs interop-fixtures
ifdef IMPL
	./priv/scripts/compliance_interop.sh $(IMPL)
else
	./priv/scripts/compliance_interop.sh self
endif

# Interop tests against other QUIC implementations
interop: test-certs interop-fixtures
ifdef IMPL
	./priv/scripts/run_interop.sh $(IMPL)
else
	./priv/scripts/run_interop.sh
endif

interop-server:
	$(REBAR) as interop shell --eval "interop_server:start()"

# Self-check every TESTCASE accepted by priv/interop/run_endpoint.sh
# (handshake, transfer, multiconnect, retry, chacha20, keyupdate,
# resumption) with nquic-vs-nquic, no Docker. Pass an explicit list
# to limit which testcases run, e.g.:
#   make runner-check TESTS="retry resumption"
runner-check: test-certs interop-fixtures
	./priv/scripts/runner_self_check.sh $(TESTS)

# Build nquic Docker image for quic-interop-runner
docker-build:
	docker build -t ghcr.io/nomasystems/nquic-interop:latest -f priv/interop/Dockerfile .
	@echo ""
	@echo "Built: ghcr.io/nomasystems/nquic-interop:latest"
