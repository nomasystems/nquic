FROM erlang:27

WORKDIR /app

# Install wait-for-it for network simulation support
RUN apt-get update && apt-get install -y --no-install-recommends \
    wait-for-it \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration
COPY rebar.config ./
COPY rebar.lock ./

# Copy source
COPY src/ src/
COPY include/ include/
COPY priv/interop/ priv/interop/

# Copy interop tooling sources (compiled under the interop profile)
COPY test/interop/compliance_tests.erl test/interop/
COPY test/interop/interop_client.erl test/interop/
COPY test/interop/interop_server.erl test/interop/

# Copy test certificates (fallback when /certs not mounted)
COPY test/conf/ test/conf/

# Copy test files for serving (fallback when /www not mounted)
COPY test/interop/www/ /www/

# Compile
RUN rebar3 as interop compile

# Copy entrypoint
COPY priv/interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

# Create downloads directory
RUN mkdir -p /downloads

# Expose QUIC port (standard for quic-interop-runner)
EXPOSE 443/udp

ENTRYPOINT ["/run_endpoint.sh"]
