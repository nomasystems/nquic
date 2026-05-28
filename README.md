# nquic

[![Hex.pm](https://img.shields.io/hexpm/v/nquic.svg)](https://hex.pm/packages/nquic)
[![CI](https://github.com/nomasystems/nquic/actions/workflows/ci.yml/badge.svg)](https://github.com/nomasystems/nquic/actions/workflows/ci.yml)

Pure Erlang QUIC transport for Erlang/OTP 27+.

## Getting started

```erlang
{deps, [{nquic, "1.0.0"}]}.
```

### Client

```erlang
{ok, Ctx0} = nquic:connect("example.com", 443, #{tls => #{alpn => [<<"h3">>]}}),
{ok, Sid, Ctx1} = nquic_lib:open_stream(Ctx0, #{type => bidi}),
{ok, Ctx2} = nquic_lib:send_fin(Ctx1, Sid, <<"Hello, QUIC!">>),
{ok, Body, true, Ctx3} = nquic_lib:recv(Ctx2, Sid),
{ok, _Ctx4} = nquic_lib:close(Ctx3).
```

`connect/3` and `accept/1,2` return an opaque `t:nquic:ctx/0` owned by
the calling process. After the handshake the owner *is* the connection
and drives it through `nquic_lib`. There is no message hop to a
connection process: stream operations are pure functions threading the
`ctx()` through.

### Server

```erlang
{ok, Listener} = nquic:listen(4433, #{
    tls => #{
        certfile => "server.pem",
        keyfile => "server.key",
        alpn => [<<"h3">>]
    }
}),
{ok, Ctx0} = nquic:accept(Listener),
{ok, Ctx1} = nquic_lib:takeover(Ctx0),
owner_loop(Ctx1).
```

The owner must run a loop that ingests inbound packets and services
timers, or the connection stalls. See the `nquic_lib` module docs for
the full owner-liveness contract; `test/support/nquic_ctx_driver.erl`
is the faithful reference loop.

## Features

- **QUIC transport** ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)) and **QUIC v2** ([RFC 9369](https://www.rfc-editor.org/rfc/rfc9369))
- **TLS 1.3 handshake** via OTP `ssl` / `crypto` ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001))
- **Loss detection and congestion control** with CUBIC (default) and NewReno ([RFC 9002](https://www.rfc-editor.org/rfc/rfc9002))
- **0-RTT** with pluggable anti-replay ([RFC 9001 §9.2](https://www.rfc-editor.org/rfc/rfc9001#section-9.2))
- **Connection migration** with path validation and server preferred-address ([RFC 9000 §9](https://www.rfc-editor.org/rfc/rfc9000#section-9))
- **Unreliable datagrams** ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221))
- **ECN** with per-path validation ([RFC 9000 §13.4](https://www.rfc-editor.org/rfc/rfc9000#section-13.4), [RFC 9002 §B.4](https://www.rfc-editor.org/rfc/rfc9002#appendix-B.4))
- **DPLPMTUD** packetization-layer PMTU search ([RFC 8899](https://www.rfc-editor.org/rfc/rfc8899))
- **Connected UDP** kernel-routed server connections, zero-hop dispatch
- **SO_REUSEPORT** multiple receivers for kernel-level load distribution
- **No dependencies** only OTP `kernel`, `stdlib`, `crypto`, `ssl`, `public_key`

## Documentation

[nquic on HexDocs](https://hexdocs.pm/nquic)

## License

Apache License 2.0
