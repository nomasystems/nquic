-module(nquic).
-moduledoc """
QUIC transport library for Erlang/OTP, implementing RFC 9000
(transport), RFC 9001 (TLS binding), RFC 9002 (loss detection and
congestion control), and RFC 9221 (unreliable datagrams).

This module is the umbrella API: client connect, server listen and
accept, and listener lifecycle and metrics. `connect/3` and
`accept/1,2` return an opaque `t:ctx/0` connection handle; all
post-handshake traffic (streams, datagrams, close, timers) is driven
through `m:nquic_lib`, which threads the updated context through each
call. Closed-form error values are defined in `m:nquic_error`.

## Connection model

nquic owns exactly one process per connection: the handshake driver.
When the handshake completes the connection (a `t:ctx/0` value) is
handed to the caller of `connect/3` or `accept/1,2` and the driver
exits. From that point the owning process *is* the connection: it
drives the protocol core directly through `m:nquic_lib` by function
call against the context, with no message hop and no nquic-owned
process. The owner pulls data when ready
(`nquic_lib:recv/2`, `nquic_lib:recv_pending/1`); there is no
pushed-message envelope and no ownership-reassignment call. To serve
a connection from a dedicated worker, call `accept/1,2` (or
`connect/3`) from that worker. This is the only connection model;
read the **owner-liveness contract** below before writing one.

## Owner-liveness contract

There is no per-connection nquic process after the handshake, so
**nothing services the connection unless the owner's loop does**.
ACKs, PTO, loss detection, and the idle timer all fire only when the
owner calls back into `m:nquic_lib`. An owner that blocks, or that
reads streams without also draining inbound packets and timer
expiries, will silently stall the connection: the peer times it out
while the owner waits forever.

The contract the owner MUST satisfy, in one loop:

1. ingest every inbound packet: `nquic_lib:handle_packet/3` for the
   dispatched server path (`{packet, Source, Bin}` messages from the
   listener's receiver) or `nquic_lib:recv_direct/1` for a connected
   or client-owned socket;
2. service every `{quic_timeout, Type}` message via
   `nquic_lib:timeout/2` (this is what drives ACK/PTO/idle);
3. `nquic_lib:flush/1` after each of the above so queued frames
   reach the wire;
4. observe `{quic_drain, Listener}` (the listener cascade-stop
   signal) and close.
```erlang
owner_loop(Ctx) ->
    Socket = nquic_lib:ctx_socket(Ctx),
    receive
        {'$socket', Socket, select, _Info} ->
            after_io(nquic_lib:recv_direct(Ctx));
        {packet, Source, Bin} ->
            after_io(nquic_lib:handle_packet(Ctx, Source, Bin));
        {quic_timeout, Type} ->
            after_io(nquic_lib:timeout(Ctx, Type));
        {quic_drain, _Listener} ->
            {ok, _Ctx1} = nquic_lib:close(Ctx)
    end.

after_io({ok, Events, Ctx1}) ->
    {ok, Ctx2} = nquic_lib:flush(Ctx1),
    owner_loop(handle_events(Events, Ctx2));
after_io({error, _Reason, _Ctx1}) ->
    ok.
```

`nquic_lib:recv_direct/1` folds packet ingest and timer servicing
into a single blocking call (it handles `{packet, _}`,
`{quic_timeout, _}`, and the connected-socket select cycle
internally), so a connected/client owner can collapse steps 1-2 to
`recv_direct/1`; it still does not observe `{quic_drain, _}`, which
the owner handles itself.

## Quick start: client

```erlang
{ok, Ctx0} = nquic:connect("example.com", 443,
                            #{tls => #{alpn => [<<"h3">>]}}),
{ok, Sid, Ctx1}       = nquic_lib:open_stream(Ctx0, #{type => bidi}),
{ok, Ctx2}            = nquic_lib:send_fin(Ctx1, Sid,
                                           <<"GET / HTTP/1.1\\r\\n\\r\\n">>),
{ok, Body, fin, Ctx3} = nquic_lib:recv(Ctx2, Sid),
{ok, _Ctx4}           = nquic_lib:close(Ctx3).
```

`connect/3` blocks until the handshake completes (or `timeout`
elapses) and returns `{ok, Ctx}`. The context cannot exist before
the handshake, so `nowait => true` is rejected with
`{error, {opts, ctx_requires_wait}}`.

## Quick start: server

```erlang
{ok, Listener} = nquic:listen(4433, #{
    tls => #{certfile => "server.pem",
             keyfile  => "server.key",
             alpn     => [<<"h3">>]}
}),
{ok, Ctx0}         = nquic:accept(Listener),
{ok, Ctx1}         = nquic_lib:takeover(Ctx0),
{ok, Events, Ctx2} = nquic_lib:recv_pending(Ctx1).
```

The listener owns one or more UDP sockets (set `receivers => N` to
fan packets across schedulers with `SO_REUSEPORT`) and a striped
dispatch table that routes datagrams to existing connections without
spawning a process per packet. An accepted context stays on the
listener's dispatch path; the owner calls `nquic_lib:takeover/1` to
re-target the connection's CIDs to itself and then drives it through
`m:nquic_lib`. Listener-wide observability is exported through
`metrics/1`.

## Listener lifecycle

`listen/2` starts a supervision tree with `supervisor:start_link/2`,
so the listener is **linked to the calling process**. If that process
dies, the listener tree comes down with it; if the listener tree
crashes abnormally, the link propagates to the owner. This is the
intended contract: tie listener lifetime to an owning process.

Stop a listener explicitly with `stop_listener/1,2`. It is
synchronous, idempotent, and exits the listener supervisor with
reason `normal`, so the owner link never turns into a kill. `cascade`
(the default) stops accepting, signals every owner-held established
connection to close (a `{quic_drain, Listener}` message the owner
loop observes), then tears down the listener tree and frees the port;
`detach` stops accepting and frees the port but sends no drain signal,
leaving established connections to run until their own idle timeout. A
blocked `accept/1,2` on a stopped listener returns `{error, closed}`.

## Send and backpressure

A stream send is bounded by two windows: the connection's `MAX_DATA`
and the stream's `MAX_STREAM_DATA` credit, both granted by the peer.
`nquic_lib:send/3` / `nquic_lib:send_fin/3` admit as much as the
windows allow and return the updated context; the owner's recv loop
processes inbound `MAX_DATA` / `MAX_STREAM_DATA` frames that reopen
the window and resumes parked stream writes.
`nquic_lib:is_writable/2` is a point-in-time probe the owner can
check between recv turns: a `false` does not guarantee the next send
fails, and a `true` can be stale before the owner acts on it.

## Datagrams

RFC 9221 unreliable datagrams are supported when both peers
negotiate `max_datagram_frame_size`. Datagrams are not retransmitted
and are not flow-controlled. Send via `nquic_lib:send_datagram/2`;
receive via `nquic_lib:recv_datagram/1`.

## Session caching and 0-RTT

The optional `session_cache` and `token_cache` options on
`connect/3` opt into TLS 1.3 session resumption and address
validation tokens. The server exposes the same surface via the
`replay_protection` and `new_token` listen options. See
`m:nquic_session_cache` for the cache contract and
`m:nquic_zero_rtt` for early-data handling on the server.

## Error handling

Every public function returns `{ok, _} | {error, t:error_reason/0}`.
`t:error_reason/0` is the closed taxonomy defined in `m:nquic_error`,
covering `closed`, `{timeout, Phase}`, `{transport, _}`, `{tls, _}`,
`{application, Code, Reason}`, `{protocol, _}`, `{flow_control, _}`,
`{opts, _}`, `{connect, _}`, and `{listen, _}`. Use
`nquic_error:category/1`, `nquic_error:is_retryable/1`, and
`nquic_error:format/1` to interrogate values without pattern-matching
on the inner shape.
""".

-export([
    accept/1,
    accept/2,
    connect/3,
    get_port/1,
    listen/2,
    metrics/1,
    stop_listener/1,
    stop_listener/2
]).
-export_type([
    accept_opts/0,
    cc_opts/0,
    cipher_suite/0,
    client_tls_opts/0,
    close_opts/0,
    conn_info/0,
    connect_opts/0,
    connection_id/0,
    ctx/0,
    error_code/0,
    error_reason/0,
    listen_opts/0,
    listener/0,
    listener_metrics/0,
    stop_listener_opts/0,
    stream_id/0,
    stream_opts/0,
    tls_opts/0,
    transport_opts/0,
    verify_mode/0
]).

-type connection_id() :: binary().
-type error_code() :: non_neg_integer().
-type stream_id() :: non_neg_integer().
-type verify_mode() :: verify_none | verify_peer.

-opaque listener() :: pid().

-doc """
Closed error taxonomy returned by every public function. Use
`nquic_error:category/1`, `nquic_error:is_retryable/1`, and
`nquic_error:format/1` to interrogate values.

Outer arms:

* `closed` - connection has been closed locally or by the peer.
* `{timeout, Phase}` - `Phase :: handshake | idle | recv | send | accept`.
* `{transport, Reason}` - peer-sent CONNECTION_CLOSE (0x1c) or local
  transport-layer I/O failure (`{posix, _}` payload).
* `{tls, Reason}` - TLS alert or local handshake-side validation error.
* `{application, Code, Reason}` - peer-sent CONNECTION_CLOSE (0x1d).
* `{protocol, Reason}` - wire-format or RFC 9000 violation detected
  locally (frame encoding, transport parameters, packet integrity, ...).
* `{flow_control, Reason}` - local flow or congestion blocking
  (`eagain`, `congestion_control_blocked`, `partial_send`, ...).
* `{opts, Reason}` - options / configuration / API misuse.
* `{connect, Posix}` - DNS or client-side connect failure.
* `{listen, Posix}` - server-side bind failure.

Example:

```erlang
case nquic:connect(Host, Port, #{tls => #{alpn => [<<"h3">>]}}) of
    {ok, Conn} -> ok;
    {error, {timeout, handshake}} -> retry;
    {error, {tls, _}} -> bad_tls;
    {error, {connect, _}} -> network;
    {error, _} -> giveup
end.
```
""".
-type error_reason() :: nquic_error:error_reason().

-doc """
Options for `open_stream/2` and `nquic_lib:open_stream/2`. Defaults
to a bidirectional stream if omitted entirely.
""".
-type stream_opts() :: #{type => bidi | uni}.

-doc """
Options for `close/2`.

* `scope` (default `transport`) - `transport` emits CONNECTION_CLOSE
  type 0x1c, `application` emits type 0x1d (RFC 9000 §19.19).
* `error_code` (default `0`) - protocol or application error code.
* `reason` (default `<<>>`) - operator-visible reason phrase.
""".
-type close_opts() :: #{
    scope => transport | application,
    error_code => non_neg_integer(),
    reason => binary()
}.

-doc """
Options for `stop_listener/2`.

* `mode` (default `cascade`) - `cascade` stops accepting, broadcasts
  a `{quic_drain, Listener}` close signal to every owner-held
  established connection, then tears the whole listener tree down
  (port released, handshake-phase processes terminated); `detach`
  stops accepting and frees the port but sends no drain signal,
  leaving established connections running until their own idle
  timeout.
* `timeout` (default `5000`) - milliseconds to wait for a graceful
  `cascade` shutdown before the supervisor is brutally killed.
""".
-type stop_listener_opts() :: #{
    mode => cascade | detach,
    timeout => timeout()
}.

-doc """
Public connection-info map returned by `nquic_conn:info/1`. The shape
is intentionally a plain map (not a record) so the library can evolve
fields without breaking callers.
""".
-type conn_info() :: #{
    state := initial | handshake | established | draining | closed,
    role := client | server,
    scid := binary(),
    dcid := binary(),
    rtt := #{
        smoothed_rtt := non_neg_integer(),
        min_rtt := non_neg_integer(),
        latest_rtt := non_neg_integer(),
        rttvar := non_neg_integer()
    },
    cwnd := non_neg_integer(),
    bytes_in_flight := non_neg_integer(),
    streams_open := non_neg_integer(),
    data_sent := non_neg_integer(),
    data_received := non_neg_integer(),
    _ => _
}.

-doc """
Per-listener metrics snapshot returned by `metrics/1`. The listener's
atomic counters are monotonic; consumers compute deltas themselves.
""".
-type listener_metrics() :: #{
    packets_in := non_neg_integer(),
    packets_dropped_mailbox := non_neg_integer(),
    packets_dropped_ratelimit := non_neg_integer(),
    conns_established := non_neg_integer(),
    conns_closed_normal := non_neg_integer(),
    conns_closed_idle_timeout := non_neg_integer(),
    conns_closed_peer := non_neg_integer(),
    conns_closed_protocol_error := non_neg_integer(),
    handshakes_inflight := integer(),
    accept_queue_depth := integer(),
    udp_rcvbuf_errs := non_neg_integer(),
    uptime_ms := non_neg_integer()
}.

-type cipher_suite() :: aes_128_gcm | aes_256_gcm | chacha20_poly1305.

-doc """
Options accepted by `accept/2`.
""".
-type accept_opts() :: #{
    timeout => timeout()
}.

-doc """
Server TLS / credentials submap (`listen/2`). `certfile` and
`keyfile` are required; the rest tune verification and negotiation.
""".
-type tls_opts() :: #{
    certfile := file:filename(),
    keyfile := file:filename(),
    cacertfile => file:filename(),
    cacerts => [binary()],
    verify => verify_mode(),
    cipher_suites => [cipher_suite()],
    alpn => [binary()]
}.

-doc """
Client TLS submap (`connect/3`). All keys optional: a client
presents no server certificate, so `certfile`/`keyfile` are absent.
""".
-type client_tls_opts() :: #{
    cacertfile => file:filename(),
    cacerts => [binary()],
    verify => verify_mode(),
    cipher_suites => [cipher_suite()],
    alpn => [binary()]
}.

-doc """
Transport tuning submap shared by `listen/2` and `connect/3`:
offload (GSO/GRO), pacing, datagram sizing, socket buffering.
""".
-type transport_opts() :: #{
    gso => boolean() | pos_integer(),
    gro => boolean(),
    pacing => boolean(),
    pacing_factor => number(),
    pacing_burst => pos_integer(),
    max_payload_size => pos_integer(),
    send_buffer => pos_integer(),
    send_timeout => timeout()
}.

-doc """
Congestion-control submap shared by `listen/2` and `connect/3`.
`algo` selects the controller; `slow_start` selects the start-up
phase behaviour.
""".
-type cc_opts() :: #{
    algo => newreno | cubic,
    slow_start => standard | hystart_plus_plus
}.

-doc """
Options for `listen/2`. Endpoint TLS credentials live in the
required `tls` submap; transport and congestion-control tuning in
the optional `transport` / `cc` submaps. Remaining keys are
listener-level policy.
""".
-type listen_opts() :: #{
    tls := tls_opts(),
    transport => transport_opts(),
    cc => cc_opts(),
    qlog => nquic_qlog:backend_config(),
    receivers => pos_integer(),
    idle_timeout => timeout(),
    max_new_conns_per_sec => non_neg_integer(),
    max_accept_queue => non_neg_integer(),
    retry => boolean(),
    retry_token_lifetime => pos_integer(),
    new_token => boolean(),
    new_token_lifetime => pos_integer(),
    spin_bit => boolean(),
    version => non_neg_integer(),
    version_preference => [non_neg_integer()],
    replay_protection => module(),
    server_per_conn_fd => boolean(),
    conn_handler => module(),
    conn_handler_opts => term()
}.

-doc """
Options for `connect/3`. TLS, transport, and congestion-control
tuning live in the optional `tls` / `transport` / `cc` submaps.
Remaining keys are connection-level policy and session resumption.
""".
-type connect_opts() :: #{
    timeout => timeout(),
    tls => client_tls_opts(),
    transport => transport_opts(),
    cc => cc_opts(),
    qlog => nquic_qlog:backend_config(),
    idle_timeout => timeout(),
    nowait => boolean(),
    version => non_neg_integer(),
    session_ticket => map(),
    session_cache => false | atom() | {module, module()},
    token_cache => false | atom() | {module, module()},
    client_token => binary(),
    proactive_cids => boolean()
}.

-type ctx() :: nquic_ctx:t().

-doc """
Accept an incoming QUIC connection with default options
(`timeout => infinity`).
""".
-spec accept(listener()) ->
    {ok, ctx()} | {error, error_reason()}.
accept(Listener) ->
    accept(Listener, #{}).

-doc """
Accept an incoming QUIC connection.
Blocks until a client connects and the handshake completes, or until
`timeout` expires, then returns the connection as an opaque
`t:ctx/0`. The owning process drives it through `m:nquic_lib`,
starting with `nquic_lib:takeover/1`.
""".
-spec accept(listener(), accept_opts()) ->
    {ok, ctx()} | {error, error_reason()}.
accept(Listener, Opts) when is_map(Opts) ->
    Timeout = maps:get(timeout, Opts, infinity),
    case nquic_listener:accept(Listener, Timeout) of
        {ok, Entry} ->
            promote_to_ctx(Entry);
        {error, Reason} ->
            nquic_error:wrap(Reason)
    end.

-doc """
Connect to a QUIC server.
`Host` and `Port` identify the endpoint; `Opts` carries everything
else: `timeout` (default `infinity`) and the `tls` / `transport` /
`cc` tuning submaps (e.g.
`#{tls => #{alpn => [<<"h3">>], verify => verify_peer}}`). See
`connect_opts/0`.
Blocks until the handshake completes (or `timeout` elapses) and
returns the connection as an opaque `t:ctx/0`, driven through
`m:nquic_lib`. The context cannot exist before the handshake, so
`nowait => true` is rejected with
`{error, {opts, ctx_requires_wait}}`.
""".
-spec connect(
    inet:hostname() | inet:ip_address(),
    inet:port_number(),
    connect_opts()
) ->
    {ok, ctx()} | {error, error_reason()}.
connect(Host, Port, Opts) when is_map(Opts) ->
    Timeout = maps:get(timeout, Opts, infinity),
    ConnectOpts0 = maps:without([timeout], Opts),
    case maps:get(nowait, ConnectOpts0, false) of
        true ->
            nquic_error:opts(ctx_requires_wait);
        false ->
            do_connect(Host, Port, ConnectOpts0#{nowait => false}, Timeout)
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-define(RELOCATED_KEYS, [
    certfile,
    keyfile,
    cacertfile,
    cacerts,
    verify,
    cipher_suites,
    alpn,
    gso,
    gro,
    pacing,
    pacing_factor,
    pacing_burst,
    max_payload_size,
    send_buffer,
    send_timeout,
    congestion_control,
    slow_start
]).
-doc false.
-spec await_client_export(pid(), reference(), timeout()) ->
    {ok, ctx()} | {error, error_reason()}.
await_client_export(Pid, MRef, Timeout) ->
    receive
        {nquic_conn_export, Pid, {ok, State, Socket, Table}} ->
            demonitor(MRef, [flush]),
            Peer = nquic_protocol:peer(State),
            {ok, nquic_ctx:new(State, Socket, Peer, Table)};
        {'DOWN', MRef, process, Pid, Reason} ->
            client_down_error(Reason)
    after Timeout ->
        demonitor(MRef, [flush]),
        catch gen_statem:stop(Pid),
        nquic_error:timeout(handshake)
    end.

-spec cc_flat(map()) -> map().
cc_flat(Cc) ->
    M0 =
        case maps:find(algo, Cc) of
            {ok, Algo} -> #{congestion_control => Algo};
            error -> #{}
        end,
    case maps:find(slow_start, Cc) of
        {ok, SlowStart} -> M0#{slow_start => SlowStart};
        error -> M0
    end.

-spec client_down_error(term()) -> {error, error_reason()}.
client_down_error(normal) -> nquic_error:closed();
client_down_error(noproc) -> nquic_error:closed();
client_down_error(shutdown) -> nquic_error:closed();
client_down_error({shutdown, _}) -> nquic_error:closed();
client_down_error(Reason) -> nquic_error:wrap(Reason).

-spec connect_socket_opts(map()) -> map().
connect_socket_opts(Opts) ->
    M0 =
        case maps:get(gso, Opts, false) of
            false -> #{};
            GSO -> #{gso => GSO}
        end,
    case maps:get(gro, Opts, false) of
        true -> M0#{gro => true};
        false -> M0
    end.

-spec do_connect(inet:hostname() | inet:ip_address(), inet:port_number(), map(), timeout()) ->
    {ok, ctx()} | {error, error_reason()}.
do_connect(Host, Port, Opts, Timeout) ->
    case validate_connect_opts(Opts) of
        {ok, Validated} ->
            Validated1 = nquic_session_cache:maybe_load_ticket(Host, Port, Validated),
            Validated2 = nquic_token_cache:maybe_load_token(Host, Port, Validated1),
            case inet:getaddr(Host, inet) of
                {error, Posix} ->
                    nquic_error:connect(Posix);
                {ok, IP} ->
                    SockOpts = nquic_recv:socket_options(connect_socket_opts(Validated2)),
                    case nquic_socket:open(SockOpts) of
                        {error, Posix} ->
                            nquic_error:from_socket(connect, Posix);
                        {ok, Socket} ->
                            InitialDCID = nquic_keys:generate_connection_id(8),
                            Peer = nquic_socket:make_sockaddr(IP, Port),
                            ConnOpts = Validated2#{
                                role => client,
                                socket => Socket,
                                peer => Peer,
                                dcid => InitialDCID,
                                hostname => Host,
                                owner => self()
                            },
                            case nquic_conn_statem:start_link(ConnOpts) of
                                {ok, Pid} ->
                                    unlink(Pid),
                                    MRef = monitor(process, Pid),
                                    ok = nquic_socket:controlling_process(Socket, Pid),
                                    await_client_export(Pid, MRef, Timeout);
                                {error, Reason} ->
                                    _ = nquic_socket:close(Socket),
                                    nquic_error:wrap(Reason)
                            end
                    end
            end;
        {error, _} = Err ->
            Err
    end.

-spec flatten_opts(map()) -> map().
flatten_opts(Opts) ->
    Tls = maps:get(tls, Opts, #{}),
    Transport = maps:get(transport, Opts, #{}),
    Cc = maps:get(cc, Opts, #{}),
    Base = maps:without([tls, transport, cc], Opts),
    Merged = maps:merge(maps:merge(Base, Tls), Transport),
    maps:merge(Merged, cc_flat(Cc)).

-doc """
Return the UDP port the listener is bound to.
Useful when the listener was started with port `0` (let the kernel
pick a free port) and the caller needs the actual port to advertise.
""".
-spec get_port(listener()) -> {ok, inet:port_number()} | {error, error_reason()}.
get_port(Listener) ->
    case nquic_listener:get_port(Listener) of
        {ok, _} = Ok -> Ok;
        {error, Reason} -> nquic_error:wrap(Reason)
    end.

-doc """
Start a QUIC listener bound to `Port`.
`Opts` requires a `tls` submap carrying at least `certfile` and
`keyfile` (e.g. `#{tls => #{certfile => C, keyfile => K}}`).
Transport and congestion-control tuning live in the optional
`transport` / `cc` submaps. See `listen_opts/0` for the full set.
## Returns
- `{ok, Listener}` on success
- `{error, Reason}` on failure
## See Also
- `accept/1`
- `accept/2`
- `stop_listener/1`
""".
-spec listen(inet:port_number(), listen_opts()) ->
    {ok, listener()} | {error, error_reason()}.
listen(Port, Opts) when is_map(Opts) ->
    case validate_listen_opts(maps:without([port], Opts)) of
        {ok, Validated} ->
            case nquic_listener:start_link(Validated#{port => Port}) of
                {ok, _} = Ok -> Ok;
                {error, Reason} -> nquic_error:wrap(Reason)
            end;
        {error, _} = Err ->
            Err
    end.

-doc """
Snapshot of the listener-wide observability counters. Counters are
monotonic; consumers compute deltas between snapshots themselves. The
`udp_rcvbuf_errs` field is a delta against the kernel value seen at
listener start on Linux; on other platforms it is always 0.
""".
-spec metrics(listener()) -> {ok, listener_metrics()} | {error, error_reason()}.
metrics(Listener) ->
    case nquic_listener:get_metrics(Listener) of
        {ok, M} -> {ok, nquic_metrics:snapshot(M)};
        {error, Reason} -> nquic_error:wrap(Reason)
    end.

-spec misplaced_key(map()) -> atom() | none.
misplaced_key(Opts) ->
    case [K || K <- ?RELOCATED_KEYS, is_map_key(K, Opts)] of
        [Key | _] -> Key;
        [] -> none
    end.

-spec promote_to_ctx(nquic_listener_mgr:accept_entry()) -> {ok, ctx()}.
promote_to_ctx({exported, State, Socket, Table, Connected, _ConnPid}) ->
    Peer = nquic_protocol:peer(State),
    Ctx0 = nquic_ctx:new(State, Socket, Peer, Table),
    Ctx =
        case Connected of
            true -> nquic_ctx:set_connected(Ctx0, true);
            false -> Ctx0
        end,
    {ok, Ctx}.

-doc """
Stop a listener returned by `listen/2`.
Cascade shutdown: stops accepting, broadcasts `{quic_drain, Listener}`
to every owner-held established connection so each closes gracefully,
then closes the listen sockets, releases the port, and tears down the
listener tree (receivers and dispatch). The drain message is delivered
to the connection's owner process; the reference owner loop closes the
connection and exits on it.
Idempotent: stopping an already-stopped listener returns `ok`. Safe
to call from any process,
including one that did not open the listener; the owner's link is
never turned into an exit. See `stop_listener/2` for the detach
variant and the lifecycle contract.
""".
-spec stop_listener(listener()) -> ok.
stop_listener(Listener) ->
    stop_listener(Listener, #{}).

-doc """
Stop a listener with options.
```erlang
nquic:stop_listener(L, #{mode => detach, timeout => 10000}).
```
`mode => cascade` (default) stops accepting, drains every owner-held
established connection via a `{quic_drain, Listener}` signal, then
tears the whole tree down; `mode => detach` stops accepting and frees
the port but sends no drain signal, leaving established connections
running until their own idle timeout. `timeout` (default `5000` ms)
bounds a graceful cascade before the supervisor is brutally killed.
See `stop_listener_opts/0`.
""".
-spec stop_listener(listener(), stop_listener_opts()) -> ok.
stop_listener(Listener, Opts) when is_pid(Listener), is_map(Opts) ->
    Mode = maps:get(mode, Opts, cascade),
    Timeout = maps:get(timeout, Opts, 5000),
    nquic_listener:stop(Listener, Mode, Timeout).

-spec validate_connect_opts(map()) -> {ok, map()} | {error, nquic_error:error_reason()}.
validate_connect_opts(Opts) when is_map(Opts) ->
    case misplaced_key(Opts) of
        none ->
            Defaults = #{
                alpn => [<<"h3">>],
                idle_timeout => 30000,
                nowait => false,
                congestion_control => cubic,
                verify => verify_peer,
                version => 1,
                send_buffer => 1048576,
                send_timeout => infinity,
                proactive_cids => false
            },
            {ok, maps:merge(Defaults, flatten_opts(Opts))};
        Key ->
            nquic_error:opts({misplaced_option, Key})
    end.

-spec validate_listen_opts(map()) -> {ok, map()} | {error, nquic_error:error_reason()}.
validate_listen_opts(Opts) when is_map(Opts) ->
    case misplaced_key(Opts) of
        none ->
            case Opts of
                #{tls := #{certfile := _, keyfile := _}} ->
                    Defaults = #{
                        alpn => [<<"h3">>],
                        idle_timeout => 30000,
                        receivers => 1,
                        congestion_control => cubic,
                        verify => verify_none,
                        max_new_conns_per_sec => 0,
                        max_accept_queue => 0,
                        retry => false,
                        retry_token_lifetime => 30,
                        send_buffer => 1048576,
                        send_timeout => infinity,
                        server_per_conn_fd => false,
                        version_preference => [1]
                    },
                    {ok, maps:merge(Defaults, flatten_opts(Opts))};
                _ ->
                    nquic_error:opts({missing_option, tls})
            end;
        Key ->
            nquic_error:opts({misplaced_option, Key})
    end.
