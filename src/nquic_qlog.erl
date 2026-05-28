-module(nquic_qlog).

-moduledoc """
qlog tracing for nquic connections (draft-ietf-quic-qlog-main-schema).

qlog is the IETF-standard observability format for QUIC. A backend
records per-connection events to a sink (file, gen_event manager,
caller-supplied module); tools like
[qvis](https://qvis.quictools.info) render the resulting NDJSON
stream into time-series and packet-level diagrams.

This module defines the backend `behaviour` and a tiny dispatcher
the protocol calls at known hook points. Backends do all the
formatting work; the dispatcher only branches on whether a backend
is attached.

The protocol carries the active backend on `#conn_state.qlog` as
`undefined | qlog_state()`. When the field is `undefined` every
`event/3` call returns immediately in a single field read.

## Hook points

Currently wired:

* `packet_sent`: every wire packet leaves with a payload, header,
  PN, encryption level. Fired from `nquic_protocol_send`.
* `packet_received`: every successfully decrypted packet. Fired
  from `nquic_protocol_recv`.

Future hook points (documented in
`plans/current/3_TRANSPORT_GAPS_PLAN.md` §C2):

* `transport:datagrams_received`
* `transport:packet_lost`
* `recovery:metrics_updated`
* `recovery:congestion_state_updated`
* `recovery:loss_timer_updated`

## Configuration

`#{qlog => Backend}` on `t:nquic:listen_opts/0` and
`t:nquic:connect_opts/0`. `Backend` is one of:

* `{file, Path}`: open a per-connection NDJSON file at `Path`
  (`nquic_qlog_file`).
* `{Module, InitArgs}`: caller-supplied backend that implements
  this behaviour.
""".

-include("nquic_conn.hrl").
-export([
    attach/2,
    detach/1,
    event/3
]).

-export_type([backend_config/0, event_data/0, event_name/0, qlog_state/0]).

-type qlog_state() :: {module(), term()}.

-type backend_config() :: {file, file:filename_all()} | {module(), term()}.

-type event_name() ::
    transport_packet_sent
    | transport_packet_received
    | transport_packet_lost
    | recovery_metrics_updated.

-type event_data() :: #{atom() => term()}.

%%%-----------------------------------------------------------------------------
%% BEHAVIOUR
%%%-----------------------------------------------------------------------------
-doc """
Initialise the backend. `Args` is the second element of the
`backend_config()` tuple. The returned state is opaque to the
dispatcher and threaded through `event/2` / `terminate/2`.
""".
-callback init(nquic:connection_id(), Args :: term()) ->
    {ok, BackendState :: term()} | {error, term()}.

-callback event(BackendState :: term(), Event :: {event_name(), event_data()}) ->
    {ok, BackendState :: term()}.

-callback terminate(BackendState :: term(), Reason :: term()) -> ok.

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc """
Construct a `qlog_state()` from a `backend_config()` for the connection
whose original DCID is `CID`. `{ok, undefined}` if `Cfg` is the
sentinel `undefined` (the option was not set).
""".
-spec attach(nquic:connection_id(), undefined | backend_config()) ->
    {ok, undefined | qlog_state()} | {error, term()}.
attach(_CID, undefined) ->
    {ok, undefined};
attach(CID, {file, Path}) ->
    attach(CID, {nquic_qlog_file, #{path => Path}});
attach(CID, {Module, Args}) when is_atom(Module) ->
    case Module:init(CID, Args) of
        {ok, BackendState} -> {ok, {Module, BackendState}};
        {error, _} = Err -> Err
    end.

-doc "Tear down the backend.".
-spec detach(undefined | qlog_state()) -> ok.
detach(undefined) ->
    ok;
detach({Module, BackendState}) ->
    Module:terminate(BackendState, normal).

-doc """
Record a qlog event. Zero-overhead when no backend is attached.
The dispatcher is intentionally unhelpful about misbehaving
backends: it threads the new backend state back into the connection
state and lets errors propagate. Backends MUST NOT crash on
malformed event payloads.
""".
-spec event(undefined | qlog_state(), event_name(), event_data()) -> undefined | qlog_state().
event(undefined, _Name, _Data) ->
    undefined;
event({Module, BackendState}, Name, Data) ->
    {ok, NewState} = Module:event(BackendState, {Name, Data}),
    {Module, NewState}.
