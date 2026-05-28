%%%-------------------------------------------------------------------
%%% @doc Test-only ergonomic owner-loop driver over a production
%%% `nquic:ctx()'.
%%%
%%% This module exists so the test suites can drive a connection with
%%% a synchronous request/response API while the connection itself
%%% runs on the **production** library path (`nquic:connect/accept'
%%% with `mode => ctx', then `m:nquic_lib' / `m:nquic_protocol'). It
%%% is the canonical owner-loop reference shape: a single process that
%%%
%%%   1. obtains a `#quic_ctx{}' via the production `mode => ctx' path,
%%%   2. takes ownership (`nquic_lib:takeover/1'), optionally upgrades
%%%      to a connected socket, and drains the handoff window
%%%      (`nquic_lib:recv_pending/1'),
%%%   3. runs one `receive' that interleaves QUIC liveness (socket
%%%      readiness, `{quic_timeout, _}', flush) with blocking client
%%%      requests, servicing ACK/PTO/idle the way every owner must,
%%%      and closes on a `{quic_drain, _}' listener-drain signal.
%%%
%%% Driver handles are plain pids; every call returns when the owner
%%% has serviced it (or `{error, closed}' if the owner died).
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_ctx_driver).
-moduledoc false.

-export([
    accept/2,
    accept_stream/1,
    accept_stream/2,
    close/1,
    close/2,
    close_stream/2,
    connect/3,
    conn_state/1,
    info/1,
    initiate_key_update/1,
    is_writable/2,
    open_stream/2,
    peercert/1,
    peername/1,
    recv/2,
    recv/3,
    recv_datagram/1,
    reset_stream/3,
    send/3,
    send/4,
    send_datagram/2,
    send_fin/3,
    send_fin/4,
    sockname/1
]).

-export([init_accept/3, init_connect/4]).

-type driver() :: pid().
-type from() :: {pid(), reference()}.

-export_type([driver/0]).

-record(waiter, {
    from :: from(),
    timer :: reference() | undefined
}).

-record(st, {
    ctx :: nquic:ctx(),
    parent :: pid(),
    socket :: nquic_socket:t(),
    recv_waiters = #{} :: #{nquic:stream_id() => [#waiter{}]},
    accept_waiters = [] :: [#waiter{}],
    pending_streams = queue:new() :: queue:queue(nquic:stream_id()),
    datagrams = queue:new() :: queue:queue(binary()),
    closed = false :: boolean()
}).

%%%-----------------------------------------------------------------------------
%% PUBLIC API
%%%-----------------------------------------------------------------------------

-doc "Connect to a server and run the owner loop. Mirrors `nquic:connect/3'.".
-spec connect(inet:hostname() | inet:ip_address(), inet:port_number(), map()) ->
    {ok, driver()} | {error, term()}.
connect(Host, Port, Opts) ->
    proc_lib:start_link(?MODULE, init_connect, [self(), Host, Port, Opts]).

-doc "Accept a connection and run the owner loop. Mirrors `nquic:accept/2'.".
-spec accept(nquic:listener(), map()) -> {ok, driver()} | {error, term()}.
accept(Listener, Opts) ->
    proc_lib:start_link(?MODULE, init_accept, [self(), Listener, Opts]).

-doc "Send data on a stream, blocking on backpressure. Mirrors `nquic:send/3'.".
-spec send(driver(), nquic:stream_id(), iodata()) -> ok | {error, term()}.
send(Drv, StreamId, Data) ->
    send(Drv, StreamId, Data, infinity).

-doc """
Send data on a stream with a per-call deadline.

Blocks until the whole payload is accepted, or returns
`{error, {timeout, send}}' if the peer's flow-control window does not
reopen within `Timeout' ms. Mirrors `nquic:send/4'.
""".
-spec send(driver(), nquic:stream_id(), iodata(), timeout()) -> ok | {error, term()}.
send(Drv, StreamId, Data, Timeout) ->
    call(Drv, {send, StreamId, Data, Timeout}).

-doc "Send data and FIN on a stream, blocking on backpressure. Mirrors `nquic:send_fin/3'.".
-spec send_fin(driver(), nquic:stream_id(), iodata()) -> ok | {error, term()}.
send_fin(Drv, StreamId, Data) ->
    send_fin(Drv, StreamId, Data, infinity).

-doc "Send data and FIN with a per-call deadline. Mirrors `nquic:send_fin/4'.".
-spec send_fin(driver(), nquic:stream_id(), iodata(), timeout()) -> ok | {error, term()}.
send_fin(Drv, StreamId, Data, Timeout) ->
    call(Drv, {send_fin, StreamId, Data, Timeout}).

-doc "Send an unreliable DATAGRAM. Mirrors `nquic:send_datagram/2'.".
-spec send_datagram(driver(), binary()) -> ok | {error, term()}.
send_datagram(Drv, Data) ->
    call(Drv, {send_datagram, Data}).

-doc "Receive from a stream, blocking forever. Mirrors `nquic:recv/2'.".
-spec recv(driver(), nquic:stream_id()) -> {ok, binary(), fin | nofin} | {error, term()}.
recv(Drv, StreamId) ->
    recv(Drv, StreamId, infinity).

-doc "Receive from a stream with a timeout. Mirrors `nquic:recv/3'.".
-spec recv(driver(), nquic:stream_id(), timeout()) ->
    {ok, binary(), fin | nofin} | {error, term()}.
recv(Drv, StreamId, Timeout) ->
    call(Drv, {recv, StreamId, Timeout}).

-doc "Read a buffered DATAGRAM. Mirrors `nquic_lib:recv_datagram/1'.".
-spec recv_datagram(driver()) -> {ok, binary()} | {error, empty}.
recv_datagram(Drv) ->
    call(Drv, recv_datagram).

-doc "Open a new stream. Mirrors `nquic:open_stream/2'.".
-spec open_stream(driver(), map()) -> {ok, nquic:stream_id()} | {error, term()}.
open_stream(Drv, Opts) ->
    call(Drv, {open_stream, Opts}).

-doc "Accept a peer-initiated stream, blocking forever. Mirrors `nquic:accept_stream/1'.".
-spec accept_stream(driver()) -> {ok, nquic:stream_id()} | {error, term()}.
accept_stream(Drv) ->
    accept_stream(Drv, infinity).

-doc "Accept a peer-initiated stream with a timeout. Mirrors `nquic:accept_stream/2'.".
-spec accept_stream(driver(), timeout()) -> {ok, nquic:stream_id()} | {error, term()}.
accept_stream(Drv, Timeout) ->
    call(Drv, {accept_stream, Timeout}).

-doc "Close a stream. Mirrors `nquic:close_stream/2'.".
-spec close_stream(driver(), nquic:stream_id()) -> ok | {error, term()}.
close_stream(Drv, StreamId) ->
    call(Drv, {close_stream, StreamId}).

-doc "Reset a stream. Mirrors `nquic:reset_stream/3'.".
-spec reset_stream(driver(), nquic:stream_id(), non_neg_integer()) -> ok | {error, term()}.
reset_stream(Drv, StreamId, ErrorCode) ->
    call(Drv, {reset_stream, StreamId, ErrorCode}).

-doc "Point-in-time stream writability. Mirrors `nquic_lib:is_writable/2'.".
-spec is_writable(driver(), nquic:stream_id()) -> boolean().
is_writable(Drv, StreamId) ->
    case call(Drv, {is_writable, StreamId}) of
        Bool when is_boolean(Bool) -> Bool;
        _ -> false
    end.

-doc "Initiate a client-side key update. Mirrors `nquic_lib:initiate_key_update/1'.".
-spec initiate_key_update(driver()) -> ok | {error, term()}.
initiate_key_update(Drv) ->
    call(Drv, initiate_key_update).

-doc "Connection info map. Mirrors `nquic_conn:info/1'.".
-spec info(driver()) -> {ok, map()} | {error, term()}.
info(Drv) ->
    call(Drv, info).

-doc "Peer address and port. Mirrors `nquic_conn:peername/1'.".
-spec peername(driver()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
peername(Drv) ->
    call(Drv, peername).

-doc "Local address and port. Mirrors `nquic_conn:sockname/1'.".
-spec sockname(driver()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
sockname(Drv) ->
    call(Drv, sockname).

-doc "Peer's DER certificate. Mirrors `nquic_conn:peercert/1'.".
-spec peercert(driver()) -> {ok, binary()} | {error, term()}.
peercert(Drv) ->
    call(Drv, peercert).

-doc """
The raw `#conn_state{}' of the owned ctx, for white-box assertions.

Returns `nquic_lib:ctx_state/1'; the caller pattern-matches the
records it needs (the suite includes `nquic.hrl').
""".
-spec conn_state(driver()) -> {ok, nquic_protocol:state()} | {error, term()}.
conn_state(Drv) ->
    call(Drv, conn_state).

-doc "Close the connection gracefully and stop the owner. Mirrors `nquic:close/1'.".
-spec close(driver()) -> ok.
close(Drv) ->
    close(Drv, #{}).

-doc "Close the connection with options and stop the owner. Mirrors `nquic:close/2'.".
-spec close(driver(), map()) -> ok.
close(Drv, Opts) ->
    case call(Drv, {close, Opts}) of
        ok -> ok;
        {error, closed} -> ok
    end.

%%%-----------------------------------------------------------------------------
%% CALL TRANSPORT
%%%-----------------------------------------------------------------------------

-spec call(driver(), term()) -> term().
call(Drv, Req) ->
    Ref = monitor(process, Drv),
    Drv ! {'$drv_call', {self(), Ref}, Req},
    receive
        {Ref, Reply} ->
            erlang:demonitor(Ref, [flush]),
            Reply;
        {'DOWN', Ref, process, Drv, _Reason} ->
            {error, closed}
    end.

-spec reply(from(), term()) -> ok.
reply({Pid, Ref}, Reply) ->
    Pid ! {Ref, Reply},
    ok.

%%%-----------------------------------------------------------------------------
%% SETUP
%%%-----------------------------------------------------------------------------

-spec init_connect(pid(), inet:hostname() | inet:ip_address(), inet:port_number(), map()) ->
    no_return().
init_connect(Parent, Host, Port, Opts) ->
    process_flag(trap_exit, true),
    case nquic:connect(Host, Port, Opts) of
        {ok, Ctx0} ->
            St = new_state(Parent, Ctx0),
            proc_lib:init_ack(Parent, {ok, self()}),
            loop(arm_recv(St));
        {error, Reason} ->
            proc_lib:init_ack(Parent, {error, Reason}),
            exit(normal)
    end.

-spec init_accept(pid(), nquic:listener(), map()) -> no_return().
init_accept(Parent, Listener, Opts) ->
    process_flag(trap_exit, true),
    case nquic:accept(Listener, Opts) of
        {ok, Ctx0} ->
            {ok, Ctx1} = nquic_lib:takeover(Ctx0),
            case nquic_lib:recv_pending(Ctx1) of
                {ok, Events, Ctx3} ->
                    {ok, Ctx4} = nquic_lib:flush(Ctx3),
                    St0 = new_state(Parent, Ctx4),
                    St1 = seed_pending_streams(process_events(Events, St0)),
                    proc_lib:init_ack(Parent, {ok, self()}),
                    loop(arm_recv(St1));
                {error, Reason, Ctx3} ->
                    _ = emit_fatal_close(Reason, Ctx3),
                    proc_lib:init_ack(Parent, {error, Reason}),
                    exit(normal)
            end;
        {error, Reason} ->
            proc_lib:init_ack(Parent, {error, Reason}),
            exit(normal)
    end.

-spec new_state(pid(), nquic:ctx()) -> #st{}.
new_state(Parent, Ctx) ->
    #st{ctx = Ctx, parent = Parent, socket = nquic_lib:ctx_socket(Ctx)}.


%%%-----------------------------------------------------------------------------
%% OWNER LOOP
%%%-----------------------------------------------------------------------------

-spec loop(#st{}) -> no_return().
loop(#st{socket = Socket, parent = Parent} = St) ->
    receive
        {'$socket', Socket, select, _SI} ->
            loop(handle_socket_ready(St));
        {immediate_packet, Source, Bin} ->
            loop(process_incoming(Source, Bin, St));
        {packet, Source, Bin} ->
            loop(process_incoming(Source, Bin, St));
        {packet, Source, Bin, _ECN} ->
            loop(process_incoming(Source, Bin, St));
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            loop(process_incoming_batch(Source, Buf, GsoSize, ECN, St));
        {quic_timeout, Type} ->
            loop(process_timeout(Type, St));
        {quic_session_ticket, _Conn, Ticket} ->
            Parent ! {quic_session_ticket, self(), Ticket},
            loop(St);
        {recv_timeout, From, StreamId} ->
            loop(expire_recv_waiter(From, StreamId, St));
        {accept_timeout, From} ->
            loop(expire_accept_waiter(From, St));
        {quic_drain, _Listener} ->
            do_close(St, #{}),
            exit(normal);
        {'$drv_call', From, {close, Opts}} ->
            do_close(St, Opts),
            reply(From, ok),
            exit(normal);
        {'$drv_call', From, Req} ->
            loop(handle_call(Req, From, St));
        {'EXIT', Parent, Reason} ->
            do_close(St, #{}),
            exit(Reason);
        {'EXIT', _Other, _Reason} ->
            loop(St)
    end.

-spec handle_socket_ready(#st{}) -> #st{}.
handle_socket_ready(#st{socket = Socket} = St) ->
    case nquic_socket:recv_now(Socket) of
        {ok, {Source, Bin}} ->
            process_incoming(Source, Bin, St);
        {select, _SI} ->
            St;
        {error, _Reason} ->
            mark_closed(St)
    end.

-spec process_incoming(nquic_socket:sockaddr(), binary(), #st{}) -> #st{}.
process_incoming(Source, Bin, #st{ctx = Ctx} = St) ->
    case nquic_lib:handle_packet(Ctx, Source, Bin) of
        {ok, Events, Ctx1} ->
            {ok, Ctx2} = nquic_lib:flush(Ctx1),
            St1 = process_events(Events, St#st{ctx = Ctx2}),
            arm_recv(St1);
        {error, Reason, Ctx1} ->
            fatal(Reason, St#st{ctx = Ctx1})
    end.

-spec process_incoming_batch(
    nquic_socket:sockaddr(), binary(), pos_integer(), nquic_socket:ecn_mark(), #st{}
) -> #st{}.
process_incoming_batch(Source, Buf, GsoSize, ECN, #st{ctx = Ctx} = St) ->
    {ok, Events, Ctx1} = nquic_lib:handle_packet_batch(Ctx, Source, Buf, GsoSize, ECN),
    {ok, Ctx2} = nquic_lib:flush(Ctx1),
    St1 = process_events(Events, St#st{ctx = Ctx2}),
    arm_recv(St1).

-spec process_timeout(nquic_protocol:timer_type(), #st{}) -> #st{}.
process_timeout(Type, #st{ctx = Ctx} = St) ->
    case nquic_lib:timeout(Ctx, Type) of
        {ok, Events, Ctx1} ->
            St1 = process_events(Events, St#st{ctx = Ctx1}),
            arm_recv(St1);
        {error, Reason, Ctx1} ->
            fatal(Reason, St#st{ctx = Ctx1})
    end.

-spec arm_recv(#st{}) -> #st{}.
arm_recv(#st{ctx = Ctx, socket = Socket} = St) ->
    OwnsSocket =
        nquic_lib:ctx_connected(Ctx) orelse nquic_lib:ctx_dispatch(Ctx) =:= undefined,
    case OwnsSocket of
        true ->
            case nquic_socket:recv_start(Socket) of
                {ok, {Source, Bin}} ->
                    self() ! {immediate_packet, Source, Bin},
                    St;
                {select, _SI} ->
                    St;
                {error, _Reason} ->
                    St
            end;
        false ->
            St
    end.

%%%-----------------------------------------------------------------------------
%% REQUEST HANDLERS
%%%-----------------------------------------------------------------------------

-spec handle_call(term(), from(), #st{}) -> #st{}.
handle_call(_Req, From, #st{closed = true} = St) ->
    reply(From, {error, closed}),
    St;
handle_call({send, StreamId, Data, Timeout}, From, St) ->
    bp_send(nofin, StreamId, Data, Timeout, From, St);
handle_call({send_fin, StreamId, Data, Timeout}, From, St) ->
    bp_send(fin, StreamId, Data, Timeout, From, St);
handle_call({send_datagram, Data}, From, #st{ctx = Ctx} = St) ->
    case nquic_lib:send_datagram(Ctx, Data) of
        {ok, Ctx1} ->
            reply(From, ok),
            St#st{ctx = Ctx1};
        {error, Reason} ->
            reply(From, {error, Reason}),
            St
    end;
handle_call({open_stream, Opts}, From, #st{ctx = Ctx} = St) ->
    case nquic_lib:open_stream(Ctx, Opts) of
        {ok, StreamId, Ctx1} ->
            reply(From, {ok, StreamId}),
            St#st{ctx = Ctx1};
        {error, Reason} ->
            reply(From, {error, Reason}),
            St
    end;
handle_call({close_stream, StreamId}, From, #st{ctx = Ctx} = St) ->
    case nquic_lib:close_stream(Ctx, StreamId) of
        {ok, Ctx1} ->
            reply(From, ok),
            St#st{ctx = Ctx1};
        {error, Reason} ->
            reply(From, {error, Reason}),
            St
    end;
handle_call({reset_stream, StreamId, ErrorCode}, From, #st{ctx = Ctx} = St) ->
    case nquic_lib:reset_stream(Ctx, StreamId, ErrorCode) of
        {ok, Ctx1} ->
            reply(From, ok),
            St#st{ctx = Ctx1};
        {error, Reason} ->
            reply(From, {error, Reason}),
            St
    end;
handle_call(initiate_key_update, From, #st{ctx = Ctx} = St) ->
    case nquic_lib:initiate_key_update(Ctx) of
        {ok, Ctx1} ->
            reply(From, ok),
            St#st{ctx = Ctx1};
        {error, Reason} ->
            reply(From, {error, Reason}),
            St
    end;
handle_call({is_writable, StreamId}, From, #st{ctx = Ctx} = St) ->
    reply(From, nquic_lib:is_writable(Ctx, StreamId)),
    St;
handle_call(info, From, #st{ctx = Ctx} = St) ->
    reply(From, {ok, nquic_protocol:info(established, nquic_ctx:state(Ctx))}),
    St;
handle_call(peername, From, #st{ctx = Ctx} = St) ->
    Reply =
        case nquic_lib:ctx_peer(Ctx) of
            SockAddr when is_map(SockAddr) ->
                {ok, nquic_socket:sockaddr_to_tuple(SockAddr)};
            _ ->
                {error, not_connected}
        end,
    reply(From, Reply),
    St;
handle_call(sockname, From, #st{ctx = Ctx} = St) ->
    Reply =
        case nquic_socket:sockname(nquic_lib:ctx_socket(Ctx)) of
            {ok, SockAddr} -> {ok, nquic_socket:sockaddr_to_tuple(SockAddr)};
            {error, _} = Err -> Err
        end,
    reply(From, Reply),
    St;
handle_call(peercert, From, #st{ctx = Ctx} = St) ->
    Reply =
        case nquic_protocol:peercert(nquic_lib:ctx_state(Ctx)) of
            DER when is_binary(DER) -> {ok, DER};
            undefined -> nquic_error:wrap(no_peercert)
        end,
    reply(From, Reply),
    St;
handle_call(conn_state, From, #st{ctx = Ctx} = St) ->
    reply(From, {ok, nquic_lib:ctx_state(Ctx)}),
    St;
handle_call(recv_datagram, From, #st{datagrams = DQ} = St) ->
    case queue:out(DQ) of
        {{value, Data}, DQ1} ->
            reply(From, {ok, Data}),
            St#st{datagrams = DQ1};
        {empty, _} ->
            reply(From, {error, empty}),
            St
    end;
handle_call({recv, StreamId, Timeout}, From, St) ->
    try_recv(StreamId, From, Timeout, St);
handle_call({accept_stream, Timeout}, From, St) ->
    try_accept(From, Timeout, St).

%%%-----------------------------------------------------------------------------
%% RECV / ACCEPT WAITERS
%%%-----------------------------------------------------------------------------

-spec try_recv(nquic:stream_id(), from(), timeout(), #st{}) -> #st{}.
try_recv(StreamId, From, Timeout, #st{ctx = Ctx} = St) ->
    case nquic_lib:recv(Ctx, StreamId) of
        {ok, Data, IsFin, Ctx1} when Data =/= <<>>; IsFin ->
            reply(From, {ok, Data, fin_atom(IsFin)}),
            St#st{ctx = Ctx1};
        {ok, <<>>, false, Ctx1} ->
            park_recv(StreamId, From, Timeout, St#st{ctx = Ctx1});
        {error, no_data} ->
            park_recv(StreamId, From, Timeout, St);
        {error, Reason} ->
            reply(From, {error, Reason}),
            St
    end.

-spec park_recv(nquic:stream_id(), from(), timeout(), #st{}) -> #st{}.
park_recv(StreamId, From, Timeout, #st{recv_waiters = W} = St) ->
    Timer = arm_timer(Timeout, {recv_timeout, From, StreamId}),
    Waiter = #waiter{from = From, timer = Timer},
    Existing = maps:get(StreamId, W, []),
    St#st{recv_waiters = W#{StreamId => Existing ++ [Waiter]}}.

-spec satisfy_recv_waiters(nquic:stream_id(), #st{}) -> #st{}.
satisfy_recv_waiters(StreamId, #st{recv_waiters = W} = St) ->
    case maps:get(StreamId, W, []) of
        [] ->
            St;
        [#waiter{from = From, timer = Timer} | Rest] ->
            case nquic_lib:recv(St#st.ctx, StreamId) of
                {ok, Data, IsFin, Ctx1} when Data =/= <<>>; IsFin ->
                    cancel_timer(Timer),
                    reply(From, {ok, Data, fin_atom(IsFin)}),
                    St1 = St#st{ctx = Ctx1, recv_waiters = W#{StreamId => Rest}},
                    satisfy_recv_waiters(StreamId, St1);
                {ok, <<>>, false, Ctx1} ->
                    St#st{ctx = Ctx1};
                {error, no_data} ->
                    St;
                {error, Reason} ->
                    cancel_timer(Timer),
                    reply(From, {error, Reason}),
                    St#st{recv_waiters = W#{StreamId => Rest}}
            end
    end.

-spec expire_recv_waiter(from(), nquic:stream_id(), #st{}) -> #st{}.
expire_recv_waiter(From, StreamId, #st{recv_waiters = W} = St) ->
    Waiters = maps:get(StreamId, W, []),
    case lists:keytake(From, #waiter.from, Waiters) of
        {value, _Waiter, Rest} ->
            reply(From, {error, timeout}),
            St#st{recv_waiters = W#{StreamId => Rest}};
        false ->
            St
    end.

-spec try_accept(from(), timeout(), #st{}) -> #st{}.
try_accept(From, Timeout, #st{pending_streams = PQ} = St) ->
    case queue:out(PQ) of
        {{value, StreamId}, PQ1} ->
            reply(From, {ok, StreamId}),
            St#st{pending_streams = PQ1};
        {empty, _} ->
            Timer = arm_timer(Timeout, {accept_timeout, From}),
            Waiter = #waiter{from = From, timer = Timer},
            St#st{accept_waiters = St#st.accept_waiters ++ [Waiter]}
    end.

-spec satisfy_accept(nquic:stream_id(), #st{}) -> #st{}.
satisfy_accept(StreamId, #st{accept_waiters = [#waiter{from = From, timer = Timer} | Rest]} = St) ->
    cancel_timer(Timer),
    reply(From, {ok, StreamId}),
    St#st{accept_waiters = Rest};
satisfy_accept(StreamId, #st{accept_waiters = [], pending_streams = PQ} = St) ->
    St#st{pending_streams = queue:in(StreamId, PQ)}.

%% Reconcile peer-initiated streams that were opened on the connection
%% *before* this owner took it over: the handshake gen_statem applied
%% them to the conn_state, so no `{stream_opened, _}' event reaches us.
%% Surface them once at init so `accept_stream/1' can return them.
-spec seed_pending_streams(#st{}) -> #st{}.
seed_pending_streams(#st{ctx = Ctx} = St) ->
    Ids = nquic_protocol:pending_stream_ids(nquic_ctx:state(Ctx)),
    lists:foldl(fun queue_if_new/2, St, Ids).

-spec queue_if_new(nquic:stream_id(), #st{}) -> #st{}.
queue_if_new(StreamId, #st{pending_streams = PQ} = St) ->
    case lists:member(StreamId, queue:to_list(PQ)) of
        true -> St;
        false -> satisfy_accept(StreamId, St)
    end.

-spec expire_accept_waiter(from(), #st{}) -> #st{}.
expire_accept_waiter(From, #st{accept_waiters = Waiters} = St) ->
    case lists:keytake(From, #waiter.from, Waiters) of
        {value, _Waiter, Rest} ->
            reply(From, {error, timeout}),
            St#st{accept_waiters = Rest};
        false ->
            St
    end.

%%%-----------------------------------------------------------------------------
%% BACKPRESSURE-AWARE SEND
%%
%% `nquic_lib:send/send_fin' is all-or-nothing: a payload that exceeds
%% the peer's connection/stream flow-control window is rejected whole.
%% The owner-loop equivalent of the old pid `send_sync' is therefore:
%% try the whole payload; on a flow-control rejection split it and
%% retry the pieces, pumping the recv loop between attempts so the
%% peer's MAX_DATA / MAX_STREAM_DATA credit grants land. This is pure
%% `nquic_lib' orchestration, no protocol logic.
%%%-----------------------------------------------------------------------------

-spec bp_send(fin | nofin, nquic:stream_id(), iodata(), timeout(), from(), #st{}) -> #st{}.
bp_send(Fin, StreamId, Data, Timeout, From, St) ->
    Deadline = deadline_at(Timeout),
    Bin = iolist_to_binary(Data),
    case backpressure_send(Fin, StreamId, Bin, Deadline, arm_recv(St)) of
        {ok, St1} ->
            reply(From, ok),
            St1;
        {error, Reason, St1} ->
            reply(From, {error, Reason}),
            St1
    end.

-spec backpressure_send(
    fin | nofin, nquic:stream_id(), binary(), integer() | infinity, #st{}
) -> {ok, #st{}} | {error, term(), #st{}}.
backpressure_send(Fin, StreamId, Bin, Deadline, #st{ctx = Ctx} = St) ->
    case lib_send(Fin, Ctx, StreamId, Bin) of
        {ok, Ctx1} ->
            {ok, arm_recv(St#st{ctx = Ctx1})};
        {blocked, Ctx1} when byte_size(Bin) >= 2 ->
            Half = byte_size(Bin) div 2,
            <<H1:Half/binary, H2/binary>> = Bin,
            case backpressure_send(nofin, StreamId, H1, Deadline, St#st{ctx = Ctx1}) of
                {ok, St2} ->
                    backpressure_send(Fin, StreamId, H2, Deadline, St2);
                Err ->
                    Err
            end;
        {blocked, Ctx1} ->
            case wait_for_credit(Deadline, arm_recv(St#st{ctx = Ctx1})) of
                {ok, St2} ->
                    backpressure_send(Fin, StreamId, Bin, Deadline, St2);
                {timeout, St2} ->
                    {error, {timeout, send}, St2}
            end;
        {error, Reason, Ctx1} ->
            {error, Reason, St#st{ctx = Ctx1}};
        {error, Reason} ->
            {error, Reason, St}
    end.

-spec lib_send(fin | nofin, nquic:ctx(), nquic:stream_id(), binary()) ->
    {ok, nquic:ctx()} | {blocked, nquic:ctx()} | {error, term(), nquic:ctx()} | {error, term()}.
lib_send(Fin, Ctx, StreamId, Bin) ->
    Result =
        case Fin of
            fin -> nquic_lib:send_fin(Ctx, StreamId, Bin);
            nofin -> nquic_lib:send(Ctx, StreamId, Bin)
        end,
    case Result of
        {ok, Ctx1} -> {ok, Ctx1};
        {error, {conn_flow_control_blocked, _}, Ctx1} -> {blocked, Ctx1};
        {error, {stream_flow_control_blocked, _}, Ctx1} -> {blocked, Ctx1};
        Other -> Other
    end.

-spec wait_for_credit(integer() | infinity, #st{}) -> {ok, #st{}} | {timeout, #st{}}.
wait_for_credit(Deadline, #st{socket = Socket, parent = Parent} = St) ->
    Remaining = remaining(Deadline),
    case Remaining =< 0 of
        true ->
            {timeout, St};
        false ->
            Tick = min(Remaining, 25),
            receive
                {'$socket', Socket, select, _SI} ->
                    {ok, handle_socket_ready(St)};
                {immediate_packet, Source, Bin} ->
                    {ok, process_incoming(Source, Bin, St)};
                {packet, Source, Bin} ->
                    {ok, process_incoming(Source, Bin, St)};
                {packet, Source, Bin, _ECN} ->
                    {ok, process_incoming(Source, Bin, St)};
                {packet_batch, Source, Buf, GsoSize, ECN} ->
                    {ok, process_incoming_batch(Source, Buf, GsoSize, ECN, St)};
                {quic_timeout, Type} ->
                    {ok, process_timeout(Type, St)};
                {quic_session_ticket, _Conn, Ticket} ->
                    Parent ! {quic_session_ticket, self(), Ticket},
                    {ok, St}
            after Tick ->
                {ok, St}
            end
    end.

-spec deadline_at(timeout()) -> integer() | infinity.
deadline_at(infinity) ->
    infinity;
deadline_at(Timeout) when is_integer(Timeout), Timeout >= 0 ->
    erlang:monotonic_time(millisecond) + Timeout.

-spec remaining(integer() | infinity) -> integer() | infinity.
remaining(infinity) ->
    infinity;
remaining(Deadline) ->
    Deadline - erlang:monotonic_time(millisecond).

%%%-----------------------------------------------------------------------------
%% EVENT PROCESSING
%%%-----------------------------------------------------------------------------

-spec process_events([nquic_protocol:event()], #st{}) -> #st{}.
process_events([], St) ->
    St;
process_events([{stream_data, StreamId} | Rest], St) ->
    process_events(Rest, satisfy_recv_waiters(StreamId, St));
process_events([{stream_opened, StreamId} | Rest], St) ->
    process_events(Rest, satisfy_accept(StreamId, St));
process_events([{stream_reset, StreamId, _Code} | Rest], St) ->
    process_events(Rest, satisfy_recv_waiters(StreamId, St));
process_events([{datagram_received, Data} | Rest], #st{datagrams = DQ} = St) ->
    process_events(Rest, St#st{datagrams = queue:in(Data, DQ)});
process_events([{new_session_ticket, Bin} | Rest], #st{ctx = Ctx} = St) ->
    State0 = nquic_ctx:state(Ctx),
    State1 = nquic_session_ticket:process_new_session_ticket(Bin, State0),
    process_events(Rest, St#st{ctx = nquic_ctx:set_state(Ctx, State1)});
process_events([connection_closed | Rest], St) ->
    process_events(Rest, mark_closed(St));
process_events([_Event | Rest], St) ->
    process_events(Rest, St).

%%%-----------------------------------------------------------------------------
%% TERMINATION / HELPERS
%%%-----------------------------------------------------------------------------

%% A `{transport_error, _}' from `handle_packet'/`timeout' is a
%% detected peer violation: the owner MUST send a CONNECTION_CLOSE
%% carrying the mapped transport error code before tearing down, the
%% same RFC behaviour the handshake gen_statem emits from
%% `nquic_conn_close:send_connection_close/3'. `nquic_lib:close/2'
%% queues + flushes the 1-RTT close; other errors close silently as
%% before. Pure `nquic_lib'/`nquic_protocol' orchestration.
-spec fatal(term(), #st{}) -> #st{}.
fatal(Reason, #st{ctx = Ctx} = St) ->
    mark_closed(St#st{ctx = emit_fatal_close(Reason, Ctx)}).

%% Emit the RFC-mapped CONNECTION_CLOSE for a detected peer violation,
%% then return the (flushed) ctx. `nquic_lib:close/2' queues + flushes
%% the 1-RTT close; non-`transport_error' reasons close silently as
%% before. Pure `nquic_lib'/`nquic_protocol' orchestration, the same
%% behaviour the handshake gen_statem emits via
%% `nquic_conn_close:send_connection_close/3'.
-spec emit_fatal_close(term(), nquic:ctx()) -> nquic:ctx().
emit_fatal_close({transport_error, Err}, Ctx) ->
    try
        nquic_lib:close(Ctx, #{
            scope => transport,
            error_code => nquic_protocol:error_code(Err),
            reason => nquic_protocol:error_to_reason_phrase(Err)
        })
    of
        {ok, C} -> C
    catch
        error:_ -> Ctx
    end;
emit_fatal_close(_Reason, Ctx) ->
    Ctx.

-spec mark_closed(#st{}) -> #st{}.
mark_closed(#st{closed = true} = St) ->
    St;
mark_closed(#st{recv_waiters = W, accept_waiters = AW} = St) ->
    ok = maps:foreach(
        fun(_StreamId, Waiters) ->
            lists:foreach(fun fail_waiter/1, Waiters)
        end,
        W
    ),
    lists:foreach(fun fail_waiter/1, AW),
    St#st{closed = true, recv_waiters = #{}, accept_waiters = []}.

-spec fail_waiter(#waiter{}) -> ok.
fail_waiter(#waiter{from = From, timer = Timer}) ->
    cancel_timer(Timer),
    reply(From, {error, closed}).

-spec do_close(#st{}, map()) -> ok.
do_close(#st{ctx = Ctx}, Opts) ->
    case maps:get(scope, Opts, transport) of
        application ->
            nquic_lib:shutdown(
                Ctx,
                maps:get(error_code, Opts, 0),
                maps:get(reason, Opts, <<>>)
            );
        _ ->
            nquic_lib:shutdown(Ctx)
    end.

-spec arm_timer(timeout(), term()) -> reference() | undefined.
arm_timer(infinity, _Msg) ->
    undefined;
arm_timer(Timeout, Msg) when is_integer(Timeout), Timeout >= 0 ->
    erlang:send_after(Timeout, self(), Msg).

-spec cancel_timer(reference() | undefined) -> ok.
cancel_timer(undefined) ->
    ok;
cancel_timer(Ref) ->
    _ = erlang:cancel_timer(Ref, [{async, true}, {info, false}]),
    ok.

-spec fin_atom(boolean()) -> fin | nofin.
fin_atom(true) -> fin;
fin_atom(false) -> nofin.
