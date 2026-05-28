-module(nquic_conn_statem).
-moduledoc """
QUIC connection handshake state machine.

Each connection is a single `gen_statem` process that drives the
handshake only, with states `initial`, `handshake`, and `draining`.
On handshake completion the process proactively exports the
connection (`#quic_ctx{}`, plus the connected UDP socket on a
per-conn-fd server) to its owner and terminates with `{shutdown,
exported}`; the owner then drives the established connection through
`m:nquic_lib` / `m:nquic_protocol`. There is no post-handshake
state in this process.
""".
-behaviour(gen_statem).

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-include("nquic_path.hrl").
-include("nquic_socket.hrl").
-export([handle_packet_event/2, start_link/1]).
-export([
    close/3,
    info/1,
    migrate/2,
    path_stats/1,
    peercert/1,
    peername/1,
    sockname/1,
    streams/1
]).

-export([callback_mode/0, init/1, terminate/3]).
-export([draining/3, handshake/3, initial/3]).

-export([apply_peer_change/2]).
-export([handle_preferred_address_migration/2]).
-export([
    flush_and_send/1,
    flush_pending_result/1,
    handle_common/4,
    schedule_deferred_flush/1
]).

-export_type([state_name/0]).

-type state_name() :: initial | handshake | draining.
-define(PER_CONN_FD_MIGRATE_POLL_MS, 20).
-define(PER_CONN_FD_MIGRATE_CAP_MS, 2000).

-spec callback_mode() -> gen_statem:callback_mode_result().
callback_mode() ->
    state_functions.

-spec close(pid(), non_neg_integer(), binary()) -> ok | {error, nquic_error:error_reason()}.
close(Conn, ErrorCode, ReasonPhrase) ->
    statem_call(Conn, {close, transport, ErrorCode, ReasonPhrase}, 5000).

-doc """
Deliver a received packet to a connection process.
A bare `Pid ! Event` send. Backpressure relies on the kernel UDP socket
buffer (overflow drops at the kernel level), QUIC retransmission (peer
recovers any dropped packet), and the receiver-side rate limit on the
slow path. A previous revision performed a per-packet
`process_info(Pid, message_queue_len)` check; on a 1M req/s pipelined
echo it cost ~26us per cross-process call and tanked throughput by ~3x.
The mailbox uses `message_queue_data => off_heap`, so unbounded growth
under sustained overload still drives the node to memory pressure
rather than OOMing the scheduler heap; if that becomes a problem in
production the right answer is sampled telemetry, not a per-packet
syscall.
""".
-spec handle_packet_event(pid(), dynamic()) -> ok.
handle_packet_event(Pid, Event) ->
    Pid ! Event,
    ok.

-spec info(pid()) -> {ok, nquic_conn:conn_info()} | {error, nquic_error:any_reason()}.
info(Conn) ->
    statem_call(Conn, get_info, 5000).

-spec migrate(pid(), nquic_socket:sockaddr()) -> ok | {error, nquic_error:any_reason()}.
migrate(Conn, NewLocalAddr) ->
    statem_call(Conn, {migrate, NewLocalAddr}, 5000).

-spec path_stats(pid()) -> {ok, nquic_loss:path_stats()} | {error, nquic_error:any_reason()}.
path_stats(Conn) ->
    statem_call(Conn, get_path_stats, 5000).

-spec peercert(pid()) -> {ok, binary()} | {error, no_peercert | closed | timeout}.
peercert(Conn) ->
    statem_call(Conn, get_peercert, 5000).

-spec peername(pid()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, nquic_error:any_reason()}.
peername(Conn) ->
    statem_call(Conn, get_peername, 5000).

-spec sockname(pid()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, nquic_error:any_reason()}.
sockname(Conn) ->
    statem_call(Conn, get_sockname, 5000).

-doc "Start a connection state machine with the given options.".
-spec start_link(map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Opts) ->
    gen_statem:start_link(?MODULE, Opts, [
        {spawn_opt, [{message_queue_data, off_heap}]}
    ]).

-spec statem_call(pid(), dynamic(), timeout()) ->
    dynamic() | {error, nquic_error:error_reason()}.
statem_call(Pid, Request, Timeout) ->
    try
        case gen_statem:call(Pid, Request, Timeout) of
            {error, Reason} -> nquic_error:wrap(Reason);
            Other -> Other
        end
    catch
        exit:{noproc, _} -> {error, closed};
        exit:{timeout, _} -> nquic_error:timeout(recv);
        exit:{_Reason, {gen_statem, call, _}} -> {error, closed}
    end.

-spec streams(pid()) -> {ok, [nquic:stream_id()]} | {error, nquic_error:any_reason()}.
streams(Conn) ->
    statem_call(Conn, get_streams, 5000).

%%%-----------------------------------------------------------------------------
%% GEN_STATEM CALLBACKS
%%%-----------------------------------------------------------------------------
-spec init(map()) ->
    {ok, state_name(), #conn_state{}, [gen_statem:action()]}.
init(Opts) ->
    Data = nquic_conn_init:new_conn_state(Opts),
    #conn_state{
        role = Role,
        scid = SCID,
        socket = Socket,
        listener = Listener,
        dispatch_table = DispatchTable
    } = Data,

    case DispatchTable of
        undefined -> ok;
        Table -> nquic_listener:dispatch_register(Table, SCID, self())
    end,

    nquic_conn_metrics:handshake_started(Data),

    Actions =
        case Role of
            client ->
                [{next_event, internal, start_handshake}];
            server when Listener =:= undefined, Socket =/= undefined ->
                [{next_event, internal, start_recv}];
            server ->
                []
        end,

    {ok, initial, Data, Actions}.

%%%-----------------------------------------------------------------------------
%% STATE FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec draining(gen_statem:event_type(), dynamic(), #conn_state{}) ->
    gen_statem:event_handler_result(state_name()).
draining({timeout, draining_timeout}, drain_expire, Data) ->
    {stop, normal, Data};
draining({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, draining}}]};
draining(_, _, _Data) ->
    keep_state_and_data.

-spec handshake(gen_statem:event_type(), dynamic(), #conn_state{}) ->
    gen_statem:event_handler_result(state_name()).
handshake({timeout, idle_timeout}, _, Data) ->
    {stop, {transport_error, idle_timeout}, Data};
handshake({timeout, pto_timeout}, _, Data) ->
    nquic_conn_timers:handle_pto(handshake, Data);
handshake(info, {'$socket', Socket, select, _SelectInfo}, #conn_state{socket = Socket} = Data) ->
    handle_client_recv(handshake, Data);
handshake(info, {packet, Source, PacketBin, ECN}, Data) ->
    {_, Data1} = apply_peer_change(Source, Data),
    handle_packet(PacketBin, handshake, Data1#conn_state{recv_ecn = ECN});
handshake(info, {packet, Source, PacketBin}, Data) ->
    {_, Data1} = apply_peer_change(Source, Data),
    handle_packet(PacketBin, handshake, Data1);
handshake(info, {packet_batch, Source, Buf, GsoSize, ECN}, Data) ->
    handle_handshake_or_initial_batch(handshake, Buf, Source, GsoSize, ECN, Data);
handshake(Type, Content, Data) ->
    handle_common(Type, Content, handshake, Data).

-spec initial(gen_statem:event_type(), dynamic(), #conn_state{}) ->
    gen_statem:event_handler_result(state_name()).
initial(internal, start_handshake, Data) ->
    {ok, Data1} = nquic_protocol_handshake:start_client_handshake(Data),
    {NewData, _Timers} = flush_and_send(Data1),
    nquic_conn_timers:ensure_handshake_timers(start_client_recv(NewData));
initial({timeout, idle_timeout}, _, Data) ->
    {stop, {transport_error, idle_timeout}, Data};
initial({timeout, pto_timeout}, _, Data) ->
    nquic_conn_timers:handle_pto(initial, Data);
initial(internal, start_recv, Data) ->
    start_client_recv(Data);
initial(info, {'$socket', Socket, select, _SelectInfo}, #conn_state{socket = Socket} = Data) ->
    handle_client_recv(initial, Data);
initial(info, {packet, Source, PacketBin, ECN}, Data) ->
    {_, Data1} = apply_peer_change(Source, Data),
    handle_packet(PacketBin, initial, Data1#conn_state{recv_ecn = ECN});
initial(info, {packet, Source, PacketBin}, Data) ->
    {_, Data1} = apply_peer_change(Source, Data),
    handle_packet(PacketBin, initial, Data1);
initial(info, {packet_batch, Source, Buf, GsoSize, ECN}, Data) ->
    handle_handshake_or_initial_batch(initial, Buf, Source, GsoSize, ECN, Data);
initial(Type, Content, Data) ->
    handle_common(Type, Content, initial, Data).

%%%-----------------------------------------------------------------------------
%% ESTABLISHED STATE DELEGATION TO NQUIC_PROTOCOL
%%%-----------------------------------------------------------------------------
-spec apply_ecn_dirty(nquic_socket:t(), nquic_loss:loss_state()) ->
    nquic_loss:loss_state().
apply_ecn_dirty(Socket, LS) ->
    Mark =
        case nquic_loss:is_ecn_enabled(LS) of
            true -> ect0;
            false -> not_ect
        end,
    ok = nquic_socket:set_egress_ecn(Socket, Mark),
    nquic_loss:clear_ecn_socket_dirty(LS).

-spec do_export_handoff(#conn_state{}) ->
    {stop, {shutdown, exported}, #conn_state{}}.
do_export_handoff(#conn_state{role = server, listener = Listener} = Data) when
    Listener =/= undefined
->
    #conn_state{
        socket = Socket,
        dispatch_table = Table,
        socket_connected = Connected
    } = Data,
    case nquic_dispatch:get_mgr(Table) of
        Mgr when is_pid(Mgr) ->
            _ =
                case Connected of
                    true -> nquic_socket:controlling_process(Socket, Mgr);
                    false -> ok
                end,
            nquic_listener_mgr:connection_established(
                Mgr, {exported, Data, Socket, Table, Connected, self()}
            );
        undefined ->
            ok
    end,
    {stop, {shutdown, exported}, Data};
do_export_handoff(#conn_state{owner = Owner, socket = Socket} = Data) when
    is_pid(Owner)
->
    _ =
        case Data#conn_state.select_info of
            undefined -> ok;
            SelectInfo -> nquic_socket:recv_cancel(Socket, SelectInfo)
        end,
    _ = nquic_socket:controlling_process(Socket, Owner),
    true = unlink(Owner),
    Owner ! {nquic_conn_export, self(), {ok, Data, Socket, undefined}},
    {stop, {shutdown, exported}, Data};
do_export_handoff(Data) ->
    {stop, {shutdown, exported}, Data}.

-spec do_proactive_export(#conn_state{}) ->
    {stop, {shutdown, exported}, #conn_state{}}.
do_proactive_export(Data0) ->
    {Data, _Timers} = flush_and_send(Data0),
    do_export_handoff(Data).

-spec do_send(nquic_socket:t(), nquic_socket:sockaddr(), boolean(), iodata()) ->
    ok | {error, nquic_error:any_reason()}.
do_send(Socket, Peer, false, Pkt) ->
    nquic_socket:send(Socket, Peer, Pkt);
do_send(Socket, _Peer, true, Pkt) ->
    nquic_socket:send_connected(Socket, Pkt).

-spec flush_and_send(#conn_state{}) -> {#conn_state{}, [nquic_protocol:timeout_action()]}.
flush_and_send(Data) ->
    case nquic_protocol:flush(Data) of
        {ok, Packets, Data1, TimerActions} ->
            #conn_state{
                socket = Socket,
                peer = Peer,
                loss_state = LS0,
                gso_size = GsoSize,
                socket_connected = Connected
            } = Data1,
            Data2 =
                case nquic_loss:is_ecn_socket_dirty(LS0) of
                    false -> Data1;
                    true -> Data1#conn_state{loss_state = apply_ecn_dirty(Socket, LS0)}
                end,
            nquic_conn_metrics:bytes_out(Data2, iolist_size(Packets)),
            send_packets(Socket, Peer, GsoSize, Connected, Packets),
            {Data2, TimerActions};
        {ok, Data1} ->
            {Data1, []}
    end.

-spec schedule_deferred_flush(#conn_state{}) -> #conn_state{}.
schedule_deferred_flush(#conn_state{deferred_flush_pending = true} = Data) ->
    Data;
schedule_deferred_flush(Data) ->
    self() ! deferred_flush,
    Data#conn_state{deferred_flush_pending = true}.

-spec send_packets(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    undefined | pos_integer(),
    boolean(),
    [iodata()]
) -> ok.
send_packets(_Socket, _Peer, _GsoSize, _Connected, []) ->
    ok;
send_packets(Socket, Peer, undefined, Connected, [Pkt | Rest]) ->
    _ = do_send(Socket, Peer, Connected, Pkt),
    send_packets(Socket, Peer, undefined, Connected, Rest);
send_packets(Socket, Peer, GsoSize, Connected, [Pkt | Rest]) ->
    case iolist_size(Pkt) of
        GsoSize ->
            {Group, Rest1} = take_gso_run(
                Rest, GsoSize, ?GSO_BATCH_BUDGET - GsoSize, [Pkt]
            ),
            _ = do_send(Socket, Peer, Connected, Group),
            send_packets(Socket, Peer, GsoSize, Connected, Rest1);
        _ ->
            _ = do_send(Socket, Peer, Connected, Pkt),
            send_packets(Socket, Peer, GsoSize, Connected, Rest)
    end.

-spec take_gso_run([iodata()], pos_integer(), integer(), [iodata(), ...]) ->
    {[iodata(), ...], [iodata()]}.
take_gso_run([], _GsoSize, _Budget, Acc) ->
    {lists:reverse(Acc), []};
take_gso_run([Pkt | Rest], GsoSize, Budget, Acc) ->
    case iolist_size(Pkt) of
        GsoSize when Budget >= GsoSize ->
            take_gso_run(Rest, GsoSize, Budget - GsoSize, [Pkt | Acc]);
        Smaller when Smaller < GsoSize, Budget >= Smaller ->
            {lists:reverse([Pkt | Acc]), Rest};
        _ ->
            {lists:reverse(Acc), [Pkt | Rest]}
    end.

-doc """
Drive handshake-complete handoff.
For a `server_per_conn_fd` server the RFC 9000 §9 migration needs a
spare peer connection ID, which the peer issues roughly one RTT
after the handshake completes. Until it arrives this stays in the
handshake-only FSM, polling on a bounded deadline; incoming 1-RTT
packets (including the peer's `NEW_CONNECTION_ID`) are processed by
the normal handshake packet path between polls. On success it
migrates and exports an already-connected ctx (the owner sees no
socket change); on deadline it exports on the shared socket
(graceful degradation). Every other connection exports immediately.
""".
-spec try_export(#conn_state{}, undefined | integer()) ->
    {stop, {shutdown, exported}, #conn_state{}}
    | {keep_state, #conn_state{}, [gen_statem:action()]}.
try_export(Data, Deadline) ->
    Data1 = nquic_conn_migration:maybe_initiate_server_migration(Data),
    case nquic_conn_migration:awaiting_per_conn_fd_cid(Data1) of
        false ->
            do_proactive_export(Data1);
        true ->
            Now = erlang:monotonic_time(millisecond),
            Deadline1 =
                case Deadline of
                    undefined -> Now + ?PER_CONN_FD_MIGRATE_CAP_MS;
                    D -> D
                end,
            case Now >= Deadline1 of
                true ->
                    do_proactive_export(Data1);
                false ->
                    {keep_state, Data1, [
                        {{timeout, retry_export}, ?PER_CONN_FD_MIGRATE_POLL_MS, Deadline1}
                    ]}
            end
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec apply_peer_change(nquic_socket:sockaddr(), #conn_state{}) ->
    {unchanged | changed, #conn_state{}}.
apply_peer_change(Source, #conn_state{path = Path0} = Data) ->
    PS = Path0#conn_path_mgmt.path_state,
    case nquic_path:detect_peer_change(PS, Source) of
        unchanged ->
            {unchanged, Data};
        {changed, NewPS} ->
            {changed, Data#conn_state{
                peer = NewPS#path_state.peer,
                path = Path0#conn_path_mgmt{path_state = NewPS}
            }}
    end.

-spec finish_client_recv(
    state_name(), state_name(), #conn_state{}, [gen_statem:action()]
) -> gen_statem:event_handler_result(state_name()).
finish_client_recv(Same, Same, Data, Actions) ->
    {keep_state, Data, Actions};
finish_client_recv(_OrigState, CurState, Data, Actions) ->
    {next_state, CurState, Data, Actions}.

-spec flush_pending_result(gen_statem:event_handler_result(dynamic())) ->
    gen_statem:event_handler_result(dynamic()).
flush_pending_result(
    {keep_state,
        #conn_state{
            flow = #conn_flow{
                pending_initial_frames = [],
                pending_handshake_frames = [],
                pending_app_frames = [],
                pending_app_pre_encoded = []
            }
        },
        _} = Result
) ->
    Result;
flush_pending_result(
    {next_state, _,
        #conn_state{
            flow = #conn_flow{
                pending_initial_frames = [],
                pending_handshake_frames = [],
                pending_app_frames = [],
                pending_app_pre_encoded = []
            }
        },
        _} = Result
) ->
    Result;
flush_pending_result({stop, _, _} = Result) ->
    Result;
flush_pending_result({stop_and_reply, _, _, _} = Result) ->
    Result;
flush_pending_result({keep_state, Data, Actions}) ->
    {Data1, _Timers} = flush_and_send(Data),
    {keep_state, Data1, Actions};
flush_pending_result({next_state, State, Data, Actions}) ->
    {Data1, _Timers} = flush_and_send(Data),
    {next_state, State, Data1, Actions}.

-spec handle_client_recv(state_name(), #conn_state{}) ->
    gen_statem:event_handler_result(state_name()).
handle_client_recv(StateName, Data) ->
    handle_client_recv(StateName, StateName, Data, []).

-spec handle_client_recv(
    state_name(), state_name(), #conn_state{}, [[gen_statem:action()]]
) -> gen_statem:event_handler_result(state_name()).
handle_client_recv(OrigState, CurState, #conn_state{socket = Socket} = Data, ActionsAcc) ->
    case nquic_socket:recv_now(Socket) of
        {ok, {Source, PacketBin}} ->
            {_, Data1} = apply_peer_change(Source, Data),
            case handle_packet(PacketBin, CurState, Data1) of
                {keep_state, NewData, Actions} ->
                    handle_client_recv(OrigState, CurState, NewData, [Actions | ActionsAcc]);
                {next_state, NewState, NewData, Actions} ->
                    handle_client_recv(OrigState, NewState, NewData, [Actions | ActionsAcc]);
                {stop, Reason, NewData} ->
                    {stop, Reason, NewData}
            end;
        {select, SelectInfo} ->
            FinalActions = lists:append(lists:reverse(ActionsAcc)),
            finish_client_recv(
                OrigState, CurState, Data#conn_state{select_info = SelectInfo}, FinalActions
            );
        {error, _Reason} ->
            FinalActions = lists:append(lists:reverse(ActionsAcc)),
            finish_client_recv(OrigState, CurState, Data, FinalActions)
    end.

-spec handle_common(gen_statem:event_type(), dynamic(), state_name(), #conn_state{}) ->
    gen_statem:event_handler_result(state_name()).
handle_common(internal, finish_handshake_export, _StateName, Data) ->
    try_export(Data, undefined);
handle_common({timeout, retry_export}, Deadline, _StateName, Data) ->
    try_export(Data, Deadline);
handle_common(cast, stop, _, _) ->
    {stop, normal};
handle_common(cast, {send_stream, StreamID, DataBin}, _StateName, Data) ->
    case nquic_protocol:send_stream(StreamID, DataBin, nofin, Data) of
        {ok, Data1} ->
            Data2 = schedule_deferred_flush(Data1),
            {keep_state, Data2};
        {error, _, Data1} ->
            {keep_state, Data1};
        {error, _} ->
            keep_state_and_data
    end;
handle_common(cast, {send_stream, StreamID, DataBin, true}, _StateName, Data) ->
    case nquic_protocol:send_stream(StreamID, DataBin, fin, Data) of
        {ok, Data1} ->
            {Data2, FlushTimerActions} = flush_and_send(Data1),
            {AllTimerActions, Data3} = nquic_protocol_timer:compute_timer_actions(Data2),
            StatemActions = nquic_conn_timers:timer_actions_to_statem(
                FlushTimerActions ++ AllTimerActions
            ),
            {keep_state, Data3, StatemActions};
        {error, _, Data1} ->
            {keep_state, Data1};
        {error, _} ->
            keep_state_and_data
    end;
handle_common({call, From}, {send_stream, StreamID, DataBin}, _StateName, Data) ->
    nquic_conn_send_waiters:handle_sync_send(From, StreamID, DataBin, nofin, Data);
handle_common({call, From}, {send_stream, StreamID, DataBin, Fin, Timeout}, _StateName, Data) when
    Fin =:= fin; Fin =:= nofin
->
    nquic_conn_send_waiters:handle_sync_send(From, StreamID, DataBin, Fin, Timeout, Data);
handle_common(cast, {send_datagram, DgramData}, _StateName, Data) ->
    case nquic_protocol:send_datagram(DgramData, Data) of
        {ok, Data1} ->
            Data2 = schedule_deferred_flush(Data1),
            {keep_state, Data2};
        {error, _} ->
            keep_state_and_data
    end;
handle_common({call, From}, {send_datagram, DgramData}, _StateName, Data) ->
    case nquic_protocol:send_datagram(DgramData, Data) of
        {ok, Data1} ->
            {Data2, FlushTimerActions} = flush_and_send(Data1),
            {AllTimerActions, Data3} = nquic_protocol_timer:compute_timer_actions(Data2),
            StatemActions = nquic_conn_timers:timer_actions_to_statem(
                FlushTimerActions ++ AllTimerActions
            ),
            {keep_state, Data3, [{reply, From, ok} | StatemActions]};
        {error, _} = Err ->
            {keep_state, Data, [{reply, From, Err}]}
    end;
handle_common({call, From}, get_info, StateName, Data) ->
    Info = nquic_protocol:info(StateName, Data),
    {keep_state_and_data, [{reply, From, {ok, Info}}]};
handle_common({call, From}, get_path_stats, _StateName, Data) ->
    Stats = nquic_protocol:path_stats(Data),
    {keep_state_and_data, [{reply, From, {ok, Stats}}]};
handle_common(
    {call, From}, get_peercert, _StateName, #conn_state{crypto = #conn_crypto{peer_cert = PeerCert}}
) ->
    Reply =
        case PeerCert of
            undefined -> {error, no_peercert};
            DER when is_binary(DER) -> {ok, DER}
        end,
    {keep_state_and_data, [{reply, From, Reply}]};
handle_common({call, From}, get_peername, _StateName, #conn_state{peer = Peer}) ->
    Reply =
        case Peer of
            undefined -> {error, not_connected};
            SockAddr when is_map(SockAddr) -> {ok, nquic_socket:sockaddr_to_tuple(SockAddr)}
        end,
    {keep_state_and_data, [{reply, From, Reply}]};
handle_common({call, From}, get_sockname, _StateName, #conn_state{socket = Socket}) ->
    Reply =
        case Socket of
            undefined ->
                {error, not_connected};
            _ ->
                case nquic_socket:sockname(Socket) of
                    {ok, SockAddr} -> {ok, nquic_socket:sockaddr_to_tuple(SockAddr)};
                    {error, _} = Err -> Err
                end
        end,
    {keep_state_and_data, [{reply, From, Reply}]};
handle_common(
    {call, From},
    get_streams,
    _StateName,
    #conn_state{streams_state = #conn_streams{streams = Streams}}
) ->
    StreamIds = maps:keys(Streams),
    {keep_state_and_data, [{reply, From, {ok, StreamIds}}]};
handle_common({call, From}, {is_writable, StreamID}, _StateName, Data) ->
    Bool = nquic_protocol_streams_send:is_writable(StreamID, Data),
    {keep_state_and_data, [{reply, From, {ok, Bool}}]};
handle_common({call, From}, {open_stream, Opts}, _StateName, Data) ->
    case nquic_protocol:open_stream(Opts, Data) of
        {ok, StreamId, Data1} ->
            {keep_state, Data1, [{reply, From, {ok, StreamId}}]};
        {error, _} = Err ->
            {keep_state_and_data, [{reply, From, Err}]}
    end;
handle_common({call, From}, {close, Scope, ErrorCode, ReasonPhrase}, _StateName, Data) ->
    {ok, Data1} =
        case Scope of
            transport -> nquic_protocol:close(ErrorCode, ReasonPhrase, Data);
            application -> nquic_protocol:close_app(ErrorCode, ReasonPhrase, Data)
        end,
    {Data2, _FlushTimerActions} = flush_and_send(Data1),
    nquic_conn_close:enter_close_draining(From, Data2);
handle_common({call, From}, wait_established, established, _Data) ->
    {keep_state_and_data, [{reply, From, ok}]};
handle_common({call, From}, wait_established, _StateName, Data) ->
    #conn_state{connect_waiters = Waiters} = Data,
    {keep_state, Data#conn_state{connect_waiters = [From | Waiters]}};
handle_common({call, From}, {recv_stream, StreamID}, _StateName, Data) ->
    wrap_stream_reply(From, nquic_conn_streams:recv_stream(From, StreamID, Data));
handle_common({call, From}, {send_stream, StreamID, DataBin, true}, _StateName, Data) ->
    nquic_conn_send_waiters:handle_sync_send(From, StreamID, DataBin, fin, Data);
handle_common({call, From}, accept_stream, _StateName, Data) ->
    wrap_stream_reply(From, nquic_conn_streams:accept_stream(From, Data));
handle_common({call, From}, {close_stream, StreamID}, _StateName, Data) ->
    case nquic_protocol:close_stream(StreamID, Data) of
        {ok, Data1} ->
            {Data2, _FlushTimerActions} = flush_and_send(Data1),
            {keep_state, Data2, [{reply, From, ok}]};
        {error, _} = Err ->
            {keep_state, Data, [{reply, From, Err}]}
    end;
handle_common({call, From}, {reset_stream, StreamID, ErrorCode}, _StateName, Data) ->
    case nquic_protocol:reset_stream(StreamID, ErrorCode, Data) of
        {ok, Data1} ->
            {Data2, _FlushTimerActions} = flush_and_send(Data1),
            {keep_state, Data2, [{reply, From, ok}]};
        {error, _} = Err ->
            {keep_state, Data, [{reply, From, Err}]}
    end;
handle_common({call, From}, {migrate, _NewLocalAddr}, StateName, _Data) when
    StateName =/= established
->
    {keep_state_and_data, [{reply, From, {error, not_established}}]};
handle_common({call, From}, {migrate, NewLocalAddr}, established, Data) ->
    case nquic_protocol_migration:check_migration_allowed(Data) of
        ok ->
            case nquic_conn_migration:initiate_client_migration(NewLocalAddr, Data) of
                {ok, Data1} ->
                    {Data2, _FlushTimerActions} = flush_and_send(Data1),
                    PVT = nquic_protocol_timer:compute_path_validation_timeout(Data2),
                    TimerActions = nquic_conn_timers:timer_actions_to_statem(
                        [{set_timer, path_validation, PVT}]
                    ),
                    {keep_state, Data2, TimerActions ++ [{reply, From, ok}]};
                {error, _} = Err ->
                    {keep_state_and_data, [{reply, From, Err}]}
            end;
        {error, _} = Err ->
            {keep_state_and_data, [{reply, From, Err}]}
    end;
handle_common({call, From}, initiate_key_update, _StateName, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_established}}]};
handle_common(
    info,
    {'DOWN', Ref, process, _Pid, _Reason},
    StateName,
    #conn_state{owner_mon = Ref} = Data
) ->
    Frame = #connection_close{
        error_code = 0,
        reason_phrase = <<"owner process died">>
    },
    _ = nquic_conn_close:send_close_frame(Frame, Data, StateName),
    Timeout = nquic_protocol:get_draining_timeout(Data),
    Data1 = Data#conn_state{owner = undefined, owner_mon = undefined},
    {next_state, draining, Data1,
        nquic_conn_close:draining_cancellations() ++
            [{{timeout, draining_timeout}, Timeout, drain_expire}]};
handle_common(info, deferred_flush, _StateName, Data) ->
    Data1 = Data#conn_state{deferred_flush_pending = false},
    {Data2, FlushTimerActions} = flush_and_send(Data1),
    {Data3, ReplyActions} = nquic_conn_send_waiters:wake(Data2),
    {AllTimerActions, Data4} = nquic_protocol_timer:compute_timer_actions(Data3),
    StatemActions = nquic_conn_timers:timer_actions_to_statem(FlushTimerActions ++ AllTimerActions),
    {keep_state, Data4, ReplyActions ++ StatemActions};
handle_common(info, {timeout, TimerRef, {send_wait_timeout, From}}, _StateName, Data) ->
    SS = Data#conn_state.streams_state,
    case nquic_conn_send_waiters:pop(From, TimerRef, SS#conn_streams.send_waiters) of
        {ok, NewQ} ->
            NewSS = SS#conn_streams{send_waiters = NewQ},
            Data1 = Data#conn_state{streams_state = NewSS},
            {keep_state, Data1, [{reply, From, {error, send_timeout}}]};
        not_found ->
            keep_state_and_data
    end;
handle_common(_Type, _Content, _, _) ->
    keep_state_and_data.

-spec handle_handshake_or_initial_batch(
    state_name(),
    binary(),
    nquic_socket:sockaddr(),
    pos_integer(),
    nquic_socket:ecn_mark(),
    #conn_state{}
) -> gen_statem:event_handler_result(state_name()).
handle_handshake_or_initial_batch(StateName, Buf, Source, GsoSize, ECN, Data) when
    byte_size(Buf) =< GsoSize
->
    {_, Data1} = apply_peer_change(Source, Data),
    handle_packet(Buf, StateName, Data1#conn_state{recv_ecn = ECN});
handle_handshake_or_initial_batch(StateName, Buf, Source, GsoSize, ECN, Data) ->
    <<First:GsoSize/binary, Rest/binary>> = Buf,
    self() ! {packet_batch, Source, Rest, GsoSize, ECN},
    {_, Data1} = apply_peer_change(Source, Data),
    handle_packet(First, StateName, Data1#conn_state{recv_ecn = ECN}).

-spec handle_packet(binary(), state_name(), #conn_state{}) ->
    gen_statem:event_handler_result(state_name()).
handle_packet(PacketBin, StateName, Data) ->
    Data1 = update_recv_anti_amp(byte_size(PacketBin), Data),
    Result = process_datagram(PacketBin, StateName, StateName, Data1, []),
    nquic_conn_close:maybe_drain(StateName, flush_pending_result(Result)).

-spec handle_preferred_address_migration(nquic_transport:preferred_address(), #conn_state{}) ->
    gen_statem:event_handler_result(term()).
handle_preferred_address_migration(PA, Data) ->
    {ok, Data1, ProtoTimerActions} = nquic_protocol_migration:handle_preferred_address(PA, Data),
    {Data2, FlushTimerActions} = flush_and_send(Data1),
    StatemActions = nquic_conn_timers:timer_actions_to_statem(
        ProtoTimerActions ++ FlushTimerActions
    ),
    {keep_state, Data2, StatemActions}.

-spec handle_single_packet(binary(), binary(), nquic_packet:header(), #conn_state{}) ->
    {ok, #conn_state{}}
    | {stop, term(), #conn_state{}}
    | gen_statem:event_handler_result(term()).
handle_single_packet(Packet, Rest, Header, Data) ->
    translate_protocol_result(
        nquic_protocol_recv:handle_single_packet(Packet, Rest, Header, Data)
    ).

-spec process_datagram(
    binary(), state_name(), state_name(), #conn_state{}, [gen_statem:action()]
) -> gen_statem:event_handler_result(state_name()).
process_datagram(<<>>, InitialState, CurrentState, Data, RevActions) ->
    PtoActions = nquic_conn_timers:set_pto_timer(Data),
    IdleActions = nquic_conn_timers:set_idle_timer(Data),
    AllActions = lists:reverse(RevActions, PtoActions ++ IdleActions),
    case CurrentState of
        InitialState -> {keep_state, Data, AllActions};
        _ -> {next_state, CurrentState, Data, AllActions}
    end;
process_datagram(Bin, InitialState, CurrentState, Data, RevActions) ->
    SCIDLen = byte_size(Data#conn_state.scid),
    case nquic_packet:parse_header(Bin, SCIDLen) of
        {ok, #long_header{type = version_negotiation} = Header, _} ->
            translate_protocol_result(
                nquic_protocol_recv:handle_version_negotiation(Header, Data)
            );
        {ok, #long_header{type = retry} = Header, _} ->
            translate_protocol_result(
                nquic_protocol_recv:handle_retry_packet(Bin, Header, Data)
            );
        {ok, Header, Rest} ->
            HeaderLen = byte_size(Bin) - byte_size(Rest),
            PayloadLen =
                case Header of
                    #long_header{payload_len = Len} -> Len;
                    #short_header{} -> byte_size(Rest)
                end,
            if
                byte_size(Rest) >= PayloadLen ->
                    PacketLen = HeaderLen + PayloadLen,
                    <<CurrentPacket:PacketLen/binary, NextPackets/binary>> = Bin,
                    SlicedRest = binary:part(Rest, 0, PayloadLen),

                    Res = handle_single_packet(CurrentPacket, SlicedRest, Header, Data),

                    case Res of
                        {keep_state, NewData, Actions} ->
                            process_datagram(
                                NextPackets,
                                InitialState,
                                CurrentState,
                                NewData,
                                lists:reverse(Actions, RevActions)
                            );
                        {next_state, NextState, NewData, Actions} ->
                            process_datagram(
                                NextPackets,
                                InitialState,
                                NextState,
                                NewData,
                                lists:reverse(Actions, RevActions)
                            );
                        {stop, Reason, NewData} ->
                            {stop, Reason, NewData}
                    end;
                true ->
                    {keep_state, Data, lists:reverse(RevActions)}
            end;
        {error, _Reason} ->
            {keep_state, Data, lists:reverse(RevActions)}
    end.

-spec start_client_recv(#conn_state{}) ->
    gen_statem:event_handler_result(state_name()).
start_client_recv(#conn_state{role = server, listener = Listener} = Data) when
    Listener =/= undefined
->
    {keep_state, Data};
start_client_recv(Data) ->
    handle_client_recv(initial, Data).

-spec terminate(term(), state_name(), #conn_state{}) -> ok.
terminate({shutdown, exported}, _State, Data) ->
    case nquic_conn_metrics:metrics(Data) of
        undefined -> ok;
        M -> nquic_metrics:delete_row(M, nquic_conn_metrics:row_key(Data))
    end,
    ok;
terminate(Reason, State, Data) ->
    nquic_conn_metrics:on_terminate(Reason, Data),
    nquic_conn_close:cleanup_dispatch(Data),
    case {Reason, State} of
        {normal, _} ->
            ok;
        {shutdown, _} ->
            ok;
        {_, draining} ->
            ok;
        {{transport_error, Error}, _} ->
            _ = nquic_conn_close:send_connection_close(Data, Error, State),
            ok;
        _ ->
            _ = nquic_conn_close:send_connection_close(Data, internal_error, State),
            ok
    end,
    nquic_conn_close:close_owned_socket(Data),
    nquic_qlog:detach(Data#conn_state.qlog),
    ok.

-spec translate_protocol_events([nquic_protocol:event()], #conn_state{}) ->
    gen_statem:event_handler_result(term()).
translate_protocol_events(Events, Data) ->
    Waiters =
        case lists:member(connected, Events) of
            true -> Data#conn_state.connect_waiters;
            false -> []
        end,
    Data1 = nquic_conn_events:deliver_protocol_events(Events, Data),
    Transition = lists:keyfind(state_transition, 1, Events),
    Migrate = lists:keyfind(migrate_to_preferred, 1, Events),
    WaiterReplies = [{reply, From, ok} || From <- Waiters],
    MigrateActions =
        case Migrate of
            {migrate_to_preferred, PA} ->
                [{next_event, internal, {migrate_to_preferred, PA}}];
            false ->
                []
        end,
    case Transition of
        {state_transition, established} ->
            {keep_state, Data1, [
                {next_event, internal, finish_handshake_export} | WaiterReplies
            ]};
        {state_transition, NewState} ->
            Actions = WaiterReplies ++ MigrateActions,
            {next_state, NewState, Data1, Actions};
        false ->
            {keep_state, Data1, WaiterReplies ++ MigrateActions}
    end.

-spec translate_protocol_result(
    {ok, [nquic_protocol:event()], #conn_state{}} | {error, term(), #conn_state{}}
) ->
    {ok, #conn_state{}}
    | {stop, term(), #conn_state{}}
    | gen_statem:event_handler_result(term()).
translate_protocol_result({ok, Events, NewData}) ->
    case lists:member(connection_closed, Events) of
        true ->
            OtherEvents = [E || E <- Events, E =/= connection_closed],
            Data1 = nquic_conn_events:deliver_protocol_events(OtherEvents, NewData),
            nquic_conn_close:enter_draining_silent(Data1);
        false ->
            translate_protocol_events(Events, NewData)
    end;
translate_protocol_result({error, Reason, NewData}) ->
    {stop, Reason, NewData}.

-spec update_recv_anti_amp(non_neg_integer(), #conn_state{}) -> #conn_state{}.
update_recv_anti_amp(_Size, #conn_state{role = client} = Data) ->
    Data;
update_recv_anti_amp(_Size, #conn_state{path = #conn_path_mgmt{address_validated = true}} = Data) ->
    Data;
update_recv_anti_amp(Size, #conn_state{path = Path0} = Data) ->
    NewPath = Path0#conn_path_mgmt{
        anti_amp_bytes_received = Path0#conn_path_mgmt.anti_amp_bytes_received + Size
    },
    Data#conn_state{path = NewPath}.

-spec wrap_stream_reply(gen_statem:from(), nquic_conn_streams:reply_result()) ->
    gen_statem:event_handler_result(state_name()).
wrap_stream_reply(From, {reply, Reply, Data}) ->
    {keep_state, Data, [{reply, From, Reply}]};
wrap_stream_reply(From, {reply, Reply, Data, flush}) ->
    {Data1, _Timers} = flush_and_send(Data),
    {keep_state, Data1, [{reply, From, Reply}]};
wrap_stream_reply(_From, {wait, Data}) ->
    {keep_state, Data}.

%%%-----------------------------------------------------------------------------
%% TESTS
%%%-----------------------------------------------------------------------------
