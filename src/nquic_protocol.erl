-module(nquic_protocol).
-moduledoc """
Pure functional QUIC protocol state machine.

Provides the core QUIC protocol logic without any process or I/O
dependencies. Takes data in, returns events and packets out. Can be
driven by any process (gen_statem, gen_server, or direct loop).

The caller is responsible for:
- Sending UDP packets returned by `flush/1`
- Scheduling timers from timeout actions
- Delivering events to the application
- Registering/unregistering connection IDs in dispatch tables

## Usage

```erlang
{ok, Events, State1} = nquic_protocol:handle_packet(Bin, Source, State),
{ok, Packets, State2} = nquic_protocol:flush(State1),
[nquic_socket:send(Socket, Peer, Pkt) || Pkt <- Packets].
```
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
-export([handle_packet/3, handle_packet/4, handle_packet_notimers/3, handle_packet_notimers/4]).
-export([
    close_stream/2,
    open_stream/2,
    reset_stream/3,
    send_datagram/2,
    send_stream/4,
    send_stream_capped/4
]).
-export([flush/1]).
-export([close/3, close_app/3]).
-export([
    clear_dispatch_table/1,
    info/2,
    local_cids/1,
    odcid/1,
    path_stats/1,
    peer/1,
    peercert/1,
    pending_stream_ids/1,
    read_stream/2,
    socket_connected/1
]).
-export([handle_handshake_timeout/3, handle_timeout/2]).
-export([reset_timer_cache/1]).

-export([
    error_code/1,
    error_to_reason_phrase/1,
    get_draining_timeout/1,
    get_idle_timeout/2,
    scale_ack_delay/2
]).

-export_type([event/0, state/0, timeout_action/0, timer_type/0]).

-type event() ::
    {stream_data, nquic:stream_id()}
    | {stream_opened, nquic:stream_id()}
    | {stream_reset, nquic:stream_id(), non_neg_integer()}
    | {stop_sending, nquic:stream_id(), non_neg_integer()}
    | connection_closed
    | {datagram_received, binary()}
    | {new_session_ticket, binary()}
    | {new_token_received, binary()}
    | {stream_writable, nquic:stream_id()}
    | {state_transition, handshake | established}
    | connected
    | listener_established
    | {migrate_to_preferred, nquic_transport:preferred_address()}
    | local_migration_validated.

-type timer_type() :: idle | pto | path_validation | draining | ack_delay | pmtud | pace.

-type timeout_action() ::
    {set_timer, timer_type(), non_neg_integer()}
    | {cancel_timer, timer_type()}.

-type state() :: #conn_state{}.

%%%-----------------------------------------------------------------------------
%% PUBLIC API
%%%-----------------------------------------------------------------------------
-spec buffer_to_binary(iodata()) -> binary().
buffer_to_binary(Buf) when is_binary(Buf) ->
    Buf;
buffer_to_binary(Buf) ->
    iolist_to_binary(Buf).

-spec can_emit_inline(#stream_state{}, non_neg_integer(), state()) -> boolean().
can_emit_inline(
    #stream_state{
        pending_send_size = 0,
        pending_send_fin = false,
        send_offset = SendOffset,
        stream_id = StreamID
    },
    DataLen,
    State
) ->
    has_app_keys(State) andalso
        begin
            FrameOverhead = nquic_protocol_streams_send:stream_frame_overhead(StreamID, SendOffset),
            FrameSize = FrameOverhead + DataLen,
            PayloadBudget = nquic_protocol_send:packet_payload_budget(State),
            FrameSize =< PayloadBudget andalso
                begin
                    Cwnd = nquic_loss:get_cwnd(State#conn_state.loss_state),
                    InFlight = nquic_loss:get_bytes_in_flight(State#conn_state.loss_state),
                    Queued = (State#conn_state.flow)#conn_flow.queued_app_send_bytes,
                    InFlight + Queued + FrameSize =< Cwnd
                end
        end;
can_emit_inline(_StreamState, _DataLen, _State) ->
    false.

-spec check_send_flow(state(), #stream_state{}, non_neg_integer()) ->
    ok | {blocked, atom(), non_neg_integer()}.
check_send_flow(State, StreamState, DataLen) ->
    classify_flow_checks(
        nquic_flow:check_conn_send(State, DataLen),
        nquic_flow:check_stream_send(StreamState, DataLen)
    ).

-spec classify_flow_checks(
    ok | {blocked, non_neg_integer()},
    ok | {blocked, non_neg_integer()}
) -> ok | {blocked, atom(), non_neg_integer()}.
classify_flow_checks(ok, ok) -> ok;
classify_flow_checks({blocked, Limit}, _) -> {blocked, conn_flow_control_blocked, Limit};
classify_flow_checks(_, {blocked, Limit}) -> {blocked, stream_flow_control_blocked, Limit}.

-doc """
Tear down the listener-side dispatch routing for this connection.
Pure state operation paired with the side-effecting CID
`dispatch_unregister/2` calls in
`nquic_conn_migration:finalize_server_migration/1`. Library-mode callers invoke this after
seeing `local_migration_validated` so subsequent CID frame handling
(RETIRE_CONNECTION_ID, key rotation issuance) stops consulting a
dispatch table that is no longer authoritative; the kernel already
routes new packets by 4-tuple to the per-connection FD.
Returns the dispatch table reference that was previously set
(`undefined` if none), letting the caller run the matching
`dispatch_unregister` loop without re-reading state.
""".
-spec clear_dispatch_table(state()) ->
    {nquic_dispatch:t() | undefined, state()}.
clear_dispatch_table(#conn_state{dispatch_table = Table} = State) ->
    {Table, State#conn_state{dispatch_table = undefined}}.

-doc "Queue a CONNECTION_CLOSE frame with a transport error code.".
-spec close(non_neg_integer(), binary(), state()) -> {ok, state()}.
close(ErrorCode, ReasonPhrase, State) ->
    Frame = #connection_close{
        error_code = ErrorCode,
        frame_type = 0,
        reason_phrase = ReasonPhrase
    },
    queue_close_frame(Frame, State).

-doc "Queue a CONNECTION_CLOSE frame with an application error code.".
-spec close_app(non_neg_integer(), binary(), state()) -> {ok, state()}.
close_app(ErrorCode, ReasonPhrase, State) ->
    Frame = #connection_close{
        error_code = ErrorCode,
        reason_phrase = ReasonPhrase,
        is_application = true
    },
    nquic_protocol_send_queues:queue_app_frame(Frame, State).

-doc """
Close the send side of a stream by latching FIN.
The actual FIN-bearing STREAM frame is emitted by the next drain at flush
time (see `nquic_protocol_streams_send:drain_pending_sends/1`). Send-side
cleanup happens later, once the FIN frame has been queued and the stream
reaches the `data_sent` state.
""".
-spec close_stream(nquic:stream_id(), state()) ->
    {ok, state()} | {error, term()}.
close_stream(StreamID, State) ->
    #conn_state{streams_state = SS, role = Role} = State,
    #conn_streams{streams = Streams} = SS,
    case nquic_stream_manager:get_or_create(StreamID, Streams, Role) of
        {ok, StreamState0, Streams0} ->
            StreamState = nquic_frame_handler:ensure_stream_limits(StreamState0, State),
            case nquic_stream_statem:handle_send(StreamState, <<>>, true) of
                {ok, NewStreamState} ->
                    NewStreams = Streams0#{StreamID => NewStreamState},
                    State0 = nquic_protocol_streams_send:clear_blocked(StreamID, State),
                    SS1 = (State0#conn_state.streams_state)#conn_streams{streams = NewStreams},
                    State1 = State0#conn_state{streams_state = SS1},
                    {ok, nquic_protocol_streams_send:mark_pending_send(StreamID, State1)};
                Error ->
                    Error
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec dispatch_send_flow(
    ok | {blocked, atom(), non_neg_integer()},
    nquic:stream_id(),
    iodata(),
    fin | nofin,
    #stream_state{},
    map(),
    non_neg_integer(),
    state()
) -> {ok, state()} | {error, term()} | {error, term(), state()}.
dispatch_send_flow(
    {blocked, Tag, Limit}, StreamID, _DataBin, _Fin, _StreamState, _Streams0, _DataLen, State
) ->
    {error, {Tag, Limit}, nquic_protocol_streams:signal_blocked(Tag, Limit, StreamID, State)};
dispatch_send_flow(ok, StreamID, DataBin, Fin, StreamState, Streams0, DataLen, State) ->
    case can_emit_inline(StreamState, DataLen, State) of
        true ->
            emit_stream_inline(
                StreamID, DataBin, Fin, DataLen, StreamState, Streams0, State
            );
        false ->
            handle_stream_send(
                nquic_stream_statem:handle_send(StreamState, DataBin, Fin =:= fin),
                StreamID,
                Streams0,
                DataLen,
                State
            )
    end.

-spec dispatch_send_lookup(
    {ok, #stream_state{}, map()} | {error, term()},
    nquic:stream_id(),
    iodata(),
    fin | nofin,
    state()
) -> {ok, state()} | {error, term()} | {error, term(), state()}.
dispatch_send_lookup({error, Reason}, _StreamID, _DataBin, _Fin, _State) ->
    {error, Reason};
dispatch_send_lookup({ok, StreamState0, Streams0}, StreamID, DataBin, Fin, State) ->
    StreamState = nquic_frame_handler:ensure_stream_limits(StreamState0, State),
    DataLen = iolist_size(DataBin),
    dispatch_send_flow(
        check_send_flow(State, StreamState, DataLen),
        StreamID,
        DataBin,
        Fin,
        StreamState,
        Streams0,
        DataLen,
        State
    ).

-spec do_flush(state()) ->
    {ok, [iodata()], state(), [timeout_action()]} | {ok, state()}.
do_flush(State0) ->
    {InitPkts, State1} = nquic_protocol_send_queues:flush_initial(State0),
    {HsPkts, State2} = nquic_protocol_send_queues:flush_handshake(State1),
    case nquic_protocol_send_queues:flush_app(State2) of
        {ok, AppPkts, State3} ->
            Packets = InitPkts ++ HsPkts ++ AppPkts,
            TimerActions = nquic_protocol_timer:compute_pto_timer_actions(State3),
            {ok, Packets, State3, TimerActions};
        {ok, State3} ->
            case InitPkts ++ HsPkts of
                [] ->
                    {ok, State3};
                Packets ->
                    TimerActions = nquic_protocol_timer:compute_pto_timer_actions(State3),
                    {ok, Packets, State3, TimerActions}
            end
    end.

-spec emit_stream_inline(
    nquic:stream_id(),
    iodata(),
    fin | nofin,
    non_neg_integer(),
    #stream_state{},
    map(),
    state()
) -> {ok, state()}.
emit_stream_inline(
    StreamID, DataBin, Fin, DataLen, StreamState, Streams0, State
) ->
    #stream_state{send_offset = Offset, send_state = SState} = StreamState,
    IsFin = Fin =:= fin,
    NewSendState =
        case IsFin of
            true ->
                data_sent;
            false ->
                case SState of
                    ready -> send;
                    Other -> Other
                end
        end,
    NewStreamState = StreamState#stream_state{
        send_offset = Offset + DataLen,
        send_state = NewSendState
    },
    Frame = #stream{
        stream_id = StreamID,
        offset = Offset,
        length = DataLen,
        fin = IsFin,
        data = DataBin
    },
    State1 = nquic_flow:on_stream_data_sent(State, StreamID, DataLen),
    NewStreams = Streams0#{StreamID => NewStreamState},
    SS1 = (State1#conn_state.streams_state)#conn_streams{streams = NewStreams},
    State2 = nquic_protocol_streams_send:clear_blocked(
        StreamID, State1#conn_state{streams_state = SS1}
    ),
    {ok, State3} = nquic_protocol_send_queues:queue_app_frame(Frame, State2),
    State4 =
        case IsFin of
            true ->
                nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
                    StreamID, NewStreamState, State3
                );
            false ->
                State3
        end,
    {ok, State4}.

-spec flow_send_avail(state(), #stream_state{}) -> non_neg_integer().
flow_send_avail(State, StreamState) ->
    #conn_state{flow = #conn_flow{remote_max_data = RMD, data_sent = Sent}} = State,
    #stream_state{send_max_data = SMD, send_offset = Off} = StreamState,
    ConnAvail = max(0, RMD - Sent),
    StreamAvail = max(0, SMD - Off),
    min(ConnAvail, StreamAvail).

-doc """
Encrypt all queued frames into QUIC packets and return them.
Returns `{ok, [iodata()], State, [timeout_action()]}` with packets
and timer actions when there are frames to send, or `{ok, State}`
if there is nothing to flush.
The packets are produced in encryption-level order: Initial first,
then Handshake, then 1-RTT (application). Each is a separate datagram;
there is no in-datagram coalescing today, so the wrapper sends each
as an independent UDP datagram.
""".
-spec flush(state()) ->
    {ok, [iodata()], state(), [timeout_action()]} | {ok, state()}.
flush(
    #conn_state{
        flow = #conn_flow{
            pending_initial_frames = [],
            pending_handshake_frames = [],
            pending_app_frames = [],
            pending_app_pre_encoded = []
        },
        pending_ack_count = 0,
        streams_state = #conn_streams{pending_send_streams = PS}
    } = State
) when map_size(PS) =:= 0 ->
    {ok, State};
flush(State0) ->
    case nquic_loss:pacer_check(State0#conn_state.loss_state, monotonic_us()) of
        pass ->
            do_flush(State0);
        {block, NextUs} ->
            {ok, [], State0, [pacer_timer_action(NextUs)]}
    end.

-doc """
Handle a timer expiration during the server handshake (`initial` /
`handshake` packet number spaces, before the connection is
established).
The established `handle_timeout/2` queues a 1-RTT PING on PTO, which is
useless before app keys exist and never retransmits the handshake
flight. This variant sends the PTO probe at the encryption level the
owner is currently driving (`Phase`), mirroring
`nquic_conn_timers:handle_pto/2`. The owner tracks `Phase` from the
`{state_transition, handshake}` event and switches to the established
`timeout/2` once it observes `connected`.
""".
-spec handle_handshake_timeout(initial | handshake, timer_type(), state()) ->
    {ok, [event()], state(), [timeout_action()]}
    | {error, term(), state()}.
handle_handshake_timeout(_Phase, idle, State) ->
    {error, {transport_error, idle_timeout}, State};
handle_handshake_timeout(Phase, pto, State) ->
    LossState1 = nquic_loss:on_pto(State#conn_state.loss_state),
    State1 = State#conn_state{loss_state = LossState1},
    {ok, State2} =
        case Phase of
            initial -> nquic_protocol_send_queues:queue_initial_frame(#ping{}, State1);
            handshake -> nquic_protocol_send_queues:queue_handshake_frame(#ping{}, State1)
        end,
    TimerActions = nquic_protocol_timer:compute_pto_timer_actions(State2),
    {ok, [], State2, TimerActions};
handle_handshake_timeout(_Phase, Type, State) ->
    handle_timeout(Type, State).

-doc """
Process an incoming UDP packet.
Source is the sockaddr map from the socket recv (e.g.
`#{family => inet, addr => {127,0,0,1}, port => 4433}`).
Returns events for the caller to handle, may queue internal frames
(ACKs, window updates) that `flush/1` will encrypt, and returns
timeout actions for the caller to schedule.
""".
-spec handle_packet(binary(), nquic_socket:sockaddr(), state()) ->
    {ok, [event()], state(), [timeout_action()]} | {error, term(), state()}.
handle_packet(PacketBin, Source, State) ->
    handle_packet(PacketBin, Source, State, not_ect).

-doc "Process an incoming UDP packet with an ECN codepoint from IP header.".
-spec handle_packet(binary(), nquic_socket:sockaddr(), state(), nquic_socket:ecn_mark()) ->
    {ok, [event()], state(), [timeout_action()]} | {error, term(), state()}.
handle_packet(PacketBin, Source, State, ECN) ->
    State1 = update_recv_anti_amp_ecn(byte_size(PacketBin), ECN, State),
    State2 = nquic_protocol_migration:apply_peer_update(Source, State1),
    case nquic_protocol_recv:process_datagram(PacketBin, State2, []) of
        {ok, Events, State3} ->
            {TimerActions, State4} = nquic_protocol_timer:compute_timer_actions(State3),
            {ok, Events, State4, TimerActions};
        {error, _, _} = Err ->
            Err
    end.

-doc """
Process an incoming UDP packet without computing timer actions.
Same as `handle_packet/3` but skips
`nquic_protocol_timer:compute_timer_actions/1` at the end. Use this
for batched recv loops where timer computation is deferred to the
final packet. The caller must call
`nquic_protocol_timer:compute_timer_actions/1` after the batch
completes.
""".
-spec handle_packet_notimers(binary(), nquic_socket:sockaddr(), state()) ->
    {ok, [event()], state()} | {error, term(), state()}.
handle_packet_notimers(PacketBin, Source, State) ->
    handle_packet_notimers(PacketBin, Source, State, not_ect).

-doc "Process an incoming packet without timer actions, with ECN codepoint.".
-spec handle_packet_notimers(binary(), nquic_socket:sockaddr(), state(), nquic_socket:ecn_mark()) ->
    {ok, [event()], state()} | {error, term(), state()}.
handle_packet_notimers(PacketBin, Source, State, ECN) ->
    State1 = update_recv_anti_amp_ecn(byte_size(PacketBin), ECN, State),
    State2 = nquic_protocol_migration:apply_peer_update(Source, State1),
    nquic_protocol_recv:process_datagram(PacketBin, State2, []).

-spec handle_stream_send(
    {ok, #stream_state{}} | {error, term()},
    nquic:stream_id(),
    map(),
    non_neg_integer(),
    state()
) -> {ok, state()} | {error, term()}.
handle_stream_send({error, _} = Error, _StreamID, _Streams0, _DataLen, _State) ->
    Error;
handle_stream_send({ok, NewStreamState}, StreamID, Streams0, DataLen, State) ->
    State1 = nquic_flow:on_stream_data_sent(State, StreamID, DataLen),
    NewStreams = Streams0#{StreamID => NewStreamState},
    SS1 = (State1#conn_state.streams_state)#conn_streams{streams = NewStreams},
    State2 = nquic_protocol_streams_send:clear_blocked(
        StreamID, State1#conn_state{streams_state = SS1}
    ),
    {ok, nquic_protocol_streams_send:mark_pending_send(StreamID, State2)}.

-doc """
Handle a timer expiry.
Returns events, updated state, and new timer actions.
The caller should deliver events and schedule returned timers.
""".
-spec handle_timeout(timer_type(), state()) ->
    {ok, [event()], state(), [timeout_action()]}
    | {error, term(), state()}.
handle_timeout(idle, State) ->
    {error, {transport_error, idle_timeout}, State};
handle_timeout(pto, State) ->
    LossState1 = nquic_loss:on_pto(State#conn_state.loss_state),
    State1 = State#conn_state{loss_state = LossState1},
    State2 = nquic_protocol_migration:maybe_detect_black_hole(State1),
    {ok, State3} = nquic_protocol_send_queues:queue_app_frame(#ping{}, State2),
    TimerActions = nquic_protocol_timer:compute_pto_timer_actions(State3),
    {ok, [], State3, TimerActions};
handle_timeout(path_validation, State) ->
    #conn_state{path = #conn_path_mgmt{path_state = PS} = Path0} = State,
    case nquic_path:is_validating(PS) of
        false ->
            {ok, [], State, []};
        true ->
            case nquic_path:on_timeout(PS) of
                {retry, NewPS, ChallengeFrame} ->
                    State1 = State#conn_state{path = Path0#conn_path_mgmt{path_state = NewPS}},
                    {ok, State2} = nquic_protocol_send_queues:queue_app_frame(
                        ChallengeFrame, State1
                    ),
                    PVTimeout = nquic_protocol_timer:compute_path_validation_timeout(State2),
                    {ok, [], State2, [{set_timer, path_validation, PVTimeout}]};
                {failed, NewPS} ->
                    State1 = nquic_protocol_migration:revert_migration(
                        State#conn_state{path = Path0#conn_path_mgmt{path_state = NewPS}}
                    ),
                    {ok, [], State1, []}
            end
    end;
handle_timeout(draining, State) ->
    {error, normal, State};
handle_timeout(ack_delay, State) ->
    case State#conn_state.pending_ack_count > 0 of
        true ->
            State1 = nquic_protocol_ack:force_queue_ack(application, State),
            State2 = State1#conn_state{pending_ack_count = 0},
            {ok, [], State2, []};
        false ->
            {ok, [], State, []}
    end;
handle_timeout(pmtud, #conn_state{pmtud = PS} = State) when PS =/= undefined ->
    PS1 = nquic_pmtud:on_timeout(PS),
    {ok, [], State#conn_state{pmtud = PS1}, []};
handle_timeout(pmtud, State) ->
    {ok, [], State, []};
handle_timeout(pace, State) ->
    {ok, [], State, []}.

-spec has_app_keys(state()) -> boolean().
has_app_keys(#conn_state{crypto = #conn_crypto{keys = Keys}}) ->
    maps:is_key(application, Keys).

-doc "Get connection information as a map.".
-spec info(atom(), state()) -> map().
info(StateName, State) ->
    #conn_state{
        role = Role,
        scid = SCID,
        dcid = DCID,
        loss_state = LossState,
        streams_state = #conn_streams{streams = Streams},
        local_params = LocalParams,
        remote_params = RemoteParams,
        pn_spaces = PnSpaces,
        crypto = #conn_crypto{zero_rtt_accepted = ZeroRTTOk},
        flow = #conn_flow{
            local_max_data = LocalMaxData,
            remote_max_data = RemoteMaxData,
            data_sent = DataSent,
            data_received = DataReceived
        }
    } = State,
    RTTStats = nquic_loss:get_rtt_stats(LossState),
    #{
        state => StateName,
        role => Role,
        scid => SCID,
        dcid => DCID,
        rtt => RTTStats,
        cwnd => nquic_loss:get_cwnd(LossState),
        bytes_in_flight => nquic_loss:get_bytes_in_flight(LossState),
        streams_open => map_size(Streams),
        local_params => LocalParams,
        remote_params => RemoteParams,
        pn_spaces => PnSpaces,
        sent_pns => nquic_loss:get_sent_packet_numbers(LossState),
        local_max_data => LocalMaxData,
        remote_max_data => RemoteMaxData,
        data_sent => DataSent,
        data_received => DataReceived,
        zero_rtt_accepted => ZeroRTTOk
    }.

-doc "Get all local connection IDs.".
-spec local_cids(state()) -> [nquic:connection_id()].
local_cids(#conn_state{path = #conn_path_mgmt{local_cids = CIDs}}) ->
    maps:values(CIDs).

-spec monotonic_us() -> integer().
monotonic_us() ->
    erlang:monotonic_time(microsecond).

-doc "Get the original destination connection ID (server connections).".
-spec odcid(state()) -> nquic:connection_id() | undefined.
odcid(#conn_state{odcid = ODCID}) -> ODCID.

-doc "Open a new stream. Returns `{ok, StreamId, State}` on success.".
-spec open_stream(#{type => bidi | uni}, state()) ->
    {ok, nquic:stream_id(), state()} | {error, term()}.
open_stream(Opts0, State) ->
    #conn_state{streams_state = SS} = State,
    #conn_streams{
        next_bidi_stream = NextBidi,
        next_uni_stream = NextUni,
        streams = Streams,
        peer_max_streams_bidi = MaxBidi,
        peer_max_streams_uni = MaxUni
    } = SS,
    Opts =
        case Opts0 of
            [] -> #{};
            _ -> Opts0
        end,
    Type = maps:get(type, Opts, bidi),
    case Type of
        bidi when NextBidi div 4 >= MaxBidi ->
            {error, stream_limit_error};
        uni when NextUni div 4 >= MaxUni ->
            {error, stream_limit_error};
        _ ->
            {StreamId, State1} =
                case Type of
                    bidi ->
                        SS1 = SS#conn_streams{next_bidi_stream = NextBidi + 4},
                        {NextBidi, State#conn_state{streams_state = SS1}};
                    uni ->
                        SS1 = SS#conn_streams{next_uni_stream = NextUni + 4},
                        {NextUni, State#conn_state{streams_state = SS1}}
                end,
            StreamState = nquic_stream_statem:new(StreamId, Type),
            NewStreams = Streams#{StreamId => StreamState},
            SS2 = (State1#conn_state.streams_state)#conn_streams{streams = NewStreams},
            {ok, StreamId, State1#conn_state{streams_state = SS2}}
    end.

-spec pacer_timer_action(integer()) -> {set_timer, pace, pos_integer()}.
pacer_timer_action(NextUs) ->
    Now = monotonic_us(),
    DelayUs = max(0, NextUs - Now),
    DelayMs = max(1, (DelayUs + 999) div 1000),
    {set_timer, pace, DelayMs}.

-doc """
Project path-level statistics from the connection state.
Combines RTT estimator state (`smoothed_rtt`, `rttvar`, `min_rtt`,
`latest_rtt`), congestion window state (`cwnd`, `bytes_in_flight`,
`ssthresh`), lifetime packet counters, and ECN state into a flat map
suitable for routing decisions and operational dashboards.
""".
-spec path_stats(state()) -> nquic_loss:path_stats().
path_stats(#conn_state{loss_state = LS}) ->
    nquic_loss:path_stats(LS).

-doc "Get the current peer address.".
-spec peer(state()) -> nquic_socket:sockaddr() | undefined.
peer(#conn_state{peer = Peer}) -> Peer.

-doc "Get the peer's TLS certificate in DER form, or `undefined` if none.".
-spec peercert(state()) -> binary() | undefined.
peercert(#conn_state{crypto = #conn_crypto{peer_cert = Cert}}) -> Cert.

-doc "Return IDs of peer-initiated streams that have buffered application data.".
-spec pending_stream_ids(state()) -> [nquic:stream_id()].
pending_stream_ids(#conn_state{streams_state = #conn_streams{streams = Streams}, role = Role}) ->
    maps:fold(
        fun
            (StreamID, #stream_state{app_buffer_size = Size}, Acc) when Size > 0 ->
                case nquic_frame_handler:is_locally_initiated(StreamID, Role) of
                    true -> Acc;
                    false -> [StreamID | Acc]
                end;
            (_, _, Acc) ->
                Acc
        end,
        [],
        Streams
    ).

-spec queue_capped(
    non_neg_integer(),
    non_neg_integer(),
    iodata(),
    fin | nofin,
    nquic:stream_id(),
    #stream_state{},
    map(),
    state()
) -> {ok, non_neg_integer(), state()} | {error, term(), state()}.
queue_capped(0, _DataLen, _DataBin, _Fin, StreamID, _StreamState, _Streams0, State) ->
    {ok, 0, nquic_protocol_streams_send:mark_blocked(StreamID, State)};
queue_capped(QueueLen, DataLen, DataBin, Fin, StreamID, StreamState, Streams0, State) ->
    Bin = iolist_to_binary(DataBin),
    <<Head:QueueLen/binary, _/binary>> = Bin,
    IsFin = Fin =:= fin andalso QueueLen =:= DataLen,
    case nquic_stream_statem:handle_send(StreamState, Head, IsFin) of
        {ok, NewStreamState} ->
            State1 = nquic_flow:on_stream_data_sent(State, StreamID, QueueLen),
            NewStreams = Streams0#{StreamID => NewStreamState},
            SS1 = (State1#conn_state.streams_state)#conn_streams{streams = NewStreams},
            State2 = nquic_protocol_streams_send:clear_blocked(
                StreamID, State1#conn_state{streams_state = SS1}
            ),
            State3 = nquic_protocol_streams_send:mark_pending_send(StreamID, State2),
            {ok, QueueLen, State3};
        {error, Reason} ->
            {error, Reason, State}
    end.

-spec queue_capped_dispatch(
    ok | {blocked, atom(), non_neg_integer()},
    nquic:stream_id(),
    iodata(),
    non_neg_integer(),
    fin | nofin,
    #stream_state{},
    map(),
    state()
) -> {ok, non_neg_integer(), state()} | {error, term(), state()}.
queue_capped_dispatch(
    {blocked, Tag, Limit}, StreamID, _DataBin, _DataLen, _Fin, _StreamState, _Streams0, State
) ->
    {error, {Tag, Limit}, nquic_protocol_streams:signal_blocked(Tag, Limit, StreamID, State)};
queue_capped_dispatch(ok, StreamID, DataBin, DataLen, Fin, StreamState, Streams0, State) ->
    HighWater =
        (State#conn_state.streams_state)#conn_streams.send_buffer_high_water,
    BufferAvail = max(0, HighWater - StreamState#stream_state.pending_send_size),
    FlowAvail = flow_send_avail(State, StreamState),
    QueueLen = min(DataLen, min(BufferAvail, FlowAvail)),
    queue_capped(QueueLen, DataLen, DataBin, Fin, StreamID, StreamState, Streams0, State).

-spec queue_close_frame(#connection_close{}, state()) -> {ok, state()}.
queue_close_frame(Frame, #conn_state{crypto = Crypto} = State) ->
    case Crypto#conn_crypto.app_send_keys of
        undefined ->
            {ok, State1} = nquic_protocol_send_queues:queue_initial_frame(Frame, State),
            case maps:is_key(handshake, Crypto#conn_crypto.keys) of
                true -> nquic_protocol_send_queues:queue_handshake_frame(Frame, State1);
                false -> {ok, State1}
            end;
        _ ->
            nquic_protocol_send_queues:queue_app_frame(Frame, State)
    end.

-doc """
Read and consume buffered data from a stream.
Returns the accumulated data and whether FIN has been received. Clears
the stream's application buffer so subsequent calls return new data only.
""".
-spec read_stream(nquic:stream_id(), state()) ->
    {ok, binary(), boolean(), state()} | {error, term()}.
read_stream(StreamID, #conn_state{streams_state = SS} = State) ->
    #conn_streams{streams = Streams} = SS,
    case maps:find(StreamID, Streams) of
        {ok,
            #stream_state{
                app_buffer = Buf, app_buffer_size = Size, recv_state = RecvState
            } = Stream} when
            Size > 0
        ->
            IsFin = RecvState =:= size_known orelse RecvState =:= data_recvd,
            Data = buffer_to_binary(Buf),
            NewRecvState =
                case IsFin of
                    true -> data_read;
                    false -> RecvState
                end,
            NewStream = Stream#stream_state{
                app_buffer = [], app_buffer_size = 0, recv_state = NewRecvState
            },
            SS1 = SS#conn_streams{streams = Streams#{StreamID => NewStream}},
            State1 = State#conn_state{streams_state = SS1},
            State2 =
                case IsFin of
                    true ->
                        nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
                            StreamID, NewStream, State1
                        );
                    false ->
                        State1
                end,
            State3 = nquic_protocol_streams:maybe_send_max_data(State2),
            {ok, Data, IsFin, State3};
        {ok, #stream_state{recv_state = RecvState} = Stream0} when
            RecvState =:= size_known; RecvState =:= data_recvd
        ->
            Stream = Stream0#stream_state{recv_state = data_read},
            SS1 = SS#conn_streams{streams = Streams#{StreamID => Stream}},
            State1 = State#conn_state{streams_state = SS1},
            State2 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
                StreamID, Stream, State1
            ),
            {ok, <<>>, true, State2};
        {ok, _} ->
            {error, no_data};
        error ->
            {error, stream_not_found}
    end.

-doc "Reset a stream with an application error code.".
-spec reset_stream(nquic:stream_id(), non_neg_integer(), state()) ->
    {ok, state()} | {error, term()}.
reset_stream(StreamID, ErrorCode, State) ->
    #conn_state{streams_state = SS} = State,
    #conn_streams{streams = Streams} = SS,
    case maps:find(StreamID, Streams) of
        {ok, Stream} ->
            #stream_state{send_state = SendState, send_offset = SendOffset} = Stream,
            case SendState of
                S when S =:= reset_sent; S =:= reset_recvd; S =:= data_recvd ->
                    {ok, State};
                _ ->
                    ResetFrame = #reset_stream{
                        stream_id = StreamID,
                        app_error_code = ErrorCode,
                        final_size = SendOffset
                    },
                    NewStream = Stream#stream_state{
                        send_state = reset_sent,
                        pending_send_data = [],
                        pending_send_size = 0,
                        pending_send_fin = false
                    },
                    NewStreams = Streams#{StreamID => NewStream},
                    State0 = nquic_protocol_streams_send:clear_pending_send(
                        StreamID, nquic_protocol_streams_send:clear_blocked(StreamID, State)
                    ),
                    SS1 = (State0#conn_state.streams_state)#conn_streams{streams = NewStreams},
                    State1 = State0#conn_state{streams_state = SS1},
                    {ok, State2} = nquic_protocol_send_queues:queue_app_frame(ResetFrame, State1),
                    State3 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
                        StreamID, NewStream, State2
                    ),
                    {ok, State3}
            end;
        error ->
            {error, unknown_stream}
    end.

-doc """
Clear the cached timer values so
`nquic_protocol_timer:compute_timer_actions/1` re-emits `set_timer`
actions for every live timer.
Use this at an ownership boundary (for example on library-mode
`takeover/1`), where the previous owner's timers were not transferred
and the new owner must schedule them afresh.
""".
-spec reset_timer_cache(state()) -> state().
reset_timer_cache(State) ->
    State#conn_state{last_idle_ms = undefined, last_pto_ms = undefined}.

-doc """
Send an unreliable DATAGRAM frame (RFC 9221).
Checks that datagrams were negotiated, that the data fits within the peer's
max_datagram_frame_size, and that the congestion window allows it.
Datagrams are not retransmitted on loss and are not flow-controlled.
""".
-spec send_datagram(binary(), state()) -> {ok, state()} | {error, nquic_error:any_reason()}.
send_datagram(Data, #conn_state{remote_params = RemoteParams} = State) ->
    PeerMax =
        case RemoteParams of
            #transport_params{max_datagram_frame_size = M} when is_integer(M), M > 0 -> M;
            _ -> 0
        end,
    case PeerMax of
        0 ->
            {error, datagrams_not_negotiated};
        _ ->
            DataLen = byte_size(Data),
            FrameSize = 1 + byte_size(nquic_varint:encode(DataLen)) + DataLen,
            case FrameSize > PeerMax of
                true ->
                    {error, datagram_too_large};
                false ->
                    case nquic_protocol_send:check_congestion_control(State, FrameSize) of
                        ok ->
                            Frame = #datagram{data = Data},
                            nquic_protocol_send_queues:queue_app_frame(Frame, State);
                        {blocked, _} ->
                            {error, congestion_control_blocked}
                    end
            end
    end.

-doc """
Queue a STREAM frame for sending. Call `flush/1` to encrypt and retrieve packets.
On flow-control or congestion-control block, returns `{error, Reason, State}`
with the stream recorded in the state's `blocked_streams` set. Callers that
need the updated state (to observe a subsequent `{stream_writable, _}`
event) should propagate it; callers that don't can discard the third
element.
""".
-spec send_stream(nquic:stream_id(), iodata(), fin | nofin, state()) ->
    {ok, state()} | {error, term()} | {error, term(), state()}.
send_stream(StreamID, DataBin, Fin, State) ->
    #conn_state{streams_state = #conn_streams{streams = Streams}, role = Role} = State,
    dispatch_send_lookup(
        nquic_stream_manager:get_or_create(StreamID, Streams, Role),
        StreamID,
        DataBin,
        Fin,
        State
    ).

-doc """
Queue at most `send_buffer_high_water - byte_size(pending_send_data)`
bytes of `DataBin` onto the stream's outbound buffer, capped further by
the peer's connection / stream flow-control windows. Returns the number
of bytes accepted; the caller is responsible for parking the unaccepted
tail (e.g. as a `send_waiter`) so it can be queued later when the drain
or a peer flow-control update frees room.
`fin` is only latched when the entire input fits; a partial accept
leaves FIN un-latched so the eventual final byte carries the FIN.
On stream / connection flow-control rejection (peer's window is full),
returns `{error, Reason, State}` with the stream recorded in
`blocked_streams` so a later `stream_writable` event can fire.
""".
-spec send_stream_capped(nquic:stream_id(), iodata(), fin | nofin, state()) ->
    {ok, non_neg_integer(), state()} | {error, term()} | {error, term(), state()}.
send_stream_capped(StreamID, DataBin, Fin, State) ->
    #conn_state{streams_state = #conn_streams{streams = Streams}, role = Role} = State,
    case nquic_stream_manager:get_or_create(StreamID, Streams, Role) of
        {error, Reason} ->
            {error, Reason};
        {ok, StreamState0, Streams0} ->
            StreamState = nquic_frame_handler:ensure_stream_limits(StreamState0, State),
            DataLen = iolist_size(DataBin),
            queue_capped_dispatch(
                check_send_flow(State, StreamState, 0),
                StreamID,
                DataBin,
                DataLen,
                Fin,
                StreamState,
                Streams0,
                State
            )
    end.

-doc """
True when the connection's socket has been `connect(2)`-bound to its
peer 4-tuple. Set after `server_per_conn_fd` migration (RFC 9000 §9):
callers exporting such a connection into library mode must drive the
send path through `socket:send/2` instead of `sendto`.
""".
-spec socket_connected(state()) -> boolean().
socket_connected(#conn_state{socket_connected = Connected}) -> Connected.

-spec update_recv_anti_amp_ecn(non_neg_integer(), nquic_socket:ecn_mark(), state()) -> state().
update_recv_anti_amp_ecn(_Size, ECN, #conn_state{role = client, recv_ecn = ECN} = State) ->
    State;
update_recv_anti_amp_ecn(_Size, ECN, #conn_state{role = client} = State) ->
    State#conn_state{recv_ecn = ECN};
update_recv_anti_amp_ecn(
    _Size,
    ECN,
    #conn_state{path = #conn_path_mgmt{address_validated = true}, recv_ecn = ECN} = State
) ->
    State;
update_recv_anti_amp_ecn(
    _Size,
    ECN,
    #conn_state{path = #conn_path_mgmt{address_validated = true}} = State
) ->
    State#conn_state{recv_ecn = ECN};
update_recv_anti_amp_ecn(Size, ECN, #conn_state{path = Path0} = State) ->
    NewPath = Path0#conn_path_mgmt{
        anti_amp_bytes_received = Path0#conn_path_mgmt.anti_amp_bytes_received + Size
    },
    State#conn_state{path = NewPath, recv_ecn = ECN}.

%%%-----------------------------------------------------------------------------
%% INTERNAL ERROR CODES
%%%-----------------------------------------------------------------------------
-spec error_code(nquic_error:any_reason()) -> non_neg_integer().
error_code({transport_error, Inner}) -> error_code(Inner);
error_code(no_error) -> 16#0;
error_code(internal_error) -> 16#1;
error_code(flow_control_error) -> 16#3;
error_code(stream_limit_error) -> 16#4;
error_code(stream_state_error) -> 16#5;
error_code(final_size_error) -> 16#6;
error_code(frame_encoding_error) -> 16#7;
error_code(transport_parameter_error) -> 16#8;
error_code(connection_id_limit_error) -> 16#9;
error_code(protocol_violation) -> 16#a;
error_code(invalid_token) -> 16#b;
error_code(application_error) -> 16#c;
error_code(crypto_buffer_exceeded) -> 16#d;
error_code({tls_alert, unexpected_message}) -> 16#10a;
error_code({tls_alert, no_application_protocol}) -> 16#178;
error_code({tls_alert, missing_extension}) -> 16#16d;
error_code({tls_alert, certificate_required}) -> 16#174;
error_code({tls_alert, handshake_failure}) -> 16#128;
error_code({tls_alert, {bad_certificate, _}}) -> 16#12a;
error_code({tls_alert, unknown_ca}) -> 16#130;
error_code(_) -> 16#1.

-spec error_to_reason_phrase(nquic_error:any_reason()) -> binary().
error_to_reason_phrase({transport_error, Inner}) ->
    error_to_reason_phrase(Inner);
error_to_reason_phrase({tls_alert, {Alert, _Detail}}) when is_atom(Alert) ->
    atom_to_binary(Alert, utf8);
error_to_reason_phrase({tls_alert, Alert}) when is_atom(Alert) ->
    atom_to_binary(Alert, utf8);
error_to_reason_phrase(Error) when is_atom(Error) ->
    atom_to_binary(Error, utf8);
error_to_reason_phrase(_) ->
    <<>>.

%%%-----------------------------------------------------------------------------
%% INTERNAL TIMEOUT HELPERS
%%%-----------------------------------------------------------------------------
-spec get_draining_timeout(state()) -> non_neg_integer().
get_draining_timeout(#conn_state{loss_state = LossState, remote_params = RemoteParams}) ->
    MaxAckDelayUs =
        case RemoteParams of
            #transport_params{max_ack_delay = MAD} -> MAD * 1000;
            undefined -> 25_000
        end,
    PtoUs = nquic_loss:get_pto_timeout(LossState, MaxAckDelayUs),
    max(1, ((3 * PtoUs) + 999) div 1000).

-spec get_idle_timeout(non_neg_integer(), non_neg_integer()) -> pos_integer() | infinity.
get_idle_timeout(0, 0) -> infinity;
get_idle_timeout(0, R) -> R;
get_idle_timeout(L, 0) -> L;
get_idle_timeout(L, R) -> min(L, R).

-spec scale_ack_delay(non_neg_integer(), #transport_params{} | undefined) -> non_neg_integer().
scale_ack_delay(Delay, undefined) ->
    Delay bsl 3;
scale_ack_delay(Delay, #transport_params{
    ack_delay_exponent = Exponent,
    max_ack_delay = MaxAckDelay
}) ->
    Scaled = Delay bsl Exponent,
    MaxUs = MaxAckDelay * 1000,
    min(Scaled, MaxUs).

%%%-----------------------------------------------------------------------------
%% TESTS
%%%-----------------------------------------------------------------------------
