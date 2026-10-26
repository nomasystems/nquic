-module(nquic_protocol_send_queues).
-moduledoc """
Per-encryption-level pending-frame queues and their flush drains.

Pure functions over `#conn_state{}` that buffer outbound frames into
three per-space queues (Initial / Handshake / 1-RTT), coalesce them,
and drain each queue into one or more encrypted packets via the packet
builders in `nquic_protocol_send`. The dependency is one-way: this
module calls down into `nquic_protocol_send` (builders, MTU batching,
send context) module-qualified, and into `nquic_protocol_ack` to
piggyback a pending ACK before an application flush. `nquic_protocol`
drives the flush; the queue functions are called from across the
protocol family whenever a control or stream frame is produced.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-export([
    flush_app/1,
    flush_app_control/1,
    flush_handshake/1,
    flush_initial/1
]).

-export([
    build_app_or_zero_rtt/3,
    enter_recovery/2,
    queue_app_frame/2,
    queue_app_frame/3,
    queue_app_frames/3,
    queue_app_pre_encoded/3,
    queue_handshake_frame/2,
    queue_initial_frame/2,
    set_cwnd_exempt/1,
    sort_frames/1
]).

%%%-----------------------------------------------------------------------------
%% PER-ENCRYPTION-LEVEL FRAME QUEUES
%%%-----------------------------------------------------------------------------
-spec build_app_or_zero_rtt(
    [nquic_protocol_send:pre_encoded()], integer(), nquic_protocol:state()
) ->
    {ok, iodata(), nquic_protocol:state()} | {error, term(), nquic_protocol:state()}.
build_app_or_zero_rtt(PreEncoded, Time, State) ->
    case (State#conn_state.crypto)#conn_crypto.app_send_keys of
        undefined ->
            case State of
                #conn_state{role = client} ->
                    nquic_protocol_send:build_zero_rtt_packet_pre(PreEncoded, Time, State);
                _ ->
                    {error, no_app_keys, State}
            end;
        _ ->
            nquic_protocol_send:build_app_packet_pre(PreEncoded, Time, State)
    end.

-doc """
Let the next flush send one packet over the congestion window when the
window of the loss state `Before` is larger than the current one. This
is the packet on entry to recovery (RFC 9002 §7.3.2).
""".
-spec enter_recovery(nquic_loss:loss_state(), nquic_protocol:state()) -> nquic_protocol:state().
enter_recovery(Before, #conn_state{loss_state = After} = State) ->
    case nquic_loss:get_cwnd(After) < nquic_loss:get_cwnd(Before) of
        true -> set_cwnd_exempt(State);
        false -> State
    end.

-spec flush_app(nquic_protocol:state()) ->
    {ok, [iodata()], nquic_protocol:state()} | {ok, nquic_protocol:state()}.
flush_app(State0) ->
    State = nquic_protocol_streams_send:drain_pending_sends(
        maybe_piggyback_ack(has_app_frames(State0), State0)
    ),
    Flow0 = State#conn_state.flow,
    Pending = Flow0#conn_flow.pending_app_frames,
    PreFromDrain = Flow0#conn_flow.pending_app_pre_encoded,
    case {Pending, PreFromDrain} of
        {[], []} ->
            {ok, State};
        {[Frame], []} ->
            Encoded = nquic_frame:encode(Frame),
            PreEncoded = [{iolist_size(Encoded), Encoded, Frame}],
            FlowEmpty = Flow0#conn_flow{
                pending_app_frames = [],
                pending_app_pre_encoded = [],
                queued_app_send_bytes = 0
            },
            Time = erlang:monotonic_time(microsecond),
            flush_app_one(PreEncoded, Time, State#conn_state{flow = FlowEmpty});
        _ ->
            FlushState =
                State#conn_state{
                    flow = Flow0#conn_flow{
                        pending_app_frames = [],
                        pending_app_pre_encoded = [],
                        queued_app_send_bytes = 0
                    }
                },
            ControlPre =
                case Pending of
                    [] ->
                        [];
                    _ ->
                        pre_encode(sort_frames(lists:reverse(Pending)))
                end,
            StreamPre =
                case PreFromDrain of
                    [] -> [];
                    _ -> lists:reverse(PreFromDrain)
                end,
            PreEncoded = ControlPre ++ StreamPre,
            Budget = nquic_protocol_send:packet_payload_budget(FlushState),
            Time = erlang:monotonic_time(microsecond),
            flush_app_many(PreEncoded, Budget, Time, FlushState)
    end.

-doc """
Flush the pending ACK and the pending 1-RTT control frames while the
pacer holds back data. STREAM and DATAGRAM frames, and the stream data
not yet drained, stay queued for the next paced flush. ACK frames are
not congestion controlled (RFC 9002 §7) and leave within
`max_ack_delay` (RFC 9000 §13.2.1). A PTO probe is not blocked by the
congestion controller (RFC 9002 §7.5).
""".
-spec flush_app_control(nquic_protocol:state()) ->
    {ok, [iodata()], nquic_protocol:state()} | {ok, nquic_protocol:state()}.
flush_app_control(#conn_state{crypto = #conn_crypto{app_send_keys = undefined}} = State) ->
    {ok, State};
flush_app_control(State0) ->
    Pending0 = (State0#conn_state.flow)#conn_flow.pending_app_frames,
    State = maybe_piggyback_ack(lists:any(fun is_control_frame/1, Pending0), State0),
    Flow0 = State#conn_state.flow,
    case lists:partition(fun is_paced_frame/1, Flow0#conn_flow.pending_app_frames) of
        {_, []} ->
            {ok, State};
        {PacedRev, ControlRev} ->
            FlushState = State#conn_state{flow = Flow0#conn_flow{pending_app_frames = PacedRev}},
            PreEncoded = pre_encode(sort_frames(lists:reverse(ControlRev))),
            Budget = nquic_protocol_send:packet_payload_budget(FlushState),
            Time = erlang:monotonic_time(microsecond),
            flush_app_many(PreEncoded, Budget, Time, FlushState)
    end.

-spec has_app_frames(nquic_protocol:state()) -> boolean().
has_app_frames(#conn_state{
    flow = #conn_flow{pending_app_frames = [], pending_app_pre_encoded = []},
    streams_state = #conn_streams{pending_send_streams = PS}
}) ->
    map_size(PS) > 0;
has_app_frames(_State) ->
    true.

-spec is_control_frame(nquic_frame:t()) -> boolean().
is_control_frame(Frame) ->
    not is_paced_frame(Frame).

-spec is_paced_frame(nquic_frame:t()) -> boolean().
is_paced_frame(#stream{}) -> true;
is_paced_frame(#datagram{}) -> true;
is_paced_frame(_) -> false.

-spec pre_encode([nquic_frame:t()]) -> [nquic_protocol_send:pre_encoded()].
pre_encode(Frames) ->
    [
        begin
            Enc = nquic_frame:encode(F),
            {iolist_size(Enc), Enc, F}
        end
     || F <- Frames
    ].

-spec flush_app_many(
    [nquic_protocol_send:pre_encoded()], pos_integer(), integer(), nquic_protocol:state()
) -> {ok, [iodata()], nquic_protocol:state()} | {ok, nquic_protocol:state()}.
flush_app_many(PreEncoded0, Budget, Time, State0) ->
    {PreEncoded, State} = cwnd_gate(PreEncoded0, Budget, State0),
    {Packets, State1} =
        case (State#conn_state.crypto)#conn_crypto.app_send_keys of
            undefined ->
                nquic_protocol_send:build_packets_mtu_pre(PreEncoded, Budget, Time, State, []);
            _ ->
                Ctx = nquic_protocol_send:make_app_send_ctx(State, Time),
                nquic_protocol_send:build_packets_mtu_pre_ctx(PreEncoded, Budget, Ctx, State, [])
        end,
    case Packets of
        [] -> {ok, State1};
        _ -> {ok, Packets, State1}
    end.

-spec flush_app_one(
    [nquic_protocol_send:pre_encoded(), ...], integer(), nquic_protocol:state()
) ->
    {ok, [iodata()], nquic_protocol:state()} | {ok, nquic_protocol:state()}.
flush_app_one(
    _PreEncoded,
    _Time,
    #conn_state{role = Role, crypto = #conn_crypto{app_send_keys = undefined}} = State
) when Role =/= client ->
    {ok, State};
flush_app_one(PreEncoded0, Time, State0) ->
    Budget = nquic_protocol_send:packet_payload_budget(State0),
    case cwnd_gate(PreEncoded0, Budget, State0) of
        {[], State} ->
            {ok, State};
        {PreEncoded, State} ->
            build_app_one(PreEncoded, Time, State)
    end.

-spec build_app_one(
    [nquic_protocol_send:pre_encoded(), ...], integer(), nquic_protocol:state()
) ->
    {ok, [iodata()], nquic_protocol:state()} | {ok, nquic_protocol:state()}.
build_app_one(PreEncoded, Time, State) ->
    Result =
        case (State#conn_state.crypto)#conn_crypto.app_send_keys of
            undefined ->
                build_app_or_zero_rtt(PreEncoded, Time, State);
            _ ->
                Ctx = nquic_protocol_send:make_app_send_ctx(State, Time),
                nquic_protocol_send:build_app_packet_pre_ctx(PreEncoded, Ctx, State)
        end,
    case Result of
        {ok, Packet, State1} ->
            {ok, [Packet], State1};
        {error, _, State1} ->
            {ok, State1}
    end.

-doc """
Keep the ack-eliciting packets of one flush inside the congestion window
(RFC 9002 §7). The frames are packed as the packet builders pack them,
and each packet costs its payload plus `packet_overhead/1`. ACK-only
packets always leave. After the first packet that does not fit, the
ack-eliciting frames stay queued in order. One packet can exceed the
window when `cwnd_exempt` is set by a PTO (RFC 9002 §6.2.4) or on entry
to recovery (RFC 9002 §7.3.2). Every 1-RTT flush clears the flag. The
packing is skipped when the flush fits at one packet per frame.
""".
-spec cwnd_gate([nquic_protocol_send:pre_encoded()], pos_integer(), nquic_protocol:state()) ->
    {[nquic_protocol_send:pre_encoded()], nquic_protocol:state()}.
cwnd_gate(PreEncoded, _Budget, #conn_state{loss_state = undefined} = State) ->
    {PreEncoded, State};
cwnd_gate(PreEncoded, Budget, #conn_state{loss_state = LS, flow = Flow} = State) ->
    Room = nquic_loss:get_cwnd(LS) - nquic_loss:get_bytes_in_flight(LS),
    Overhead = nquic_protocol_send:packet_overhead(State),
    {Send, Deferred} =
        case worst_case_bytes(PreEncoded, Overhead, 0) =< Room of
            true ->
                {PreEncoded, []};
            false ->
                gate_packets(PreEncoded, Budget, Overhead, Room, Flow#conn_flow.cwnd_exempt, [])
        end,
    {Send,
        requeue_deferred(Deferred, State#conn_state{flow = Flow#conn_flow{cwnd_exempt = false}})}.

-spec worst_case_bytes([nquic_protocol_send:pre_encoded()], pos_integer(), non_neg_integer()) ->
    non_neg_integer().
worst_case_bytes([], _Overhead, Acc) ->
    Acc;
worst_case_bytes([{Size, _, _} | Rest], Overhead, Acc) ->
    worst_case_bytes(Rest, Overhead, Acc + Size + Overhead).

-spec gate_packets(
    [nquic_protocol_send:pre_encoded()],
    pos_integer(),
    pos_integer(),
    integer(),
    boolean(),
    [[nquic_protocol_send:pre_encoded()]]
) -> {[nquic_protocol_send:pre_encoded()], [nquic_protocol_send:pre_encoded()]}.
gate_packets([], _Budget, _Overhead, _Room, _Exempt, Acc) ->
    {lists:append(lists:reverse(Acc)), []};
gate_packets(PreEncoded, Budget, Overhead, Room, Exempt, Acc) ->
    {Packet, Rest} = nquic_protocol_send:take_frames_for_mtu_pre(PreEncoded, Budget),
    Size = Overhead + lists:sum([S || {S, _, _} <- Packet]),
    case {lists:all(fun is_not_ack_eliciting/1, Packet), Size =< Room, Exempt} of
        {true, _, _} ->
            gate_packets(Rest, Budget, Overhead, Room, Exempt, [Packet | Acc]);
        {false, true, _} ->
            gate_packets(Rest, Budget, Overhead, Room - Size, Exempt, [Packet | Acc]);
        {false, false, true} ->
            gate_packets(Rest, Budget, Overhead, Room - Size, false, [Packet | Acc]);
        {false, false, false} ->
            {NotEliciting, Held} = lists:partition(fun is_not_ack_eliciting/1, Packet ++ Rest),
            {lists:append(lists:reverse(Acc)) ++ NotEliciting, Held}
    end.

-spec is_not_ack_eliciting(nquic_protocol_send:pre_encoded()) -> boolean().
is_not_ack_eliciting({_, _, #ack{}}) -> true;
is_not_ack_eliciting({_, _, #padding{}}) -> true;
is_not_ack_eliciting({_, _, #connection_close{}}) -> true;
is_not_ack_eliciting(_) -> false.

-spec is_stream_entry(nquic_protocol_send:pre_encoded()) -> boolean().
is_stream_entry({_, _, #stream{}}) -> true;
is_stream_entry(_) -> false.

-spec requeue_deferred([nquic_protocol_send:pre_encoded()], nquic_protocol:state()) ->
    nquic_protocol:state().
requeue_deferred([], State) ->
    State;
requeue_deferred(Deferred, #conn_state{flow = Flow} = State) ->
    {StreamPre, Others} = lists:partition(fun is_stream_entry/1, Deferred),
    #conn_flow{
        pending_app_frames = Frames,
        pending_app_pre_encoded = Pre,
        queued_app_send_bytes = Queued
    } = Flow,
    State#conn_state{
        flow = Flow#conn_flow{
            pending_app_frames = Frames ++ lists:reverse([F || {_, _, F} <- Others]),
            pending_app_pre_encoded = Pre ++ lists:reverse(StreamPre),
            queued_app_send_bytes =
                Queued + lists:sum([stream_frame_bytes(F) || {_, _, F} <- StreamPre])
        }
    }.

-spec flush_handshake(nquic_protocol:state()) -> {[iodata()], nquic_protocol:state()}.
flush_handshake(#conn_state{flow = #conn_flow{pending_handshake_frames = []}} = State) ->
    {[], State};
flush_handshake(State) ->
    Flow0 = State#conn_state.flow,
    Frames = lists:reverse(Flow0#conn_flow.pending_handshake_frames),
    FlowEmpty = Flow0#conn_flow{pending_handshake_frames = []},
    State1 = State#conn_state{flow = FlowEmpty},
    {ok, Packets, State2} = nquic_protocol_send:build_handshake_packets(Frames, State1),
    {Packets, State2}.

-spec flush_initial(nquic_protocol:state()) -> {[iodata()], nquic_protocol:state()}.
flush_initial(#conn_state{flow = #conn_flow{pending_initial_frames = []}} = State) ->
    {[], State};
flush_initial(State) ->
    Flow0 = State#conn_state.flow,
    Frames = lists:reverse(Flow0#conn_flow.pending_initial_frames),
    FlowEmpty = Flow0#conn_flow{pending_initial_frames = []},
    State1 = State#conn_state{flow = FlowEmpty},
    case nquic_protocol_send:build_initial_packet(Frames, State1) of
        {ok, <<>>, State2} ->
            {[], State2};
        {ok, Packet, State2} ->
            {[Packet], State2};
        {error, _, State2} ->
            {[], State2}
    end.

-spec maybe_piggyback_ack(boolean(), nquic_protocol:state()) -> nquic_protocol:state().
maybe_piggyback_ack(true, State) ->
    nquic_protocol_ack:queue_pending_ack(State);
maybe_piggyback_ack(false, State) ->
    case nquic_protocol_ack:is_ack_due(State) of
        true -> nquic_protocol_ack:queue_pending_ack(State);
        false -> State
    end.

-spec queue_app_frame(nquic_frame:t(), nquic_protocol:state()) -> {ok, nquic_protocol:state()}.
queue_app_frame(Frame, State) ->
    queue_app_frame(Frame, stream_frame_bytes(Frame), State).

-spec queue_app_frame(nquic_frame:t(), non_neg_integer(), nquic_protocol:state()) ->
    {ok, nquic_protocol:state()}.
queue_app_frame(Frame, Bytes, State) ->
    Flow0 = State#conn_state.flow,
    Pending = Flow0#conn_flow.pending_app_frames,
    NewQueued = Flow0#conn_flow.queued_app_send_bytes + Bytes,
    {ok, State#conn_state{
        flow = Flow0#conn_flow{
            pending_app_frames = [Frame | Pending],
            queued_app_send_bytes = NewQueued
        }
    }}.

-spec queue_app_frames([nquic_frame:t()], non_neg_integer(), nquic_protocol:state()) ->
    {ok, nquic_protocol:state()}.
queue_app_frames([], _Bytes, State) ->
    {ok, State};
queue_app_frames(Frames, Bytes, State) ->
    Flow0 = State#conn_state.flow,
    Pending = Flow0#conn_flow.pending_app_frames,
    NewQueued = Flow0#conn_flow.queued_app_send_bytes + Bytes,
    {ok, State#conn_state{
        flow = Flow0#conn_flow{
            pending_app_frames = Frames ++ Pending,
            queued_app_send_bytes = NewQueued
        }
    }}.

-spec queue_app_pre_encoded(
    [nquic_protocol_send:pre_encoded()], non_neg_integer(), nquic_protocol:state()
) ->
    {ok, nquic_protocol:state()}.
queue_app_pre_encoded([], _Bytes, State) ->
    {ok, State};
queue_app_pre_encoded(Pre, Bytes, State) ->
    Flow0 = State#conn_state.flow,
    Existing = Flow0#conn_flow.pending_app_pre_encoded,
    NewQueued = Flow0#conn_flow.queued_app_send_bytes + Bytes,
    {ok, State#conn_state{
        flow = Flow0#conn_flow{
            pending_app_pre_encoded = Pre ++ Existing,
            queued_app_send_bytes = NewQueued
        }
    }}.

-doc """
Queue a frame for a Handshake-space packet. Drained by `flush/1` into a
Handshake-coalesced packet at the next flush. Used for retransmits of
Handshake CRYPTO and PTO probes between Initial and Established.
""".
-spec queue_handshake_frame(nquic_frame:t(), nquic_protocol:state()) ->
    {ok, nquic_protocol:state()}.
queue_handshake_frame(Frame, State) ->
    Flow0 = State#conn_state.flow,
    Pending = Flow0#conn_flow.pending_handshake_frames,
    {ok, State#conn_state{
        flow = Flow0#conn_flow{pending_handshake_frames = [Frame | Pending]}
    }}.

-doc """
Queue a frame for an Initial-space packet. Drained by `flush/1` into an
Initial-coalesced packet at the next flush. Used for retransmits of
client/server Initial CRYPTO and PTO probes during the handshake.
""".
-spec queue_initial_frame(nquic_frame:t(), nquic_protocol:state()) -> {ok, nquic_protocol:state()}.
queue_initial_frame(Frame, State) ->
    Flow0 = State#conn_state.flow,
    Pending = Flow0#conn_flow.pending_initial_frames,
    {ok, State#conn_state{
        flow = Flow0#conn_flow{pending_initial_frames = [Frame | Pending]}
    }}.

-doc """
Let the next flush send one ack-eliciting packet over the congestion
window: a PTO probe (RFC 9002 §6.2.4) or the packet on entry to
recovery (RFC 9002 §7.3.2).
""".
-spec set_cwnd_exempt(nquic_protocol:state()) -> nquic_protocol:state().
set_cwnd_exempt(#conn_state{flow = Flow} = State) ->
    State#conn_state{flow = Flow#conn_flow{cwnd_exempt = true}}.

-spec sort_frames([nquic_frame:t()]) -> [nquic_frame:t()].
sort_frames(Frames) ->
    {Acks, Rest} = lists:partition(
        fun
            (#ack{}) -> true;
            (_) -> false
        end,
        Frames
    ),
    Acks ++ Rest.

-spec stream_frame_bytes(nquic_frame:t()) -> non_neg_integer().
stream_frame_bytes(#stream{stream_id = SID, offset = Off, length = Len}) ->
    nquic_protocol_streams_send:stream_frame_overhead(SID, Off) + Len;
stream_frame_bytes(_) ->
    0.
