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
    flush_handshake/1,
    flush_initial/1,
    maybe_piggyback_ack/1
]).

-export([
    build_app_or_zero_rtt/3,
    queue_app_frame/2,
    queue_app_frame/3,
    queue_app_frames/3,
    queue_app_pre_encoded/3,
    queue_handshake_frame/2,
    queue_initial_frame/2,
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

-spec flush_app(nquic_protocol:state()) ->
    {ok, [iodata()], nquic_protocol:state()} | {ok, nquic_protocol:state()}.
flush_app(State0) ->
    State = nquic_protocol_streams_send:drain_pending_sends(maybe_piggyback_ack(State0)),
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
                        Frames = sort_frames(lists:reverse(Pending)),
                        [
                            begin
                                Enc = nquic_frame:encode(F),
                                {iolist_size(Enc), Enc, F}
                            end
                         || F <- Frames
                        ]
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

-spec flush_app_many(
    [nquic_protocol_send:pre_encoded()], pos_integer(), integer(), nquic_protocol:state()
) -> {ok, [iodata()], nquic_protocol:state()} | {ok, nquic_protocol:state()}.
flush_app_many(PreEncoded, Budget, Time, State) ->
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
flush_app_one(PreEncoded, Time, State) ->
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

-spec flush_handshake(nquic_protocol:state()) -> {[iodata()], nquic_protocol:state()}.
flush_handshake(#conn_state{flow = #conn_flow{pending_handshake_frames = []}} = State) ->
    {[], State};
flush_handshake(State) ->
    Flow0 = State#conn_state.flow,
    Frames = lists:reverse(Flow0#conn_flow.pending_handshake_frames),
    FlowEmpty = Flow0#conn_flow{pending_handshake_frames = []},
    State1 = State#conn_state{flow = FlowEmpty},
    case nquic_protocol_send:build_handshake_packet(Frames, State1) of
        {ok, <<>>, State2} ->
            {[], State2};
        {ok, Packet, State2} ->
            {[Packet], State2};
        {error, _, State2} ->
            {[], State2}
    end.

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

-spec maybe_piggyback_ack(nquic_protocol:state()) -> nquic_protocol:state().
maybe_piggyback_ack(#conn_state{pending_ack_count = 0} = State) ->
    State;
maybe_piggyback_ack(State) ->
    State1 = nquic_protocol_ack:force_queue_ack(application, State),
    State1#conn_state{pending_ack_count = 0}.

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
