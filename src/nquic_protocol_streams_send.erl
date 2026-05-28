-module(nquic_protocol_streams_send).
-moduledoc """
Send-side stream drain engine and blocked/pending stream tracking.

Pure functions over `#conn_state{}` that turn buffered outbound stream
bytes into STREAM frames and maintain the indices that keep the flush
path O(1) in the number of idle streams.

The drain engine (`drain_pending_sends/1`, `drain_round_robin/2`,
`drain_streams/3`, `drain_streams_capped/4`, `drain_one_stream/4`,
`drain_chunks/5`, `drain_chunks_loop/11`, `emit_lone_fin/5`,
`peel_bytes/2,3`) walks the `pending_send_streams` index, sizing each
STREAM frame to fit one MTU-bounded short-header packet and capping the
total bytes per call by the connection cwnd headroom (`cwnd_budget/1`).
Frame sizing helpers are `stream_frame_overhead/2` and
`stream_frame_size/3`.

Readiness/blocked tracking (`check_writable_1byte/2`, `is_writable/2`,
`mark_blocked/2`, `clear_blocked/2`, `scan_blocked_streams/1`,
`scan_blocked_stream/2`) detects flow/CC writable-edge transitions, and
the pending-send index (`mark_pending_send/2`, `clear_pending_send/2`,
`has_pending_send/1`, `sync_pending_send/2`, `put_stream/3`) plus peer
stream-id tracking (`track_peer_stream_id/2`) round out the send-side
bookkeeping. Terminal reclamation and MAX_STREAMS auto-extension are
delegated to `nquic_protocol_streams_lifecycle`.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-export([
    check_writable_1byte/2,
    clear_blocked/2,
    clear_pending_send/2,
    drain_pending_sends/1,
    has_pending_send/1,
    is_writable/2,
    mark_blocked/2,
    mark_pending_send/2,
    scan_blocked_stream/2,
    scan_blocked_streams/1,
    stream_frame_overhead/2,
    stream_frame_size/3,
    sync_pending_send/2,
    track_peer_stream_id/2
]).

-define(MAX_STREAM_FRAME_LENGTH, 16383).

-doc """
Check that at least one byte can be sent on the given stream right now.

Runs the three send-side checks (connection flow, stream flow, congestion
control) against a length of 1, gated on the stream's send state being
still writable. Returns true iff all checks pass. Used to detect
writable-edge transitions for previously flow/CC-blocked streams.
""".
-spec check_writable_1byte(#stream_state{}, nquic_protocol:state()) -> boolean().
check_writable_1byte(#stream_state{send_state = SState} = Stream, State) when
    SState =:= ready; SState =:= send
->
    case nquic_flow:check_conn_send(State, 1) of
        ok ->
            case nquic_flow:check_stream_send(Stream, 1) of
                ok ->
                    case nquic_protocol_send:check_congestion_control(State, 1) of
                        ok -> true;
                        _ -> false
                    end;
                _ ->
                    false
            end;
        _ ->
            false
    end;
check_writable_1byte(_Stream, _State) ->
    false.

-spec clear_blocked(nquic:stream_id(), nquic_protocol:state()) -> nquic_protocol:state().
clear_blocked(StreamID, #conn_state{streams_state = SS0} = State) ->
    BS = SS0#conn_streams.blocked_streams,
    case maps:is_key(StreamID, BS) of
        true ->
            NewSS = SS0#conn_streams{blocked_streams = maps:remove(StreamID, BS)},
            State#conn_state{streams_state = NewSS};
        false ->
            State
    end.

-doc """
Remove `StreamID` from the pending-send index. Idempotent.
Call after a drain empties the buffer (and any FIN has been emitted) or
after `cleanup_stream`/`reset_stream` purge the buffer.
""".
-spec clear_pending_send(nquic:stream_id(), nquic_protocol:state()) ->
    nquic_protocol:state().
clear_pending_send(StreamID, #conn_state{streams_state = SS0} = State) ->
    PS0 = SS0#conn_streams.pending_send_streams,
    case maps:is_key(StreamID, PS0) of
        false ->
            State;
        true ->
            PS = maps:remove(StreamID, PS0),
            State#conn_state{streams_state = SS0#conn_streams{pending_send_streams = PS}}
    end.

-spec cwnd_budget(nquic_protocol:state()) -> non_neg_integer().
cwnd_budget(#conn_state{loss_state = LossState, flow = Flow}) ->
    Cwnd = nquic_loss:get_cwnd(LossState),
    InFlight = nquic_loss:get_bytes_in_flight(LossState),
    Queued = Flow#conn_flow.queued_app_send_bytes,
    Used = InFlight + Queued,
    case Cwnd > Used of
        true -> Cwnd - Used;
        false -> 0
    end.

-spec drain_chunks(
    nquic:stream_id(), #stream_state{}, non_neg_integer(), pos_integer(), nquic_protocol:state()
) -> {non_neg_integer(), nquic_protocol:state()}.
drain_chunks(StreamID, Stream, Budget, PayloadBudget, State) ->
    #stream_state{
        pending_send_data = RevBuf,
        pending_send_size = BufSize,
        pending_send_fin = FinPending,
        send_offset = SendOffset
    } = Stream,
    BaseOffset = SendOffset - BufSize,
    case BufSize of
        0 when FinPending ->
            emit_lone_fin(StreamID, BaseOffset, Stream, Budget, State);
        0 ->
            {Budget, State};
        _ ->
            FifoBuf = lists:reverse(RevBuf),
            drain_chunks_loop(
                StreamID,
                Stream,
                FifoBuf,
                BufSize,
                FinPending,
                BaseOffset,
                Budget,
                PayloadBudget,
                State,
                [],
                0
            )
    end.

-spec drain_chunks_loop(
    nquic:stream_id(),
    #stream_state{},
    [binary()],
    non_neg_integer(),
    boolean(),
    non_neg_integer(),
    non_neg_integer(),
    pos_integer(),
    nquic_protocol:state(),
    [{non_neg_integer(), iodata(), nquic_frame:t()}],
    non_neg_integer()
) -> {non_neg_integer(), nquic_protocol:state()}.
drain_chunks_loop(
    StreamID,
    Stream,
    FifoBuf,
    BufSize,
    FinPending,
    BaseOffset,
    Budget,
    PayloadBudget,
    State,
    PreAcc,
    AccBytes
) ->
    FrameOverhead = stream_frame_overhead(StreamID, BaseOffset),
    ChunkBudget = min(BufSize, max(0, PayloadBudget - FrameOverhead)),
    CwndChunk = min(ChunkBudget, max(0, Budget - FrameOverhead)),
    case CwndChunk of
        0 ->
            NewStream = Stream#stream_state{
                pending_send_data = lists:reverse(FifoBuf),
                pending_send_size = BufSize,
                pending_send_fin = FinPending
            },
            {ok, State1} = nquic_protocol_send_queues:queue_app_pre_encoded(
                PreAcc, AccBytes, State
            ),
            {Budget, put_stream(StreamID, NewStream, State1)};
        _ ->
            {ChunkIO, RestFifo} = peel_bytes(CwndChunk, FifoBuf),
            NewSize = BufSize - CwndChunk,
            EmitFin = NewSize =:= 0 andalso FinPending,
            Frame = #stream{
                stream_id = StreamID,
                offset = BaseOffset,
                length = CwndChunk,
                fin = EmitFin,
                data = ChunkIO
            },
            FrameSize = FrameOverhead + CwndChunk,
            EncodedFrame = nquic_frame:encode(Frame),
            PreEntry = {FrameSize, EncodedFrame, Frame},
            NewBudget = max(0, Budget - FrameSize),
            NewPreAcc = [PreEntry | PreAcc],
            NewAccBytes = AccBytes + FrameSize,
            case NewSize of
                0 ->
                    {ok, State1} = nquic_protocol_send_queues:queue_app_pre_encoded(
                        NewPreAcc, NewAccBytes, State
                    ),
                    NewStream0 = Stream#stream_state{
                        pending_send_data = [],
                        pending_send_size = 0,
                        pending_send_fin = FinPending andalso not EmitFin
                    },
                    NewStream =
                        case EmitFin of
                            true -> NewStream0#stream_state{send_state = data_sent};
                            false -> NewStream0
                        end,
                    State2 = put_stream(StreamID, NewStream, State1),
                    State3 = clear_pending_send(StreamID, State2),
                    State4 =
                        case EmitFin of
                            true ->
                                nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
                                    StreamID, NewStream, State3
                                );
                            false ->
                                State3
                        end,
                    {NewBudget, State4};
                _ ->
                    drain_chunks_loop(
                        StreamID,
                        Stream,
                        RestFifo,
                        NewSize,
                        FinPending,
                        BaseOffset + CwndChunk,
                        NewBudget,
                        PayloadBudget,
                        State,
                        NewPreAcc,
                        NewAccBytes
                    )
            end
    end.

-spec drain_one_stream(
    nquic:stream_id(), #stream_state{}, non_neg_integer(), nquic_protocol:state()
) -> {non_neg_integer(), nquic_protocol:state()}.
drain_one_stream(
    StreamID,
    #stream_state{pending_send_size = 0, pending_send_fin = false},
    Budget,
    State
) ->
    {Budget, clear_pending_send(StreamID, State)};
drain_one_stream(StreamID, Stream, Budget, State) ->
    PayloadBudget = nquic_protocol_send:packet_payload_budget(State),
    drain_chunks(StreamID, Stream, Budget, PayloadBudget, State).

-doc """
Walk all streams with buffered outbound data and produce STREAM frames.
Each frame is sized to fit in one MTU-bounded short-header packet and
is queued onto `pending_app_frames`. The per-connection cwnd headroom
caps the total bytes drained per call: anything that doesn't fit stays
in the stream's `pending_send_data` and is drained on the next flush
(typically triggered when an ACK frees `bytes_in_flight`).
Iterates the `pending_send_streams` index rather than the full streams
map, so connections with many idle streams pay only for the ones with
buffered bytes or a latched FIN.
""".
-spec drain_pending_sends(nquic_protocol:state()) -> nquic_protocol:state().
drain_pending_sends(
    #conn_state{streams_state = #conn_streams{pending_send_streams = PS}} = State
) when map_size(PS) =:= 0 ->
    State;
drain_pending_sends(State) ->
    PS = (State#conn_state.streams_state)#conn_streams.pending_send_streams,
    case map_size(PS) of
        1 ->
            CwndBudget = cwnd_budget(State),
            {_, State1} = drain_streams(maps:keys(PS), CwndBudget, State),
            State1;
        _ ->
            CwndBudget = cwnd_budget(State),
            drain_round_robin(CwndBudget, State)
    end.

-spec drain_round_robin(non_neg_integer(), nquic_protocol:state()) ->
    nquic_protocol:state().
drain_round_robin(0, State) ->
    State;
drain_round_robin(Budget, State) ->
    PS = (State#conn_state.streams_state)#conn_streams.pending_send_streams,
    case map_size(PS) of
        0 ->
            State;
        N ->
            PayloadBudget = nquic_protocol_send:packet_payload_budget(State),
            PerStream = max(PayloadBudget, Budget div N),
            {NewBudget, State1} = drain_streams_capped(
                maps:keys(PS), Budget, PerStream, State
            ),
            case Budget - NewBudget of
                0 ->
                    State1;
                _ ->
                    drain_round_robin(NewBudget, State1)
            end
    end.

-spec drain_streams([nquic:stream_id()], non_neg_integer(), nquic_protocol:state()) ->
    {non_neg_integer(), nquic_protocol:state()}.
drain_streams([], Budget, State) ->
    {Budget, State};
drain_streams(_, 0, State) ->
    {0, State};
drain_streams([StreamID | Rest], Budget, State) ->
    Streams = (State#conn_state.streams_state)#conn_streams.streams,
    case maps:find(StreamID, Streams) of
        {ok, Stream} ->
            {NewBudget, State1} = drain_one_stream(StreamID, Stream, Budget, State),
            drain_streams(Rest, NewBudget, State1);
        error ->
            drain_streams(Rest, Budget, clear_pending_send(StreamID, State))
    end.

-spec drain_streams_capped(
    [nquic:stream_id()], non_neg_integer(), non_neg_integer(), nquic_protocol:state()
) -> {non_neg_integer(), nquic_protocol:state()}.
drain_streams_capped([], Budget, _PerStream, State) ->
    {Budget, State};
drain_streams_capped(_, 0, _PerStream, State) ->
    {0, State};
drain_streams_capped([StreamID | Rest], Budget, PerStream, State) ->
    StreamBudget = min(Budget, PerStream),
    Streams = (State#conn_state.streams_state)#conn_streams.streams,
    case maps:find(StreamID, Streams) of
        {ok, Stream} ->
            {NewStreamBudget, State1} = drain_one_stream(
                StreamID, Stream, StreamBudget, State
            ),
            Drained = StreamBudget - NewStreamBudget,
            drain_streams_capped(Rest, Budget - Drained, PerStream, State1);
        error ->
            drain_streams_capped(
                Rest, Budget, PerStream, clear_pending_send(StreamID, State)
            )
    end.

-spec emit_lone_fin(
    nquic:stream_id(), non_neg_integer(), #stream_state{}, non_neg_integer(), nquic_protocol:state()
) -> {non_neg_integer(), nquic_protocol:state()}.
emit_lone_fin(StreamID, BaseOffset, Stream, Budget, State) ->
    FrameSize = stream_frame_size(StreamID, BaseOffset, 0),
    case Budget >= FrameSize of
        true ->
            Frame = #stream{
                stream_id = StreamID,
                offset = BaseOffset,
                length = 0,
                fin = true,
                data = <<>>
            },
            EncodedFrame = nquic_frame:encode(Frame),
            PreEntry = {FrameSize, EncodedFrame, Frame},
            {ok, State1} = nquic_protocol_send_queues:queue_app_pre_encoded(
                [PreEntry], FrameSize, State
            ),
            NewStream = Stream#stream_state{
                pending_send_fin = false,
                send_state = data_sent
            },
            State2 = put_stream(StreamID, NewStream, State1),
            State3 = clear_pending_send(StreamID, State2),
            State4 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
                StreamID, NewStream, State3
            ),
            {Budget - FrameSize, State4};
        false ->
            {Budget, State}
    end.

-doc "Quick check: does any stream still have buffered outbound data or a latched FIN?".
-spec has_pending_send(nquic_protocol:state()) -> boolean().
has_pending_send(
    #conn_state{streams_state = #conn_streams{pending_send_streams = PS}}
) ->
    map_size(PS) > 0.

-spec incr_opened_peer_count(bidi | uni, nquic_protocol:state()) -> nquic_protocol:state().
incr_opened_peer_count(bidi, #conn_state{streams_state = SS} = State) ->
    State#conn_state{
        streams_state = SS#conn_streams{
            opened_peer_bidi_count = SS#conn_streams.opened_peer_bidi_count + 1
        }
    };
incr_opened_peer_count(uni, #conn_state{streams_state = SS} = State) ->
    State#conn_state{
        streams_state = SS#conn_streams{
            opened_peer_uni_count = SS#conn_streams.opened_peer_uni_count + 1
        }
    }.

-doc """
Public predicate: is this stream currently writable?
Unknown stream IDs return false. Applies the lazy stream-limit
initialisation used by `send_stream/4` so freshly-opened streams report
accurately before the first send. Used by `nquic_lib:is_writable/2`.
""".
-spec is_writable(nquic:stream_id(), nquic_protocol:state()) -> boolean().
is_writable(StreamID, #conn_state{streams_state = #conn_streams{streams = Streams}} = State) ->
    case maps:find(StreamID, Streams) of
        {ok, Stream0} ->
            Stream = nquic_frame_handler:ensure_stream_limits(Stream0, State),
            check_writable_1byte(Stream, State);
        error ->
            false
    end.

-spec mark_blocked(nquic:stream_id(), nquic_protocol:state()) -> nquic_protocol:state().
mark_blocked(StreamID, #conn_state{streams_state = SS0} = State) ->
    BS = SS0#conn_streams.blocked_streams,
    NewSS = SS0#conn_streams{blocked_streams = BS#{StreamID => true}},
    State#conn_state{streams_state = NewSS}.

-doc """
Add `StreamID` to the pending-send index. Idempotent.
Call after any operation that grows `pending_send_data` or latches
`pending_send_fin` on a live stream. Maintaining the index allows
`flush/1` and `drain_pending_sends/1` to short-circuit in O(1).
""".
-spec mark_pending_send(nquic:stream_id(), nquic_protocol:state()) ->
    nquic_protocol:state().
mark_pending_send(StreamID, #conn_state{streams_state = SS0} = State) ->
    PS0 = SS0#conn_streams.pending_send_streams,
    case maps:is_key(StreamID, PS0) of
        true ->
            State;
        false ->
            PS = PS0#{StreamID => true},
            State#conn_state{streams_state = SS0#conn_streams{pending_send_streams = PS}}
    end.

-spec peel_bytes(pos_integer(), [binary(), ...]) -> {iodata(), [binary()]}.
peel_bytes(N, [Bin | Rest] = FifoBuf) ->
    case byte_size(Bin) of
        Sz when Sz > N ->
            <<Head:N/binary, Tail/binary>> = Bin,
            {[Head], [Tail | Rest]};
        Sz when Sz =:= N ->
            {[Bin], Rest};
        _ ->
            peel_bytes(N, FifoBuf, [])
    end.

-spec peel_bytes(non_neg_integer(), [binary()], [binary()]) -> {iodata(), [binary()]}.
peel_bytes(0, Rest, Acc) ->
    {lists:reverse(Acc), Rest};
peel_bytes(N, [Bin | Rest], Acc) ->
    case byte_size(Bin) of
        Sz when Sz =< N ->
            peel_bytes(N - Sz, Rest, [Bin | Acc]);
        _ ->
            <<Head:N/binary, Tail/binary>> = Bin,
            {lists:reverse([Head | Acc]), [Tail | Rest]}
    end.

-spec put_stream(nquic:stream_id(), #stream_state{}, nquic_protocol:state()) ->
    nquic_protocol:state().
put_stream(StreamID, Stream, #conn_state{streams_state = SS0} = State) ->
    Streams = SS0#conn_streams.streams,
    NewSS = SS0#conn_streams{streams = Streams#{StreamID => Stream}},
    State#conn_state{streams_state = NewSS}.

-spec scan_blocked_stream(nquic:stream_id(), nquic_protocol:state()) ->
    {[nquic_protocol:event()], nquic_protocol:state()}.
scan_blocked_stream(
    StreamID,
    #conn_state{streams_state = #conn_streams{blocked_streams = BS, streams = Streams}} = State
) ->
    case maps:is_key(StreamID, BS) of
        false ->
            {[], State};
        true ->
            case maps:find(StreamID, Streams) of
                {ok, Stream} ->
                    case check_writable_1byte(Stream, State) of
                        true ->
                            {[{stream_writable, StreamID}], clear_blocked(StreamID, State)};
                        false ->
                            {[], State}
                    end;
                error ->
                    {[], clear_blocked(StreamID, State)}
            end
    end.

-spec scan_blocked_streams(nquic_protocol:state()) ->
    {[nquic_protocol:event()], nquic_protocol:state()}.
scan_blocked_streams(
    #conn_state{streams_state = #conn_streams{blocked_streams = BS}} = State
) when map_size(BS) =:= 0 ->
    {[], State};
scan_blocked_streams(
    #conn_state{streams_state = #conn_streams{blocked_streams = BS, streams = Streams}} = State
) ->
    maps:fold(
        fun(StreamID, _, {Events, StateAcc}) ->
            case maps:find(StreamID, Streams) of
                {ok, Stream} ->
                    case check_writable_1byte(Stream, StateAcc) of
                        true ->
                            StateAcc1 = clear_blocked(StreamID, StateAcc),
                            {[{stream_writable, StreamID} | Events], StateAcc1};
                        false ->
                            {Events, StateAcc}
                    end;
                error ->
                    {Events, clear_blocked(StreamID, StateAcc)}
            end
        end,
        {[], State},
        BS
    ).

-spec stream_frame_overhead(nquic:stream_id(), non_neg_integer()) -> pos_integer().
stream_frame_overhead(StreamID, Offset) ->
    OffsetSize =
        case Offset of
            0 -> 0;
            _ -> nquic_varint:size(Offset)
        end,
    1 + nquic_varint:size(StreamID) + OffsetSize + nquic_varint:size(?MAX_STREAM_FRAME_LENGTH).

-spec stream_frame_size(nquic:stream_id(), non_neg_integer(), non_neg_integer()) ->
    pos_integer().
stream_frame_size(StreamID, Offset, Length) when is_integer(Length), Length >= 0 ->
    stream_frame_overhead(StreamID, Offset) + Length.

-doc """
Reconcile the pending-send index for `StreamID` against the stream's
current `pending_send_size` / `pending_send_fin`. Use after operations
that may have flipped membership in either direction.
""".
-spec sync_pending_send(nquic:stream_id(), nquic_protocol:state()) ->
    nquic_protocol:state().
sync_pending_send(StreamID, State) ->
    Streams = (State#conn_state.streams_state)#conn_streams.streams,
    case maps:find(StreamID, Streams) of
        {ok, #stream_state{pending_send_size = Size, pending_send_fin = Fin}} when
            Size > 0; Fin
        ->
            mark_pending_send(StreamID, State);
        _ ->
            clear_pending_send(StreamID, State)
    end.

-spec track_peer_stream_id(nquic:stream_id(), nquic_protocol:state()) -> nquic_protocol:state().
track_peer_stream_id(StreamID, #conn_state{role = Role, streams_state = SS0} = State) ->
    case nquic_frame_handler:is_locally_initiated(StreamID, Role) of
        true ->
            State;
        false ->
            Type = nquic_stream_manager:type(StreamID),
            case Type of
                bidi ->
                    Max = SS0#conn_streams.max_peer_bidi_stream_id,
                    State1 =
                        case Max of
                            undefined ->
                                NewSS = SS0#conn_streams{max_peer_bidi_stream_id = StreamID},
                                State#conn_state{streams_state = NewSS};
                            _ when StreamID > Max ->
                                NewSS = SS0#conn_streams{max_peer_bidi_stream_id = StreamID},
                                State#conn_state{streams_state = NewSS};
                            _ ->
                                State
                        end,
                    State2 = incr_opened_peer_count(bidi, State1),
                    nquic_protocol_streams_lifecycle:maybe_auto_extend_max_streams(bidi, State2);
                uni ->
                    Max = SS0#conn_streams.max_peer_uni_stream_id,
                    State1 =
                        case Max of
                            undefined ->
                                NewSS = SS0#conn_streams{max_peer_uni_stream_id = StreamID},
                                State#conn_state{streams_state = NewSS};
                            _ when StreamID > Max ->
                                NewSS = SS0#conn_streams{max_peer_uni_stream_id = StreamID},
                                State#conn_state{streams_state = NewSS};
                            _ ->
                                State
                        end,
                    State2 = incr_opened_peer_count(uni, State1),
                    nquic_protocol_streams_lifecycle:maybe_auto_extend_max_streams(uni, State2)
            end
    end.
