-module(nquic_stream_statem).

-moduledoc """
Stream state machine per RFC 9000 Section 3.

Manages per-stream send/receive state, data buffering, and reassembly.
Handles contiguous delivery, out-of-order buffering, FIN processing,
and the send state transitions (ready -> send -> data_sent).
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-export([handle_recv/2, handle_send/3, new/2]).

-spec add_to_buffer(
    gb_trees:tree(non_neg_integer(), {binary(), boolean()}),
    non_neg_integer(),
    binary(),
    boolean()
) -> gb_trees:tree(non_neg_integer(), {binary(), boolean()}).
add_to_buffer(Buffer, Offset, Data, Fin) ->
    gb_trees:enter(Offset, {Data, Fin}, Buffer).

-spec append_data(#stream_state{}, binary()) -> #stream_state{}.
append_data(State, Data) ->
    #stream_state{
        recv_offset = Off,
        app_buffer = AppBuf,
        app_buffer_size = BufSize
    } = State,
    Sz = byte_size(Data),
    NewBuf =
        case BufSize of
            0 -> Data;
            _ -> [AppBuf, Data]
        end,
    State#stream_state{
        recv_offset = Off + Sz,
        app_buffer = NewBuf,
        app_buffer_size = BufSize + Sz
    }.

-spec apply_chunk(
    non_neg_integer(), non_neg_integer(), binary(), boolean(), #stream_state{}
) -> {ok, #stream_state{}}.
apply_chunk(0, _Offset, _Data, true, State) ->
    process_fin(State);
apply_chunk(0, _Offset, _Data, false, State) ->
    {ok, State};
apply_chunk(_Size, Offset, Data, Fin, #stream_state{recv_offset = Offset} = State) ->
    State1 = append_data(State, Data),
    process_buffer(maybe_process_fin(State1, Fin));
apply_chunk(_Size, Offset, Data, Fin, State) ->
    buffer_data(State, Offset, Data, Fin).

-spec buffer_data(#stream_state{}, non_neg_integer(), binary(), boolean()) ->
    {ok, #stream_state{}}.
buffer_data(State, Offset, Data, Fin) ->
    #stream_state{recv_buffer = Buffer} = State,
    NewBuffer = add_to_buffer(Buffer, Offset, Data, Fin),
    {ok, State#stream_state{recv_buffer = NewBuffer}}.

-spec classify_offset(non_neg_integer(), non_neg_integer()) -> contiguous | overlap | gap.
classify_offset(BufOff, RecvOffset) when BufOff =:= RecvOffset -> contiguous;
classify_offset(BufOff, RecvOffset) when BufOff < RecvOffset -> overlap;
classify_offset(_, _) -> gap.

-spec consume_head(
    contiguous | overlap | gap,
    non_neg_integer(),
    binary(),
    boolean(),
    #stream_state{}
) -> {ok, #stream_state{}}.
consume_head(contiguous, BufOff, BufData, BufFin, #stream_state{recv_buffer = Buffer} = State) ->
    Rest = gb_trees:delete(BufOff, Buffer),
    State1 = append_data(State#stream_state{recv_buffer = Rest}, BufData),
    process_buffer(maybe_process_fin(State1, BufFin));
consume_head(
    overlap,
    BufOff,
    BufData,
    BufFin,
    #stream_state{recv_buffer = Buffer, recv_offset = RecvOffset} = State
) ->
    Rest = gb_trees:delete(BufOff, Buffer),
    {NewOff, NewData} = trim_data(BufOff, BufData, RecvOffset),
    reinsert_or_drop(byte_size(NewData), NewOff, NewData, BufFin, State#stream_state{
        recv_buffer = Rest
    });
consume_head(gap, _BufOff, _BufData, _BufFin, State) ->
    {ok, State}.

-spec continue_incoming(#stream_state{}, non_neg_integer(), binary(), boolean()) ->
    {ok, #stream_state{}}.
continue_incoming(#stream_state{recv_offset = RecvOffset} = State, Offset, Data, Fin) ->
    {TrimmedOffset, TrimmedData} = trim_data(Offset, Data, RecvOffset),
    apply_chunk(byte_size(TrimmedData), TrimmedOffset, TrimmedData, Fin, State).

-spec drain_buffer(boolean(), #stream_state{}) -> {ok, #stream_state{}}.
drain_buffer(true, State) ->
    {ok, State};
drain_buffer(false, #stream_state{recv_buffer = Buffer, recv_offset = RecvOffset} = State) ->
    {BufOff, {BufData, BufFin}} = gb_trees:smallest(Buffer),
    consume_head(classify_offset(BufOff, RecvOffset), BufOff, BufData, BufFin, State).

-spec enqueue_send(#stream_state{}, iodata(), boolean()) -> #stream_state{}.
enqueue_send(State, Data, Fin) ->
    #stream_state{
        send_offset = Offset,
        pending_send_data = Pending,
        pending_send_size = PendingSize,
        pending_send_fin = PendingFin
    } = State,
    case iolist_to_binary(Data) of
        <<>> ->
            State#stream_state{pending_send_fin = PendingFin orelse Fin};
        Bin ->
            Len = byte_size(Bin),
            State#stream_state{
                send_offset = Offset + Len,
                pending_send_data = [Bin | Pending],
                pending_send_size = PendingSize + Len,
                pending_send_fin = PendingFin orelse Fin
            }
    end.

-spec handle_incoming_chunk(#stream_state{}, #stream{}) ->
    {ok, #stream_state{}} | {error, term()}.
handle_incoming_chunk(
    #stream_state{recv_state = size_known, recv_offset = RecvOffset},
    #stream{offset = Offset, data = Data}
) when Offset + byte_size(Data) > RecvOffset ->
    {error, final_size_error};
handle_incoming_chunk(State, #stream{offset = Offset, data = Data, fin = Fin}) ->
    continue_incoming(State, Offset, Data, Fin).

-doc "Process an incoming STREAM frame, buffering and reassembling data.".
-spec handle_recv(#stream_state{}, nquic_frame:t()) ->
    {ok, #stream_state{}} | {error, nquic_error:any_reason()}.
handle_recv(#stream_state{recv_state = recv} = State, #stream{} = Frame) ->
    handle_incoming_chunk(State, Frame);
handle_recv(#stream_state{recv_state = size_known} = State, #stream{} = Frame) ->
    handle_incoming_chunk(State, Frame);
handle_recv(State, _) ->
    {ok, State}.

-doc """
Buffer outgoing data on a stream.
Appends `Data` to the stream's `pending_send_data` and latches `Fin`.
The actual STREAM frame(s) are produced later by
`nquic_protocol_streams_send:drain_pending_sends/1` at flush time, where they
can be split to fit the path MTU and the congestion window. Advancing
`send_offset` here (rather than at drain time) keeps the existing
flow-control checks honest: they already treat `send_offset` as
"bytes committed to the stream", which is what we want.
Returns `{error, stream_closed}` when the send-side is already terminal
(`data_sent`, `data_recvd`, `reset_sent`, `reset_recvd`).
""".
-spec handle_send(#stream_state{}, iodata(), boolean()) ->
    {ok, #stream_state{}} | {error, term()}.
handle_send(State, Data, Fin) ->
    #stream_state{send_state = SState} = State,
    case SState of
        ready -> {ok, enqueue_send(State#stream_state{send_state = send}, Data, Fin)};
        send -> {ok, enqueue_send(State, Data, Fin)};
        _ -> {error, stream_closed}
    end.

-spec maybe_process_fin(#stream_state{}, boolean()) -> #stream_state{}.
maybe_process_fin(State, false) ->
    State;
maybe_process_fin(State, true) ->
    {ok, State1} = process_fin(State),
    State1.

-doc "Create a new stream state for the given stream ID and type.".
-spec new(nquic:stream_id(), bidi | uni) -> #stream_state{}.
new(StreamID, Type) ->
    #stream_state{
        stream_id = StreamID,
        type = Type,
        send_state = ready,
        recv_state = recv,
        recv_buffer = gb_trees:empty()
    }.

-spec process_buffer(#stream_state{}) -> {ok, #stream_state{}}.
process_buffer(#stream_state{recv_buffer = Buffer} = State) ->
    drain_buffer(gb_trees:is_empty(Buffer), State).

-spec process_fin(#stream_state{}) -> {ok, #stream_state{}}.
process_fin(State) ->
    {ok, State#stream_state{recv_state = size_known}}.

-spec reinsert_or_drop(
    non_neg_integer(),
    non_neg_integer(),
    binary(),
    boolean(),
    #stream_state{}
) -> {ok, #stream_state{}}.
reinsert_or_drop(0, _Off, _Data, true, State) ->
    process_fin(State);
reinsert_or_drop(0, _Off, _Data, false, State) ->
    process_buffer(State);
reinsert_or_drop(_Size, Off, Data, Fin, #stream_state{recv_buffer = Buffer} = State) ->
    process_buffer(State#stream_state{recv_buffer = gb_trees:enter(Off, {Data, Fin}, Buffer)}).

-spec trim_data(non_neg_integer(), binary(), non_neg_integer()) ->
    {non_neg_integer(), binary()}.
trim_data(Offset, Data, RecvOffset) ->
    if
        Offset < RecvOffset ->
            Overlap = RecvOffset - Offset,
            if
                Overlap >= byte_size(Data) ->
                    {RecvOffset, <<>>};
                true ->
                    <<_:Overlap/binary, Rest/binary>> = Data,
                    {RecvOffset, Rest}
            end;
        true ->
            {Offset, Data}
    end.
