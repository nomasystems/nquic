-module(nquic_protocol_streams).
-moduledoc """
Inbound STREAM frame processing and RESET_STREAM / STOP_SENDING handling.

Pure functions over `#conn_state{}` covering peer-initiated stream
ingest: STREAM frame processing with connection- and stream-level flow
control and window-update emission (`handle_stream_frame/7`,
`maybe_send_max_data/1`), DATA_BLOCKED / STREAM_DATA_BLOCKED responses
(`respond_to_data_blocked/2`, `respond_to_stream_data_blocked/3`), the
sender-side blocked signal (`signal_blocked/4`), and RESET_STREAM /
STOP_SENDING dispatch with final-size flow accounting
(`handle_reset_stream/5`, `handle_reset_stream_new/2`,
`handle_stop_sending/3`).

Send-side drain/blocked bookkeeping lives in
`nquic_protocol_streams_send`; terminal-state reclamation and
stream-limit window bookkeeping in `nquic_protocol_streams_lifecycle`.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
-export([
    handle_reset_stream/5,
    handle_reset_stream_new/2,
    handle_stop_sending/3,
    handle_stream_frame/7,
    maybe_send_max_data/1,
    respond_to_data_blocked/2,
    respond_to_stream_data_blocked/3,
    signal_blocked/4
]).

-spec apply_reset_stream(
    already_done | final_size_err | apply,
    nquic:stream_id(),
    non_neg_integer(),
    non_neg_integer(),
    #stream_state{},
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
apply_reset_stream(already_done, _StreamID, _FinalSize, _Code, _Stream, State) ->
    {ok, [], State};
apply_reset_stream(final_size_err, _StreamID, _FinalSize, _Code, _Stream, State) ->
    {error, {transport_error, final_size_error}, State};
apply_reset_stream(apply, StreamID, FinalSize, AppErrorCode, Stream, State) ->
    Increase = max(0, FinalSize - Stream#stream_state.recv_max_offset),
    Flow = State#conn_state.flow,
    NewReceived = Flow#conn_flow.data_received + Increase,
    apply_reset_with_flow_check(
        NewReceived > Flow#conn_flow.local_max_data,
        NewReceived,
        StreamID,
        FinalSize,
        AppErrorCode,
        Stream,
        State
    ).

-spec apply_reset_with_flow_check(
    boolean(),
    non_neg_integer(),
    nquic:stream_id(),
    non_neg_integer(),
    non_neg_integer(),
    #stream_state{},
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
apply_reset_with_flow_check(true, _NewReceived, _StreamID, _FinalSize, _Code, _Stream, State) ->
    {error, {transport_error, flow_control_error}, State};
apply_reset_with_flow_check(false, NewReceived, StreamID, FinalSize, AppErrorCode, Stream, State) ->
    NewStream = Stream#stream_state{
        recv_state = reset_recvd,
        recv_offset = FinalSize,
        recv_max_offset = FinalSize,
        recv_buffer = gb_trees:empty(),
        app_buffer = [],
        app_buffer_size = 0
    },
    #conn_state{streams_state = SS, flow = Flow} = State,
    #conn_streams{streams = Streams} = SS,
    State1 = State#conn_state{
        streams_state = SS#conn_streams{streams = Streams#{StreamID => NewStream}},
        flow = Flow#conn_flow{data_received = NewReceived}
    },
    {ok, [{stream_reset, StreamID, AppErrorCode}], State1}.

-spec classify_data_received(
    {ok, nquic_protocol:state(), #stream_state{}} | {error, term()},
    nquic:stream_id(),
    nquic_frame:t(),
    boolean(),
    map(),
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
classify_data_received({error, flow_control_error}, _ID, _F, _New, _Streams, State) ->
    {error, {transport_error, flow_control_error}, State};
classify_data_received({ok, State1, StreamState1}, StreamID, Frame, IsNewStream, Streams0, _State) ->
    State2 = maybe_track_peer_stream_id(IsNewStream, StreamID, State1),
    State3 = maybe_send_max_data(State2),
    {StreamState2, State4} = maybe_send_max_stream_data(StreamState1, State3),
    classify_handle_recv(
        nquic_stream_statem:handle_recv(StreamState2, Frame),
        StreamID,
        IsNewStream,
        Streams0,
        State4
    ).

-spec classify_get_or_create(
    {ok, #stream_state{}, map()} | {error, term()},
    nquic:stream_id(),
    non_neg_integer(),
    binary(),
    nquic_frame:t(),
    boolean(),
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
classify_get_or_create({error, stream_limit_error}, _ID, _Off, _Data, _F, _New, State) ->
    {error, {transport_error, stream_limit_error}, State};
classify_get_or_create({error, Reason}, _ID, _Off, _Data, _F, _New, State) ->
    {error, {stream_creation_error, Reason}, State};
classify_get_or_create(
    {ok, StreamState0, Streams0}, StreamID, Offset, StreamData, Frame, IsNewStream, State
) ->
    StreamState = nquic_frame_handler:ensure_stream_limits(StreamState0, State),
    Len = byte_size(StreamData),
    classify_data_received(
        nquic_flow:on_stream_data_received(State, StreamState, Offset, Len),
        StreamID,
        Frame,
        IsNewStream,
        Streams0,
        State
    ).

-spec classify_handle_recv(
    {ok, #stream_state{}} | {error, term()},
    nquic:stream_id(),
    boolean(),
    map(),
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
classify_handle_recv({error, Reason}, _StreamID, _IsNewStream, _Streams0, State) ->
    {error, {stream_error, Reason}, State};
classify_handle_recv({ok, NewStreamState}, StreamID, IsNewStream, Streams0, State) ->
    NewStreams = Streams0#{StreamID => NewStreamState},
    SS = (State#conn_state.streams_state)#conn_streams{streams = NewStreams},
    State1 = State#conn_state{streams_state = SS},
    Events = stream_events(IsNewStream, StreamID, State1#conn_state.role),
    State2 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
        StreamID, NewStreamState, State1
    ),
    {ok, Events, State2}.

-spec classify_reset_state(atom(), non_neg_integer(), non_neg_integer()) ->
    already_done | final_size_err | apply.
classify_reset_state(data_read, _, _) ->
    already_done;
classify_reset_state(reset_read, _, _) ->
    already_done;
classify_reset_state(reset_recvd, _, _) ->
    already_done;
classify_reset_state(size_known, FinalSize, RecvMaxOffset) when FinalSize =/= RecvMaxOffset ->
    final_size_err;
classify_reset_state(_, FinalSize, RecvMaxOffset) when FinalSize < RecvMaxOffset ->
    final_size_err;
classify_reset_state(_, _, _) ->
    apply.

-spec handle_max_data(
    {ok, nquic_protocol:state(), nquic_frame:t()} | false, nquic_protocol:state()
) ->
    nquic_protocol:state().
handle_max_data(false, State) ->
    State;
handle_max_data({ok, NewState, WinFrame}, _State) ->
    {ok, NewState1} = nquic_protocol_send_queues:queue_app_frame(WinFrame, NewState),
    NewState1.

-spec handle_max_stream_data(
    {ok, #stream_state{}, nquic_frame:t()} | false, #stream_state{}, nquic_protocol:state()
) -> {#stream_state{}, nquic_protocol:state()}.
handle_max_stream_data(false, StreamState, State) ->
    {StreamState, State};
handle_max_stream_data({ok, NewStreamState, SWinFrame}, _StreamState, State) ->
    {ok, NewState} = nquic_protocol_send_queues:queue_app_frame(SWinFrame, State),
    {NewStreamState, NewState}.

-spec handle_reset_stream(
    nquic:stream_id(), non_neg_integer(), non_neg_integer(), #stream_state{}, nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_reset_stream(StreamID, FinalSize, AppErrorCode, Stream, State) ->
    #stream_state{recv_state = RecvState, recv_max_offset = RecvMaxOffset} = Stream,
    apply_reset_stream(
        classify_reset_state(RecvState, FinalSize, RecvMaxOffset),
        StreamID,
        FinalSize,
        AppErrorCode,
        Stream,
        State
    ).

-spec handle_reset_stream_new(non_neg_integer(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_reset_stream_new(FinalSize, State) ->
    Flow0 = State#conn_state.flow,
    NewReceived = Flow0#conn_flow.data_received + FinalSize,
    case NewReceived > Flow0#conn_flow.local_max_data of
        true ->
            {error, {transport_error, flow_control_error}, State};
        false ->
            {ok, [], State#conn_state{flow = Flow0#conn_flow{data_received = NewReceived}}}
    end.

-spec handle_stop_sending(nquic:stream_id(), non_neg_integer(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
handle_stop_sending(StreamID, ErrCode, State) ->
    #conn_state{streams_state = SS} = State,
    #conn_streams{streams = Streams} = SS,
    case maps:find(StreamID, Streams) of
        {ok, Stream} ->
            #stream_state{send_state = SendState, send_offset = SendOffset} = Stream,
            case SendState of
                S when S =:= reset_sent; S =:= reset_recvd; S =:= data_recvd ->
                    {ok, [], State};
                _ ->
                    ResetFrame = #reset_stream{
                        stream_id = StreamID,
                        app_error_code = ErrCode,
                        final_size = SendOffset
                    },
                    NewStream = Stream#stream_state{send_state = reset_sent},
                    NewStreams = Streams#{StreamID => NewStream},
                    State0 = nquic_protocol_streams_send:clear_blocked(StreamID, State),
                    SS1 = (State0#conn_state.streams_state)#conn_streams{streams = NewStreams},
                    State1 = State0#conn_state{streams_state = SS1},
                    {ok, State2} = nquic_protocol_send_queues:queue_app_frame(ResetFrame, State1),
                    State3 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
                        StreamID, NewStream, State2
                    ),
                    {ok, [{stop_sending, StreamID, ErrCode}], State3}
            end;
        error ->
            {ok, [], State}
    end.

-spec handle_stream_frame(
    nquic:stream_id(),
    non_neg_integer(),
    binary(),
    nquic_frame:t(),
    {ok, #stream_state{}} | error,
    map(),
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_stream_frame(StreamID, Offset, StreamData, Frame, Existing, Limits, State) ->
    #conn_state{streams_state = #conn_streams{streams = Streams}, role = Role} = State,
    IsNewStream = Existing =:= error,
    GetOrCreate =
        case Existing of
            {ok, StreamState} ->
                {ok, StreamState, Streams};
            error ->
                nquic_stream_manager:get_or_create(StreamID, Streams, Role, Limits)
        end,
    classify_get_or_create(
        GetOrCreate,
        StreamID,
        Offset,
        StreamData,
        Frame,
        IsNewStream,
        State
    ).

-spec maybe_send_max_data(nquic_protocol:state()) -> nquic_protocol:state().
maybe_send_max_data(State) ->
    Window = State#conn_state.local_params#transport_params.initial_max_data,
    handle_max_data(nquic_flow:maybe_update_conn_window(State, Window), State).

-spec maybe_send_max_stream_data(#stream_state{}, nquic_protocol:state()) ->
    {#stream_state{}, nquic_protocol:state()}.
maybe_send_max_stream_data(StreamState, State) ->
    Window = State#conn_state.local_params#transport_params.initial_max_stream_data_bidi_local,
    handle_max_stream_data(
        nquic_flow:maybe_update_stream_window(StreamState, Window), StreamState, State
    ).

-spec maybe_track_peer_stream_id(boolean(), nquic:stream_id(), nquic_protocol:state()) ->
    nquic_protocol:state().
maybe_track_peer_stream_id(true, StreamID, State) ->
    nquic_protocol_streams_send:track_peer_stream_id(StreamID, State);
maybe_track_peer_stream_id(false, _StreamID, State) ->
    State.

-doc """
Respond to a peer DATA_BLOCKED frame (RFC 9000 §4.1 / §19.12).
Unconditionally advertises a connection limit strictly above where
the peer reported it is blocked: `max(local_max_data, PeerLimit +
initial_max_data)`. This guarantees forward progress whenever a sender
signals it is stuck at the window edge; the receipt/reader ratchets
are proactive and can decline, but a peer that has explicitly said it
is blocked must always be granted headroom. Bounded and auto-tuning:
`PeerLimit` only grows as the peer makes progress, so the grant tracks
one window ahead of the peer's blocked offset rather than unbounded.
""".
-spec respond_to_data_blocked(non_neg_integer(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
respond_to_data_blocked(PeerLimit, State) ->
    Flow = State#conn_state.flow,
    Window = State#conn_state.local_params#transport_params.initial_max_data,
    Current = Flow#conn_flow.local_max_data,
    Target = max(Current, PeerLimit + Window),
    State1 =
        case Target > Current of
            true -> State#conn_state{flow = Flow#conn_flow{local_max_data = Target}};
            false -> State
        end,
    {ok, State2} = nquic_protocol_send_queues:queue_app_frame(
        #max_data{max_data = Target}, State1
    ),
    {ok, [], State2}.

-doc """
Respond to a peer STREAM_DATA_BLOCKED frame (RFC 9000 §19.13).
Per-stream analogue of `respond_to_data_blocked/2`: unconditionally
advertise `max(recv_window, PeerLimit + initial_max_stream_data_bidi_local)`
so a peer blocked on a stream limit is always granted headroom.
Unknown streams are ignored.
""".
-spec respond_to_stream_data_blocked(nquic:stream_id(), non_neg_integer(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
respond_to_stream_data_blocked(StreamID, PeerLimit, State) ->
    SS0 = State#conn_state.streams_state,
    case maps:find(StreamID, SS0#conn_streams.streams) of
        {ok, Stream0} ->
            Window =
                State#conn_state.local_params#transport_params.initial_max_stream_data_bidi_local,
            Current = Stream0#stream_state.recv_window,
            Target = max(Current, PeerLimit + Window),
            Stream1 = Stream0#stream_state{recv_window = Target},
            SS1 = SS0#conn_streams{
                streams = maps:put(StreamID, Stream1, SS0#conn_streams.streams)
            },
            State1 = State#conn_state{streams_state = SS1},
            {ok, State2} = nquic_protocol_send_queues:queue_app_frame(
                #max_stream_data{stream_id = StreamID, max_stream_data = Target},
                State1
            ),
            {ok, [], State2};
        error ->
            {ok, [], State}
    end.

-doc """
Mark a stream flow-control-blocked and signal the peer (RFC 9000 §4.1).
A sender that is blocked by a flow-control limit SHOULD emit
DATA_BLOCKED (connection) or STREAM_DATA_BLOCKED (stream) so the
receiver can extend the limit. Emission is deduplicated per limit
value so a stream parked across many retry turns produces one frame
per limit, not one per turn.
""".
-spec signal_blocked(atom(), non_neg_integer(), nquic:stream_id(), nquic_protocol:state()) ->
    nquic_protocol:state().
signal_blocked(conn_flow_control_blocked, Limit, StreamID, State) ->
    State1 = nquic_protocol_streams_send:mark_blocked(StreamID, State),
    Flow = State1#conn_state.flow,
    case Limit > Flow#conn_flow.last_data_blocked of
        true ->
            {ok, State2} = nquic_protocol_send_queues:queue_app_frame(
                #data_blocked{limit = Limit}, State1
            ),
            Flow2 = State2#conn_state.flow,
            State2#conn_state{flow = Flow2#conn_flow{last_data_blocked = Limit}};
        false ->
            State1
    end;
signal_blocked(stream_flow_control_blocked, Limit, StreamID, State) ->
    State1 = nquic_protocol_streams_send:mark_blocked(StreamID, State),
    SS0 = State1#conn_state.streams_state,
    case maps:find(StreamID, SS0#conn_streams.streams) of
        {ok, Stream} when Limit > Stream#stream_state.last_stream_data_blocked ->
            {ok, State2} = nquic_protocol_send_queues:queue_app_frame(
                #stream_data_blocked{stream_id = StreamID, limit = Limit}, State1
            ),
            Stream1 = Stream#stream_state{last_stream_data_blocked = Limit},
            SS1 = State2#conn_state.streams_state,
            SS2 = SS1#conn_streams{
                streams = maps:put(StreamID, Stream1, SS1#conn_streams.streams)
            },
            State2#conn_state{streams_state = SS2};
        _ ->
            State1
    end.

-spec stream_events(boolean(), nquic:stream_id(), client | server) -> [nquic_protocol:event()].
stream_events(true, StreamID, Role) ->
    case nquic_frame_handler:is_locally_initiated(StreamID, Role) of
        true -> [{stream_data, StreamID}];
        false -> [{stream_opened, StreamID}, {stream_data, StreamID}]
    end;
stream_events(false, StreamID, _Role) ->
    [{stream_data, StreamID}].
