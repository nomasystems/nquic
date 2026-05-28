-module(nquic_protocol_streams_lifecycle).
-moduledoc """
Stream terminal-state cleanup and stream-limit bookkeeping.

Pure functions over `#conn_state{}` that decide when a stream has
reached a terminal state and reclaim it: per-side terminal predicates
(`is_stream_terminal/3`, `is_send_done/1`, `is_recv_done/1`,
`is_closed_stream/2`), terminal-state reclamation. The recv-side
predicate treats `size_known` with an empty app buffer as terminal:
the peer's FIN has been delivered and there is nothing left for the
caller to drain, so the stream can be reclaimed without waiting for
an explicit `recv` round-trip from the application.
(`maybe_cleanup_stream/2,3`, `cleanup_stream/2`), the watermark
bookkeeping that keeps `closed_peer_streams` bounded
(`record_peer_closed/2`, `advance_peer_wm/3`, `set_peer_wm/3`), and
MAX_STREAMS window-update emission as peer-initiated streams are
consumed and reclaimed (`bump_max_streams/2`,
`maybe_send_max_streams/2`, `maybe_auto_extend_max_streams/2`,
`peer_consumed_bidi_streams/1`, `peer_consumed_uni_streams/1`).

`cleanup_stream/2` purges the reclaimed stream from the send-side
pending/blocked indices via `nquic_protocol_streams_send`; the send
engine calls back here for `maybe_cleanup_stream/3` and
`maybe_auto_extend_max_streams/2`.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-export([
    bump_max_streams/2,
    is_closed_stream/2,
    is_stream_terminal/3,
    maybe_auto_extend_max_streams/2,
    maybe_cleanup_stream/2,
    maybe_cleanup_stream/3,
    peer_consumed_bidi_streams/1,
    peer_consumed_uni_streams/1
]).

-spec advance_peer_wm(bidi | uni, nquic:stream_id(), nquic_protocol:state()) ->
    nquic_protocol:state().
advance_peer_wm(Type, StreamID, State) ->
    SS0 = State#conn_state.streams_state,
    Closed = SS0#conn_streams.closed_peer_streams,
    NextID = StreamID + 4,
    case maps:take(NextID, Closed) of
        {true, Closed1} ->
            NewSS = SS0#conn_streams{closed_peer_streams = Closed1},
            State1 = set_peer_wm(Type, StreamID, State#conn_state{streams_state = NewSS}),
            advance_peer_wm(Type, NextID, State1);
        error ->
            set_peer_wm(Type, StreamID, State)
    end.

-spec bump_max_streams(nquic:stream_id(), nquic_protocol:state()) -> nquic_protocol:state().
bump_max_streams(StreamID, State) ->
    SS0 = State#conn_state.streams_state,
    Type = nquic_stream_manager:type(StreamID),
    case Type of
        bidi ->
            NewLimit = SS0#conn_streams.local_max_streams_bidi + 1,
            NewSS = SS0#conn_streams{local_max_streams_bidi = NewLimit},
            maybe_send_max_streams(bidi, State#conn_state{streams_state = NewSS});
        uni ->
            NewLimit = SS0#conn_streams.local_max_streams_uni + 1,
            NewSS = SS0#conn_streams{local_max_streams_uni = NewLimit},
            maybe_send_max_streams(uni, State#conn_state{streams_state = NewSS})
    end.

-spec cleanup_stream(nquic:stream_id(), nquic_protocol:state()) -> nquic_protocol:state().
cleanup_stream(StreamID, State) ->
    #conn_state{streams_state = SS, role = Role} = State,
    #conn_streams{streams = Streams} = SS,
    State0 = nquic_protocol_streams_send:clear_pending_send(
        StreamID, nquic_protocol_streams_send:clear_blocked(StreamID, State)
    ),
    SS0 = State0#conn_state.streams_state,
    NewSS = SS0#conn_streams{streams = maps:remove(StreamID, Streams)},
    case nquic_frame_handler:is_locally_initiated(StreamID, Role) of
        true ->
            State0#conn_state{streams_state = NewSS};
        false ->
            State1 = State0#conn_state{streams_state = NewSS},
            State2 = record_peer_closed(StreamID, State1),
            bump_max_streams(StreamID, State2)
    end.

-spec is_closed_stream(nquic:stream_id(), nquic_protocol:state()) -> boolean().
is_closed_stream(StreamID, State) ->
    #conn_state{role = Role, streams_state = SS} = State,
    #conn_streams{
        next_bidi_stream = NextBidi,
        next_uni_stream = NextUni,
        closed_peer_bidi_wm = BidiWm,
        closed_peer_uni_wm = UniWm,
        closed_peer_streams = Closed,
        streams = Streams
    } = SS,
    case nquic_frame_handler:is_locally_initiated(StreamID, Role) of
        true ->
            not maps:is_key(StreamID, Streams) andalso
                case nquic_stream_manager:type(StreamID) of
                    bidi -> StreamID < NextBidi;
                    uni -> StreamID < NextUni
                end;
        false ->
            case nquic_stream_manager:type(StreamID) of
                bidi -> StreamID =< BidiWm orelse maps:is_key(StreamID, Closed);
                uni -> StreamID =< UniWm orelse maps:is_key(StreamID, Closed)
            end
    end.

-spec is_recv_done(#stream_state{}) -> boolean().
is_recv_done(#stream_state{recv_state = data_read}) -> true;
is_recv_done(#stream_state{recv_state = reset_recvd}) -> true;
is_recv_done(#stream_state{recv_state = reset_read}) -> true;
is_recv_done(#stream_state{recv_state = size_known, app_buffer_size = 0}) -> true;
is_recv_done(_) -> false.

-spec is_send_done(atom()) -> boolean().
is_send_done(data_sent) -> true;
is_send_done(data_recvd) -> true;
is_send_done(reset_sent) -> true;
is_send_done(reset_recvd) -> true;
is_send_done(_) -> false.

-spec is_stream_terminal(nquic:stream_id(), client | server | undefined, #stream_state{}) ->
    boolean().
is_stream_terminal(StreamID, Role, #stream_state{type = uni, send_state = SS} = Stream) ->
    case nquic_frame_handler:is_locally_initiated(StreamID, Role) of
        true -> is_send_done(SS);
        false -> is_recv_done(Stream)
    end;
is_stream_terminal(_StreamID, _Role, #stream_state{send_state = SS} = Stream) ->
    is_send_done(SS) andalso is_recv_done(Stream).

-spec maybe_auto_extend_max_streams(bidi | uni, nquic_protocol:state()) -> nquic_protocol:state().
maybe_auto_extend_max_streams(bidi, State) ->
    SS0 = State#conn_state.streams_state,
    Consumed = peer_consumed_bidi_streams(State),
    Current = SS0#conn_streams.local_max_streams_bidi,
    case Consumed * 4 >= Current * 3 of
        true ->
            NewLimit = Current * 2,
            NewSS1 = SS0#conn_streams{local_max_streams_bidi = NewLimit},
            State1 = State#conn_state{streams_state = NewSS1},
            Frame = #max_streams{max_streams = NewLimit, is_uni = false},
            {ok, State2} = nquic_protocol_send_queues:queue_app_frame(Frame, State1),
            SS2 = (State2#conn_state.streams_state)#conn_streams{
                last_sent_max_streams_bidi = NewLimit
            },
            State2#conn_state{streams_state = SS2};
        false ->
            State
    end;
maybe_auto_extend_max_streams(uni, State) ->
    SS0 = State#conn_state.streams_state,
    Consumed = peer_consumed_uni_streams(State),
    Current = SS0#conn_streams.local_max_streams_uni,
    case Consumed * 4 >= Current * 3 of
        true ->
            NewLimit = Current * 2,
            NewSS1 = SS0#conn_streams{local_max_streams_uni = NewLimit},
            State1 = State#conn_state{streams_state = NewSS1},
            Frame = #max_streams{max_streams = NewLimit, is_uni = true},
            {ok, State2} = nquic_protocol_send_queues:queue_app_frame(Frame, State1),
            SS2 = (State2#conn_state.streams_state)#conn_streams{
                last_sent_max_streams_uni = NewLimit
            },
            State2#conn_state{streams_state = SS2};
        false ->
            State
    end.

-spec maybe_cleanup_stream(nquic:stream_id(), nquic_protocol:state()) -> nquic_protocol:state().
maybe_cleanup_stream(StreamID, State) ->
    #conn_state{streams_state = #conn_streams{streams = Streams}, role = Role} = State,
    case maps:find(StreamID, Streams) of
        {ok, Stream} ->
            case is_stream_terminal(StreamID, Role, Stream) of
                true -> cleanup_stream(StreamID, State);
                false -> State
            end;
        error ->
            State
    end.

-spec maybe_cleanup_stream(nquic:stream_id(), #stream_state{}, nquic_protocol:state()) ->
    nquic_protocol:state().
maybe_cleanup_stream(StreamID, Stream, State) ->
    case is_stream_terminal(StreamID, State#conn_state.role, Stream) of
        true -> cleanup_stream(StreamID, State);
        false -> State
    end.

-spec maybe_send_max_streams(bidi | uni, nquic_protocol:state()) -> nquic_protocol:state().
maybe_send_max_streams(bidi, State) ->
    SS0 = State#conn_state.streams_state,
    Current = SS0#conn_streams.local_max_streams_bidi,
    LastSent = SS0#conn_streams.last_sent_max_streams_bidi,
    PeerConsumed = peer_consumed_bidi_streams(State),
    Remaining = LastSent - PeerConsumed,
    Threshold = max(1, LastSent div 2),
    case Remaining =< Threshold of
        true ->
            Frame = #max_streams{max_streams = Current, is_uni = false},
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
            SS1 = (State1#conn_state.streams_state)#conn_streams{
                last_sent_max_streams_bidi = Current
            },
            State1#conn_state{streams_state = SS1};
        false ->
            State
    end;
maybe_send_max_streams(uni, State) ->
    SS0 = State#conn_state.streams_state,
    Current = SS0#conn_streams.local_max_streams_uni,
    LastSent = SS0#conn_streams.last_sent_max_streams_uni,
    PeerConsumed = peer_consumed_uni_streams(State),
    Remaining = LastSent - PeerConsumed,
    Threshold = max(1, LastSent div 2),
    case Remaining =< Threshold of
        true ->
            Frame = #max_streams{max_streams = Current, is_uni = true},
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
            SS1 = (State1#conn_state.streams_state)#conn_streams{
                last_sent_max_streams_uni = Current
            },
            State1#conn_state{streams_state = SS1};
        false ->
            State
    end.

-spec peer_consumed_bidi_streams(nquic_protocol:state()) -> non_neg_integer().
peer_consumed_bidi_streams(
    #conn_state{streams_state = #conn_streams{opened_peer_bidi_count = N}}
) ->
    N.

-spec peer_consumed_uni_streams(nquic_protocol:state()) -> non_neg_integer().
peer_consumed_uni_streams(
    #conn_state{streams_state = #conn_streams{opened_peer_uni_count = N}}
) ->
    N.

-spec record_peer_closed(nquic:stream_id(), nquic_protocol:state()) -> nquic_protocol:state().
record_peer_closed(StreamID, State) ->
    SS0 = State#conn_state.streams_state,
    Type = nquic_stream_manager:type(StreamID),
    Wm =
        case Type of
            bidi -> SS0#conn_streams.closed_peer_bidi_wm;
            uni -> SS0#conn_streams.closed_peer_uni_wm
        end,
    InOrder =
        case Wm of
            -1 ->
                FirstID = nquic_stream_manager:first_peer_stream_id(
                    State#conn_state.role, Type
                ),
                StreamID =:= FirstID;
            _ ->
                StreamID =:= Wm + 4
        end,
    case InOrder of
        true ->
            advance_peer_wm(Type, StreamID, State);
        false ->
            Closed = SS0#conn_streams.closed_peer_streams,
            NewSS = SS0#conn_streams{closed_peer_streams = Closed#{StreamID => true}},
            State#conn_state{streams_state = NewSS}
    end.

-spec set_peer_wm(bidi | uni, nquic:stream_id(), nquic_protocol:state()) -> nquic_protocol:state().
set_peer_wm(bidi, ID, State) ->
    SS0 = State#conn_state.streams_state,
    State#conn_state{streams_state = SS0#conn_streams{closed_peer_bidi_wm = ID}};
set_peer_wm(uni, ID, State) ->
    SS0 = State#conn_state.streams_state,
    State#conn_state{streams_state = SS0#conn_streams{closed_peer_uni_wm = ID}}.
