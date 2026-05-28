-module(nquic_flow).

-moduledoc """
Connection and stream flow control per RFC 9000 Section 4.

Enforces data limits at both connection and stream levels. Tracks the highest
byte offset seen (`recv_max_offset`) separately from contiguous bytes delivered
to the application (`recv_offset`). Generates MAX_DATA and MAX_STREAM_DATA
frames when the available window drops below half the configured size.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
-export([
    check_conn_send/2,
    check_stream_send/2,
    init_conn_limits/1,
    init_stream_limits/3,
    maybe_update_conn_window/2,
    maybe_update_stream_window/2,
    on_stream_data_received/4,
    on_stream_data_sent/3
]).

-define(WINDOW_UPDATE_THRESHOLD_DIV, 2).

%%%-----------------------------------------------------------------------------
%% CONNECTION FLOW CONTROL
%%%-----------------------------------------------------------------------------
-doc "Check if connection-level flow control allows sending the given number of bytes.".
-spec check_conn_send(#conn_state{}, non_neg_integer()) ->
    ok | {blocked, non_neg_integer()}.
check_conn_send(ConnState, Length) ->
    #conn_state{flow = #conn_flow{data_sent = Sent, remote_max_data = Max}} = ConnState,

    if
        Sent + Length =< Max -> ok;
        true -> {blocked, Max}
    end.

-doc "Initialize connection-level send and receive limits from transport parameters.".
-spec init_conn_limits(#conn_state{}) -> #conn_state{}.
init_conn_limits(ConnState) ->
    #conn_state{
        local_params = Local,
        remote_params = Remote
    } = ConnState,

    RemoteMaxData =
        case Remote of
            undefined -> 0;
            #transport_params{initial_max_data = RMD} -> RMD
        end,

    {PeerMaxBidi, PeerMaxUni} =
        case Remote of
            undefined ->
                {0, 0};
            _ ->
                {
                    Remote#transport_params.initial_max_streams_bidi,
                    Remote#transport_params.initial_max_streams_uni
                }
        end,

    #conn_state{flow = Flow, streams_state = SS} = ConnState,
    NewFlow = Flow#conn_flow{
        local_max_data = Local#transport_params.initial_max_data,
        remote_max_data = RemoteMaxData,
        data_sent = 0,
        data_received = 0
    },
    NewSS = SS#conn_streams{
        peer_max_streams_bidi = PeerMaxBidi,
        peer_max_streams_uni = PeerMaxUni,
        local_max_streams_bidi = Local#transport_params.initial_max_streams_bidi,
        local_max_streams_uni = Local#transport_params.initial_max_streams_uni,
        last_sent_max_streams_bidi = Local#transport_params.initial_max_streams_bidi,
        last_sent_max_streams_uni = Local#transport_params.initial_max_streams_uni
    },
    ConnState#conn_state{flow = NewFlow, streams_state = NewSS}.

-doc "Generate a MAX_DATA frame if the connection receive window is below half the target size.".
-spec maybe_update_conn_window(#conn_state{}, pos_integer()) ->
    {ok, #conn_state{}, nquic_frame:t()} | false.
maybe_update_conn_window(ConnState, WindowSize) ->
    #conn_state{flow = Flow} = ConnState,
    #conn_flow{local_max_data = MaxData, data_received = Received} = Flow,

    Available = MaxData - Received,
    Threshold = WindowSize div ?WINDOW_UPDATE_THRESHOLD_DIV,

    if
        Available < Threshold ->
            NewMaxData = Received + WindowSize * 2,
            NewFlow = Flow#conn_flow{local_max_data = NewMaxData},
            NewConnState = ConnState#conn_state{flow = NewFlow},
            Frame = #max_data{max_data = NewMaxData},
            {ok, NewConnState, Frame};
        true ->
            false
    end.

%%%-----------------------------------------------------------------------------
%% STREAM FLOW CONTROL
%%%-----------------------------------------------------------------------------
-doc "Check if stream-level flow control allows sending the given number of bytes.".
-spec check_stream_send(#stream_state{}, non_neg_integer()) ->
    ok | {blocked, non_neg_integer()}.
check_stream_send(StreamState, Length) ->
    #stream_state{
        send_offset = Off,
        send_max_data = Max
    } = StreamState,

    if
        Off + Length =< Max -> ok;
        true -> {blocked, Max}
    end.

-doc "Initialize stream-level send and receive limits based on stream type and transport parameters.".
-spec init_stream_limits(#stream_state{}, #conn_state{}, bidi | uni) -> #stream_state{}.
init_stream_limits(StreamState, ConnState, Type) ->
    #conn_state{
        local_params = Local,
        remote_params = Remote,
        role = Role
    } = ConnState,

    SendMax =
        case Remote of
            undefined ->
                0;
            _ ->
                IsLocalInitiated = nquic_frame_handler:is_locally_initiated(
                    StreamState#stream_state.stream_id, Role
                ),

                case {Type, IsLocalInitiated} of
                    {bidi, true} ->
                        Remote#transport_params.initial_max_stream_data_bidi_remote;
                    {bidi, false} ->
                        Remote#transport_params.initial_max_stream_data_bidi_local;
                    {uni, _} ->
                        Remote#transport_params.initial_max_stream_data_uni
                end
        end,

    RecvWindow =
        case
            {Type,
                nquic_frame_handler:is_locally_initiated(StreamState#stream_state.stream_id, Role)}
        of
            {bidi, true} -> Local#transport_params.initial_max_stream_data_bidi_local;
            {bidi, false} -> Local#transport_params.initial_max_stream_data_bidi_remote;
            {uni, _} -> Local#transport_params.initial_max_stream_data_uni
        end,

    StreamState#stream_state{
        send_max_data = SendMax,
        recv_window = RecvWindow
    }.

-doc "Generate a MAX_STREAM_DATA frame if the stream receive window is below half the target size.".
-spec maybe_update_stream_window(#stream_state{}, pos_integer()) ->
    {ok, #stream_state{}, nquic_frame:t()} | false.
maybe_update_stream_window(StreamState, WindowSize) ->
    #stream_state{
        recv_window = MaxData,
        recv_max_offset = Received,
        stream_id = ID
    } = StreamState,

    Available = MaxData - Received,
    Threshold = WindowSize div ?WINDOW_UPDATE_THRESHOLD_DIV,

    if
        Available < Threshold ->
            NewMaxData = Received + WindowSize * 2,
            NewStreamState = StreamState#stream_state{recv_window = NewMaxData},
            Frame = #max_stream_data{stream_id = ID, max_stream_data = NewMaxData},
            {ok, NewStreamState, Frame};
        true ->
            false
    end.

-doc "Update receive offsets after receiving data, returning an error if limits are exceeded.".
-spec on_stream_data_received(#conn_state{}, #stream_state{}, non_neg_integer(), non_neg_integer()) ->
    {ok, #conn_state{}, #stream_state{}} | {error, flow_control_error}.
on_stream_data_received(ConnState, StreamState, Offset, Length) ->
    NewRecvMaxOffset = max(StreamState#stream_state.recv_max_offset, Offset + Length),

    StreamLimit = StreamState#stream_state.recv_window,
    if
        NewRecvMaxOffset > StreamLimit ->
            {error, flow_control_error};
        true ->
            OldStreamMax = StreamState#stream_state.recv_max_offset,
            Increase = max(0, NewRecvMaxOffset - OldStreamMax),

            #conn_state{flow = Flow} = ConnState,
            #conn_flow{data_received = TotalReceived, local_max_data = ConnLimit} = Flow,
            NewTotalReceived = TotalReceived + Increase,

            if
                NewTotalReceived > ConnLimit ->
                    {error, flow_control_error};
                true ->
                    NewFlow = Flow#conn_flow{data_received = NewTotalReceived},
                    ConnState1 = ConnState#conn_state{flow = NewFlow},

                    StreamState1 = StreamState#stream_state{
                        recv_max_offset = NewRecvMaxOffset
                    },

                    {ok, ConnState1, StreamState1}
            end
    end.

-doc "Update connection and stream send offsets after sending data on a stream.".
-spec on_stream_data_sent(#conn_state{}, nquic:stream_id(), non_neg_integer()) -> #conn_state{}.
on_stream_data_sent(ConnState, StreamID, Length) ->
    #conn_state{flow = Flow, streams_state = SS} = ConnState,
    #conn_flow{data_sent = Sent} = Flow,
    #conn_streams{streams = Streams} = SS,

    Streams1 =
        case maps:get(StreamID, Streams, undefined) of
            undefined ->
                Streams;
            S ->
                S1 = S#stream_state{send_offset = S#stream_state.send_offset + Length},
                Streams#{StreamID => S1}
        end,

    NewFlow = Flow#conn_flow{data_sent = Sent + Length},
    NewSS = SS#conn_streams{streams = Streams1},
    ConnState#conn_state{flow = NewFlow, streams_state = NewSS}.
