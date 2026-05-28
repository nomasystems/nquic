-module(nquic_flow_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("nquic/src/nquic_conn.hrl").
-include_lib("nquic/src/nquic_frame.hrl").
-include_lib("nquic/src/nquic_transport.hrl").
init_stream_limits_test() ->
    Local = #transport_params{
        initial_max_stream_data_bidi_local = 1000,
        initial_max_stream_data_bidi_remote = 2000,
        initial_max_stream_data_uni = 3000
    },
    Remote = #transport_params{
        initial_max_stream_data_bidi_local = 4000,
        initial_max_stream_data_bidi_remote = 5000,
        initial_max_stream_data_uni = 6000
    },
    ConnState = #conn_state{
        local_params = Local,
        remote_params = Remote,
        role = client
    },

    S0 = #stream_state{stream_id = 0},
    S0_Init = nquic_flow:init_stream_limits(S0, ConnState, bidi),
    ?assertEqual(5000, S0_Init#stream_state.send_max_data),
    ?assertEqual(1000, S0_Init#stream_state.recv_window),

    S1 = #stream_state{stream_id = 1},
    S1_Init = nquic_flow:init_stream_limits(S1, ConnState, bidi),
    ?assertEqual(4000, S1_Init#stream_state.send_max_data),
    ?assertEqual(2000, S1_Init#stream_state.recv_window).

recv_data_test() ->
    ConnState = #conn_state{
        flow = #conn_flow{data_received = 0, local_max_data = 1000000}
    },
    StreamState = #stream_state{stream_id = 0, recv_max_offset = 0, recv_window = 1000000},

    {ok, C1, S1} = nquic_flow:on_stream_data_received(ConnState, StreamState, 0, 100),
    ?assertEqual(100, (C1#conn_state.flow)#conn_flow.data_received),
    ?assertEqual(100, S1#stream_state.recv_max_offset),

    {ok, C2, S2} = nquic_flow:on_stream_data_received(C1, S1, 50, 100),
    ?assertEqual(150, (C2#conn_state.flow)#conn_flow.data_received),
    ?assertEqual(150, S2#stream_state.recv_max_offset).

window_update_test() ->
    Window = 1000,
    _Threshold = 500,

    ConnState = #conn_state{
        flow = #conn_flow{local_max_data = 1000, data_received = 400}
    },
    ?assertEqual(false, nquic_flow:maybe_update_conn_window(ConnState, Window)),

    Flow0 = ConnState#conn_state.flow,
    ConnState2 = ConnState#conn_state{flow = Flow0#conn_flow{data_received = 600}},
    {ok, NewConn, Frame} = nquic_flow:maybe_update_conn_window(ConnState2, Window),
    ?assertEqual(2600, (NewConn#conn_state.flow)#conn_flow.local_max_data),
    ?assertMatch(#max_data{max_data = 2600}, Frame).
