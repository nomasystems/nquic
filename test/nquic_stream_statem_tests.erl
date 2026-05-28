-module(nquic_stream_statem_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
simple_recv_test() ->
    State = nquic_stream_statem:new(0, bidi),

    Frame = #stream{offset = 0, data = <<"hello">>, fin = false},
    {ok, NewState} = nquic_stream_statem:handle_recv(State, Frame),

    ?assertEqual(5, NewState#stream_state.recv_offset),
    ?assertEqual(recv, NewState#stream_state.recv_state).

out_of_order_test() ->
    State = nquic_stream_statem:new(0, bidi),

    Frame1 = #stream{offset = 5, data = <<"world">>, fin = false},
    {ok, State1} = nquic_stream_statem:handle_recv(State, Frame1),

    ?assertEqual(0, State1#stream_state.recv_offset),
    ?assertEqual(1, gb_trees:size(State1#stream_state.recv_buffer)),

    Frame2 = #stream{offset = 0, data = <<"hello">>, fin = false},
    {ok, State2} = nquic_stream_statem:handle_recv(State1, Frame2),

    ?assertEqual(10, State2#stream_state.recv_offset),
    ?assertEqual(0, gb_trees:size(State2#stream_state.recv_buffer)).

overlap_test() ->
    State = nquic_stream_statem:new(0, bidi),

    Frame1 = #stream{offset = 0, data = <<"0123456789">>, fin = false},
    {ok, State1} = nquic_stream_statem:handle_recv(State, Frame1),
    ?assertEqual(10, State1#stream_state.recv_offset),

    Frame2 = #stream{offset = 5, data = <<"56789abcde">>, fin = false},
    {ok, State2} = nquic_stream_statem:handle_recv(State1, Frame2),

    ?assertEqual(15, State2#stream_state.recv_offset).

gap_overlap_test() ->
    State = nquic_stream_statem:new(0, bidi),

    Frame1 = #stream{offset = 10, data = <<"abcdefghij">>, fin = false},
    {ok, State1} = nquic_stream_statem:handle_recv(State, Frame1),

    Frame2 = #stream{offset = 0, data = <<"0123456789abcde">>, fin = false},
    {ok, State2} = nquic_stream_statem:handle_recv(State1, Frame2),

    ?assertEqual(20, State2#stream_state.recv_offset).

fin_test() ->
    State = nquic_stream_statem:new(0, bidi),

    Frame1 = #stream{offset = 5, data = <<"end">>, fin = true},
    {ok, State1} = nquic_stream_statem:handle_recv(State, Frame1),

    Frame2 = #stream{offset = 0, data = <<"start">>, fin = false},
    {ok, State2} = nquic_stream_statem:handle_recv(State1, Frame2),

    ?assertEqual(8, State2#stream_state.recv_offset),
    ?assertEqual(size_known, State2#stream_state.recv_state).
