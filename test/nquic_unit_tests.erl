%%%-------------------------------------------------------------------
%%% @doc Unit tests for nquic modules
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_unit_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_loss.hrl").
-include("nquic_packet.hrl").
-include("nquic_transport.hrl").
cid_generate_default_test() ->
    CID = nquic_keys:generate_connection_id(),
    ?assertEqual(8, byte_size(CID)),
    ?assert(is_binary(CID)).

cid_generate_custom_length_test() ->
    CID1 = nquic_keys:generate_connection_id(1),
    ?assertEqual(1, byte_size(CID1)),

    CID20 = nquic_keys:generate_connection_id(20),
    ?assertEqual(20, byte_size(CID20)),

    CID10 = nquic_keys:generate_connection_id(10),
    ?assertEqual(10, byte_size(CID10)).

cid_generate_uniqueness_test() ->
    CIDs = [nquic_keys:generate_connection_id() || _ <- lists:seq(1, 100)],
    UniqueCIDs = lists:usort(CIDs),
    ?assertEqual(length(CIDs), length(UniqueCIDs)).

stream_type_test() ->
    ?assertEqual(bidi, nquic_stream_manager:type(0)),
    ?assertEqual(bidi, nquic_stream_manager:type(1)),
    ?assertEqual(uni, nquic_stream_manager:type(2)),
    ?assertEqual(uni, nquic_stream_manager:type(3)),
    ?assertEqual(bidi, nquic_stream_manager:type(4)),
    ?assertEqual(bidi, nquic_stream_manager:type(5)),
    ?assertEqual(uni, nquic_stream_manager:type(6)),
    ?assertEqual(uni, nquic_stream_manager:type(7)).

stream_is_local_initiated_test() ->
    ?assert(nquic_frame_handler:is_locally_initiated(0, client)),
    ?assertNot(nquic_frame_handler:is_locally_initiated(1, client)),
    ?assert(nquic_frame_handler:is_locally_initiated(2, client)),
    ?assertNot(nquic_frame_handler:is_locally_initiated(3, client)),

    ?assertNot(nquic_frame_handler:is_locally_initiated(0, server)),
    ?assert(nquic_frame_handler:is_locally_initiated(1, server)),
    ?assertNot(nquic_frame_handler:is_locally_initiated(2, server)),
    ?assert(nquic_frame_handler:is_locally_initiated(3, server)).

stream_get_or_create_new_test() ->
    Streams = #{},
    {ok, State, NewStreams} = nquic_stream_manager:get_or_create(0, Streams, client),
    ?assertEqual(0, State#stream_state.stream_id),
    ?assertEqual(bidi, State#stream_state.type),
    ?assert(maps:is_key(0, NewStreams)).

stream_get_or_create_existing_test() ->
    State = nquic_stream_statem:new(0, bidi),
    Streams = #{0 => State},
    {ok, RetState, Streams} = nquic_stream_manager:get_or_create(0, Streams, client),
    ?assertEqual(State, RetState).

stream_limit_check_test() ->
    Streams = #{},
    Limits = #{max_bidi => 2, max_uni => 2},

    {ok, _, S1} = nquic_stream_manager:get_or_create(0, Streams, server, Limits),
    {ok, _, _S2} = nquic_stream_manager:get_or_create(4, S1, server, Limits),

    ?assertMatch(
        {error, stream_limit_error},
        nquic_stream_manager:get_or_create(8, Streams, server, Limits)
    ).

stream_invalid_id_test() ->
    Streams = #{},
    LargeID = 16#4000000000000000,
    ?assertMatch(
        {error, invalid_stream_id},
        nquic_stream_manager:get_or_create(LargeID, Streams, client)
    ).

cc_new_test() ->
    {Mod, State} = nquic_cc:new(newreno),
    ?assertEqual(nquic_cc_newreno, Mod),
    ?assertEqual(12000, nquic_cc:get_cwnd({Mod, State})).

cc_new_cubic_test() ->
    {Mod, State} = nquic_cc:new(cubic),
    ?assertEqual(nquic_cc_cubic, Mod),
    ?assertEqual(12000, nquic_cc:get_cwnd({Mod, State})).

cc_unknown_algorithm_test() ->
    {Mod, _State} = nquic_cc:new(unknown),
    ?assertEqual(nquic_cc_cubic, Mod).

cc_on_packet_sent_test() ->
    CC = nquic_cc:new(newreno),
    CC1 = nquic_cc:on_packet_sent(CC, 1000, 0),
    ?assertEqual(12000, nquic_cc:get_cwnd(CC1)).

cc_on_packet_acked_slow_start_test() ->
    CC = nquic_cc:new(newreno),
    Packet = #sent_packet{
        packet_number = 1,
        time_sent = os:system_time(microsecond) - 100000,
        size = 1000,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    CC1 = nquic_cc:on_packet_acked(CC, Packet, 1000, #{}),
    ?assertEqual(13000, nquic_cc:get_cwnd(CC1)).

cc_on_congestion_event_test() ->
    CC = nquic_cc:new(newreno),
    CC1 = nquic_cc:on_congestion_event(CC, 1000, 5000, 1),
    NewCwnd = nquic_cc:get_cwnd(CC1),
    ?assertEqual(6000, NewCwnd),
    ?assertEqual(6000, nquic_cc:get_ssthresh(CC1)).

cc_minimum_cwnd_test() ->
    CC = nquic_cc:new(newreno),
    Now = os:system_time(microsecond),

    CC1 = nquic_cc:on_congestion_event(CC, 1000, 5000, Now + 1000000),
    CC2 = nquic_cc:on_congestion_event(CC1, 1000, 3000, Now + 2000000),
    CC3 = nquic_cc:on_congestion_event(CC2, 1000, 1500, Now + 3000000),
    ?assertEqual(2400, nquic_cc:get_cwnd(CC3)).

varint_size_test() ->
    ?assertEqual(1, nquic_varint:size(0)),
    ?assertEqual(1, nquic_varint:size(63)),
    ?assertEqual(2, nquic_varint:size(64)),
    ?assertEqual(2, nquic_varint:size(16383)),
    ?assertEqual(4, nquic_varint:size(16384)),
    ?assertEqual(4, nquic_varint:size(1073741823)),
    ?assertEqual(8, nquic_varint:size(1073741824)),
    ?assertEqual(8, nquic_varint:size(4611686018427387903)).

varint_decode_with_rest_test() ->
    Encoded = nquic_varint:encode(100),
    Trailing = <<1, 2, 3>>,
    Combined = <<Encoded/binary, Trailing/binary>>,
    {ok, 100, Rest} = nquic_varint:decode(Combined),
    ?assertEqual(Trailing, Rest).

varint_boundary_values_test() ->
    Boundaries = [0, 63, 64, 16383, 16384, 1073741823, 1073741824],
    lists:foreach(
        fun(V) ->
            Encoded = nquic_varint:encode(V),
            {ok, Decoded, <<>>} = nquic_varint:decode(Encoded),
            ?assertEqual(V, Decoded)
        end,
        Boundaries
    ).

pn_encode_small_delta_test() ->
    {1, _} = nquic_packet_number:encode(100, 99),
    {1, _} = nquic_packet_number:encode(100, 50).

pn_encode_large_delta_test() ->
    {2, _} = nquic_packet_number:encode(200, 0),
    {3, _} = nquic_packet_number:encode(50000, 0),
    {4, _} = nquic_packet_number:encode(10000000, 0).

pn_decode_roundtrip_all_sizes_test() ->
    TestCases = [
        {100, 99},
        {300, 100},
        {50000, 100},
        {20000000, 0}
    ],
    lists:foreach(
        fun({PN, Largest}) ->
            {Len, Trunc} = nquic_packet_number:encode(PN, Largest),
            Decoded = nquic_packet_number:decode(Largest, Trunc, Len),
            ?assertEqual(PN, Decoded)
        end,
        TestCases
    ).

frame_reset_stream_test() ->
    Frame = #reset_stream{stream_id = 4, app_error_code = 1, final_size = 1000},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_stop_sending_test() ->
    Frame = #stop_sending{stream_id = 8, app_error_code = 2},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_max_data_test() ->
    Frame = #max_data{max_data = 1000000},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_max_stream_data_test() ->
    Frame = #max_stream_data{stream_id = 4, max_stream_data = 500000},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_max_streams_bidi_test() ->
    Frame = #max_streams{max_streams = 100, is_uni = false},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_max_streams_uni_test() ->
    Frame = #max_streams{max_streams = 50, is_uni = true},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_data_blocked_test() ->
    Frame = #data_blocked{limit = 1000000},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_stream_data_blocked_test() ->
    Frame = #stream_data_blocked{stream_id = 4, limit = 50000},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_streams_blocked_bidi_test() ->
    Frame = #streams_blocked{limit = 100, is_uni = false},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_streams_blocked_uni_test() ->
    Frame = #streams_blocked{limit = 50, is_uni = true},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_new_connection_id_test() ->
    Frame = #new_connection_id{
        seq_num = 1,
        retire_prior_to = 0,
        cid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        stateless_reset_token = crypto:strong_rand_bytes(16)
    },
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_retire_connection_id_test() ->
    Frame = #retire_connection_id{seq_num = 5},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_path_challenge_test() ->
    Data = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Frame = #path_challenge{data = Data},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_path_response_test() ->
    Data = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    Frame = #path_response{data = Data},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_connection_close_app_test() ->
    Frame = #connection_close{
        error_code = 0,
        frame_type = 0,
        reason_phrase = <<"bye">>,
        is_application = true
    },
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_new_token_test() ->
    Token = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>,
    Frame = #new_token{token = Token},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_ack_no_ecn_test() ->
    Frame = #ack{
        largest_acknowledged = 10,
        delay = 5,
        first_ack_range = 3,
        ack_ranges = [],
        ecn_counts = undefined
    },
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_stream_no_offset_test() ->
    Frame = #stream{stream_id = 0, offset = 0, length = 5, data = <<"hello">>, fin = false},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

frame_unknown_type_test() ->
    ?assertMatch({error, frame_encoding_error}, nquic_frame:decode(<<99>>)).

stream_statem_send_test() ->
    State = nquic_stream_statem:new(0, bidi),
    Data = <<"test data">>,
    {ok, State1} = nquic_stream_statem:handle_send(State, Data, false),
    ?assertEqual(9, State1#stream_state.send_offset),
    ?assertEqual(send, State1#stream_state.send_state),
    ?assertEqual(Data, iolist_to_binary(State1#stream_state.pending_send_data)),
    ?assertEqual(byte_size(Data), State1#stream_state.pending_send_size),
    ?assertNot(State1#stream_state.pending_send_fin).

stream_statem_send_with_fin_test() ->
    State = nquic_stream_statem:new(0, bidi),
    Data = <<"final">>,
    {ok, State1} = nquic_stream_statem:handle_send(State, Data, true),
    ?assertEqual(send, State1#stream_state.send_state),
    ?assertEqual(Data, iolist_to_binary(State1#stream_state.pending_send_data)),
    ?assertEqual(byte_size(Data), State1#stream_state.pending_send_size),
    ?assert(State1#stream_state.pending_send_fin).

stream_statem_send_closed_test() ->
    State = #stream_state{stream_id = 0, type = bidi, send_state = fin_sent},
    ?assertMatch({error, stream_closed}, nquic_stream_statem:handle_send(State, <<"data">>, false)).

stream_statem_recv_contiguous_test() ->
    State = nquic_stream_statem:new(0, bidi),
    Frame1 = #stream{offset = 0, data = <<"hello">>, fin = false},
    {ok, State1} = nquic_stream_statem:handle_recv(State, Frame1),
    ?assertEqual(5, State1#stream_state.recv_offset),

    Frame2 = #stream{offset = 5, data = <<" world">>, fin = false},
    {ok, State2} = nquic_stream_statem:handle_recv(State1, Frame2),
    ?assertEqual(11, State2#stream_state.recv_offset).

stream_statem_final_size_error_test() ->
    State = #stream_state{
        stream_id = 0,
        type = bidi,
        recv_state = size_known,
        recv_offset = 10,
        recv_buffer = gb_trees:empty(),
        app_buffer = []
    },
    Frame = #stream{offset = 5, data = <<"exceeds final size">>, fin = false},
    ?assertMatch({error, final_size_error}, nquic_stream_statem:handle_recv(State, Frame)).

flow_check_conn_send_ok_test() ->
    ConnState = #conn_state{flow = #conn_flow{data_sent = 1000, remote_max_data = 10000}},
    ?assertEqual(ok, nquic_flow:check_conn_send(ConnState, 5000)).

flow_check_conn_send_blocked_test() ->
    ConnState = #conn_state{flow = #conn_flow{data_sent = 9000, remote_max_data = 10000}},
    ?assertMatch({blocked, 10000}, nquic_flow:check_conn_send(ConnState, 5000)).

flow_check_stream_send_ok_test() ->
    StreamState = #stream_state{send_offset = 100, send_max_data = 1000},
    ?assertEqual(ok, nquic_flow:check_stream_send(StreamState, 500)).

flow_check_stream_send_blocked_test() ->
    StreamState = #stream_state{send_offset = 900, send_max_data = 1000},
    ?assertMatch({blocked, 1000}, nquic_flow:check_stream_send(StreamState, 500)).

flow_on_stream_data_sent_test() ->
    StreamState = #stream_state{stream_id = 0, send_offset = 0},
    ConnState = #conn_state{
        flow = #conn_flow{data_sent = 0},
        streams_state = #conn_streams{streams = #{0 => StreamState}}
    },
    ConnState1 = nquic_flow:on_stream_data_sent(ConnState, 0, 100),
    ?assertEqual(100, (ConnState1#conn_state.flow)#conn_flow.data_sent).

flow_stream_window_update_test() ->
    StreamState = #stream_state{stream_id = 4, recv_window = 1000, recv_max_offset = 900},
    {ok, NewState, Frame} = nquic_flow:maybe_update_stream_window(StreamState, 1000),
    ?assertEqual(2900, NewState#stream_state.recv_window),
    ?assertMatch(#max_stream_data{stream_id = 4, max_stream_data = 2900}, Frame).

flow_stream_window_no_update_test() ->
    StreamState = #stream_state{stream_id = 4, recv_window = 1000, recv_max_offset = 100},
    ?assertEqual(false, nquic_flow:maybe_update_stream_window(StreamState, 1000)).

loss_get_cwnd_test() ->
    State = nquic_loss:init(),
    Cwnd = nquic_loss:get_cwnd(State),
    ?assertEqual(12000, Cwnd).

loss_get_bytes_in_flight_test() ->
    State = nquic_loss:init(),
    ?assertEqual(0, nquic_loss:get_bytes_in_flight(State)).

loss_get_timer_empty_test() ->
    State = nquic_loss:init(),
    ?assertEqual(undefined, nquic_loss:get_loss_timer(State)).

loss_detect_no_loss_test() ->
    State = nquic_loss:init(),
    Now = os:system_time(microsecond),
    {ok, State1, Lost} = nquic_loss:detect_loss(State, application, Now),
    ?assertEqual([], Lost),
    ?assertEqual(State, State1).

dispatch_register_lookup_test() ->
    D = nquic_dispatch:new(4),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Pid = self(),

    true = nquic_listener:dispatch_register(D, DCID, Pid),
    ?assertEqual(Pid, nquic_listener:dispatch_lookup(D, DCID)),

    nquic_dispatch:destroy(D).

dispatch_lookup_not_found_test() ->
    D = nquic_dispatch:new(4),
    DCID = <<1, 2, 3, 4>>,
    ?assertEqual(undefined, nquic_listener:dispatch_lookup(D, DCID)),
    nquic_dispatch:destroy(D).

dispatch_unregister_test() ->
    D = nquic_dispatch:new(4),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Pid = self(),

    true = nquic_listener:dispatch_register(D, DCID, Pid),
    ?assertEqual(Pid, nquic_listener:dispatch_lookup(D, DCID)),

    true = nquic_listener:dispatch_unregister(D, DCID),
    ?assertEqual(undefined, nquic_listener:dispatch_lookup(D, DCID)),

    nquic_dispatch:destroy(D).

dispatch_multiple_connections_test() ->
    D = nquic_dispatch:new(4),
    DCID1 = <<1, 1, 1, 1>>,
    DCID2 = <<2, 2, 2, 2>>,
    DCID3 = <<3, 3, 3, 3>>,

    nquic_listener:dispatch_register(D, DCID1, self()),
    nquic_listener:dispatch_register(D, DCID2, self()),
    nquic_listener:dispatch_register(D, DCID3, self()),

    ?assertEqual(self(), nquic_listener:dispatch_lookup(D, DCID1)),
    ?assertEqual(self(), nquic_listener:dispatch_lookup(D, DCID2)),
    ?assertEqual(self(), nquic_listener:dispatch_lookup(D, DCID3)),

    nquic_dispatch:destroy(D).

cc_newreno_init_test() ->
    State = nquic_cc_newreno:init(),
    ?assertEqual(12000, nquic_cc_newreno:get_cwnd(State)),
    ?assertEqual(16#FFFFFFFFFFFFFFFF, nquic_cc_newreno:get_ssthresh(State)).

cc_newreno_congestion_avoidance_test() ->
    CC = nquic_cc:new(newreno),

    CC1 = nquic_cc:on_congestion_event(CC, 1000, 5000, 1),

    Packet = #sent_packet{
        packet_number = 1,
        time_sent = os:system_time(microsecond) + 1000000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    CC2 = nquic_cc:on_packet_acked(CC1, Packet, 0, #{}),
    ?assertEqual(6240, nquic_cc:get_cwnd(CC2)).

cc_newreno_recovery_filter_test() ->
    CC = nquic_cc:new(newreno),
    Now = erlang:monotonic_time(microsecond),
    CC1 = nquic_cc:on_congestion_event(CC, 1000, 5000, Now),

    Packet = #sent_packet{
        packet_number = 1,
        time_sent = Now - 1000000,
        size = 1000,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    CC2 = nquic_cc:on_packet_acked(CC1, Packet, 0, #{}),
    ?assertEqual(6000, nquic_cc:get_cwnd(CC2)).

cc_newreno_recovery_no_double_reduce_test() ->
    CC = nquic_cc:new(newreno),
    Now = erlang:monotonic_time(microsecond),
    CC1 = nquic_cc:on_congestion_event(CC, 1000, 5000, Now),
    ?assertEqual(6000, nquic_cc:get_cwnd(CC1)),
    CC2 = nquic_cc:on_congestion_event(CC1, 500, 4000, Now - 1000000),
    ?assertEqual(6000, nquic_cc:get_cwnd(CC2)).

loss_init_cubic_test() ->
    State = nquic_loss:init(cubic),
    ?assertEqual(cubic, nquic_loss:get_cc_algorithm(State)).

loss_init_default_test() ->
    State = nquic_loss:init(),
    ?assertEqual(newreno, nquic_loss:get_cc_algorithm(State)).

idle_timeout_both_zero_test() ->
    ?assertEqual(infinity, nquic_protocol:get_idle_timeout(0, 0)).

idle_timeout_local_only_test() ->
    ?assertEqual(30000, nquic_protocol:get_idle_timeout(30000, 0)).

idle_timeout_remote_only_test() ->
    ?assertEqual(15000, nquic_protocol:get_idle_timeout(0, 15000)).

idle_timeout_min_selected_test() ->
    ?assertEqual(10000, nquic_protocol:get_idle_timeout(10000, 20000)),
    ?assertEqual(10000, nquic_protocol:get_idle_timeout(20000, 10000)).

idle_timeout_equal_values_test() ->
    ?assertEqual(5000, nquic_protocol:get_idle_timeout(5000, 5000)).

handshake_timeout_state() ->
    #conn_state{
        role = server,
        scid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        dcid = <<9, 9, 9, 9>>,
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{},
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        flow = #conn_flow{},
        streams_state = #conn_streams{streams = #{}}
    }.

handshake_timeout_idle_errors_test() ->
    State = handshake_timeout_state(),
    ?assertMatch(
        {error, {transport_error, idle_timeout}, _},
        nquic_protocol:handle_handshake_timeout(initial, idle, State)
    ).

handshake_timeout_initial_pto_queues_ping_test() ->
    State = handshake_timeout_state(),
    {ok, [], State1, _Timers} = nquic_protocol:handle_handshake_timeout(initial, pto, State),
    ?assertEqual(
        [#ping{}], (State1#conn_state.flow)#conn_flow.pending_initial_frames
    ),
    ?assertEqual([], (State1#conn_state.flow)#conn_flow.pending_handshake_frames).

handshake_timeout_handshake_pto_queues_ping_test() ->
    State = handshake_timeout_state(),
    {ok, [], State1, _Timers} = nquic_protocol:handle_handshake_timeout(handshake, pto, State),
    ?assertEqual(
        [#ping{}], (State1#conn_state.flow)#conn_flow.pending_handshake_frames
    ),
    ?assertEqual([], (State1#conn_state.flow)#conn_flow.pending_initial_frames).

retire_peer_cids_none_test() ->
    PeerCids = #{0 => #{cid => <<1>>, token => <<>>}, 3 => #{cid => <<2>>, token => <<>>}},
    {Retired, Remaining} = nquic_protocol_cid:retire_peer_cids(0, PeerCids),
    ?assertEqual([], Retired),
    ?assertEqual(PeerCids, Remaining).

retire_peer_cids_partial_test() ->
    PeerCids = #{
        0 => #{cid => <<1>>, token => <<>>},
        1 => #{cid => <<2>>, token => <<>>},
        2 => #{cid => <<3>>, token => <<>>}
    },
    {Retired, Remaining} = nquic_protocol_cid:retire_peer_cids(2, PeerCids),
    ?assertEqual(lists:sort(Retired), [0, 1]),
    ?assertEqual(#{2 => #{cid => <<3>>, token => <<>>}}, Remaining).

retire_peer_cids_all_test() ->
    PeerCids = #{0 => #{cid => <<1>>, token => <<>>}, 1 => #{cid => <<2>>, token => <<>>}},
    {Retired, Remaining} = nquic_protocol_cid:retire_peer_cids(5, PeerCids),
    ?assertEqual(lists:sort(Retired), [0, 1]),
    ?assertEqual(#{}, Remaining).

handle_new_connection_id_stores_cid_test() ->
    Data = #conn_state{
        role = client,
        scid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        dcid = <<>>,
        path = #conn_path_mgmt{
            peer_cids = #{},
            local_cids = #{0 => <<1, 2, 3, 4, 5, 6, 7, 8>>},
            local_cid_seq = 1,
            peer_retire_prior_to = 0
        },
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{},
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        streams_state = #conn_streams{streams = #{}}
    },
    CID = <<10, 11, 12, 13, 14, 15, 16, 17>>,
    Token = crypto:strong_rand_bytes(16),
    {ok, NewData} = nquic_protocol_cid:handle_new_connection_id(1, 0, CID, Token, Data),
    ?assertEqual(
        #{1 => #{cid => CID, token => Token}}, (NewData#conn_state.path)#conn_path_mgmt.peer_cids
    ).

handle_new_connection_id_retire_prior_test() ->
    CID0 = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    CID1 = <<9, 10, 11, 12, 13, 14, 15, 16>>,
    Token = <<0:128>>,
    Data = #conn_state{
        role = client,
        scid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        dcid = CID0,
        path = #conn_path_mgmt{
            peer_cids = #{
                0 => #{cid => CID0, token => <<>>},
                1 => #{cid => CID1, token => Token}
            },
            local_cids = #{0 => <<1, 2, 3, 4, 5, 6, 7, 8>>},
            local_cid_seq = 1,
            peer_retire_prior_to = 0
        },
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{},
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        streams_state = #conn_streams{streams = #{}}
    },
    NewCID = <<17, 18, 19, 20, 21, 22, 23, 24>>,
    NewToken = crypto:strong_rand_bytes(16),
    {ok, NewData} = nquic_protocol_cid:handle_new_connection_id(2, 2, NewCID, NewToken, Data),
    ?assertEqual(
        #{2 => #{cid => NewCID, token => NewToken}},
        (NewData#conn_state.path)#conn_path_mgmt.peer_cids
    ),
    ?assertEqual(2, (NewData#conn_state.path)#conn_path_mgmt.peer_retire_prior_to).

handle_retire_connection_id_unknown_test() ->
    Data = #conn_state{
        role = server,
        scid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        dcid = <<>>,
        path = #conn_path_mgmt{
            peer_cids = #{},
            local_cids = #{0 => <<1, 2, 3, 4, 5, 6, 7, 8>>},
            local_cid_seq = 1,
            peer_retire_prior_to = 0
        },
        dispatch_table = undefined,
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{},
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        streams_state = #conn_streams{streams = #{}}
    },
    {ok, NewData} = nquic_protocol_cid:handle_retire_connection_id(99, Data),
    ?assertEqual(
        #{0 => <<1, 2, 3, 4, 5, 6, 7, 8>>}, (NewData#conn_state.path)#conn_path_mgmt.local_cids
    ).

handle_retire_connection_id_removes_and_issues_test() ->
    SCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Data = #conn_state{
        role = server,
        scid = SCID,
        dcid = <<>>,
        path = #conn_path_mgmt{
            peer_cids = #{},
            local_cids = #{0 => SCID},
            local_cid_seq = 1,
            peer_retire_prior_to = 0
        },
        dispatch_table = undefined,
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{},
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        streams_state = #conn_streams{streams = #{}}
    },
    {ok, NewData} = nquic_protocol_cid:handle_retire_connection_id(0, Data),
    ?assertEqual(
        undefined, maps:get(0, (NewData#conn_state.path)#conn_path_mgmt.local_cids, undefined)
    ),
    ?assertMatch(<<_:8/binary>>, maps:get(1, (NewData#conn_state.path)#conn_path_mgmt.local_cids)),
    ?assertEqual(2, (NewData#conn_state.path)#conn_path_mgmt.local_cid_seq).

perform_key_update_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DCID),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientSecret, aes_128_gcm, 1),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerSecret, aes_128_gcm, 1),
    AppKeys = #{
        client => #{key => CKey, iv => CIV, hp => CHP},
        server => #{key => SKey, iv => SIV, hp => SHP}
    },
    {SendKeys, RecvKeys} = nquic_keys:resolve_role_keys(client, AppKeys),
    Data = #conn_state{
        role = client,
        scid = DCID,
        dcid = <<>>,
        crypto = #conn_crypto{
            cipher = aes_128_gcm,
            key_phase = false,
            client_app_secret = ClientSecret,
            server_app_secret = ServerSecret,
            keys = #{application => AppKeys},
            app_send_keys = SendKeys,
            app_recv_keys = RecvKeys
        },
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        streams_state = #conn_streams{streams = #{}}
    },
    NewData = nquic_protocol_key_update:perform_key_update(Data),
    ?assertEqual(true, (NewData#conn_state.crypto)#conn_crypto.key_phase),
    ?assertNotEqual(ClientSecret, (NewData#conn_state.crypto)#conn_crypto.client_app_secret),
    ?assertNotEqual(ServerSecret, (NewData#conn_state.crypto)#conn_crypto.server_app_secret),
    #{application := NewAppKeys} = (NewData#conn_state.crypto)#conn_crypto.keys,
    #{client := NewCKeys, server := NewSKeys} = NewAppKeys,
    ?assertNotEqual(CKey, maps:get(key, NewCKeys)),
    ?assertNotEqual(SKey, maps:get(key, NewSKeys)),
    ?assertEqual(CHP, maps:get(hp, NewCKeys)),
    ?assertEqual(SHP, maps:get(hp, NewSKeys)),
    ?assertEqual(#{key => SKey, iv => SIV}, (NewData#conn_state.crypto)#conn_crypto.old_read_keys).

perform_key_update_double_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DCID),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientSecret, aes_128_gcm, 1),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerSecret, aes_128_gcm, 1),
    AppKeys = #{
        client => #{key => CKey, iv => CIV, hp => CHP},
        server => #{key => SKey, iv => SIV, hp => SHP}
    },
    {SendKeys, RecvKeys} = nquic_keys:resolve_role_keys(server, AppKeys),
    Data = #conn_state{
        role = server,
        scid = DCID,
        dcid = <<>>,
        crypto = #conn_crypto{
            cipher = aes_128_gcm,
            key_phase = false,
            client_app_secret = ClientSecret,
            server_app_secret = ServerSecret,
            keys = #{application => AppKeys},
            app_send_keys = SendKeys,
            app_recv_keys = RecvKeys
        },
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        streams_state = #conn_streams{streams = #{}}
    },
    Data1 = nquic_protocol_key_update:perform_key_update(Data),
    Data2 = nquic_protocol_key_update:perform_key_update(Data1),
    ?assertEqual(true, (Data1#conn_state.crypto)#conn_crypto.key_phase),
    ?assertEqual(false, (Data2#conn_state.crypto)#conn_crypto.key_phase),
    ?assertNotEqual(
        (Data1#conn_state.crypto)#conn_crypto.client_app_secret,
        (Data2#conn_state.crypto)#conn_crypto.client_app_secret
    ).

make_recv_key_update_pair(SenderRole, RecvRole) ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DCID),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientSecret, aes_128_gcm, 1),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerSecret, aes_128_gcm, 1),
    AppKeys = #{
        client => #{key => CKey, iv => CIV, hp => CHP},
        server => #{key => SKey, iv => SIV, hp => SHP}
    },
    Make = fun(Role) ->
        {SendKeys, RecvKeys} = nquic_keys:resolve_role_keys(Role, AppKeys),
        #conn_state{
            role = Role,
            scid = DCID,
            dcid = DCID,
            crypto = #conn_crypto{
                cipher = aes_128_gcm,
                key_phase = false,
                client_app_secret = ClientSecret,
                server_app_secret = ServerSecret,
                keys = #{application => AppKeys},
                app_send_keys = SendKeys,
                app_recv_keys = RecvKeys
            },
            pn_spaces = #{application => #{next_pn => 0}},
            loss_state = nquic_loss:init(),
            local_params = #transport_params{},
            streams_state = #conn_streams{streams = #{}},
            path = #conn_path_mgmt{address_validated = true}
        }
    end,
    {Make(SenderRole), Make(RecvRole)}.

recv_key_update_peer_initiated_test() ->
    {Sender0, Recv0} = make_recv_key_update_pair(server, client),
    Sender1 = nquic_protocol_key_update:perform_key_update(Sender0),
    ?assertEqual(true, (Sender1#conn_state.crypto)#conn_crypto.key_phase),
    {ok, Packet, _Sender2} = nquic_protocol_send:build_app_packet([#ping{}], Sender1),
    PacketBin = iolist_to_binary(Packet),
    {ok, _Events, Recv1} = nquic_protocol_recv:process_datagram(PacketBin, Recv0, []),
    ?assertEqual(true, (Recv1#conn_state.crypto)#conn_crypto.key_phase),
    ?assertEqual(false, (Recv1#conn_state.crypto)#conn_crypto.key_update_pending),
    ?assertNotEqual(undefined, (Recv1#conn_state.crypto)#conn_crypto.old_read_keys).

recv_key_update_peer_acks_local_initiated_test() ->
    {Sender0, Recv0} = make_recv_key_update_pair(server, client),
    {ok, Recv1} = nquic_protocol_key_update:initiate_key_update(Recv0),
    ?assertEqual(true, (Recv1#conn_state.crypto)#conn_crypto.key_phase),
    ?assertEqual(true, (Recv1#conn_state.crypto)#conn_crypto.key_update_pending),
    Sender1 = nquic_protocol_key_update:perform_key_update(Sender0),
    {ok, Packet, _} = nquic_protocol_send:build_app_packet([#ping{}], Sender1),
    {ok, _Events, Recv2} = nquic_protocol_recv:process_datagram(
        iolist_to_binary(Packet), Recv1, []
    ),
    ?assertEqual(true, (Recv2#conn_state.crypto)#conn_crypto.key_phase),
    ?assertEqual(false, (Recv2#conn_state.crypto)#conn_crypto.key_update_pending).

recv_key_update_delayed_old_phase_test() ->
    {Sender0, Recv0} = make_recv_key_update_pair(server, client),
    {ok, OldPacket, _Sender1} = nquic_protocol_send:build_app_packet(
        [#ping{}], Sender0
    ),
    Sender2 = nquic_protocol_key_update:perform_key_update(Sender0),
    {ok, Recv1} = nquic_protocol_key_update:initiate_key_update(Recv0),
    {ok, NewPacket, _Sender3} = nquic_protocol_send:build_app_packet(
        [#ping{}], Sender2
    ),
    {ok, _, Recv2} = nquic_protocol_recv:process_datagram(
        iolist_to_binary(NewPacket), Recv1, []
    ),
    {ok, _, Recv3} = nquic_protocol_recv:process_datagram(
        iolist_to_binary(OldPacket), Recv2, []
    ),
    ?assertEqual(
        (Recv2#conn_state.crypto)#conn_crypto.key_phase,
        (Recv3#conn_state.crypto)#conn_crypto.key_phase
    ),
    ?assertEqual(
        (Recv2#conn_state.crypto)#conn_crypto.client_app_secret,
        (Recv3#conn_state.crypto)#conn_crypto.client_app_secret
    ).

process_datagram_two_stream_frames_event_order_test() ->
    {Sender0, Recv0} = make_recv_key_update_pair(server, client),
    Frame1 = #stream{
        stream_id = 1, offset = 0, length = 4, fin = false, data = <<"AAAA">>
    },
    Frame2 = #stream{
        stream_id = 5, offset = 0, length = 4, fin = false, data = <<"BBBB">>
    },
    SS0 = Recv0#conn_state.streams_state,
    Flow0 = Recv0#conn_state.flow,
    Recv1 = Recv0#conn_state{
        streams_state = SS0#conn_streams{local_max_streams_bidi = 16},
        flow = Flow0#conn_flow{local_max_data = 65536},
        local_params = Recv0#conn_state.local_params#transport_params{
            initial_max_stream_data_bidi_remote = 65536
        }
    },
    {ok, Packet, _Sender1} = nquic_protocol_send:build_app_packet(
        [Frame1, Frame2], Sender0
    ),
    PacketBin = iolist_to_binary(Packet),
    {ok, Events, _Recv2} = nquic_protocol_recv:process_datagram(PacketBin, Recv1, []),
    ?assertEqual(
        [
            {stream_opened, 1},
            {stream_data, 1},
            {stream_opened, 5},
            {stream_data, 5}
        ],
        Events
    ).

install_zero_rtt_keys_test() ->
    ClientHelloHash = crypto:hash(sha256, <<"fake_client_hello">>),
    Data = #conn_state{
        role = server,
        scid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        dcid = <<>>,
        crypto = #conn_crypto{
            cipher = aes_128_gcm,
            keys = #{initial => #{client => #{}, server => #{}}}
        },
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        streams_state = #conn_streams{streams = #{}}
    },
    NewData = nquic_protocol_zero_rtt:install_zero_rtt_keys(ClientHelloHash, aes_128_gcm, Data),
    #{rtt0 := ZeroRTTKeys} = (NewData#conn_state.crypto)#conn_crypto.keys,
    #{client := #{key := Key, iv := IV, hp := HP}} = ZeroRTTKeys,
    ?assertEqual(16, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(16, byte_size(HP)).

install_zero_rtt_keys_psk_test() ->
    PSK = crypto:strong_rand_bytes(32),
    ClientHelloHash = crypto:hash(sha256, <<"fake_client_hello">>),
    Data = #conn_state{
        role = server,
        scid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        dcid = <<>>,
        crypto = #conn_crypto{cipher = aes_128_gcm, keys = #{}},
        loss_state = nquic_loss:init(),
        local_params = #transport_params{},
        streams_state = #conn_streams{streams = #{}}
    },
    D1 = nquic_protocol_zero_rtt:install_zero_rtt_keys(ClientHelloHash, aes_128_gcm, Data),
    D2 = nquic_protocol_zero_rtt:install_zero_rtt_keys_psk(
        PSK, ClientHelloHash, aes_128_gcm, Data
    ),
    #{rtt0 := #{client := #{key := K1}}} = (D1#conn_state.crypto)#conn_crypto.keys,
    #{rtt0 := #{client := #{key := K2}}} = (D2#conn_state.crypto)#conn_crypto.keys,
    ?assertNotEqual(K1, K2).

decrypt_ticket_roundtrip_test() ->
    StaticKey = crypto:strong_rand_bytes(32),
    PSK = crypto:strong_rand_bytes(32),
    CipherBin = <<"aes_128_gcm">>,
    Plain = <<PSK/binary, CipherBin/binary>>,
    IV = crypto:strong_rand_bytes(12),
    {Ct, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm, StaticKey, IV, Plain, <<>>, true
    ),
    TicketValue = <<IV/binary, Tag/binary, Ct/binary>>,
    ?assertMatch({ok, PSK, aes_128_gcm}, nquic_tls:decrypt_ticket(TicketValue, StaticKey)).

decrypt_ticket_wrong_key_test() ->
    StaticKey = crypto:strong_rand_bytes(32),
    WrongKey = crypto:strong_rand_bytes(32),
    Plain = <<(crypto:strong_rand_bytes(32))/binary, "aes_128_gcm">>,
    IV = crypto:strong_rand_bytes(12),
    {Ct, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm, StaticKey, IV, Plain, <<>>, true
    ),
    TicketValue = <<IV/binary, Tag/binary, Ct/binary>>,
    ?assertMatch({error, _}, nquic_tls:decrypt_ticket(TicketValue, WrongKey)).

decrypt_ticket_too_short_test() ->
    ?assertMatch({error, ticket_too_short}, nquic_tls:decrypt_ticket(<<1, 2, 3>>, <<0:256>>)).

decrypt_ticket_aes256_cipher_test() ->
    StaticKey = crypto:strong_rand_bytes(32),
    PSK = crypto:strong_rand_bytes(32),
    Plain = <<PSK/binary, "aes_256_gcm">>,
    IV = crypto:strong_rand_bytes(12),
    {Ct, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm, StaticKey, IV, Plain, <<>>, true
    ),
    Ticket = <<IV/binary, Tag/binary, Ct/binary>>,
    ?assertMatch({ok, PSK, aes_256_gcm}, nquic_tls:decrypt_ticket(Ticket, StaticKey)).

decrypt_ticket_chacha_cipher_test() ->
    StaticKey = crypto:strong_rand_bytes(32),
    PSK = crypto:strong_rand_bytes(32),
    Plain = <<PSK/binary, "chacha20_poly1305">>,
    IV = crypto:strong_rand_bytes(12),
    {Ct, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm, StaticKey, IV, Plain, <<>>, true
    ),
    Ticket = <<IV/binary, Tag/binary, Ct/binary>>,
    ?assertMatch({ok, PSK, chacha20_poly1305}, nquic_tls:decrypt_ticket(Ticket, StaticKey)).

decrypt_ticket_48byte_psk_test() ->
    StaticKey = crypto:strong_rand_bytes(32),
    PSK = crypto:strong_rand_bytes(48),
    Plain = <<PSK/binary, "aes_256_gcm">>,
    IV = crypto:strong_rand_bytes(12),
    {Ct, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm, StaticKey, IV, Plain, <<>>, true
    ),
    Ticket = <<IV/binary, Tag/binary, Ct/binary>>,
    ?assertMatch({ok, PSK, aes_256_gcm}, nquic_tls:decrypt_ticket(Ticket, StaticKey)).

validate_psk_offer_no_matching_test() ->
    PSKInfo = #{
        identities => [{<<"garbage">>, 0}],
        binders => [<<0:256>>],
        early_data => false
    },
    StaticKey = crypto:strong_rand_bytes(32),
    CH = crypto:strong_rand_bytes(100),
    ?assertMatch(
        {error, _}, nquic_tls_server:validate_psk_offer(PSKInfo, CH, StaticKey, aes_128_gcm)
    ).

validate_psk_offer_empty_test() ->
    PSKInfo = #{identities => [], binders => [], early_data => false},
    ?assertMatch(
        {error, no_matching_psk},
        nquic_tls_server:validate_psk_offer(PSKInfo, <<>>, <<0:256>>, aes_128_gcm)
    ).

validate_psk_offer_mismatched_count_test() ->
    PSKInfo = #{
        identities => [{<<"a">>, 0}, {<<"b">>, 0}],
        binders => [<<0:256>>],
        early_data => false
    },
    ?assertMatch(
        {error, _},
        nquic_tls_server:validate_psk_offer(PSKInfo, <<>>, <<0:256>>, aes_128_gcm)
    ).

process_client_hello_with_psk_selected_test() ->
    ClientTP = #transport_params{
        initial_max_data = 65536,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    ServerTP = #transport_params{
        initial_max_data = 65536,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<9, 10, 11, 12>>
    },
    {ok, CHBin, _} = nquic_tls_client:make_client_hello(ClientTP, [<<"h3">>], <<"localhost">>),
    {ok, SH1, _, _} = nquic_tls_server:process_client_hello(CHBin, ServerTP, [<<"h3">>]),
    {ok, SH2, _, _} = nquic_tls_server:process_client_hello(
        CHBin, ServerTP, [<<"h3">>], #{psk_selected => 0}
    ),
    ?assert(byte_size(SH2) > byte_size(SH1)),
    ?assertMatch({_, _}, binary:match(SH2, <<0, 41>>)).

make_server_handshake_flight_psk_test() ->
    ClientTP = #transport_params{
        initial_max_data = 65536,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    ServerTP = #transport_params{
        initial_max_data = 65536,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<9, 10, 11, 12>>
    },
    {ok, CHBin, _} = nquic_tls_client:make_client_hello(ClientTP, [<<"h3">>], <<"localhost">>),
    {ok, _SH, Keys, TLSState} = nquic_tls_server:process_client_hello(
        CHBin, ServerTP, [<<"h3">>]
    ),
    HSSecret = maps:get(handshake_secret, Keys),
    {ok, FlightBin, AppKeys, _NewState} =
        nquic_tls_server:make_server_handshake_flight_psk(HSSecret, Keys, TLSState, false),
    ?assert(byte_size(FlightBin) > 0),
    ?assert(maps:is_key(client_key, AppKeys)),
    ?assert(maps:is_key(server_key, AppKeys)),
    TestDir = filename:dirname(code:which(?MODULE)),
    ConfDir = filename:join([filename:dirname(TestDir), "test", "conf"]),
    ok = nquic_test_util:ensure_test_certs(ConfDir),
    CertFile = filename:join(ConfDir, "server.pem"),
    KeyFile = filename:join(ConfDir, "server.key"),
    {ok, CertBin} = file:read_file(CertFile),
    {ok, KeyBin} = file:read_file(KeyFile),
    [{_, CertDER, _}] = public_key:pem_decode(CertBin),
    [KeyEntry | _] = public_key:pem_decode(KeyBin),
    PrivKey = public_key:pem_entry_decode(KeyEntry),
    {ok, FullFlight, _, _} = nquic_tls_server:make_server_handshake_flight(
        HSSecret, Keys, TLSState, CertDER, [], PrivKey
    ),
    ?assert(byte_size(FlightBin) < byte_size(FullFlight)).

make_server_handshake_flight_psk_early_data_test() ->
    ClientTP = #transport_params{
        initial_max_data = 65536,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    ServerTP = #transport_params{
        initial_max_data = 65536,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<9, 10, 11, 12>>
    },
    {ok, CHBin, _} = nquic_tls_client:make_client_hello(ClientTP, [<<"h3">>], <<"localhost">>),
    {ok, _SH, Keys, TLSState} = nquic_tls_server:process_client_hello(
        CHBin, ServerTP, [<<"h3">>]
    ),
    HSSecret = maps:get(handshake_secret, Keys),
    {ok, FlightED, _, _} =
        nquic_tls_server:make_server_handshake_flight_psk(HSSecret, Keys, TLSState, true),
    {ok, FlightNoED, _, _} =
        nquic_tls_server:make_server_handshake_flight_psk(HSSecret, Keys, TLSState, false),
    ?assert(byte_size(FlightED) > byte_size(FlightNoED)).

process_server_hello_psk_accepted_test() ->
    ClientTP = #transport_params{
        initial_max_data = 65536,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    ServerTP = #transport_params{
        initial_max_data = 65536,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<9, 10, 11, 12>>
    },
    {ok, CHBin, ClientState} = nquic_tls_client:make_client_hello(
        ClientTP, [<<"h3">>], <<"localhost">>
    ),
    {ok, SHBin, _Keys, _TLS} = nquic_tls_server:process_client_hello(
        CHBin, ServerTP, [<<"h3">>], #{psk_selected => 0}
    ),
    {ok, Result} = nquic_tls_client:process_server_hello(SHBin, CHBin, ClientState),
    ?assertEqual(true, maps:get(psk_accepted, Result)).

process_server_hello_no_psk_test() ->
    ClientTP = #transport_params{
        initial_max_data = 65536,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    ServerTP = #transport_params{
        initial_max_data = 65536,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<9, 10, 11, 12>>
    },
    {ok, CHBin, ClientState} = nquic_tls_client:make_client_hello(
        ClientTP, [<<"h3">>], <<"localhost">>
    ),
    {ok, SHBin, _Keys, _TLS} = nquic_tls_server:process_client_hello(
        CHBin, ServerTP, [<<"h3">>]
    ),
    {ok, Result} = nquic_tls_client:process_server_hello(SHBin, CHBin, ClientState),
    ?assertEqual(false, maps:get(psk_accepted, Result)).

process_handshake_messages_psk_test() ->
    ClientTP = #transport_params{
        initial_max_data = 65536,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    ServerTP = #transport_params{
        initial_max_data = 65536,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<9, 10, 11, 12>>
    },
    {ok, CHBin, ClientState} = nquic_tls_client:make_client_hello(
        ClientTP, [<<"h3">>], <<"localhost">>
    ),
    {ok, SHBin, ServerKeys, ServerTLS} = nquic_tls_server:process_client_hello(
        CHBin, ServerTP, [<<"h3">>]
    ),
    {ok, HSKeys} = nquic_tls_client:process_server_hello(SHBin, CHBin, ClientState),
    HSSecret = maps:get(handshake_secret, ServerKeys),
    {ok, FlightBin, _AppKeys, _NewTLS} =
        nquic_tls_server:make_server_handshake_flight_psk(
            HSSecret, ServerKeys, ServerTLS, false
        ),
    ProcessState = HSKeys#{
        cipher => maps:get(cipher, HSKeys, aes_128_gcm)
    },
    {ok, AppKeys} = nquic_tls_client:process_handshake_messages_psk(
        FlightBin, maps:get(handshake_secret, HSKeys), ProcessState
    ),
    ?assert(maps:is_key(client_key, AppKeys)),
    ?assert(maps:is_key(server_key, AppKeys)),
    ?assertEqual(undefined, maps:get(peer_cert, AppKeys)),
    ?assertEqual(false, maps:get(zero_rtt_accepted, AppKeys)).

process_handshake_messages_psk_early_data_test() ->
    ClientTP = #transport_params{
        initial_max_data = 65536,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    ServerTP = #transport_params{
        initial_max_data = 65536,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<9, 10, 11, 12>>
    },
    {ok, CHBin, ClientState} = nquic_tls_client:make_client_hello(
        ClientTP, [<<"h3">>], <<"localhost">>
    ),
    {ok, SHBin, ServerKeys, ServerTLS} = nquic_tls_server:process_client_hello(
        CHBin, ServerTP, [<<"h3">>]
    ),
    {ok, HSKeys} = nquic_tls_client:process_server_hello(SHBin, CHBin, ClientState),
    HSSecret = maps:get(handshake_secret, ServerKeys),
    {ok, FlightBin, _, _} =
        nquic_tls_server:make_server_handshake_flight_psk(
            HSSecret, ServerKeys, ServerTLS, true
        ),
    ProcessState = HSKeys#{cipher => maps:get(cipher, HSKeys, aes_128_gcm)},
    {ok, AppKeys} = nquic_tls_client:process_handshake_messages_psk(
        FlightBin, maps:get(handshake_secret, HSKeys), ProcessState
    ),
    ?assertEqual(true, maps:get(zero_rtt_accepted, AppKeys)).

make_client_hello_maybe_psk_no_ticket_test() ->
    TP = #transport_params{initial_source_connection_id = <<1, 2, 3, 4>>},
    {ok, CHBin, State} = nquic_protocol_handshake:make_client_hello_maybe_psk(
        TP, [<<"h3">>], <<"localhost">>, undefined
    ),
    ?assert(byte_size(CHBin) > 0),
    ?assertEqual(undefined, maps:get(psk, State, undefined)).

make_client_hello_maybe_psk_with_ticket_test() ->
    TP = #transport_params{initial_source_connection_id = <<1, 2, 3, 4>>},
    PSK = crypto:strong_rand_bytes(32),
    Ticket = #{
        psk => PSK,
        cipher => aes_128_gcm,
        lifetime => 7200,
        age_add => 12345,
        nonce => <<1, 2, 3, 4>>,
        ticket => <<"ticket_value">>,
        received_at => erlang:system_time(millisecond) - 500
    },
    {ok, CHBin, State} = nquic_protocol_handshake:make_client_hello_maybe_psk(
        TP, [<<"h3">>], <<"localhost">>, Ticket
    ),
    ?assert(byte_size(CHBin) > 0),
    ?assertEqual(PSK, maps:get(psk, State)),
    ?assertEqual(aes_128_gcm, maps:get(cipher, State)).

connect_opts_session_ticket_passthrough_test() ->
    Ticket = #{psk => <<1:256>>, cipher => aes_128_gcm},
    Opts = #{session_ticket => Ticket, alpn => [<<"h3">>]},
    ?assertEqual(Ticket, maps:get(session_ticket, Opts)).

ecn_from_cmsg_empty_test() ->
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg([])).

ecn_from_cmsg_undefined_test() ->
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(undefined)).

ecn_from_cmsg_ect0_test() ->
    Cmsg = [#{level => ip, type => tos, value => 2}],
    ?assertEqual(ect0, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_from_cmsg_ect1_test() ->
    Cmsg = [#{level => ip, type => tos, value => 1}],
    ?assertEqual(ect1, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_from_cmsg_ce_test() ->
    Cmsg = [#{level => ip, type => tos, value => 3}],
    ?assertEqual(ce, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_from_cmsg_not_ect_test() ->
    Cmsg = [#{level => ip, type => tos, value => 0}],
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_from_cmsg_tos_with_dscp_test() ->
    Cmsg = [#{level => ip, type => tos, value => 16#42}],
    ?assertEqual(ect0, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_from_cmsg_skip_other_test() ->
    Cmsg = [
        #{level => socket, type => timestamp, value => 0},
        #{level => ip, type => tos, value => 3}
    ],
    ?assertEqual(ce, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_from_cmsg_ipv6_tclass_ect0_test() ->
    Cmsg = [#{level => ipv6, type => tclass, value => 2}],
    ?assertEqual(ect0, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_from_cmsg_ipv6_tclass_ce_test() ->
    Cmsg = [#{level => ipv6, type => tclass, value => 16#43}],
    ?assertEqual(ce, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_from_cmsg_skip_other_then_ipv6_test() ->
    Cmsg = [
        #{level => socket, type => timestamp, value => 0},
        #{level => ipv6, type => tclass, value => 1}
    ],
    ?assertEqual(ect1, nquic_socket:get_ecn_from_cmsg(Cmsg)).

ecn_set_socket_test() ->
    {ok, Socket} = socket:open(inet, dgram, udp),
    ?assertEqual(ok, nquic_socket:set_ecn(Socket, true)),
    ?assertEqual(ok, nquic_socket:set_ecn(Socket, false)),
    socket:close(Socket).

socket_capabilities_shape_test() ->
    Caps = nquic_socket:capabilities(),
    ?assert(is_map(Caps)),
    ?assert(is_boolean(maps:get(gso, Caps))),
    ?assert(is_boolean(maps:get(gro, Caps))).

gso_size_set_is_safe_test() ->
    {ok, Socket} = socket:open(inet, dgram, udp),
    ?assertEqual(ok, nquic_socket:set_gso_size(Socket, 1200)),
    ?assertEqual(ok, nquic_socket:set_gso_size(Socket, 0)),
    ok = socket:close(Socket).

gro_set_is_safe_test() ->
    {ok, Socket} = socket:open(inet, dgram, udp),
    ?assertEqual(ok, nquic_socket:set_gro(Socket, true)),
    ?assertEqual(ok, nquic_socket:set_gro(Socket, false)),
    ok = socket:close(Socket).

gso_size_from_cmsg_undefined_test() ->
    ?assertEqual(undefined, nquic_socket:get_gso_size_from_cmsg(undefined)).

gso_size_from_cmsg_empty_test() ->
    ?assertEqual(undefined, nquic_socket:get_gso_size_from_cmsg([])).

gso_size_from_cmsg_padded_test() ->
    Cmsg = [#{level => udp, type => 104, data => <<1000:16/native, 0:16>>}],
    ?assertEqual(1000, nquic_socket:get_gso_size_from_cmsg(Cmsg)).

gso_size_from_cmsg_skip_other_test() ->
    Cmsg = [
        #{level => ip, type => tos, value => 0},
        #{level => udp, type => 104, data => <<512:16/native, 0:16>>}
    ],
    ?assertEqual(512, nquic_socket:get_gso_size_from_cmsg(Cmsg)).

gso_size_from_cmsg_zero_skipped_test() ->
    Cmsg = [#{level => udp, type => 104, data => <<0:16/native, 0:16>>}],
    ?assertEqual(undefined, nquic_socket:get_gso_size_from_cmsg(Cmsg)).

gso_open_pair(GsoSize) ->
    {ok, Recv} = socket:open(inet, dgram, udp),
    ok = socket:bind(Recv, #{family => inet, addr => {127, 0, 0, 1}, port => 0}),
    {ok, RecvAddr} = socket:sockname(Recv),
    {ok, Sender} = socket:open(inet, dgram, udp),
    ok = socket:bind(Sender, #{family => inet, addr => {127, 0, 0, 1}, port => 0}),
    ok = nquic_socket:set_gso_size(Sender, GsoSize),
    {Sender, Recv, RecvAddr}.

gso_drain(_Recv, 0, Acc, _Timeout) ->
    lists:reverse(Acc);
gso_drain(Recv, N, Acc, Timeout) ->
    case socket:recvfrom(Recv, 65535, Timeout) of
        {ok, {_Source, Bin}} -> gso_drain(Recv, N - 1, [byte_size(Bin) | Acc], Timeout);
        _ -> lists:reverse(Acc)
    end.

gso_e2e_segments_equal_run_test() ->
    GsoSize = 200,
    {Sender, Recv, Dest} = gso_open_pair(GsoSize),
    Buf = binary:copy(<<7>>, 3 * GsoSize),
    ok = socket:sendto(Sender, Buf, Dest),
    Sizes = gso_drain(Recv, 3, [], 200),
    socket:close(Sender),
    socket:close(Recv),
    ?assertEqual([GsoSize, GsoSize, GsoSize], Sizes).

gso_e2e_segments_with_trailer_test() ->
    GsoSize = 200,
    {Sender, Recv, Dest} = gso_open_pair(GsoSize),
    Buf = <<(binary:copy(<<7>>, 2 * GsoSize))/binary, (binary:copy(<<8>>, 50))/binary>>,
    ok = socket:sendto(Sender, Buf, Dest),
    Sizes = gso_drain(Recv, 3, [], 200),
    socket:close(Sender),
    socket:close(Recv),
    ?assertEqual([GsoSize, GsoSize, 50], Sizes).

nquic_accept_timeout_test() ->
    FakePid = spawn(fun() ->
        receive
            _ -> ok
        after 100 -> ok
        end
    end),
    timer:sleep(150),
    Result =
        try
            nquic:accept(FakePid, #{timeout => 10})
        catch
            _:_ -> {error, noproc}
        end,
    ?assertMatch({error, _}, Result).

packet_short_header_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Header = #short_header{dcid = DCID, packet_number = 0},
    Encoded = nquic_packet:encode_header(Header),
    {ok, Decoded, _Rest} = nquic_packet:parse_header(Encoded, byte_size(DCID)),
    ?assertEqual(DCID, Decoded#short_header.dcid).

packet_long_header_version_test() ->
    Header = #long_header{
        type = initial,
        version = 1,
        dcid = <<1, 2, 3, 4>>,
        scid = <<5, 6, 7, 8>>,
        token = <<>>,
        payload_len = 100,
        packet_number = 0
    },
    Encoded = nquic_packet:encode_header(Header),
    {ok, Decoded, _Rest} = nquic_packet:parse_header(Encoded),
    ?assertEqual(1, Decoded#long_header.version).

transport_client_params_test() ->
    Params = #transport_params{
        max_idle_timeout = 30000,
        initial_max_data = 100000,
        initial_source_connection_id = <<1, 2, 3, 4>>
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, client),
    ?assertEqual(30000, Decoded#transport_params.max_idle_timeout).

transport_server_required_params_test() ->
    Params = #transport_params{
        initial_source_connection_id = <<1, 2, 3, 4>>
    },
    Encoded = nquic_transport:encode(Params),
    ?assertMatch(
        {error, {transport_parameter_error, missing_original_dest_cid}},
        nquic_transport:decode(Encoded, server)
    ).

transport_duplicate_param_test() ->
    Bin = <<16#0f, 4, 1, 2, 3, 4, 16#0f, 4, 5, 6, 7, 8>>,
    ?assertMatch({error, duplicate_parameter}, nquic_transport:decode(Bin, client)).

transport_invalid_ack_delay_exponent_test() ->
    Bin = <<16#0f, 4, 1, 2, 3, 4, 10, 1, 21>>,
    ?assertMatch({error, transport_parameter_error}, nquic_transport:decode(Bin, client)).

transport_invalid_max_udp_payload_test() ->
    InitSrcCid = <<16#0f, 4, 1, 2, 3, 4>>,
    MaxUDP = <<3, 2, 4, 175>>,
    Bin = <<InitSrcCid/binary, MaxUDP/binary>>,
    ?assertMatch({error, transport_parameter_error}, nquic_transport:decode(Bin, client)).

packet_invalid_header_test() ->
    ?assertMatch({error, invalid_packet}, nquic_packet:parse_header(<<>>)),
    ?assertMatch({error, invalid_packet}, nquic_packet:parse_header(<<0>>)).

packet_version_negotiation_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<9, 10, 11, 12>>,
    Bin = <<16#80, 0:32, 8, DCID/binary, 4, SCID/binary, 1:32, 16#FF000020:32>>,
    {ok, Header, <<>>} = nquic_packet:parse_header(Bin),
    ?assertEqual(version_negotiation, Header#long_header.type),
    ?assertEqual(0, Header#long_header.version),
    ?assertEqual(DCID, Header#long_header.dcid),
    ?assertEqual(SCID, Header#long_header.scid),
    ?assertEqual(<<1:32, 16#FF000020:32>>, Header#long_header.token).

packet_version_negotiation_encode_test() ->
    DCID = <<1, 2, 3, 4>>,
    SCID = <<5, 6, 7, 8>>,
    Encoded = nquic_packet:encode_version_negotiation(DCID, SCID, [1]),
    {ok, Header, <<>>} = nquic_packet:parse_header(Encoded),
    ?assertEqual(version_negotiation, Header#long_header.type),
    ?assertEqual(DCID, Header#long_header.dcid),
    ?assertEqual(SCID, Header#long_header.scid),
    ?assertEqual(<<1:32>>, Header#long_header.token).

is_supported_version_test() ->
    ?assert(nquic_packet:is_supported_version(1)),
    ?assert(nquic_packet:is_supported_version(16#6b3343cf)),
    ?assertNot(nquic_packet:is_supported_version(0)),
    ?assertNot(nquic_packet:is_supported_version(16#FF000020)).

initial_secrets_v2_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {CV1, SV1} = nquic_keys:initial_secrets(DCID, 1),
    {CV2, SV2} = nquic_keys:initial_secrets(DCID, 16#6b3343cf),
    ?assertNotEqual(CV1, CV2),
    ?assertNotEqual(SV1, SV2),
    ?assertEqual(32, byte_size(CV2)),
    ?assertEqual(32, byte_size(SV2)).

retry_key_v2_test() ->
    ?assertNotEqual(nquic_retry:retry_key(1), nquic_retry:retry_key(16#6b3343cf)),
    ?assertNotEqual(nquic_retry:retry_nonce(1), nquic_retry:retry_nonce(16#6b3343cf)).

packet_type_bits_v2_test() ->
    ?assertEqual(1, nquic_packet:packet_type_bits(initial, 16#6b3343cf)),
    ?assertEqual(2, nquic_packet:packet_type_bits(rtt0, 16#6b3343cf)),
    ?assertEqual(3, nquic_packet:packet_type_bits(handshake, 16#6b3343cf)),
    ?assertEqual(0, nquic_packet:packet_type_bits(retry, 16#6b3343cf)).

bits_to_packet_type_v2_test() ->
    ?assertEqual(retry, nquic_packet:bits_to_packet_type(0, 16#6b3343cf)),
    ?assertEqual(initial, nquic_packet:bits_to_packet_type(1, 16#6b3343cf)),
    ?assertEqual(rtt0, nquic_packet:bits_to_packet_type(2, 16#6b3343cf)),
    ?assertEqual(handshake, nquic_packet:bits_to_packet_type(3, 16#6b3343cf)).

vn_encode_supported_versions_test() ->
    Supported = nquic_packet:supported_versions(),
    ?assert(lists:member(1, Supported)),
    ?assert(lists:member(16#6b3343cf, Supported)).

v2_derive_initial_keys_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Keys = nquic_handshake:derive_initial_keys(DCID, 16#6b3343cf),
    ?assert(is_map(Keys)),
    #{client := CK, server := SK} = Keys,
    ?assert(maps:is_key(key, CK)),
    ?assert(maps:is_key(iv, CK)),
    ?assert(maps:is_key(hp, CK)),
    ?assert(maps:is_key(key, SK)).

v2_rfc9369_initial_keys_test() ->
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DCID, 16#6b3343cf),
    ?assertEqual(
        <<16#14, 16#ec, 16#9d, 16#6e, 16#b9, 16#fd, 16#7a, 16#f8, 16#3b, 16#f5, 16#a6, 16#68, 16#bc,
            16#17, 16#a7, 16#e2, 16#83, 16#76, 16#6a, 16#ad, 16#e7, 16#ec, 16#d0, 16#89, 16#1f,
            16#70, 16#f9, 16#ff, 16#7f, 16#4b, 16#f4, 16#7b>>,
        ClientSecret
    ),
    ?assertEqual(
        <<16#02, 16#63, 16#db, 16#17, 16#82, 16#73, 16#1b, 16#f4, 16#58, 16#8e, 16#7e, 16#4d, 16#93,
            16#b7, 16#46, 16#39, 16#07, 16#cb, 16#8c, 16#d8, 16#20, 16#0b, 16#5d, 16#a5, 16#5a,
            16#8b, 16#d4, 16#88, 16#ea, 16#fc, 16#37, 16#c1>>,
        ServerSecret
    ),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(
        ClientSecret, aes_128_gcm, 16#6b3343cf
    ),
    ?assertEqual(
        <<16#8b, 16#1a, 16#0b, 16#c1, 16#21, 16#28, 16#42, 16#90, 16#a2, 16#9e, 16#09, 16#71, 16#b5,
            16#cd, 16#04, 16#5d>>,
        CKey
    ),
    ?assertEqual(
        <<16#91, 16#f7, 16#3e, 16#23, 16#51, 16#d8, 16#fa, 16#91, 16#66, 16#0e, 16#90, 16#9f>>, CIV
    ),
    ?assertEqual(
        <<16#45, 16#b9, 16#5e, 16#15, 16#23, 16#5d, 16#6f, 16#45, 16#a6, 16#b1, 16#9c, 16#bc, 16#b0,
            16#29, 16#4b, 16#a9>>,
        CHP
    ),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(
        ServerSecret, aes_128_gcm, 16#6b3343cf
    ),
    ?assertEqual(
        <<16#82, 16#db, 16#63, 16#78, 16#61, 16#d5, 16#5e, 16#1d, 16#01, 16#1f, 16#19, 16#ea, 16#71,
            16#d5, 16#d2, 16#a7>>,
        SKey
    ),
    ?assertEqual(
        <<16#dd, 16#13, 16#c2, 16#76, 16#49, 16#9c, 16#02, 16#49, 16#d3, 16#31, 16#06, 16#52>>, SIV
    ),
    ?assertEqual(
        <<16#ed, 16#f6, 16#d0, 16#5c, 16#83, 16#12, 16#12, 16#01, 16#b4, 16#36, 16#e1, 16#68, 16#77,
            16#59, 16#3c, 16#3a>>,
        SHP
    ).

v2_retry_integrity_test() ->
    ODCID = <<1, 2, 3, 4>>,
    PacketNoTag = <<16#F0, 16#6b, 16#33, 16#43, 16#cf, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, "token">>,
    Tag = nquic_retry:compute_integrity_tag(ODCID, PacketNoTag, 16#6b3343cf),
    ?assertEqual(16, byte_size(Tag)),
    ?assertEqual(ok, nquic_retry:verify_integrity_tag(ODCID, PacketNoTag, Tag, 16#6b3343cf)),
    TagV1 = nquic_retry:compute_integrity_tag(ODCID, PacketNoTag, 1),
    ?assertNotEqual(Tag, TagV1).

select_server_compat_version_no_remote_params_test() ->
    no_switch = nquic_protocol_handshake:select_server_compat_version(
        undefined, [16#6b3343cf, 1], 1
    ).

select_server_compat_version_no_version_info_test() ->
    TP = #transport_params{},
    no_switch = nquic_protocol_handshake:select_server_compat_version(
        TP, [16#6b3343cf, 1], 1
    ).

select_server_compat_version_client_only_v1_test() ->
    TP = #transport_params{
        version_information = #{chosen_version => 1, other_versions => [1]}
    },
    no_switch = nquic_protocol_handshake:select_server_compat_version(
        TP, [16#6b3343cf, 1], 1
    ).

select_server_compat_version_default_preference_test() ->
    TP = #transport_params{
        version_information = #{
            chosen_version => 1, other_versions => [16#6b3343cf, 1]
        }
    },
    no_switch = nquic_protocol_handshake:select_server_compat_version(TP, [1], 1).

select_server_compat_version_switch_to_v2_test() ->
    TP = #transport_params{
        version_information = #{
            chosen_version => 1, other_versions => [16#6b3343cf, 1]
        }
    },
    {switch, 16#6b3343cf} = nquic_protocol_handshake:select_server_compat_version(
        TP, [16#6b3343cf, 1], 1
    ).

select_server_compat_version_skips_unsupported_test() ->
    TP = #transport_params{
        version_information = #{
            chosen_version => 1, other_versions => [16#FF00DEAD, 16#6b3343cf, 1]
        }
    },
    {switch, 16#6b3343cf} = nquic_protocol_handshake:select_server_compat_version(
        TP, [16#FF00DEAD, 16#6b3343cf, 1], 1
    ).

select_server_compat_version_first_match_is_initial_test() ->
    TP = #transport_params{
        version_information = #{
            chosen_version => 1, other_versions => [16#6b3343cf, 1]
        }
    },
    no_switch = nquic_protocol_handshake:select_server_compat_version(
        TP, [1, 16#6b3343cf], 1
    ).

select_server_compat_version_rejects_not_in_other_versions_test() ->
    TP = #transport_params{
        version_information = #{chosen_version => 1, other_versions => [1]}
    },
    no_switch = nquic_protocol_handshake:select_server_compat_version(
        TP, [16#6b3343cf, 1], 1
    ).

select_server_compat_version_initial_v2_no_switch_test() ->
    TP = #transport_params{
        version_information = #{
            chosen_version => 16#6b3343cf, other_versions => [16#6b3343cf, 1]
        }
    },
    no_switch = nquic_protocol_handshake:select_server_compat_version(
        TP, [16#6b3343cf, 1], 16#6b3343cf
    ).

apply_server_compat_version_switch_to_v2_test() ->
    ODCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,
    {V1CSecret, _} = nquic_keys:initial_secrets(ODCID, 1),
    {V1CKey, V1CIV, V1CHP} = nquic_keys:derive_packet_protection(V1CSecret, aes_128_gcm, 1),
    V1Initial = #{
        client => nquic_keys:make_role_keys(aes_128_gcm, V1CKey, V1CIV, V1CHP),
        server => nquic_keys:make_role_keys(aes_128_gcm, V1CKey, V1CIV, V1CHP)
    },
    State0 = #conn_state{
        role = server,
        scid = <<1, 2, 3, 4>>,
        dcid = <<5, 6, 7, 8>>,
        odcid = ODCID,
        version = 1,
        local_params = #transport_params{
            version_information = #{
                chosen_version => 1, other_versions => [16#6b3343cf, 1]
            }
        },
        crypto = #conn_crypto{
            keys = #{initial => V1Initial},
            tls_state = #{quic_version => 1}
        }
    },
    State1 = nquic_protocol_handshake:apply_server_compat_version_switch(16#6b3343cf, State0),
    ?assertEqual(16#6b3343cf, State1#conn_state.version),
    Crypto = State1#conn_state.crypto,
    NewInitial = maps:get(initial, Crypto#conn_crypto.keys),
    ?assertNotEqual(V1Initial, NewInitial),
    ?assertEqual(16#6b3343cf, maps:get(quic_version, Crypto#conn_crypto.tls_state)),
    VI = (State1#conn_state.local_params)#transport_params.version_information,
    ?assertEqual(16#6b3343cf, maps:get(chosen_version, VI)),
    ?assertEqual([16#6b3343cf, 1], maps:get(other_versions, VI)),
    {V2ClientSecret, _} = nquic_keys:initial_secrets(ODCID, 16#6b3343cf),
    {V2CKey, _, _} = nquic_keys:derive_packet_protection(
        V2ClientSecret, aes_128_gcm, 16#6b3343cf
    ),
    #{client := ClientRoleKeys} = NewInitial,
    ?assertEqual(V2CKey, maps:get(key, ClientRoleKeys)).

apply_server_compat_version_switch_uses_retry_dcid_test() ->
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    RetrySCID = <<9, 10, 11, 12, 13, 14, 15, 16>>,
    State0 = #conn_state{
        role = server,
        scid = <<1, 2, 3, 4>>,
        dcid = <<5, 6, 7, 8>>,
        odcid = ODCID,
        version = 1,
        local_params = #transport_params{
            version_information = #{
                chosen_version => 1, other_versions => [16#6b3343cf, 1]
            },
            retry_source_connection_id = RetrySCID
        },
        crypto = #conn_crypto{keys = #{}, tls_state = undefined}
    },
    State1 = nquic_protocol_handshake:apply_server_compat_version_switch(16#6b3343cf, State0),
    #{initial := Initial} = (State1#conn_state.crypto)#conn_crypto.keys,
    {ExpectedCSecret, _} = nquic_keys:initial_secrets(RetrySCID, 16#6b3343cf),
    {ExpectedCKey, _, _} = nquic_keys:derive_packet_protection(
        ExpectedCSecret, aes_128_gcm, 16#6b3343cf
    ),
    #{client := CRoleKeys} = Initial,
    ?assertEqual(ExpectedCKey, maps:get(key, CRoleKeys)).

packet_long_header_rtt0_test() ->
    DCID = <<1, 2, 3, 4>>,
    SCID = <<5, 6, 7, 8>>,
    PayloadLen = 50,
    Version = 1,
    FirstByte = 2#11010000,
    Bin =
        <<FirstByte, Version:32, (byte_size(DCID)):8, DCID/binary, (byte_size(SCID)):8, SCID/binary,
            (nquic_varint:encode(PayloadLen))/binary>>,
    {ok, Header, _} = nquic_packet:parse_header(Bin),
    ?assertEqual(rtt0, Header#long_header.type).

packet_long_header_handshake_test() ->
    DCID = <<1, 2, 3, 4>>,
    SCID = <<5, 6, 7, 8>>,
    PayloadLen = 50,
    Version = 1,
    FirstByte = 2#11100000,
    Bin =
        <<FirstByte, Version:32, (byte_size(DCID)):8, DCID/binary, (byte_size(SCID)):8, SCID/binary,
            (nquic_varint:encode(PayloadLen))/binary>>,
    {ok, Header, _} = nquic_packet:parse_header(Bin),
    ?assertEqual(handshake, Header#long_header.type).

packet_long_header_retry_test() ->
    DCID = <<1, 2, 3, 4>>,
    SCID = <<5, 6, 7, 8>>,
    PayloadLen = 50,
    Version = 1,
    FirstByte = 2#11110000,
    Bin =
        <<FirstByte, Version:32, (byte_size(DCID)):8, DCID/binary, (byte_size(SCID)):8, SCID/binary,
            (nquic_varint:encode(PayloadLen))/binary>>,
    {ok, Header, _} = nquic_packet:parse_header(Bin),
    ?assertEqual(retry, Header#long_header.type).

packet_encode_all_types_test() ->
    lists:foreach(
        fun(Type) ->
            Header = #long_header{
                type = Type,
                version = 1,
                dcid = <<1, 2, 3, 4>>,
                scid = <<5, 6, 7, 8>>,
                token =
                    case Type of
                        initial -> <<>>;
                        _ -> undefined
                    end,
                payload_len = 100,
                packet_number = 0
            },
            Encoded = nquic_packet:encode_header(Header),
            ?assert(is_binary(Encoded))
        end,
        [initial, rtt0, handshake, retry]
    ).

packet_short_header_key_phase_test() ->
    DCID = <<1, 2, 3, 4>>,
    Header = #short_header{dcid = DCID, packet_number = 0, key_phase = true},
    Encoded = nquic_packet:encode_header(Header),
    <<FirstByte:8, _/binary>> = Encoded,
    KeyPhaseBit = (FirstByte bsr 2) band 1,
    ?assertEqual(1, KeyPhaseBit).

packet_short_header_spin_bit_encoded_test() ->
    DCID = <<1, 2, 3, 4>>,
    Encoded0 = nquic_packet:encode_header(
        #short_header{dcid = DCID, packet_number = 0, spin = 0}
    ),
    Encoded1 = nquic_packet:encode_header(
        #short_header{dcid = DCID, packet_number = 0, spin = 1}
    ),
    <<First0:8, _/binary>> = Encoded0,
    <<First1:8, _/binary>> = Encoded1,
    ?assertEqual(0, First0 band 16#20),
    ?assertEqual(16#20, First1 band 16#20).

packet_short_header_spin_bit_extracted_test() ->
    H0 = #short_header{dcid = <<>>},
    H1 = nquic_packet:maybe_extract_key_phase(H0, 2#01100000),
    ?assertEqual(1, H1#short_header.spin),
    H2 = nquic_packet:maybe_extract_key_phase(H0, 2#01000000),
    ?assertEqual(0, H2#short_header.spin).

protocol_send_outgoing_spin_test() ->
    Off = #conn_state{role = client, spin_enabled = false, peer_spin = 1},
    ?assertEqual(0, nquic_protocol_send:outgoing_spin(Off)),
    Client = #conn_state{role = client, spin_enabled = true, peer_spin = 1},
    Server = #conn_state{role = server, spin_enabled = true, peer_spin = 1},
    ?assertEqual(1, nquic_protocol_send:outgoing_spin(Client)),
    ?assertEqual(0, nquic_protocol_send:outgoing_spin(Server)).

protocol_recv_peer_spin_tracks_largest_pn_test() ->
    State0 = #conn_state{
        role = server,
        spin_enabled = true,
        peer_spin = 0,
        app_largest_received = 5
    },
    H = #short_header{dcid = <<>>, spin = 1},
    State1 = nquic_protocol_recv:maybe_update_peer_spin(H, application, 6, State0),
    ?assertEqual(1, State1#conn_state.peer_spin),
    State2 = nquic_protocol_recv:maybe_update_peer_spin(H, application, 5, State1),
    ?assertEqual(1, State2#conn_state.peer_spin),
    State3 = nquic_protocol_recv:maybe_update_peer_spin(
        H#short_header{spin = 0}, application, 3, State1
    ),
    ?assertEqual(1, State3#conn_state.peer_spin).

protocol_recv_peer_spin_disabled_ignores_test() ->
    State0 = #conn_state{
        role = server,
        spin_enabled = false,
        peer_spin = 0,
        app_largest_received = 0
    },
    H = #short_header{dcid = <<>>, spin = 1},
    State1 = nquic_protocol_recv:maybe_update_peer_spin(H, application, 1, State0),
    ?assertEqual(0, State1#conn_state.peer_spin).

new_token_generate_validate_roundtrip_test() ->
    StaticKey = <<1:256>>,
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Token = nquic_new_token:generate(StaticKey, Peer, 3600),
    ?assertEqual(ok, nquic_new_token:validate(Token, StaticKey, Peer, 3600)).

new_token_wrong_addr_rejected_test() ->
    StaticKey = <<2:256>>,
    Issuer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Other = nquic_socket:make_sockaddr({127, 0, 0, 2}, 4433),
    Token = nquic_new_token:generate(StaticKey, Issuer, 3600),
    ?assertMatch({error, _}, nquic_new_token:validate(Token, StaticKey, Other, 3600)).

new_token_expired_rejected_test() ->
    StaticKey = <<3:256>>,
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Past = erlang:system_time(second) - 7200,
    Token = nquic_new_token:generate(StaticKey, Peer, 3600, Past),
    ?assertMatch({error, _}, nquic_new_token:validate(Token, StaticKey, Peer, 3600)).

new_token_wrong_key_rejected_test() ->
    K1 = <<4:256>>,
    K2 = <<5:256>>,
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Token = nquic_new_token:generate(K1, Peer, 3600),
    ?assertMatch({error, _}, nquic_new_token:validate(Token, K2, Peer, 3600)).

new_token_domain_separated_from_retry_test() ->
    StaticKey = <<6:256>>,
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    RetryToken = nquic_retry:generate_token(StaticKey, ODCID, Peer, 3600),
    ?assertMatch({error, _}, nquic_new_token:validate(RetryToken, StaticKey, Peer, 3600)),
    NewToken = nquic_new_token:generate(StaticKey, Peer, 3600),
    ?assertMatch({error, _}, nquic_retry:validate_token(NewToken, StaticKey, Peer, 3600)).

new_token_truncated_rejected_test() ->
    StaticKey = <<7:256>>,
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Token = nquic_new_token:generate(StaticKey, Peer, 3600),
    Truncated = binary:part(Token, 0, byte_size(Token) - 1),
    ?assertMatch({error, _}, nquic_new_token:validate(Truncated, StaticKey, Peer, 3600)).

new_token_protocol_recv_emits_event_test() ->
    State0 = #conn_state{role = client},
    Frame = #new_token{token = <<"deadbeef">>},
    Header = #short_header{dcid = <<>>},
    {ok, Events, _State1} = nquic_protocol_recv:handle_frame(Frame, Header, State0),
    ?assert(lists:member({new_token_received, <<"deadbeef">>}, Events)).

new_token_protocol_recv_server_rejects_test() ->
    State0 = #conn_state{role = server},
    Frame = #new_token{token = <<"x">>},
    Header = #short_header{dcid = <<>>},
    ?assertMatch(
        {error, {transport_error, protocol_violation}, _},
        nquic_protocol_recv:handle_frame(Frame, Header, State0)
    ).

token_cache_store_lookup_roundtrip_test() ->
    Name = nquic_test_token_cache_rt,
    nquic_token_cache:stop(Name),
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        ok = nquic_token_cache:store(Name, "example.com", 4433, <<"tok">>),
        ?assertEqual({ok, <<"tok">>}, nquic_token_cache:lookup(Name, "example.com", 4433))
    after
        nquic_token_cache:stop(Name)
    end.

token_cache_lookup_miss_test() ->
    Name = nquic_test_token_cache_miss,
    nquic_token_cache:stop(Name),
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        ?assertEqual(
            {error, not_found}, nquic_token_cache:lookup(Name, "nope.example", 4433)
        )
    after
        nquic_token_cache:stop(Name)
    end.

token_cache_delete_test() ->
    Name = nquic_test_token_cache_del,
    nquic_token_cache:stop(Name),
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        ok = nquic_token_cache:store(Name, "h", 1, <<"t">>),
        ?assertEqual({ok, <<"t">>}, nquic_token_cache:lookup(Name, "h", 1)),
        ok = nquic_token_cache:delete(Name, "h", 1),
        ?assertEqual({error, not_found}, nquic_token_cache:lookup(Name, "h", 1))
    after
        nquic_token_cache:stop(Name)
    end.

token_cache_clear_test() ->
    Name = nquic_test_token_cache_clear,
    nquic_token_cache:stop(Name),
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        ok = nquic_token_cache:store(Name, "h", 1, <<"a">>),
        ok = nquic_token_cache:store(Name, "h", 2, <<"b">>),
        ok = nquic_token_cache:clear(Name),
        ?assertEqual(0, nquic_token_cache:size(Name))
    after
        nquic_token_cache:stop(Name)
    end.

qlog_undefined_backend_is_noop_test() ->
    ?assertEqual(
        undefined,
        nquic_qlog:event(undefined, transport_packet_received, #{})
    ),
    ?assertEqual(ok, nquic_qlog:detach(undefined)).

qlog_attach_undefined_config_test() ->
    ?assertEqual({ok, undefined}, nquic_qlog:attach(<<0:64>>, undefined)).

qlog_file_backend_roundtrip_test() ->
    {ok, Dir} = file_tmp_dir("qlog_roundtrip"),
    try
        Path = filename:join(Dir, "trace.qlog"),
        CID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        {ok, QLog0} = nquic_qlog:attach(CID, {file, Path}),
        QLog1 = nquic_qlog:event(QLog0, transport_packet_received, #{
            packet_type => application,
            packet_number => 42
        }),
        _ = nquic_qlog:event(QLog1, transport_packet_received, #{
            packet_type => initial,
            packet_number => 0
        }),
        ok = nquic_qlog:detach(QLog1),
        {ok, Bin} = file:read_file(Path),
        Lines = binary:split(Bin, <<"\n">>, [global, trim_all]),
        ?assertMatch([_Header, _Ev1, _Ev2], Lines),
        [Header | _] = Lines,
        ?assertMatch({_, _}, binary:match(Header, <<"\"qlog_format\":\"JSON-SEQ\"">>)),
        ?assertMatch({_, _}, binary:match(Header, <<"\"ODCID\":\"0102030405060708\"">>)),
        [_, Ev1, _Ev2] = Lines,
        ?assertMatch({_, _}, binary:match(Ev1, <<"\"name\":\"transport_packet_received\"">>)),
        ?assertMatch({_, _}, binary:match(Ev1, <<"\"packet_number\":42">>))
    after
        rm_rf(Dir)
    end.

qlog_file_backend_directory_target_test() ->
    {ok, Dir} = file_tmp_dir("qlog_dir_target"),
    try
        CID = <<16#aa, 16#bb>>,
        {ok, QLog} = nquic_qlog:attach(CID, {file, Dir}),
        ok = nquic_qlog:detach(QLog),
        Expected = filename:join(Dir, "aabb.qlog"),
        ?assert(filelib:is_regular(Expected))
    after
        rm_rf(Dir)
    end.

file_tmp_dir(Prefix) ->
    Tmp = filename:join(
        "/tmp",
        lists:flatten(
            io_lib:format(
                "nquic_~s_~B_~B", [Prefix, erlang:system_time(microsecond), rand:uniform(1_000_000)]
            )
        )
    ),
    ok = filelib:ensure_path(Tmp),
    {ok, Tmp}.

rm_rf(Dir) ->
    case file:list_dir(Dir) of
        {ok, Names} ->
            lists:foreach(
                fun(N) ->
                    Path = filename:join(Dir, N),
                    case filelib:is_dir(Path) of
                        true -> rm_rf(Path);
                        false -> _ = file:delete(Path)
                    end
                end,
                Names
            );
        _ ->
            ok
    end,
    _ = file:del_dir(Dir),
    ok.

packet_incomplete_binary_test() ->
    Bin = <<16#C0, 0, 0, 0, 1, 8, 1, 2, 3>>,
    ?assertMatch({error, _}, nquic_packet:parse_header(Bin)).

stream_statem_multiple_sends_test() ->
    State0 = nquic_stream_statem:new(0, bidi),
    {ok, State1} = nquic_stream_statem:handle_send(State0, <<"first">>, false),
    {ok, State2} = nquic_stream_statem:handle_send(State1, <<"second">>, false),
    ?assertEqual(11, State2#stream_state.send_offset),
    ?assertEqual(11, State2#stream_state.pending_send_size),
    Pending = State2#stream_state.pending_send_data,
    ?assertEqual(<<"firstsecond">>, iolist_to_binary(lists:reverse(Pending))).

stream_statem_recv_non_stream_frame_test() ->
    State = nquic_stream_statem:new(0, bidi),
    {ok, State} = nquic_stream_statem:handle_recv(State, #ping{}),
    {ok, State} = nquic_stream_statem:handle_recv(State, #ack{
        largest_acknowledged = 0, delay = 0, first_ack_range = 0, ack_ranges = []
    }).

stream_statem_data_read_state_test() ->
    State = #stream_state{
        stream_id = 0,
        type = bidi,
        recv_state = data_read,
        recv_offset = 100,
        recv_buffer = gb_trees:empty(),
        app_buffer = []
    },
    Frame = #stream{offset = 50, data = <<"ignored">>, fin = false},
    {ok, State} = nquic_stream_statem:handle_recv(State, Frame).

stream_statem_duplicate_data_test() ->
    State = nquic_stream_statem:new(0, bidi),
    Frame = #stream{offset = 0, data = <<"hello">>, fin = false},
    {ok, State1} = nquic_stream_statem:handle_recv(State, Frame),
    {ok, State2} = nquic_stream_statem:handle_recv(State1, Frame),
    ?assertEqual(5, State2#stream_state.recv_offset).

loss_set_max_datagram_size_test() ->
    State = nquic_loss:init(),
    State1 = nquic_loss:set_max_datagram_size(State, 1400),
    Cwnd = nquic_loss:get_cwnd(State1),
    ?assert(Cwnd > 0).

loss_get_rtt_stats_test() ->
    State = nquic_loss:init(),
    Stats = nquic_loss:get_rtt_stats(State),
    ?assert(is_map(Stats)),
    ?assert(maps:is_key(smoothed_rtt, Stats)).

loss_non_ack_eliciting_test() ->
    State0 = nquic_loss:init(),
    Frames = [
        #padding{}, #ack{largest_acknowledged = 0, delay = 0, first_ack_range = 0, ack_ranges = []}
    ],
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames, 1000, 100),
    ?assertEqual(100, nquic_loss:get_bytes_in_flight(State1)).

loss_ack_no_packets_test() ->
    State = nquic_loss:init(),
    {ok, State1, Acked, Lost} = nquic_loss:on_ack_received(
        State, application, [{1, 3}], 0, 1000, 25_000
    ),
    ?assertEqual([], Acked),
    ?assertEqual([], Lost),
    ?assertEqual(State, State1).

loss_multiple_packets_test() ->
    State0 = nquic_loss:init(),
    Frames1 = [#ping{}],
    Frames2 = [#ping{}],
    Now = 1000,
    Size = 1000,

    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames1, Now, Size),
    State2 = nquic_loss:on_packet_sent(State1, application, 2, Frames2, Now + 100, Size),

    ?assertEqual(2000, nquic_loss:get_bytes_in_flight(State2)).

frame_max_streams_limit_test() ->
    LargeValue = 16#1000000000000000,
    LargeBin = nquic_varint:encode(LargeValue),
    Encoded = <<18, LargeBin/binary>>,
    ?assertMatch({error, frame_encoding_error}, nquic_frame:decode(Encoded)).

frame_new_connection_id_validation_test() ->
    SeqBin = nquic_varint:encode(5),
    RetireBin = nquic_varint:encode(10),
    CID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Token = crypto:strong_rand_bytes(16),
    Encoded = <<24, SeqBin/binary, RetireBin/binary, 8, CID/binary, Token/binary>>,
    ?assertMatch({error, frame_encoding_error}, nquic_frame:decode(Encoded)).

frame_new_connection_id_cid_length_test() ->
    SeqBin = nquic_varint:encode(1),
    RetireBin = nquic_varint:encode(0),
    Token = crypto:strong_rand_bytes(16),
    Encoded = <<24, SeqBin/binary, RetireBin/binary, 0, Token/binary>>,
    ?assertMatch({error, frame_encoding_error}, nquic_frame:decode(Encoded)).

flow_init_conn_limits_test() ->
    Local = #transport_params{initial_max_data = 100000},
    Remote = #transport_params{initial_max_data = 200000},
    ConnState = #conn_state{local_params = Local, remote_params = Remote},

    Initialized = nquic_flow:init_conn_limits(ConnState),

    ?assertEqual(100000, (Initialized#conn_state.flow)#conn_flow.local_max_data),
    ?assertEqual(200000, (Initialized#conn_state.flow)#conn_flow.remote_max_data),
    ?assertEqual(0, (Initialized#conn_state.flow)#conn_flow.data_sent),
    ?assertEqual(0, (Initialized#conn_state.flow)#conn_flow.data_received).

flow_init_conn_limits_no_remote_test() ->
    Local = #transport_params{initial_max_data = 100000},
    ConnState = #conn_state{local_params = Local, remote_params = undefined},

    Initialized = nquic_flow:init_conn_limits(ConnState),

    ?assertEqual(100000, (Initialized#conn_state.flow)#conn_flow.local_max_data),
    ?assertEqual(0, (Initialized#conn_state.flow)#conn_flow.remote_max_data).

flow_init_stream_limits_uni_test() ->
    Local = #transport_params{initial_max_stream_data_uni = 3000},
    Remote = #transport_params{initial_max_stream_data_uni = 6000},
    ConnState = #conn_state{local_params = Local, remote_params = Remote, role = client},
    StreamState = #stream_state{stream_id = 2},

    Initialized = nquic_flow:init_stream_limits(StreamState, ConnState, uni),

    ?assertEqual(6000, Initialized#stream_state.send_max_data),
    ?assertEqual(3000, Initialized#stream_state.recv_window).

flow_data_received_limit_exceeded_test() ->
    ConnState = #conn_state{flow = #conn_flow{data_received = 9500, local_max_data = 10000}},
    StreamState = #stream_state{stream_id = 0, recv_max_offset = 9500, recv_window = 100000},

    ?assertMatch(
        {error, flow_control_error},
        nquic_flow:on_stream_data_received(ConnState, StreamState, 9500, 600)
    ).

flow_stream_limit_exceeded_test() ->
    ConnState = #conn_state{flow = #conn_flow{data_received = 0, local_max_data = 100000}},
    StreamState = #stream_state{stream_id = 0, recv_max_offset = 900, recv_window = 1000},

    ?assertMatch(
        {error, flow_control_error},
        nquic_flow:on_stream_data_received(ConnState, StreamState, 900, 200)
    ).

rtt_min_rtt_test() ->
    State = nquic_rtt:new(),
    State1 = nquic_rtt:update(State, 100, 0),
    Stats1 = nquic_rtt:get(State1),
    ?assertEqual(100, maps:get(min_rtt, Stats1)),

    State2 = nquic_rtt:update(State1, 50, 0),
    Stats2 = nquic_rtt:get(State2),
    ?assertEqual(50, maps:get(min_rtt, Stats2)),

    State3 = nquic_rtt:update(State2, 200, 0),
    Stats3 = nquic_rtt:get(State3),
    ?assertEqual(50, maps:get(min_rtt, Stats3)).

cc_set_max_datagram_size_test() ->
    CC = nquic_cc:new(newreno),
    CC1 = nquic_cc:set_max_datagram_size(CC, 1400),
    ?assertEqual(1400, nquic_cc:get_max_datagram_size(CC1)).

cc_get_max_datagram_size_default_test() ->
    CC = nquic_cc:new(newreno),
    ?assertEqual(1200, nquic_cc:get_max_datagram_size(CC)).

cc_set_max_datagram_size_minimum_test() ->
    CC = nquic_cc:new(newreno),
    CC1 = nquic_cc:set_max_datagram_size(CC, 1200),
    ?assertEqual(1200, nquic_cc:get_max_datagram_size(CC1)).

keys_master_secrets_test() ->
    SharedSecret = crypto:strong_rand_bytes(32),
    TranscriptHash = crypto:hash(sha256, <<"test transcript">>),
    {Client, _Server, _} = nquic_keys:handshake_secrets(SharedSecret, TranscriptHash),

    TranscriptHash2 = crypto:hash(sha256, <<"full transcript">>),
    {ClientApp, ServerApp} = nquic_keys:master_secrets(Client, TranscriptHash2),

    ?assert(is_binary(ClientApp)),
    ?assert(is_binary(ServerApp)),
    ?assertEqual(32, byte_size(ClientApp)),
    ?assertEqual(32, byte_size(ServerApp)).

keys_qhkdf_expand_test() ->
    Secret = crypto:strong_rand_bytes(32),
    Label = <<"test label">>,
    Context = <<"context">>,

    Derived = nquic_keys:qhkdf_expand(Secret, Label, Context, 32),

    ?assert(is_binary(Derived)),
    ?assertEqual(32, byte_size(Derived)).

crypto_encrypt_decrypt_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    AAD = <<"additional auth data">>,
    Plaintext = <<"secret message">>,
    PN = 0,

    {Ciphertext, Tag} = nquic_crypto:encrypt(aes_128_gcm, Key, IV, PN, AAD, Plaintext),
    CiphertextWithTag = <<Ciphertext/binary, Tag/binary>>,

    Result = nquic_crypto:decrypt(aes_128_gcm, Key, IV, PN, AAD, CiphertextWithTag),

    ?assertEqual(Plaintext, Result).

crypto_decrypt_wrong_key_test() ->
    Key = crypto:strong_rand_bytes(16),
    WrongKey = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    AAD = <<"aad">>,
    Plaintext = <<"message">>,
    PN = 0,

    {Ciphertext, Tag} = nquic_crypto:encrypt(aes_128_gcm, Key, IV, PN, AAD, Plaintext),
    CiphertextWithTag = <<Ciphertext/binary, Tag/binary>>,

    Result = nquic_crypto:decrypt(aes_128_gcm, WrongKey, IV, PN, AAD, CiphertextWithTag),

    ?assertMatch({error, _}, Result).

-spec minimal_protocol_state() -> #conn_state{}.
minimal_protocol_state() ->
    #conn_state{
        role = client,
        scid = <<0:64>>,
        dcid = <<1:64>>,
        streams_state = #conn_streams{
            next_bidi_stream = 0,
            next_uni_stream = 2,
            peer_max_streams_bidi = 100,
            peer_max_streams_uni = 100,
            local_max_streams_bidi = 100,
            local_max_streams_uni = 100
        },
        flow = #conn_flow{
            local_max_data = 16777216,
            remote_max_data = 16777216,
            data_sent = 0,
            data_received = 0,
            pending_app_frames = []
        },
        pn_spaces = #{application => #{next_pn => 0}},
        loss_state = nquic_loss:init()
    }.

-spec minimal_protocol_state_with_stream(
    nquic:stream_id(), bidi | uni, ready | send | data_sent | data_recvd | reset_sent
) -> #conn_state{}.
minimal_protocol_state_with_stream(StreamID, Type, SendState) ->
    Stream = nquic_stream_statem:new(StreamID, Type),
    Stream1 = Stream#stream_state{send_state = SendState},
    State = minimal_protocol_state(),
    SS0 = State#conn_state.streams_state,
    State#conn_state{
        streams_state = SS0#conn_streams{
            streams = #{StreamID => Stream1},
            next_bidi_stream = 4,
            next_uni_stream = 6
        }
    }.

protocol_send_stream_conn_flow_blocked_test() ->
    State0 = minimal_protocol_state(),
    {ok, StreamID, State1} = nquic_protocol:open_stream(#{type => bidi}, State0),
    Flow0 = State1#conn_state.flow,
    State2 = State1#conn_state{
        flow = Flow0#conn_flow{remote_max_data = 0, data_sent = 0}
    },
    Result = nquic_protocol:send_stream(StreamID, <<"data">>, nofin, State2),
    ?assertMatch({error, {conn_flow_control_blocked, _}, _}, Result),
    {error, _, State3} = Result,
    ?assert(maps:is_key(StreamID, (State3#conn_state.streams_state)#conn_streams.blocked_streams)).

protocol_send_stream_stream_flow_blocked_test() ->
    State0 = minimal_protocol_state(),
    {ok, StreamID, State1} = nquic_protocol:open_stream(#{type => bidi}, State0),
    Streams = (State1#conn_state.streams_state)#conn_streams.streams,
    #{StreamID := Stream} = Streams,
    Stream1 = Stream#stream_state{send_max_data = 0},
    SS0 = State1#conn_state.streams_state,
    State2 = State1#conn_state{
        streams_state = SS0#conn_streams{streams = Streams#{StreamID => Stream1}}
    },
    Result = nquic_protocol:send_stream(StreamID, <<"data">>, nofin, State2),
    ?assertMatch({error, {stream_flow_control_blocked, _}, _}, Result),
    {error, _, State3} = Result,
    ?assert(maps:is_key(StreamID, (State3#conn_state.streams_state)#conn_streams.blocked_streams)).

protocol_open_stream_bidi_limit_test() ->
    State = minimal_protocol_state(),
    SS0 = State#conn_state.streams_state,
    State1 = State#conn_state{
        streams_state = SS0#conn_streams{peer_max_streams_bidi = 0}
    },
    ?assertEqual({error, stream_limit_error}, nquic_protocol:open_stream(#{type => bidi}, State1)).

protocol_open_stream_uni_limit_test() ->
    State = minimal_protocol_state(),
    SS0 = State#conn_state.streams_state,
    State1 = State#conn_state{
        streams_state = SS0#conn_streams{peer_max_streams_uni = 0}
    },
    ?assertEqual({error, stream_limit_error}, nquic_protocol:open_stream(#{type => uni}, State1)).

protocol_open_stream_bidi_success_test() ->
    State = minimal_protocol_state(),
    {ok, StreamID, State1} = nquic_protocol:open_stream(#{type => bidi}, State),
    ?assertEqual(0, StreamID),
    ?assert(maps:is_key(0, (State1#conn_state.streams_state)#conn_streams.streams)),
    ?assertEqual(4, (State1#conn_state.streams_state)#conn_streams.next_bidi_stream).

protocol_open_stream_uni_success_test() ->
    State = minimal_protocol_state(),
    {ok, StreamID, State1} = nquic_protocol:open_stream(#{type => uni}, State),
    ?assertEqual(2, StreamID),
    ?assert(maps:is_key(2, (State1#conn_state.streams_state)#conn_streams.streams)),
    ?assertEqual(6, (State1#conn_state.streams_state)#conn_streams.next_uni_stream).

protocol_close_stream_already_closed_test() ->
    State = minimal_protocol_state_with_stream(0, bidi, data_sent),
    Result = nquic_protocol:close_stream(0, State),
    ?assertEqual({error, stream_closed}, Result).

protocol_reset_stream_not_found_test() ->
    State = minimal_protocol_state(),
    ?assertEqual(
        {error, unknown_stream},
        nquic_protocol:reset_stream(99, 1, State)
    ).

protocol_reset_stream_already_reset_test() ->
    State = minimal_protocol_state_with_stream(0, bidi, reset_sent),
    {ok, _State1} = nquic_protocol:reset_stream(0, 1, State).

protocol_reset_stream_data_recvd_test() ->
    State = minimal_protocol_state_with_stream(0, bidi, data_recvd),
    {ok, _State1} = nquic_protocol:reset_stream(0, 1, State).

protocol_reset_stream_active_test() ->
    State = minimal_protocol_state_with_stream(0, bidi, send),
    {ok, State1} = nquic_protocol:reset_stream(0, 42, State),
    #{0 := Stream} = (State1#conn_state.streams_state)#conn_streams.streams,
    ?assertEqual(reset_sent, Stream#stream_state.send_state),
    ?assertMatch([#reset_stream{} | _], (State1#conn_state.flow)#conn_flow.pending_app_frames).

protocol_read_stream_not_found_test() ->
    State = minimal_protocol_state(),
    ?assertEqual({error, stream_not_found}, nquic_protocol:read_stream(99, State)).

protocol_read_stream_no_data_test() ->
    Stream = nquic_stream_statem:new(0, bidi),
    State = minimal_protocol_state(),
    SS0 = State#conn_state.streams_state,
    State1 = State#conn_state{streams_state = SS0#conn_streams{streams = #{0 => Stream}}},
    ?assertEqual({error, no_data}, nquic_protocol:read_stream(0, State1)).

protocol_read_stream_with_data_test() ->
    Stream = nquic_stream_statem:new(0, bidi),
    Stream1 = Stream#stream_state{
        app_buffer = [<<"hello">>],
        app_buffer_size = 5,
        recv_state = recv
    },
    State = minimal_protocol_state(),
    SS0 = State#conn_state.streams_state,
    State1 = State#conn_state{streams_state = SS0#conn_streams{streams = #{0 => Stream1}}},
    {ok, Data, IsFin, _State2} = nquic_protocol:read_stream(0, State1),
    ?assertEqual(<<"hello">>, Data),
    ?assertNot(IsFin).

protocol_read_stream_with_fin_test() ->
    Stream = nquic_stream_statem:new(0, bidi),
    Stream1 = Stream#stream_state{
        app_buffer = [<<"done">>],
        app_buffer_size = 4,
        recv_state = data_recvd
    },
    State = minimal_protocol_state(),
    SS0 = State#conn_state.streams_state,
    State1 = State#conn_state{streams_state = SS0#conn_streams{streams = #{0 => Stream1}}},
    {ok, Data, IsFin, State2} = nquic_protocol:read_stream(0, State1),
    ?assertEqual(<<"done">>, Data),
    ?assert(IsFin),
    #{0 := Stream2} = (State2#conn_state.streams_state)#conn_streams.streams,
    ?assertEqual(data_read, Stream2#stream_state.recv_state).

protocol_read_stream_fin_no_data_test() ->
    Stream = nquic_stream_statem:new(0, bidi),
    Stream1 = Stream#stream_state{
        app_buffer = [],
        app_buffer_size = 0,
        recv_state = data_recvd
    },
    State = minimal_protocol_state(),
    SS0 = State#conn_state.streams_state,
    State1 = State#conn_state{streams_state = SS0#conn_streams{streams = #{0 => Stream1}}},
    {ok, Data, IsFin, _State2} = nquic_protocol:read_stream(0, State1),
    ?assertEqual(<<>>, Data),
    ?assert(IsFin).

data_blocked_triggers_max_data_test() ->
    Window = 16777216,
    S0 = minimal_protocol_state(),
    Flow0 = S0#conn_state.flow,
    S1 = S0#conn_state{
        flow = Flow0#conn_flow{local_max_data = Window, data_received = Window}
    },
    Header = #short_header{dcid = <<>>},
    {ok, [], S2} = nquic_protocol_recv:handle_frame(
        #data_blocked{limit = Window}, Header, S1
    ),
    Expected = Window + Window,
    ?assertEqual(
        [#max_data{max_data = Expected}],
        (S2#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(Expected, (S2#conn_state.flow)#conn_flow.local_max_data).

data_blocked_below_current_still_grants_test() ->
    Window = 16777216,
    S0 = minimal_protocol_state(),
    Header = #short_header{dcid = <<>>},
    {ok, [], S1} = nquic_protocol_recv:handle_frame(
        #data_blocked{limit = 1000}, Header, S0
    ),
    Expected = 1000 + Window,
    ?assertEqual(
        [#max_data{max_data = Expected}],
        (S1#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(Expected, (S1#conn_state.flow)#conn_flow.local_max_data).

data_blocked_always_grants_window_above_peer_test() ->
    Window = 16777216,
    S0 = minimal_protocol_state(),
    Header = #short_header{dcid = <<>>},
    {ok, [], S1} = nquic_protocol_recv:handle_frame(
        #data_blocked{limit = Window}, Header, S0
    ),
    Expected = Window + Window,
    ?assertEqual(
        [#max_data{max_data = Expected}],
        (S1#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assert(Expected > Window).

stream_data_blocked_triggers_max_stream_data_test() ->
    Window = 1048576,
    S0 = minimal_protocol_state(),
    Stream = (nquic_stream_statem:new(0, bidi))#stream_state{
        recv_window = Window, recv_max_offset = Window
    },
    SS0 = S0#conn_state.streams_state,
    S1 = S0#conn_state{streams_state = SS0#conn_streams{streams = #{0 => Stream}}},
    Header = #short_header{dcid = <<>>},
    {ok, [], S2} = nquic_protocol_recv:handle_frame(
        #stream_data_blocked{stream_id = 0, limit = Window}, Header, S1
    ),
    Expected = Window + Window,
    ?assertEqual(
        [#max_stream_data{stream_id = 0, max_stream_data = Expected}],
        (S2#conn_state.flow)#conn_flow.pending_app_frames
    ),
    #{0 := S2Stream} = (S2#conn_state.streams_state)#conn_streams.streams,
    ?assertEqual(Expected, S2Stream#stream_state.recv_window).

stream_data_blocked_unknown_stream_noop_test() ->
    S0 = minimal_protocol_state(),
    Header = #short_header{dcid = <<>>},
    {ok, [], S1} = nquic_protocol_recv:handle_frame(
        #stream_data_blocked{stream_id = 40, limit = 100}, Header, S0
    ),
    ?assertEqual([], (S1#conn_state.flow)#conn_flow.pending_app_frames).

read_stream_reader_driven_max_data_test() ->
    S0 = minimal_protocol_state(),
    Flow0 = S0#conn_state.flow,
    S1 = S0#conn_state{
        flow = Flow0#conn_flow{local_max_data = 16777216, data_received = 16777216}
    },
    Stream = (nquic_stream_statem:new(0, bidi))#stream_state{
        app_buffer = [<<"hi">>], app_buffer_size = 2, recv_state = recv
    },
    SS0 = S1#conn_state.streams_state,
    S2 = S1#conn_state{streams_state = SS0#conn_streams{streams = #{0 => Stream}}},
    {ok, <<"hi">>, false, S3} = nquic_protocol:read_stream(0, S2),
    ?assertEqual(
        [#max_data{max_data = 50331648}],
        (S3#conn_state.flow)#conn_flow.pending_app_frames
    ).

send_blocked_conn_emits_data_blocked_test() ->
    S0 = minimal_protocol_state(),
    Flow0 = S0#conn_state.flow,
    S1 = S0#conn_state{flow = Flow0#conn_flow{remote_max_data = 5, data_sent = 0}},
    {error, {conn_flow_control_blocked, 5}, S2} =
        nquic_protocol:send_stream(0, <<"hello world">>, fin, S1),
    ?assertEqual(
        [#data_blocked{limit = 5}],
        (S2#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(5, (S2#conn_state.flow)#conn_flow.last_data_blocked),
    {error, {conn_flow_control_blocked, 5}, S3} =
        nquic_protocol:send_stream(0, <<"hello world">>, fin, S2),
    ?assertEqual(
        [#data_blocked{limit = 5}],
        (S3#conn_state.flow)#conn_flow.pending_app_frames
    ).

signal_blocked_stream_dedup_test() ->
    S0 = minimal_protocol_state(),
    Stream = nquic_stream_statem:new(0, bidi),
    SS0 = S0#conn_state.streams_state,
    S1 = S0#conn_state{streams_state = SS0#conn_streams{streams = #{0 => Stream}}},
    S2 = nquic_protocol_streams:signal_blocked(stream_flow_control_blocked, 100, 0, S1),
    ?assertEqual(
        [#stream_data_blocked{stream_id = 0, limit = 100}],
        (S2#conn_state.flow)#conn_flow.pending_app_frames
    ),
    #{0 := St2} = (S2#conn_state.streams_state)#conn_streams.streams,
    ?assertEqual(100, St2#stream_state.last_stream_data_blocked),
    S3 = nquic_protocol_streams:signal_blocked(stream_flow_control_blocked, 100, 0, S2),
    ?assertEqual(
        [#stream_data_blocked{stream_id = 0, limit = 100}],
        (S3#conn_state.flow)#conn_flow.pending_app_frames
    ),
    S4 = nquic_protocol_streams:signal_blocked(stream_flow_control_blocked, 200, 0, S3),
    ?assertEqual(
        [
            #stream_data_blocked{stream_id = 0, limit = 200},
            #stream_data_blocked{stream_id = 0, limit = 100}
        ],
        (S4#conn_state.flow)#conn_flow.pending_app_frames
    ).

protocol_initiate_key_update_pending_test() ->
    State = minimal_protocol_state(),
    Crypto0 = State#conn_state.crypto,
    State1 = State#conn_state{crypto = Crypto0#conn_crypto{key_update_pending = true}},
    ?assertEqual(
        {error, key_update_pending}, nquic_protocol_key_update:initiate_key_update(State1)
    ).

protocol_close_queues_frame_test() ->
    State = (minimal_protocol_state())#conn_state{crypto = #conn_crypto{app_send_keys = #{}}},
    {ok, State1} = nquic_protocol:close(0, <<"goodbye">>, State),
    ?assertMatch(
        [#connection_close{error_code = 0, is_application = false} | _],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ).

protocol_close_app_queues_frame_test() ->
    State = minimal_protocol_state(),
    {ok, State1} = nquic_protocol:close_app(42, <<"app error">>, State),
    ?assertMatch(
        [#connection_close{error_code = 42, is_application = true} | _],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ).

protocol_info_test() ->
    State = minimal_protocol_state(),
    Info = nquic_protocol:info(established, State),
    ?assertEqual(established, maps:get(state, Info)),
    ?assertEqual(client, maps:get(role, Info)),
    ?assert(maps:is_key(rtt, Info)),
    ?assert(maps:is_key(cwnd, Info)),
    ?assert(maps:is_key(streams_open, Info)).

protocol_peer_test() ->
    State = minimal_protocol_state(),
    ?assertEqual(undefined, nquic_protocol:peer(State)),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    State1 = State#conn_state{peer = Peer},
    ?assertEqual(Peer, nquic_protocol:peer(State1)).

protocol_local_cids_test() ->
    State = minimal_protocol_state(),
    CID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Path0 = State#conn_state.path,
    State1 = State#conn_state{path = Path0#conn_path_mgmt{local_cids = #{0 => CID}}},
    ?assertEqual([CID], nquic_protocol:local_cids(State1)).

protocol_pending_stream_ids_empty_test() ->
    State = minimal_protocol_state(),
    ?assertEqual([], nquic_protocol:pending_stream_ids(State)).

protocol_pending_stream_ids_peer_only_test() ->
    Stream = nquic_stream_statem:new(1, bidi),
    Stream1 = Stream#stream_state{app_buffer = [<<"x">>], app_buffer_size = 1},
    LocalStream = nquic_stream_statem:new(0, bidi),
    LocalStream1 = LocalStream#stream_state{app_buffer = [<<"y">>], app_buffer_size = 1},
    State = minimal_protocol_state(),
    SS0 = State#conn_state.streams_state,
    State1 = State#conn_state{
        streams_state = SS0#conn_streams{streams = #{1 => Stream1, 0 => LocalStream1}}
    },
    Ids = nquic_protocol:pending_stream_ids(State1),
    ?assertEqual([1], Ids).

protocol_handle_timeout_ack_delay_with_pending_test() ->
    State = minimal_protocol_state(),
    State1 = State#conn_state{
        pending_ack_count = 2,
        pn_spaces = #{
            application => #{
                next_pn => 0,
                largest_received => 5,
                received_ranges => [{5, 3}]
            }
        }
    },
    {ok, [], State2, []} = nquic_protocol:handle_timeout(ack_delay, State1),
    ?assertEqual(0, State2#conn_state.pending_ack_count).

protocol_handle_timeout_ack_delay_no_pending_test() ->
    State = minimal_protocol_state(),
    State1 = State#conn_state{pending_ack_count = 0},
    {ok, [], State1, []} = nquic_protocol:handle_timeout(ack_delay, State1).

protocol_flush_empty_test() ->
    State = minimal_protocol_state(),
    ?assertMatch({ok, _}, nquic_protocol:flush(State)).

protocol_new_token_server_error_test() ->
    State = minimal_protocol_state(),
    State1 = State#conn_state{role = server},
    Header = #short_header{dcid = <<>>, packet_number = 0},
    ?assertMatch(
        {error, {transport_error, protocol_violation}, _},
        nquic_protocol_recv:handle_frame(#new_token{token = <<"t">>}, Header, State1)
    ).

protocol_new_token_client_ok_test() ->
    State = minimal_protocol_state(),
    Header = #short_header{dcid = <<>>, packet_number = 0},
    ?assertMatch(
        {ok, [{new_token_received, <<"t">>}], _},
        nquic_protocol_recv:handle_frame(#new_token{token = <<"t">>}, Header, State)
    ).

protocol_handshake_done_server_error_test() ->
    State = minimal_protocol_state(),
    State1 = State#conn_state{role = server},
    Header = #short_header{dcid = <<>>, packet_number = 0},
    ?assertMatch(
        {error, {transport_error, protocol_violation}, _},
        nquic_protocol_recv:handle_frame(#handshake_done{}, Header, State1)
    ).

protocol_path_challenge_handshake_error_test() ->
    State = minimal_protocol_state(),
    Header = #long_header{type = handshake, version = 1, dcid = <<>>, scid = <<>>},
    ?assertMatch(
        {error, {transport_error, protocol_violation}, _},
        nquic_protocol_recv:handle_frame(
            #path_challenge{data = <<1:64>>}, Header, State
        )
    ).

protocol_find_cid_seq_found_test() ->
    CID = <<1, 2, 3, 4>>,
    PeerCids = #{0 => #{cid => CID, token => <<>>}, 1 => #{cid => <<5, 6>>, token => <<>>}},
    ?assertEqual(0, nquic_protocol_cid:find_cid_seq(CID, PeerCids)).

protocol_find_cid_seq_not_found_test() ->
    PeerCids = #{0 => #{cid => <<1, 2>>, token => <<>>}},
    ?assertEqual(undefined, nquic_protocol_cid:find_cid_seq(<<9, 9>>, PeerCids)).

protocol_retire_peer_cids_test() ->
    PeerCids = #{
        0 => #{cid => <<1>>, token => <<>>},
        1 => #{cid => <<2>>, token => <<>>},
        2 => #{cid => <<3>>, token => <<>>}
    },
    {Retired, Remaining} = nquic_protocol_cid:retire_peer_cids(2, PeerCids),
    ?assertEqual(1, maps:size(Remaining)),
    ?assert(maps:is_key(2, Remaining)),
    ?assertEqual(2, length(Retired)).

track_ecn_mark_not_ect_noop_test() ->
    State = #conn_state{pn_spaces = #{application => #{next_pn => 0}}},
    State2 = nquic_protocol_ack:track_ecn_mark(application, not_ect, State),
    SpaceMap = maps:get(application, State2#conn_state.pn_spaces),
    ?assertEqual(0, maps:get(ecn_ect0, SpaceMap, 0)),
    ?assertEqual(0, maps:get(ecn_ect1, SpaceMap, 0)),
    ?assertEqual(0, maps:get(ecn_ce, SpaceMap, 0)).

track_ecn_mark_ect0_test() ->
    State = #conn_state{pn_spaces = #{application => #{next_pn => 0}}},
    State2 = nquic_protocol_ack:track_ecn_mark(application, ect0, State),
    SpaceMap = maps:get(application, State2#conn_state.pn_spaces),
    ?assertEqual(1, maps:get(ecn_ect0, SpaceMap)),
    ?assertEqual(0, maps:get(ecn_ect1, SpaceMap, 0)).

track_ecn_mark_ect1_test() ->
    State = #conn_state{pn_spaces = #{application => #{next_pn => 0}}},
    State2 = nquic_protocol_ack:track_ecn_mark(application, ect1, State),
    SpaceMap = maps:get(application, State2#conn_state.pn_spaces),
    ?assertEqual(1, maps:get(ecn_ect1, SpaceMap)).

track_ecn_mark_ce_test() ->
    State = #conn_state{pn_spaces = #{application => #{next_pn => 0}}},
    State2 = nquic_protocol_ack:track_ecn_mark(application, ce, State),
    SpaceMap = maps:get(application, State2#conn_state.pn_spaces),
    ?assertEqual(1, maps:get(ecn_ce, SpaceMap)).

track_ecn_mark_accumulates_test() ->
    State0 = #conn_state{pn_spaces = #{application => #{next_pn => 0}}},
    State1 = nquic_protocol_ack:track_ecn_mark(application, ect0, State0),
    State2 = nquic_protocol_ack:track_ecn_mark(application, ect0, State1),
    State3 = nquic_protocol_ack:track_ecn_mark(application, ce, State2),
    SpaceMap = maps:get(application, State3#conn_state.pn_spaces),
    ?assertEqual(2, maps:get(ecn_ect0, SpaceMap)),
    ?assertEqual(0, maps:get(ecn_ect1, SpaceMap, 0)),
    ?assertEqual(1, maps:get(ecn_ce, SpaceMap)).

track_ecn_mark_per_space_test() ->
    State0 = #conn_state{
        pn_spaces = #{
            initial => #{next_pn => 0},
            application => #{next_pn => 0}
        }
    },
    State1 = nquic_protocol_ack:track_ecn_mark(initial, ect0, State0),
    State2 = nquic_protocol_ack:track_ecn_mark(application, ce, State1),
    InitMap = maps:get(initial, State2#conn_state.pn_spaces),
    AppMap = maps:get(application, State2#conn_state.pn_spaces),
    ?assertEqual(1, maps:get(ecn_ect0, InitMap)),
    ?assertEqual(0, maps:get(ecn_ce, InitMap, 0)),
    ?assertEqual(0, maps:get(ecn_ect0, AppMap, 0)),
    ?assertEqual(1, maps:get(ecn_ce, AppMap)).

build_ack_ecn_none_test() ->
    State = #conn_state{
        pn_spaces = #{
            application => #{
                next_pn => 1,
                largest_received => 5,
                received_ranges => [{5, 0}]
            }
        }
    },
    {ok, Ack} = nquic_protocol_ack:build_ack_for_space(application, State),
    ?assertEqual(undefined, Ack#ack.ecn_counts).

build_ack_ecn_present_test() ->
    State = #conn_state{
        pn_spaces = #{
            application => #{
                next_pn => 1,
                largest_received => 5,
                received_ranges => [{5, 0}],
                ecn_ect0 => 10,
                ecn_ect1 => 2,
                ecn_ce => 1
            }
        }
    },
    {ok, Ack} = nquic_protocol_ack:build_ack_for_space(application, State),
    ?assertEqual({10, 2, 1}, Ack#ack.ecn_counts).

build_ack_ecn_zero_undefined_test() ->
    State = #conn_state{
        pn_spaces = #{
            application => #{
                next_pn => 1,
                largest_received => 3,
                received_ranges => [{3, 0}],
                ecn_ect0 => 0,
                ecn_ect1 => 0,
                ecn_ce => 0
            }
        }
    },
    {ok, Ack} = nquic_protocol_ack:build_ack_for_space(application, State),
    ?assertEqual(undefined, Ack#ack.ecn_counts).

ack_ecn_encode_decode_roundtrip_test() ->
    Frame = #ack{
        largest_acknowledged = 100,
        delay = 5,
        first_ack_range = 10,
        ack_ranges = [],
        ecn_counts = {50, 3, 1}
    },
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    <<3, _/binary>> = Encoded,
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(100, Decoded#ack.largest_acknowledged),
    ?assertEqual({50, 3, 1}, Decoded#ack.ecn_counts).

ack_no_ecn_encode_decode_roundtrip_test() ->
    Frame = #ack{
        largest_acknowledged = 100,
        delay = 5,
        first_ack_range = 10,
        ack_ranges = [],
        ecn_counts = undefined
    },
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    <<2, _/binary>> = Encoded,
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(100, Decoded#ack.largest_acknowledged),
    ?assertEqual(undefined, Decoded#ack.ecn_counts).

recv_msg_now_test() ->
    {ok, Socket} = nquic_socket:open(#{ecn => true}),
    {ok, Port} = nquic_socket:port(Socket),
    {ok, Sender} = nquic_socket:open(#{}),
    Dest = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port),
    ok = nquic_socket:send(Sender, Dest, <<"test">>),
    timer:sleep(10),
    case nquic_socket:recv_msg_now(Socket) of
        {ok, {_Source, Data, Ctrl}} ->
            ?assertEqual(<<"test">>, Data),
            ?assert(is_list(Ctrl));
        {select, _} ->
            timer:sleep(50),
            {ok, {_Source, Data, Ctrl}} = nquic_socket:recv_msg_now(Socket),
            ?assertEqual(<<"test">>, Data),
            ?assert(is_list(Ctrl))
    end,
    nquic_socket:close(Socket),
    nquic_socket:close(Sender).

recv_socket_options_ecn_test() ->
    Opts = nquic_recv:socket_options(#{ecn => true}),
    ?assertEqual(true, maps:get(ecn, Opts)).

recv_socket_options_no_ecn_test() ->
    Opts = nquic_recv:socket_options(#{}),
    ?assertNot(maps:is_key(ecn, Opts)).

ecn_process_undefined_test() ->
    State = nquic_loss:init(),
    State2 = nquic_loss:process_ecn_counts(State, application, undefined),
    ?assertEqual(nquic_loss:get_cwnd(State), nquic_loss:get_cwnd(State2)).

ecn_process_first_no_ce_test() ->
    State = nquic_loss:init(),
    State2 = nquic_loss:process_ecn_counts(State, application, {10, 0, 0}),
    ?assertEqual(nquic_loss:get_cwnd(State), nquic_loss:get_cwnd(State2)).

ecn_ce_increase_reduces_cwnd_test() ->
    State0 = nquic_loss:init(),
    State1 = nquic_loss:process_ecn_counts(State0, application, {5, 0, 0}),
    CwndBefore = nquic_loss:get_cwnd(State1),
    State2 = nquic_loss:process_ecn_counts(State1, application, {8, 0, 1}),
    CwndAfter = nquic_loss:get_cwnd(State2),
    ?assert(CwndAfter < CwndBefore).

ecn_ce_same_no_reduce_test() ->
    State0 = nquic_loss:init(),
    State1 = nquic_loss:process_ecn_counts(State0, application, {5, 0, 2}),
    CwndBefore = nquic_loss:get_cwnd(State1),
    State2 = nquic_loss:process_ecn_counts(State1, application, {8, 0, 2}),
    CwndAfter = nquic_loss:get_cwnd(State2),
    ?assertEqual(CwndBefore, CwndAfter).

ecn_validation_failure_disables_test() ->
    State0 = nquic_loss:init(),
    State1 = nquic_loss:set_ecn_enabled(State0, true),
    State2 = nquic_loss:process_ecn_counts(State1, application, {5, 3, 2}),
    ?assert(nquic_loss:is_ecn_enabled(State2)),
    State3 = nquic_loss:process_ecn_counts(State2, application, {4, 2, 2}),
    ?assertNot(nquic_loss:is_ecn_enabled(State3)).

ecn_per_space_isolation_test() ->
    State0 = nquic_loss:init(),
    State1 = nquic_loss:process_ecn_counts(State0, initial, {3, 0, 1}),
    State2 = nquic_loss:process_ecn_counts(State1, application, {5, 0, 0}),
    CwndAfterCE = nquic_loss:get_cwnd(State1),
    CwndAfterNoCE = nquic_loss:get_cwnd(State2),
    ?assertEqual(CwndAfterCE, CwndAfterNoCE).

ecn_enabled_toggle_test() ->
    State0 = nquic_loss:init(),
    ?assert(nquic_loss:is_ecn_enabled(State0)),
    State1 = nquic_loss:set_ecn_enabled(State0, false),
    ?assertNot(nquic_loss:is_ecn_enabled(State1)),
    State2 = nquic_loss:set_ecn_enabled(State1, true),
    ?assert(nquic_loss:is_ecn_enabled(State2)).

path_stats_initial_test() ->
    State = nquic_loss:init(),
    Stats = nquic_loss:path_stats(State),
    ?assertEqual(0, maps:get(bytes_in_flight, Stats)),
    ?assertEqual(0, maps:get(pto_count, Stats)),
    ?assertEqual(true, maps:get(ecn_enabled, Stats)),
    ?assertEqual(0, maps:get(peer_ecn_ce, Stats)),
    ?assertEqual(0, maps:get(peer_ecn_total, Stats)),
    ?assert(maps:get(cwnd, Stats) > 0),
    ?assert(maps:get(mss, Stats) >= 1200).

path_stats_bytes_in_flight_test() ->
    State0 = nquic_loss:init(),
    Frame = #ping{},
    State1 = nquic_loss:on_packet_sent(State0, application, 0, [Frame], 0, 100),
    State2 = nquic_loss:on_packet_sent(State1, application, 1, [Frame], 1000, 100),
    Stats = nquic_loss:path_stats(State2),
    ?assertEqual(200, maps:get(bytes_in_flight, Stats)).

path_stats_ecn_counters_summed_test() ->
    State0 = nquic_loss:init(),
    State1 = nquic_loss:process_ecn_counts(State0, application, {3, 0, 1}),
    State2 = nquic_loss:process_ecn_counts(State1, handshake, {2, 0, 1}),
    Stats = nquic_loss:path_stats(State2),
    ?assertEqual(2, maps:get(peer_ecn_ce, Stats)),
    ?assertEqual(7, maps:get(peer_ecn_total, Stats)).

datagram_frame_roundtrip_test() ->
    Frame = #datagram{data = <<"hello datagram">>},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    ?assertMatch(
        {ok, #datagram{data = <<"hello datagram">>}, <<>>},
        nquic_frame:decode(Encoded)
    ).

datagram_frame_empty_data_test() ->
    Frame = #datagram{data = <<>>},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    ?assertMatch(
        {ok, #datagram{data = <<>>}, <<>>},
        nquic_frame:decode(Encoded)
    ).

datagram_frame_large_data_test() ->
    Data = crypto:strong_rand_bytes(1200),
    Frame = #datagram{data = Data},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
    ?assertEqual(Data, Decoded#datagram.data).

datagram_no_length_decode_test() ->
    Bin = <<16#30, "payload">>,
    ?assertMatch(
        {ok, #datagram{data = <<"payload">>}, <<>>},
        nquic_frame:decode(Bin)
    ).

datagram_with_length_trailing_test() ->
    Data = <<"test">>,
    Trailing = <<"extra">>,
    Encoded = iolist_to_binary([<<16#31>>, nquic_varint:encode(4), Data, Trailing]),
    ?assertMatch(
        {ok, #datagram{data = <<"test">>}, <<"extra">>},
        nquic_frame:decode(Encoded)
    ).

datagram_transport_param_roundtrip_test() ->
    SCID = <<1, 2, 3, 4>>,
    Params = #transport_params{
        initial_source_connection_id = SCID,
        original_destination_connection_id = <<5, 6, 7, 8>>,
        max_datagram_frame_size = 1200
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),
    ?assertEqual(1200, Decoded#transport_params.max_datagram_frame_size).

datagram_transport_param_undefined_test() ->
    SCID = <<1, 2, 3, 4>>,
    Params = #transport_params{
        initial_source_connection_id = SCID,
        original_destination_connection_id = <<5, 6, 7, 8>>
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),
    ?assertEqual(undefined, Decoded#transport_params.max_datagram_frame_size).

datagram_transport_param_zero_test() ->
    SCID = <<1, 2, 3, 4>>,
    Params = #transport_params{
        initial_source_connection_id = SCID,
        original_destination_connection_id = <<5, 6, 7, 8>>,
        max_datagram_frame_size = 0
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),
    ?assertEqual(0, Decoded#transport_params.max_datagram_frame_size).

datagram_send_ok_test() ->
    State0 = minimal_protocol_state(),
    RemoteParams = #transport_params{max_datagram_frame_size = 1200},
    State = State0#conn_state{remote_params = RemoteParams},
    ?assertMatch({ok, _}, nquic_protocol:send_datagram(<<"hello">>, State)).

datagram_send_not_negotiated_test() ->
    State0 = minimal_protocol_state(),
    State = State0#conn_state{remote_params = #transport_params{}},
    ?assertEqual(
        {error, datagrams_not_negotiated},
        nquic_protocol:send_datagram(<<"hello">>, State)
    ).

datagram_send_no_remote_params_test() ->
    State0 = minimal_protocol_state(),
    State = State0#conn_state{remote_params = undefined},
    ?assertEqual(
        {error, datagrams_not_negotiated},
        nquic_protocol:send_datagram(<<"hello">>, State)
    ).

datagram_send_disabled_test() ->
    State0 = minimal_protocol_state(),
    RemoteParams = #transport_params{max_datagram_frame_size = 0},
    State = State0#conn_state{remote_params = RemoteParams},
    ?assertEqual(
        {error, datagrams_not_negotiated},
        nquic_protocol:send_datagram(<<"hello">>, State)
    ).

datagram_send_too_large_test() ->
    State0 = minimal_protocol_state(),
    RemoteParams = #transport_params{max_datagram_frame_size = 10},
    State = State0#conn_state{remote_params = RemoteParams},
    ?assertEqual(
        {error, datagram_too_large},
        nquic_protocol:send_datagram(<<"hello world!">>, State)
    ).

datagram_send_queues_frame_test() ->
    State0 = minimal_protocol_state(),
    RemoteParams = #transport_params{max_datagram_frame_size = 1200},
    State = State0#conn_state{remote_params = RemoteParams},
    {ok, State1} = nquic_protocol:send_datagram(<<"test">>, State),
    ?assertMatch(
        [#datagram{data = <<"test">>} | _],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ).

datagram_handle_frame_test() ->
    State = minimal_protocol_state(),
    Header = #short_header{dcid = <<0:64>>},
    Frame = #datagram{data = <<"incoming">>},
    ?assertMatch(
        {ok, [{datagram_received, <<"incoming">>}], _},
        nquic_protocol_recv:handle_frame(Frame, Header, State)
    ).

datagram_lib_recv_empty_test() ->
    Ctx = make_dummy_ctx(),
    ?assertEqual({error, empty}, nquic_lib:recv_datagram(Ctx)).

datagram_lib_buffer_recv_test() ->
    Ctx0 = make_dummy_ctx(),
    Events = [{datagram_received, <<"msg1">>}, {datagram_received, <<"msg2">>}],
    {Remaining, Ctx1} = nquic_lib:buffer_events(Events, Ctx0),
    ?assertEqual([], Remaining),
    {ok, <<"msg1">>, Ctx2} = nquic_lib:recv_datagram(Ctx1),
    {ok, <<"msg2">>, Ctx3} = nquic_lib:recv_datagram(Ctx2),
    ?assertEqual({error, empty}, nquic_lib:recv_datagram(Ctx3)).

datagram_lib_buffer_mixed_events_test() ->
    Ctx0 = make_dummy_ctx(),
    Events = [
        {stream_data, 0},
        {datagram_received, <<"dg">>},
        {stream_opened, 4}
    ],
    {Remaining, Ctx1} = nquic_lib:buffer_events(Events, Ctx0),
    ?assertEqual([{stream_data, 0}, {stream_opened, 4}], Remaining),
    {ok, <<"dg">>, _} = nquic_lib:recv_datagram(Ctx1).

datagram_lib_buffer_overflow_test() ->
    Ctx0 = make_dummy_ctx(),
    Ctx1 = nquic_ctx:set_datagram_max(Ctx0, 2),
    Events = [
        {datagram_received, <<"a">>},
        {datagram_received, <<"b">>},
        {datagram_received, <<"c">>}
    ],
    {[], Ctx2} = nquic_lib:buffer_events(Events, Ctx1),
    {ok, <<"b">>, Ctx3} = nquic_lib:recv_datagram(Ctx2),
    {ok, <<"c">>, Ctx4} = nquic_lib:recv_datagram(Ctx3),
    ?assertEqual({error, empty}, nquic_lib:recv_datagram(Ctx4)).

make_dummy_ctx() ->
    nquic_ctx:new(minimal_protocol_state(), undefined, undefined, undefined).

lib_initiate_key_update_test() ->
    {_Sender, Client} = make_recv_key_update_pair(server, client),
    Ctx0 = nquic_ctx:new(Client, undefined, undefined, undefined),
    {ok, Ctx1} = nquic_lib:initiate_key_update(Ctx0),
    Crypto = (nquic_ctx:state(Ctx1))#conn_state.crypto,
    ?assertEqual(true, Crypto#conn_crypto.key_phase),
    ?assertEqual(true, Crypto#conn_crypto.key_update_pending).

lib_initiate_key_update_pending_test() ->
    {_Sender, Client} = make_recv_key_update_pair(server, client),
    Crypto0 = Client#conn_state.crypto,
    Client1 = Client#conn_state{crypto = Crypto0#conn_crypto{key_update_pending = true}},
    Ctx0 = nquic_ctx:new(Client1, undefined, undefined, undefined),
    ?assertEqual({error, key_update_pending}, nquic_lib:initiate_key_update(Ctx0)).

lib_takeover_registers_cids_test() ->
    Dispatch = nquic_dispatch:new(2),
    CID1 = <<10:64>>,
    CID2 = <<11:64>>,
    ODCID = <<12:64>>,
    OtherPid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    nquic_dispatch:register(Dispatch, CID1, OtherPid),
    nquic_dispatch:register(Dispatch, CID2, OtherPid),
    nquic_dispatch:register(Dispatch, ODCID, OtherPid),
    State = minimal_protocol_state(),
    Path0 = State#conn_state.path,
    State1 = State#conn_state{
        path = Path0#conn_path_mgmt{local_cids = #{0 => CID1, 1 => CID2}},
        odcid = ODCID
    },
    Ctx = nquic_ctx:new(State1, undefined, undefined, Dispatch),
    ?assertEqual(OtherPid, nquic_dispatch:lookup(Dispatch, CID1)),
    ?assertEqual(OtherPid, nquic_dispatch:lookup(Dispatch, CID2)),
    ?assertEqual(OtherPid, nquic_dispatch:lookup(Dispatch, ODCID)),
    {ok, _Ctx1} = nquic_lib:takeover(Ctx),
    ?assertEqual(self(), nquic_dispatch:lookup(Dispatch, CID1)),
    ?assertEqual(self(), nquic_dispatch:lookup(Dispatch, CID2)),
    ?assertEqual(self(), nquic_dispatch:lookup(Dispatch, ODCID)),
    OtherPid ! stop,
    nquic_dispatch:destroy(Dispatch).

lib_takeover_no_dispatch_test() ->
    Ctx = make_dummy_ctx(),
    ?assertMatch({ok, _}, nquic_lib:takeover(Ctx)).

lib_takeover_no_odcid_test() ->
    Dispatch = nquic_dispatch:new(1),
    CID = <<20:64>>,
    State = minimal_protocol_state(),
    Path0 = State#conn_state.path,
    State1 = State#conn_state{path = Path0#conn_path_mgmt{local_cids = #{0 => CID}}},
    Ctx = nquic_ctx:new(State1, undefined, undefined, Dispatch),
    {ok, _} = nquic_lib:takeover(Ctx),
    ?assertEqual(self(), nquic_dispatch:lookup(Dispatch, CID)),
    nquic_dispatch:destroy(Dispatch).

lib_recv_pending_empty_test() ->
    Ctx = make_dummy_ctx(),
    {ok, [], Ctx} = nquic_lib:recv_pending(Ctx).

pmtud_enable_test() ->
    State0 = minimal_protocol_state(),
    State1 = nquic_protocol_migration:enable_pmtud(State0),
    ?assertNotEqual(undefined, State1#conn_state.pmtud),
    ?assertEqual(searching, nquic_pmtud:get_state(State1#conn_state.pmtud)).

pmtud_probe_acked_updates_mtu_test() ->
    State0 = minimal_protocol_state(),
    State1 = nquic_protocol_migration:enable_pmtud(State0),
    State2 = nquic_protocol_migration:pmtud_on_probe_acked(State1),
    NewMTU = nquic_pmtud:get_current_mtu(State2#conn_state.pmtud),
    ?assert(NewMTU > 1200).

pmtud_probe_lost_test() ->
    State0 = minimal_protocol_state(),
    State1 = nquic_protocol_migration:enable_pmtud(State0),
    State2 = nquic_protocol_migration:pmtud_on_probe_lost(State1),
    ?assertEqual(searching, nquic_pmtud:get_state(State2#conn_state.pmtud)).

pmtud_noop_on_undefined_test() ->
    State0 = minimal_protocol_state(),
    ?assertEqual(State0, nquic_protocol_migration:pmtud_on_probe_acked(State0)),
    ?assertEqual(State0, nquic_protocol_migration:pmtud_on_probe_lost(State0)).

pmtud_timeout_reprobes_test() ->
    State0 = minimal_protocol_state(),
    State1 = nquic_protocol_migration:enable_pmtud(State0),
    PS0 = State1#conn_state.pmtud,
    {ok, _, _, PS1} = nquic_pmtud:generate_probe(PS0),
    PS2 = nquic_pmtud:on_probe_acked(PS1),
    PS3 = search_pmtud_complete(PS2),
    State2 = State1#conn_state{pmtud = PS3},
    {ok, [], State3, []} = nquic_protocol:handle_timeout(pmtud, State2),
    PMTUD3 = State3#conn_state.pmtud,
    case nquic_pmtud:get_current_mtu(PS3) < 1452 of
        true ->
            ?assertEqual(searching, nquic_pmtud:get_state(PMTUD3));
        false ->
            ?assertEqual(search_complete, nquic_pmtud:get_state(PMTUD3))
    end.

pmtud_timeout_undefined_test() ->
    State0 = minimal_protocol_state(),
    {ok, [], State0, []} = nquic_protocol:handle_timeout(pmtud, State0).

search_pmtud_complete(PS) ->
    case nquic_pmtud:get_state(PS) of
        search_complete ->
            PS;
        searching ->
            case nquic_pmtud:needs_probe(PS) of
                true ->
                    {ok, _, _, PS1} = nquic_pmtud:generate_probe(PS),
                    PS2 = nquic_pmtud:on_probe_acked(PS1),
                    search_pmtud_complete(PS2);
                false ->
                    PS
            end
    end.

pmtud_black_hole_reverts_test() ->
    State0 = minimal_protocol_state(),
    State1 = nquic_protocol_migration:enable_pmtud(State0),
    State2 = nquic_protocol_migration:pmtud_on_probe_acked(State1),
    ?assert(nquic_pmtud:get_current_mtu(State2#conn_state.pmtud) > 1200),
    State3 = nquic_protocol_migration:pmtud_on_black_hole(State2),
    ?assertEqual(error, nquic_pmtud:get_state(State3#conn_state.pmtud)),
    ?assertEqual(1200, nquic_pmtud:get_current_mtu(State3#conn_state.pmtud)).

pmtud_black_hole_auto_detect_test() ->
    State0 = minimal_protocol_state(),
    State1 = nquic_protocol_migration:enable_pmtud(State0),
    State2 = nquic_protocol_migration:pmtud_on_probe_acked(State1),
    ?assert(nquic_pmtud:get_current_mtu(State2#conn_state.pmtud) > 1200),
    LS0 = State2#conn_state.loss_state,
    LS1 = nquic_loss:on_pto(LS0),
    LS2 = nquic_loss:on_pto(LS1),
    LS3 = nquic_loss:on_pto(LS2),
    State3 = State2#conn_state{loss_state = LS3},
    {ok, [], State4, _} = nquic_protocol:handle_timeout(pto, State3),
    ?assertEqual(error, nquic_pmtud:get_state(State4#conn_state.pmtud)),
    ?assertEqual(1200, nquic_pmtud:get_current_mtu(State4#conn_state.pmtud)).

pmtud_no_black_hole_at_base_test() ->
    State0 = minimal_protocol_state(),
    State1 = nquic_protocol_migration:enable_pmtud(State0),
    LS0 = State1#conn_state.loss_state,
    LS1 = nquic_loss:on_pto(LS0),
    LS2 = nquic_loss:on_pto(LS1),
    LS3 = nquic_loss:on_pto(LS2),
    State2 = State1#conn_state{loss_state = LS3},
    {ok, [], State3, _} = nquic_protocol:handle_timeout(pto, State2),
    ?assertEqual(searching, nquic_pmtud:get_state(State3#conn_state.pmtud)).

pmtud_black_hole_undefined_noop_test() ->
    State0 = minimal_protocol_state(),
    ?assertEqual(State0, nquic_protocol_migration:pmtud_on_black_hole(State0)).

loss_get_pto_count_test() ->
    LS0 = nquic_loss:init(),
    ?assertEqual(0, nquic_loss:get_pto_count(LS0)),
    LS1 = nquic_loss:on_pto(LS0),
    ?assertEqual(1, nquic_loss:get_pto_count(LS1)),
    LS2 = nquic_loss:reset_pto_count(LS1),
    ?assertEqual(0, nquic_loss:get_pto_count(LS2)).

state_with_buffered_stream(StreamID, Type, Data, Fin) ->
    State0 = minimal_protocol_state(),
    Stream0 = nquic_stream_statem:new(StreamID, Type),
    PendingData =
        case byte_size(Data) of
            0 -> [];
            _ -> [Data]
        end,
    Stream = Stream0#stream_state{
        send_state = send,
        send_offset = byte_size(Data),
        send_max_data = 16#FFFFFFFF,
        pending_send_data = PendingData,
        pending_send_size = byte_size(Data),
        pending_send_fin = Fin
    },
    SS0 = State0#conn_state.streams_state,
    PS =
        case PendingData =/= [] orelse Fin of
            true -> #{StreamID => true};
            false -> #{}
        end,
    State0#conn_state{
        streams_state = SS0#conn_streams{
            streams = #{StreamID => Stream},
            pending_send_streams = PS
        }
    }.

drained_stream_frames(State) ->
    Flow = State#conn_state.flow,
    PreFrames = [F || {_S, _E, F} <- Flow#conn_flow.pending_app_pre_encoded],
    PreFrames ++ Flow#conn_flow.pending_app_frames.

drain_pending_sends_empty_test() ->
    State = minimal_protocol_state(),
    ?assertNot(nquic_protocol_streams_send:has_pending_send(State)),
    ?assertEqual(State, nquic_protocol_streams_send:drain_pending_sends(State)).

drain_pending_sends_single_frame_test() ->
    Payload = <<"hello world">>,
    State0 = state_with_buffered_stream(0, bidi, Payload, false),
    State1 = nquic_protocol_streams_send:drain_pending_sends(State0),
    Frames = drained_stream_frames(State1),
    ?assertMatch([#stream{stream_id = 0, offset = 0, fin = false}], Frames),
    [#stream{data = FrameData}] = Frames,
    ?assertEqual(Payload, iolist_to_binary(FrameData)),
    Streams = (State1#conn_state.streams_state)#conn_streams.streams,
    #{0 := Stream} = Streams,
    ?assertEqual([], Stream#stream_state.pending_send_data),
    ?assertEqual(0, Stream#stream_state.pending_send_size).

drain_pending_sends_splits_into_mtu_chunks_test() ->
    Size = 9000,
    Payload = binary:copy(<<"a">>, Size),
    State0 = state_with_buffered_stream(0, bidi, Payload, true),
    State1 = nquic_protocol_streams_send:drain_pending_sends(State0),
    Frames = lists:reverse(drained_stream_frames(State1)),
    Budget = nquic_protocol_send:packet_payload_budget(State0),
    lists:foreach(
        fun(#stream{data = D}) ->
            ?assert(iolist_size(D) =< Budget)
        end,
        Frames
    ),
    {TotalBytes, NextOff} = lists:foldl(
        fun(#stream{offset = Off, data = D}, {Acc, Expected}) ->
            ?assertEqual(Expected, Off),
            Len = iolist_size(D),
            {Acc + Len, Expected + Len}
        end,
        {0, 0},
        Frames
    ),
    ?assertEqual(Size, TotalBytes),
    ?assertEqual(Size, NextOff),
    ?assert(length(Frames) >= 2),
    [#stream{fin = LastFin} | _] = lists:reverse(Frames),
    ?assert(LastFin),
    Streams = (State1#conn_state.streams_state)#conn_streams.streams,
    #{0 := Stream} = Streams,
    ?assertEqual([], Stream#stream_state.pending_send_data),
    ?assertEqual(0, Stream#stream_state.pending_send_size),
    ?assertNot(Stream#stream_state.pending_send_fin),
    ?assertEqual(data_sent, Stream#stream_state.send_state).

drain_pending_sends_caps_at_cwnd_test() ->
    OneMB = 1024 * 1024,
    Payload = binary:copy(<<"a">>, OneMB),
    State0 = state_with_buffered_stream(0, bidi, Payload, true),
    State1 = nquic_protocol_streams_send:drain_pending_sends(State0),
    Frames = drained_stream_frames(State1),
    Budget = nquic_protocol_send:packet_payload_budget(State0),
    DrainedBytes = lists:foldl(
        fun(#stream{data = D}, Acc) -> Acc + iolist_size(D) end,
        0,
        Frames
    ),
    ?assert(DrainedBytes < OneMB),
    ?assert(DrainedBytes >= 8 * Budget),
    Streams = (State1#conn_state.streams_state)#conn_streams.streams,
    #{0 := Stream} = Streams,
    ?assertEqual(OneMB - DrainedBytes, Stream#stream_state.pending_send_size),
    ?assertEqual(
        OneMB - DrainedBytes,
        iolist_size(Stream#stream_state.pending_send_data)
    ),
    ?assert(Stream#stream_state.pending_send_fin),
    ?assertEqual(send, Stream#stream_state.send_state).

drain_pending_sends_emits_lone_fin_test() ->
    State0 = state_with_buffered_stream(0, bidi, <<>>, true),
    State1 = nquic_protocol_streams_send:drain_pending_sends(State0),
    Frames = drained_stream_frames(State1),
    ?assertMatch([#stream{stream_id = 0, offset = 0, fin = true, data = <<>>}], Frames),
    Streams = (State1#conn_state.streams_state)#conn_streams.streams,
    #{0 := Stream} = Streams,
    ?assertNot(Stream#stream_state.pending_send_fin),
    ?assertEqual(data_sent, Stream#stream_state.send_state).

state_with_buffered_streams(Specs) ->
    State0 = minimal_protocol_state(),
    SS0 = State0#conn_state.streams_state,
    {StreamMap, PSMap} = lists:foldl(
        fun({StreamID, Type, Data, Fin}, {SAcc, PAcc}) ->
            Stream0 = nquic_stream_statem:new(StreamID, Type),
            PendingData =
                case byte_size(Data) of
                    0 -> [];
                    _ -> [Data]
                end,
            Stream = Stream0#stream_state{
                send_state = send,
                send_offset = byte_size(Data),
                send_max_data = 16#FFFFFFFF,
                pending_send_data = PendingData,
                pending_send_size = byte_size(Data),
                pending_send_fin = Fin
            },
            PAcc1 =
                case PendingData =/= [] orelse Fin of
                    true -> PAcc#{StreamID => true};
                    false -> PAcc
                end,
            {SAcc#{StreamID => Stream}, PAcc1}
        end,
        {#{}, #{}},
        Specs
    ),
    State0#conn_state{
        streams_state = SS0#conn_streams{
            streams = StreamMap,
            pending_send_streams = PSMap
        }
    }.

drain_pending_sends_round_robin_fairness_test() ->
    BytesPerStream = 64 * 1024,
    Payload = binary:copy(<<"a">>, BytesPerStream),
    Specs = [
        {0, bidi, Payload, true},
        {4, bidi, Payload, true},
        {8, bidi, Payload, true},
        {12, bidi, Payload, true}
    ],
    State0 = state_with_buffered_streams(Specs),
    State1 = nquic_protocol_streams_send:drain_pending_sends(State0),
    Streams = (State1#conn_state.streams_state)#conn_streams.streams,
    PerStreamRemaining = [
        (maps:get(SID, Streams))#stream_state.pending_send_size
     || {SID, _, _, _} <- Specs
    ],
    lists:foreach(fun(R) -> ?assert(R > 0) end, PerStreamRemaining),
    Budget = nquic_protocol_send:packet_payload_budget(State0),
    MaxRemaining = lists:max(PerStreamRemaining),
    MinRemaining = lists:min(PerStreamRemaining),
    Spread = MaxRemaining - MinRemaining,
    ?assert(
        Spread =< 2 * Budget,
        io_lib:format(
            "spread=~p exceeds 2 x MTU=~p, drain monopolised one stream",
            [Spread, 2 * Budget]
        )
    ).

drain_pending_sends_round_robin_small_stream_completes_test() ->
    SmallPayload = binary:copy(<<"a">>, 100),
    LargePayload = binary:copy(<<"b">>, 64 * 1024),
    Specs = [
        {0, bidi, SmallPayload, true},
        {4, bidi, LargePayload, true},
        {8, bidi, LargePayload, true},
        {12, bidi, LargePayload, true}
    ],
    State0 = state_with_buffered_streams(Specs),
    State1 = nquic_protocol_streams_send:drain_pending_sends(State0),
    Streams = (State1#conn_state.streams_state)#conn_streams.streams,
    #{0 := Stream0} = Streams,
    ?assertEqual(0, Stream0#stream_state.pending_send_size),
    ?assertNot(Stream0#stream_state.pending_send_fin),
    PS = (State1#conn_state.streams_state)#conn_streams.pending_send_streams,
    ?assertNot(maps:is_key(0, PS)).
