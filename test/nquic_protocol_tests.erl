%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_protocol}.
%%%-------------------------------------------------------------------
-module(nquic_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-include("nquic_transport.hrl").
check_congestion_control_test_() ->
    LossState = nquic_loss:init(),
    State = #conn_state{loss_state = LossState},
    [
        ?_assertEqual(ok, nquic_protocol_send:check_congestion_control(State, 1000)),
        ?_assertEqual(ok, nquic_protocol_send:check_congestion_control(State, 12000)),
        ?_assertMatch({blocked, _}, nquic_protocol_send:check_congestion_control(State, 15000))
    ].

check_anti_amplification_test_() ->
    Client = #conn_state{
        role = client, path = #conn_path_mgmt{address_validated = false}
    },
    ServerUnvalidated = #conn_state{
        role = server,
        path = #conn_path_mgmt{
            address_validated = false,
            anti_amp_bytes_received = 100,
            anti_amp_bytes_sent = 200
        }
    },
    ServerValidated = #conn_state{
        role = server,
        path = #conn_path_mgmt{
            address_validated = true,
            anti_amp_bytes_received = 100,
            anti_amp_bytes_sent = 200
        }
    },
    [
        ?_assertEqual(ok_no_track, nquic_protocol_send:check_anti_amplification(Client, 10000)),
        ?_assertEqual(
            ok_no_track, nquic_protocol_send:check_anti_amplification(ServerValidated, 10000)
        ),
        ?_assertEqual(
            ok_track, nquic_protocol_send:check_anti_amplification(ServerUnvalidated, 50)
        ),
        ?_assertEqual(
            ok_track, nquic_protocol_send:check_anti_amplification(ServerUnvalidated, 100)
        ),
        ?_assertEqual(
            amplification_limited,
            nquic_protocol_send:check_anti_amplification(ServerUnvalidated, 101)
        )
    ].

error_code_test_() ->
    [
        ?_assertEqual(16#0, nquic_protocol:error_code(no_error)),
        ?_assertEqual(16#1, nquic_protocol:error_code(internal_error)),
        ?_assertEqual(16#3, nquic_protocol:error_code(flow_control_error)),
        ?_assertEqual(16#4, nquic_protocol:error_code(stream_limit_error)),
        ?_assertEqual(16#5, nquic_protocol:error_code(stream_state_error)),
        ?_assertEqual(16#6, nquic_protocol:error_code(final_size_error)),
        ?_assertEqual(16#7, nquic_protocol:error_code(frame_encoding_error)),
        ?_assertEqual(16#8, nquic_protocol:error_code(transport_parameter_error)),
        ?_assertEqual(16#9, nquic_protocol:error_code(connection_id_limit_error)),
        ?_assertEqual(16#a, nquic_protocol:error_code(protocol_violation)),
        ?_assertEqual(16#b, nquic_protocol:error_code(invalid_token)),
        ?_assertEqual(16#c, nquic_protocol:error_code(application_error)),
        ?_assertEqual(16#d, nquic_protocol:error_code(crypto_buffer_exceeded)),
        ?_assertEqual(16#10a, nquic_protocol:error_code({tls_alert, unexpected_message})),
        ?_assertEqual(16#178, nquic_protocol:error_code({tls_alert, no_application_protocol})),
        ?_assertEqual(16#16d, nquic_protocol:error_code({tls_alert, missing_extension})),
        ?_assertEqual(16#174, nquic_protocol:error_code({tls_alert, certificate_required})),
        ?_assertEqual(16#128, nquic_protocol:error_code({tls_alert, handshake_failure})),
        ?_assertEqual(16#1, nquic_protocol:error_code(unknown_error))
    ].

error_to_reason_phrase_test_() ->
    [
        ?_assertEqual(
            <<"unexpected_message">>,
            nquic_protocol:error_to_reason_phrase({tls_alert, unexpected_message})
        ),
        ?_assertEqual(<<"internal_error">>, nquic_protocol:error_to_reason_phrase(internal_error)),
        ?_assertEqual(<<>>, nquic_protocol:error_to_reason_phrase({unknown, tuple}))
    ].

scale_ack_delay_test_() ->
    DefaultParams = #transport_params{ack_delay_exponent = 3, max_ack_delay = 25},
    ZeroExp = #transport_params{ack_delay_exponent = 0, max_ack_delay = 25},
    LargeExp = #transport_params{ack_delay_exponent = 10, max_ack_delay = 25},
    [
        ?_assertEqual(800, nquic_protocol:scale_ack_delay(100, DefaultParams)),
        ?_assertEqual(100, nquic_protocol:scale_ack_delay(100, ZeroExp)),
        ?_assertEqual(25000, nquic_protocol:scale_ack_delay(100, LargeExp)),
        ?_assertEqual(800, nquic_protocol:scale_ack_delay(100, undefined))
    ].

crypto_buffer_contiguous_test() ->
    B0 = {0, <<>>, []},
    B1 = nquic_protocol_recv:crypto_buffer_add(0, <<"hello">>, B0),
    ?assertEqual(<<"hello">>, nquic_protocol_recv:crypto_buffer_data(B1)),
    B2 = nquic_protocol_recv:crypto_buffer_add(5, <<" world">>, B1),
    ?assertEqual(<<"hello world">>, nquic_protocol_recv:crypto_buffer_data(B2)).

crypto_buffer_out_of_order_test() ->
    B0 = {0, <<>>, []},
    B1 = nquic_protocol_recv:crypto_buffer_add(5, <<" world">>, B0),
    ?assertEqual(<<>>, nquic_protocol_recv:crypto_buffer_data(B1)),
    B2 = nquic_protocol_recv:crypto_buffer_add(0, <<"hello">>, B1),
    ?assertEqual(<<"hello world">>, nquic_protocol_recv:crypto_buffer_data(B2)).

crypto_buffer_duplicate_test() ->
    B0 = {0, <<>>, []},
    B1 = nquic_protocol_recv:crypto_buffer_add(0, <<"hello">>, B0),
    B2 = nquic_protocol_recv:crypto_buffer_add(0, <<"hello">>, B1),
    ?assertEqual(<<"hello">>, nquic_protocol_recv:crypto_buffer_data(B2)).

crypto_buffer_overlap_test() ->
    B0 = {0, <<>>, []},
    B1 = nquic_protocol_recv:crypto_buffer_add(0, <<"hello">>, B0),
    B2 = nquic_protocol_recv:crypto_buffer_add(3, <<"lo world">>, B1),
    ?assertEqual(<<"hello world">>, nquic_protocol_recv:crypto_buffer_data(B2)).

crypto_buffer_gap_test() ->
    B0 = {0, <<>>, []},
    B1 = nquic_protocol_recv:crypto_buffer_add(0, <<"aaaaa">>, B0),
    B2 = nquic_protocol_recv:crypto_buffer_add(10, <<"ccccc">>, B1),
    ?assertEqual(<<"aaaaa">>, nquic_protocol_recv:crypto_buffer_data(B2)),
    B3 = nquic_protocol_recv:crypto_buffer_add(5, <<"bbbbb">>, B2),
    ?assertEqual(<<"aaaaabbbbbccccc">>, nquic_protocol_recv:crypto_buffer_data(B3)).

insert_pn_range_contiguous_test() ->
    R1 = nquic_protocol_ack:insert_pn_range(0, []),
    ?assertEqual([{0, 0}], R1),
    R2 = nquic_protocol_ack:insert_pn_range(1, R1),
    ?assertEqual([{1, 0}], R2),
    R3 = nquic_protocol_ack:insert_pn_range(2, R2),
    ?assertEqual([{2, 0}], R3).

insert_pn_range_gap_test() ->
    R1 = nquic_protocol_ack:insert_pn_range(0, []),
    R2 = nquic_protocol_ack:insert_pn_range(1, R1),
    R3 = nquic_protocol_ack:insert_pn_range(2, R2),
    R4 = nquic_protocol_ack:insert_pn_range(5, R3),
    ?assertEqual([{5, 5}, {2, 0}], R4).

insert_pn_range_fill_gap_test() ->
    R = [{5, 5}, {2, 0}],
    R1 = nquic_protocol_ack:insert_pn_range(3, R),
    R2 = nquic_protocol_ack:insert_pn_range(4, R1),
    ?assertEqual([{5, 0}], R2).

insert_pn_range_duplicate_test() ->
    R = [{5, 3}, {1, 0}],
    ?assertEqual(R, nquic_protocol_ack:insert_pn_range(4, R)).

ranges_to_ack_ranges_test() ->
    ?assertEqual([], nquic_protocol_ack:ranges_to_ack_ranges(0, [])),
    AckRanges = nquic_protocol_ack:ranges_to_ack_ranges(8, [{5, 3}]),
    ?assertEqual([#ack_range{gap = 1, length = 2}], AckRanges),
    AckRanges2 = nquic_protocol_ack:ranges_to_ack_ranges(18, [{15, 13}, {10, 8}]),
    ?assertEqual(
        [#ack_range{gap = 1, length = 2}, #ack_range{gap = 1, length = 2}],
        AckRanges2
    ).

build_ack_for_space_test() ->
    State0 = #conn_state{pn_spaces = #{initial => #{next_pn => 0}}},
    ?assertEqual(none, nquic_protocol_ack:build_ack_for_space(initial, State0)),
    State1 = #conn_state{
        pn_spaces = #{
            initial => #{next_pn => 1, largest_received => 2, received_ranges => [{2, 0}]}
        }
    },
    {ok, Ack} = nquic_protocol_ack:build_ack_for_space(initial, State1),
    ?assertEqual(2, Ack#ack.largest_acknowledged),
    ?assertEqual(2, Ack#ack.first_ack_range),
    ?assertEqual([], Ack#ack.ack_ranges).

prune_received_ranges_below_all_test() ->
    Ranges = [{20, 15}, {10, 5}],
    ?assertEqual(Ranges, nquic_protocol_ack:prune_received_ranges(Ranges, 4)),
    ?assertEqual(Ranges, nquic_protocol_ack:prune_received_ranges(Ranges, 0)).

prune_received_ranges_truncates_straddling_test() ->
    Ranges = [{20, 15}, {10, 5}],
    ?assertEqual(
        [{20, 15}, {10, 8}],
        nquic_protocol_ack:prune_received_ranges(Ranges, 7)
    ).

prune_received_ranges_inclusive_high_test() ->
    Ranges = [{20, 15}, {10, 5}],
    ?assertEqual(
        [{20, 15}],
        nquic_protocol_ack:prune_received_ranges(Ranges, 10)
    ).

prune_received_ranges_truncates_top_test() ->
    Ranges = [{20, 15}, {10, 5}],
    ?assertEqual(
        [{20, 17}],
        nquic_protocol_ack:prune_received_ranges(Ranges, 16)
    ).

prune_received_ranges_full_drop_test() ->
    Ranges = [{20, 15}, {10, 5}],
    ?assertEqual([], nquic_protocol_ack:prune_received_ranges(Ranges, 20)),
    ?assertEqual([], nquic_protocol_ack:prune_received_ranges(Ranges, 100)).

prune_received_ranges_empty_test() ->
    ?assertEqual([], nquic_protocol_ack:prune_received_ranges([], 0)),
    ?assertEqual([], nquic_protocol_ack:prune_received_ranges([], 1_000_000)).

apply_received_ranges_prune_no_acks_test() ->
    PnSpaces = #{application => #{received_ranges => [{20, 0}]}},
    State = #conn_state{pn_spaces = PnSpaces},
    State1 = nquic_protocol_ack:apply_received_ranges_prune(
        application, [#padding{}, #ping{}], State
    ),
    ?assertEqual(
        [{20, 0}],
        maps:get(received_ranges, maps:get(application, State1#conn_state.pn_spaces))
    ).

apply_received_ranges_prune_uses_max_largest_test() ->
    PnSpaces = #{application => #{received_ranges => [{50, 0}]}},
    State = #conn_state{pn_spaces = PnSpaces},
    AckedFrames = [
        #ack{largest_acknowledged = 10, delay = 0, first_ack_range = 0, ack_ranges = []},
        #padding{},
        #ack{largest_acknowledged = 30, delay = 0, first_ack_range = 0, ack_ranges = []},
        #ack{largest_acknowledged = 20, delay = 0, first_ack_range = 0, ack_ranges = []}
    ],
    State1 = nquic_protocol_ack:apply_received_ranges_prune(
        application, AckedFrames, State
    ),
    ?assertEqual(
        [{50, 31}],
        maps:get(received_ranges, maps:get(application, State1#conn_state.pn_spaces))
    ).

apply_received_ranges_prune_scoped_to_space_test() ->
    PnSpaces = #{
        initial => #{received_ranges => [{10, 0}]},
        application => #{received_ranges => [{20, 0}]}
    },
    State = #conn_state{pn_spaces = PnSpaces},
    AckedFrames = [
        #ack{largest_acknowledged = 5, delay = 0, first_ack_range = 0, ack_ranges = []}
    ],
    State1 = nquic_protocol_ack:apply_received_ranges_prune(
        application, AckedFrames, State
    ),
    ?assertEqual(
        [{10, 0}],
        maps:get(received_ranges, maps:get(initial, State1#conn_state.pn_spaces))
    ),
    ?assertEqual(
        [{20, 6}],
        maps:get(received_ranges, maps:get(application, State1#conn_state.pn_spaces))
    ).

get_draining_timeout_test() ->
    State = #conn_state{
        loss_state = nquic_loss:init(),
        remote_params = #transport_params{max_ack_delay = 25}
    },
    Timeout = nquic_protocol:get_draining_timeout(State),
    ?assert(Timeout > 0),
    PtoUs = nquic_loss:get_pto_timeout(State#conn_state.loss_state, 25_000),
    ExpectedMs = max(1, ((3 * PtoUs) + 999) div 1000),
    ?assertEqual(ExpectedMs, Timeout).

handle_reset_stream_basic_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = recv,
        recv_offset = 100,
        recv_max_offset = 100,
        recv_buffer = gb_trees:enter(200, {<<"data">>, false}, gb_trees:empty()),
        app_buffer = <<"existing">>,
        app_buffer_size = 8
    },
    State = #conn_state{
        role = client,
        streams_state = #conn_streams{streams = #{0 => Stream}},
        flow = #conn_flow{data_received = 100, local_max_data = 10000}
    },
    Frame = #reset_stream{stream_id = 0, app_error_code = 0, final_size = 500},
    Header = #short_header{dcid = <<>>, packet_number = 0},
    {ok, Events, NewState} = nquic_protocol_recv:handle_frame(Frame, Header, State),
    ?assertMatch([{stream_reset, 0, 0}], Events),
    NewStream = maps:get(0, (NewState#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual(reset_recvd, NewStream#stream_state.recv_state),
    ?assertEqual(500, NewStream#stream_state.recv_offset),
    ?assertEqual(500, (NewState#conn_state.flow)#conn_flow.data_received).

handle_reset_stream_final_size_error_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = size_known,
        recv_max_offset = 200
    },
    State = #conn_state{
        role = client,
        streams_state = #conn_streams{streams = #{0 => Stream}},
        flow = #conn_flow{data_received = 200, local_max_data = 10000}
    },
    Frame = #reset_stream{stream_id = 0, app_error_code = 0, final_size = 300},
    Header = #short_header{dcid = <<>>, packet_number = 0},
    ?assertMatch(
        {error, {transport_error, final_size_error}, _},
        nquic_protocol_recv:handle_frame(Frame, Header, State)
    ).

handle_stop_sending_test() ->
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        send_state = send,
        send_offset = 150
    },
    State = #conn_state{
        role = client,
        streams_state = #conn_streams{streams = #{0 => Stream}},
        crypto = #conn_crypto{keys = #{}},
        socket = undefined,
        pn_spaces = #{}
    },
    Frame = #stop_sending{stream_id = 0, app_error_code = 42},
    Header = #short_header{dcid = <<>>, packet_number = 0},
    {ok, Events, NewState} = nquic_protocol_recv:handle_frame(Frame, Header, State),
    ?assertMatch([{stop_sending, 0, 42}], Events),
    NewStream = maps:get(0, (NewState#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual(reset_sent, NewStream#stream_state.send_state).

handle_stop_sending_already_reset_test() ->
    Stream = #stream_state{
        stream_id = 0,
        send_state = reset_sent,
        send_offset = 100
    },
    State = #conn_state{
        role = client, streams_state = #conn_streams{streams = #{0 => Stream}}
    },
    Frame = #stop_sending{stream_id = 0, app_error_code = 42},
    Header = #short_header{dcid = <<>>, packet_number = 0},
    {ok, [], State} = nquic_protocol_recv:handle_frame(Frame, Header, State).

handle_stop_sending_unknown_stream_test() ->
    State = #conn_state{role = server, streams_state = #conn_streams{streams = #{}}},
    Frame = #stop_sending{stream_id = 0, app_error_code = 42},
    Header = #short_header{dcid = <<>>, packet_number = 0},
    {ok, [], State} = nquic_protocol_recv:handle_frame(Frame, Header, State).

complete_migration_updates_peer_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{data = C}} = nquic_path:initiate_validation(PS0, New),
    {validated, PS2} = nquic_path:on_response(PS1, C),
    CurrentDCID = <<1, 2, 3, 4>>,
    SpareDCID = crypto:strong_rand_bytes(8),
    PeerCids = #{
        0 => #{cid => CurrentDCID, token => <<>>},
        1 => #{cid => SpareDCID, token => <<>>}
    },
    State = #conn_state{
        peer = New,
        loss_state = nquic_loss:init(),
        dcid = CurrentDCID,
        flow = #conn_flow{pending_app_frames = []},
        path = #conn_path_mgmt{
            path_state = PS2,
            peer_cids = PeerCids,
            address_validated = false,
            anti_amp_bytes_sent = 100,
            anti_amp_bytes_received = 200
        }
    },
    {ok, State1} = nquic_protocol_migration:complete_migration(State),
    ?assertEqual(New, State1#conn_state.peer),
    ?assert((State1#conn_state.path)#conn_path_mgmt.address_validated),
    ?assertEqual(0, (State1#conn_state.path)#conn_path_mgmt.anti_amp_bytes_sent).

rotate_dcid_selects_unused_test() ->
    CurrentDCID = <<1, 2, 3, 4>>,
    Spare1 = <<5, 6, 7, 8>>,
    Spare2 = <<9, 10, 11, 12>>,
    PeerCids = #{
        0 => #{cid => CurrentDCID, token => <<>>},
        1 => #{cid => Spare1, token => <<>>},
        2 => #{cid => Spare2, token => <<>>}
    },
    State = #conn_state{
        dcid = CurrentDCID,
        path = #conn_path_mgmt{peer_cids = PeerCids},
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, State1} = nquic_protocol_cid:rotate_dcid(State),
    ?assertEqual(Spare1, State1#conn_state.dcid).

rotate_dcid_no_available_test() ->
    OnlyCID = <<1, 2, 3, 4>>,
    PeerCids = #{0 => #{cid => OnlyCID, token => <<>>}},
    State = #conn_state{
        dcid = OnlyCID, path = #conn_path_mgmt{peer_cids = PeerCids}
    },
    ?assertEqual({error, no_available_cids}, nquic_protocol_cid:rotate_dcid(State)).

check_migration_allowed_test_() ->
    RemoteEnabled = #transport_params{disable_active_migration = false},
    RemoteDisabled = #transport_params{disable_active_migration = true},
    CurrentDCID = <<1, 2, 3, 4>>,
    SpareCID = <<5, 6, 7, 8>>,
    [
        ?_assertEqual(
            {error, migration_disabled},
            nquic_protocol_migration:check_migration_allowed(#conn_state{
                remote_params = RemoteDisabled,
                dcid = CurrentDCID,
                path = #conn_path_mgmt{
                    peer_cids = #{1 => #{cid => SpareCID, token => <<>>}}
                }
            })
        ),
        ?_assertEqual(
            {error, no_available_cids},
            nquic_protocol_migration:check_migration_allowed(#conn_state{
                remote_params = RemoteEnabled,
                dcid = CurrentDCID,
                path = #conn_path_mgmt{
                    peer_cids = #{0 => #{cid => CurrentDCID, token => <<>>}}
                }
            })
        ),
        ?_assertEqual(
            ok,
            nquic_protocol_migration:check_migration_allowed(#conn_state{
                remote_params = RemoteEnabled,
                dcid = CurrentDCID,
                path = #conn_path_mgmt{
                    peer_cids = #{
                        0 => #{cid => CurrentDCID, token => <<>>},
                        1 => #{cid => SpareCID, token => <<>>}
                    }
                }
            })
        )
    ].

select_preferred_peer_ipv4_test() ->
    PA = #{
        ipv4 => {{10, 0, 0, 1}, 4433},
        ipv6 => {{0, 0, 0, 0, 0, 0, 0, 1}, 4434}
    },
    CurrentPeer = #{family => inet, addr => {192, 168, 1, 1}, port => 5000},
    Expected = nquic_socket:make_sockaddr({10, 0, 0, 1}, 4433),
    ?assertEqual(Expected, nquic_protocol_migration:select_preferred_peer(PA, CurrentPeer)).

handle_preferred_address_test() ->
    PA = #{
        ipv4 => {{10, 0, 0, 1}, 4433},
        ipv6 => {{0, 0, 0, 0, 0, 0, 0, 1}, 4434},
        cid => <<9, 8, 7, 6>>,
        stateless_reset_token => <<0:128>>
    },
    Peer = nquic_socket:make_sockaddr({10, 0, 0, 1}, 5000),
    PS = nquic_path:new(Peer),
    State = #conn_state{
        peer = Peer,
        path = #conn_path_mgmt{
            path_state = PS,
            peer_cids = #{0 => #{cid => <<1, 2, 3, 4>>, token => <<>>}}
        },
        flow = #conn_flow{pending_app_frames = []},
        loss_state = nquic_loss:init(newreno),
        remote_params = #transport_params{max_ack_delay = 25}
    },
    {ok, State1, TimerActions} = nquic_protocol_migration:handle_preferred_address(PA, State),
    ?assertEqual(
        #{cid => <<9, 8, 7, 6>>, token => <<0:128>>},
        maps:get(1, (State1#conn_state.path)#conn_path_mgmt.peer_cids)
    ),
    ?assertEqual(nquic_socket:make_sockaddr({10, 0, 0, 1}, 4433), State1#conn_state.peer),
    ?assert(nquic_path:is_validating((State1#conn_state.path)#conn_path_mgmt.path_state)),
    ?assertMatch([#path_challenge{} | _], (State1#conn_state.flow)#conn_flow.pending_app_frames),
    ?assertMatch([{set_timer, path_validation, _}], TimerActions).

handle_frame_ping_test() ->
    State = #conn_state{},
    {ok, [], State} = nquic_protocol_recv:handle_frame(
        #ping{}, #short_header{dcid = <<>>, packet_number = 0}, State
    ).

handle_frame_max_data_test() ->
    State = #conn_state{flow = #conn_flow{remote_max_data = 1000}},
    {ok, [], State1} = nquic_protocol_recv:handle_frame(
        #max_data{max_data = 2000}, #short_header{dcid = <<>>, packet_number = 0}, State
    ),
    ?assertEqual(2000, (State1#conn_state.flow)#conn_flow.remote_max_data).

handle_frame_max_data_emits_writable_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = ready, send_max_data = 10000
    },
    LS = nquic_loss:init(),
    State = #conn_state{
        flow = #conn_flow{remote_max_data = 0, data_sent = 0},
        streams_state = #conn_streams{
            streams = #{0 => Stream}, blocked_streams = #{0 => true}
        },
        loss_state = LS
    },
    Header = #short_header{dcid = <<>>, packet_number = 0},
    {ok, Events, State1} = nquic_protocol_recv:handle_frame(
        #max_data{max_data = 10000}, Header, State
    ),
    ?assertEqual([{stream_writable, 0}], Events),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.blocked_streams).

handle_frame_max_data_no_writable_when_stream_still_blocked_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = ready, send_max_data = 0
    },
    LS = nquic_loss:init(),
    State = #conn_state{
        flow = #conn_flow{remote_max_data = 0, data_sent = 0},
        streams_state = #conn_streams{
            streams = #{0 => Stream}, blocked_streams = #{0 => true}
        },
        loss_state = LS
    },
    Header = #short_header{dcid = <<>>, packet_number = 0},
    {ok, Events, State1} = nquic_protocol_recv:handle_frame(
        #max_data{max_data = 10000}, Header, State
    ),
    ?assertEqual([], Events),
    ?assert(maps:is_key(0, (State1#conn_state.streams_state)#conn_streams.blocked_streams)).

handle_frame_max_stream_data_emits_writable_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = ready, send_max_data = 0
    },
    LS = nquic_loss:init(),
    State = #conn_state{
        role = client,
        flow = #conn_flow{remote_max_data = 10000, data_sent = 0},
        streams_state = #conn_streams{
            streams = #{0 => Stream}, blocked_streams = #{0 => true}
        },
        loss_state = LS
    },
    Header = #short_header{dcid = <<>>, packet_number = 0},
    Frame = #max_stream_data{stream_id = 0, max_stream_data = 10000},
    {ok, Events, State1} = nquic_protocol_recv:handle_frame(Frame, Header, State),
    ?assertEqual([{stream_writable, 0}], Events),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.blocked_streams).

handle_frame_max_stream_data_no_writable_when_conn_still_blocked_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = ready, send_max_data = 0
    },
    LS = nquic_loss:init(),
    State = #conn_state{
        role = client,
        flow = #conn_flow{remote_max_data = 0, data_sent = 0},
        streams_state = #conn_streams{
            streams = #{0 => Stream}, blocked_streams = #{0 => true}
        },
        loss_state = LS
    },
    Header = #short_header{dcid = <<>>, packet_number = 0},
    Frame = #max_stream_data{stream_id = 0, max_stream_data = 10000},
    {ok, Events, State1} = nquic_protocol_recv:handle_frame(Frame, Header, State),
    ?assertEqual([], Events),
    ?assert(maps:is_key(0, (State1#conn_state.streams_state)#conn_streams.blocked_streams)).

is_writable_test() ->
    LS = nquic_loss:init(),
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = ready, send_max_data = 10
    },
    State = #conn_state{
        role = client,
        flow = #conn_flow{remote_max_data = 10, data_sent = 0},
        streams_state = #conn_streams{streams = #{0 => Stream}},
        loss_state = LS
    },
    SetStreams = fun(St, M) ->
        SS0 = St#conn_state.streams_state,
        St#conn_state{streams_state = SS0#conn_streams{streams = M}}
    end,
    ?assert(nquic_protocol_streams_send:is_writable(0, State)),
    Stream2 = Stream#stream_state{send_max_data = 1, recv_window = 1},
    State2 = SetStreams(State, #{0 => Stream2}),
    ?assert(nquic_protocol_streams_send:is_writable(0, State2)),
    Stream2b = Stream#stream_state{send_max_data = 0, recv_window = 1},
    State2b = SetStreams(State, #{0 => Stream2b}),
    ?assertNot(nquic_protocol_streams_send:is_writable(0, State2b)),
    Stream3 = Stream#stream_state{send_state = data_sent},
    State3 = SetStreams(State, #{0 => Stream3}),
    ?assertNot(nquic_protocol_streams_send:is_writable(0, State3)),
    ?assertNot(nquic_protocol_streams_send:is_writable(99, State)).

send_stream_clears_blocked_on_success_test() ->
    LS = nquic_loss:init(),
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = ready, send_max_data = 10
    },
    State = #conn_state{
        role = client,
        flow = #conn_flow{remote_max_data = 10, data_sent = 0, pending_app_frames = []},
        streams_state = #conn_streams{
            streams = #{0 => Stream}, blocked_streams = #{0 => true}
        },
        loss_state = LS
    },
    {ok, State1} = nquic_protocol:send_stream(0, <<"x">>, nofin, State),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.blocked_streams).

cleanup_stream_scrubs_blocked_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = data_recvd, recv_state = data_read
    },
    State = #conn_state{
        role = client,
        streams_state = #conn_streams{
            streams = #{0 => Stream},
            blocked_streams = #{0 => true},
            next_bidi_stream = 4
        }
    },
    State1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(0, Stream, State),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.blocked_streams),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.streams).

handle_frame_connection_close_test() ->
    State = #conn_state{},
    {ok, [connection_closed], State} = nquic_protocol_recv:handle_frame(
        #connection_close{error_code = 0, reason_phrase = <<>>},
        #short_header{dcid = <<>>, packet_number = 0},
        State
    ).

handle_frame_path_challenge_test() ->
    State = #conn_state{flow = #conn_flow{pending_app_frames = []}},
    ChallengeData = crypto:strong_rand_bytes(8),
    {ok, [], State1} = nquic_protocol_recv:handle_frame(
        #path_challenge{data = ChallengeData},
        #short_header{dcid = <<>>, packet_number = 0},
        State
    ),
    ?assertMatch(
        [#path_response{data = ChallengeData}],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ).

compute_timer_actions_idle_test() ->
    LP = #transport_params{max_idle_timeout = 30000},
    RP = #transport_params{max_idle_timeout = 20000},
    State = #conn_state{
        local_params = LP,
        remote_params = RP,
        loss_state = nquic_loss:init()
    },
    {Actions, _State1} = nquic_protocol_timer:compute_timer_actions(State),
    ?assert(
        lists:any(
            fun
                ({set_timer, idle, 20000}) -> true;
                (_) -> false
            end,
            Actions
        )
    ),
    ?assert(
        lists:any(
            fun
                ({cancel_timer, pto}) -> true;
                (_) -> false
            end,
            Actions
        )
    ).

compute_timer_actions_no_idle_test() ->
    LP = #transport_params{max_idle_timeout = 0},
    RP = #transport_params{max_idle_timeout = 0},
    State = #conn_state{
        local_params = LP,
        remote_params = RP,
        loss_state = nquic_loss:init()
    },
    {Actions, _State1} = nquic_protocol_timer:compute_timer_actions(State),
    ?assertNot(
        lists:any(
            fun
                ({set_timer, idle, _}) -> true;
                (_) -> false
            end,
            Actions
        )
    ).

handle_timeout_idle_test() ->
    State = #conn_state{},
    ?assertMatch(
        {error, {transport_error, idle_timeout}, _}, nquic_protocol:handle_timeout(idle, State)
    ).

handle_timeout_pto_queues_ping_test() ->
    State = #conn_state{
        loss_state = nquic_loss:init(),
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, [], State1, TimerActions} = nquic_protocol:handle_timeout(pto, State),
    ?assertMatch([#ping{}], (State1#conn_state.flow)#conn_flow.pending_app_frames),
    ?assert(is_list(TimerActions)).

handle_timeout_draining_test() ->
    State = #conn_state{},
    ?assertMatch({error, normal, _}, nquic_protocol:handle_timeout(draining, State)).

handle_timeout_path_validation_not_validating_test() ->
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => 4433},
    PS = nquic_path:new(Peer),
    State = #conn_state{path = #conn_path_mgmt{path_state = PS}},
    {ok, [], State, []} = nquic_protocol:handle_timeout(path_validation, State).

is_stream_terminal_bidi_both_done_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = data_sent, recv_state = data_read
    },
    ?assert(nquic_protocol_streams_lifecycle:is_stream_terminal(0, client, Stream)).

is_stream_terminal_bidi_send_only_test() ->
    Stream = #stream_state{stream_id = 0, type = bidi, send_state = data_sent, recv_state = recv},
    ?assertNot(nquic_protocol_streams_lifecycle:is_stream_terminal(0, client, Stream)).

is_stream_terminal_bidi_recv_only_test() ->
    Stream = #stream_state{stream_id = 0, type = bidi, send_state = send, recv_state = data_read},
    ?assertNot(nquic_protocol_streams_lifecycle:is_stream_terminal(0, client, Stream)).

is_stream_terminal_bidi_reset_both_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = reset_sent, recv_state = reset_recvd
    },
    ?assert(nquic_protocol_streams_lifecycle:is_stream_terminal(0, client, Stream)).

is_stream_terminal_bidi_size_known_empty_buffer_test() ->
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        send_state = data_sent,
        recv_state = size_known,
        app_buffer_size = 0
    },
    ?assert(nquic_protocol_streams_lifecycle:is_stream_terminal(0, client, Stream)).

is_stream_terminal_bidi_size_known_buffered_data_test() ->
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        send_state = data_sent,
        recv_state = size_known,
        app_buffer = [<<"pending">>],
        app_buffer_size = 7
    },
    ?assertNot(nquic_protocol_streams_lifecycle:is_stream_terminal(0, client, Stream)).

is_stream_terminal_uni_peer_size_known_empty_buffer_test() ->
    Stream = #stream_state{
        stream_id = 2,
        type = uni,
        send_state = ready,
        recv_state = size_known,
        app_buffer_size = 0
    },
    ?assert(nquic_protocol_streams_lifecycle:is_stream_terminal(2, server, Stream)).

is_stream_terminal_uni_peer_size_known_buffered_data_test() ->
    Stream = #stream_state{
        stream_id = 2,
        type = uni,
        send_state = ready,
        recv_state = size_known,
        app_buffer = [<<"abc">>],
        app_buffer_size = 3
    },
    ?assertNot(nquic_protocol_streams_lifecycle:is_stream_terminal(2, server, Stream)).

zombie_stream_reclaimed_on_late_fin_test() ->
    %% Server-side peer-initiated bidi stream 0 with response already sent
    %% (send_state = data_sent). Peer's FIN arrives as a standalone
    %% zero-length frame after the app has drained the request body. Expect
    %% the stream to be reclaimed and MAX_STREAMS to advance, even though
    %% the application never calls `recv` again.
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        send_state = data_sent,
        send_offset = 7,
        send_max_data = 65536,
        recv_state = recv,
        recv_offset = 0,
        recv_max_offset = 0,
        recv_window = 65536,
        app_buffer = [],
        app_buffer_size = 0
    },
    LP = #transport_params{
        initial_max_data = 1048576,
        initial_max_stream_data_bidi_local = 65536,
        initial_max_stream_data_bidi_remote = 65536,
        initial_max_streams_bidi = 100,
        initial_max_streams_uni = 100
    },
    State = #conn_state{
        role = server,
        local_params = LP,
        flow = #conn_flow{local_max_data = 1048576, pending_app_frames = []},
        streams_state = #conn_streams{
            streams = #{0 => Stream},
            local_max_streams_bidi = 100,
            last_sent_max_streams_bidi = 100,
            opened_peer_bidi_count = 99,
            max_peer_bidi_stream_id = 0
        }
    },
    Frame = #stream{stream_id = 0, offset = 0, length = 0, fin = true, data = <<>>},
    {ok, _Events, State1} = nquic_protocol_streams:handle_stream_frame(
        0, 0, <<>>, Frame, {ok, Stream}, #{max_bidi => 100, max_uni => 100}, State
    ),
    ?assertNot(
        maps:is_key(0, (State1#conn_state.streams_state)#conn_streams.streams),
        "stream 0 must be reclaimed once peer FIN is delivered"
    ),
    ?assertEqual(101, (State1#conn_state.streams_state)#conn_streams.local_max_streams_bidi).

zombie_stream_not_reclaimed_when_buffer_has_data_test() ->
    %% FIN arrives together with the last byte of data. The app has not
    %% drained the buffer yet, so we must keep the stream around until
    %% the app reads it.
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        send_state = data_sent,
        send_offset = 4,
        send_max_data = 65536,
        recv_state = recv,
        recv_offset = 0,
        recv_max_offset = 0,
        recv_window = 65536,
        app_buffer = [],
        app_buffer_size = 0
    },
    LP = #transport_params{
        initial_max_data = 1048576,
        initial_max_stream_data_bidi_local = 65536,
        initial_max_stream_data_bidi_remote = 65536,
        initial_max_streams_bidi = 100,
        initial_max_streams_uni = 100
    },
    State = #conn_state{
        role = server,
        local_params = LP,
        flow = #conn_flow{local_max_data = 1048576, pending_app_frames = []},
        streams_state = #conn_streams{
            streams = #{0 => Stream},
            local_max_streams_bidi = 100,
            last_sent_max_streams_bidi = 100,
            opened_peer_bidi_count = 99,
            max_peer_bidi_stream_id = 0
        }
    },
    Frame = #stream{stream_id = 0, offset = 0, length = 3, fin = true, data = <<"req">>},
    {ok, _Events, State1} = nquic_protocol_streams:handle_stream_frame(
        0, 0, <<"req">>, Frame, {ok, Stream}, #{max_bidi => 100, max_uni => 100}, State
    ),
    ?assert(
        maps:is_key(0, (State1#conn_state.streams_state)#conn_streams.streams),
        "stream 0 must remain until app drains buffered data"
    ).

zombie_stream_bounded_growth_under_late_fin_test() ->
    %% Long pipelined H3-style sequence: many peer-initiated bidi streams,
    %% each driven through "request arrives without FIN -> server sends
    %% response with FIN -> peer FIN arrives as a separate frame after
    %% the app has moved on". Without the late-FIN reclamation, the
    %% streams map would grow unboundedly and MAX_STREAMS would never
    %% advance. With the fix, both stay bounded.
    LP = #transport_params{
        initial_max_data = 8 * 1024 * 1024,
        initial_max_stream_data_bidi_local = 65536,
        initial_max_stream_data_bidi_remote = 65536,
        initial_max_streams_bidi = 32,
        initial_max_streams_uni = 32
    },
    State0 = #conn_state{
        role = server,
        local_params = LP,
        flow = #conn_flow{local_max_data = 8 * 1024 * 1024, pending_app_frames = []},
        streams_state = #conn_streams{
            streams = #{},
            local_max_streams_bidi = 32,
            last_sent_max_streams_bidi = 32,
            opened_peer_bidi_count = 0
        }
    },
    StreamIDs = [N * 4 || N <- lists:seq(0, 999)],
    Limits = #{max_bidi => infinity, max_uni => infinity},
    StateN = lists:foldl(
        fun(ID, StAcc) ->
            DataFrame = #stream{
                stream_id = ID, offset = 0, length = 3, fin = false, data = <<"req">>
            },
            {ok, _, StAfterData} = nquic_protocol_streams:handle_stream_frame(
                ID, 0, <<"req">>, DataFrame, error, Limits, StAcc
            ),
            {ok, Drained, _Fin, StAfterRead} = nquic_protocol:read_stream(ID, StAfterData),
            ?assertEqual(<<"req">>, Drained),
            StreamsAfterRead =
                (StAfterRead#conn_state.streams_state)#conn_streams.streams,
            {ok, Stream2} = maps:find(ID, StreamsAfterRead),
            Stream3 = Stream2#stream_state{send_state = data_sent, send_offset = 5},
            SS2 = (StAfterRead#conn_state.streams_state)#conn_streams{
                streams = StreamsAfterRead#{ID => Stream3}
            },
            StSent = StAfterRead#conn_state{streams_state = SS2},
            FinFrame = #stream{
                stream_id = ID, offset = 3, length = 0, fin = true, data = <<>>
            },
            {ok, _, StAfterFin} = nquic_protocol_streams:handle_stream_frame(
                ID, 3, <<>>, FinFrame, {ok, Stream3}, Limits, StSent
            ),
            SSFin = (StAfterFin#conn_state.streams_state),
            CurrentStreams = SSFin#conn_streams.streams,
            ?assertNot(
                maps:is_key(ID, CurrentStreams),
                {stream_not_reclaimed, ID}
            ),
            ?assert(
                map_size(CurrentStreams) < 16,
                {stream_map_grew_unboundedly, map_size(CurrentStreams)}
            ),
            StAfterFin
        end,
        State0,
        StreamIDs
    ),
    FinalSS = StateN#conn_state.streams_state,
    ?assertEqual(0, map_size(FinalSS#conn_streams.streams)),
    ?assertEqual(1000, FinalSS#conn_streams.opened_peer_bidi_count),
    ?assert(
        FinalSS#conn_streams.local_max_streams_bidi >= 1000,
        {max_streams_did_not_keep_pace, FinalSS#conn_streams.local_max_streams_bidi}
    ).

is_stream_terminal_uni_local_send_done_test() ->
    Stream = #stream_state{stream_id = 2, type = uni, send_state = data_sent, recv_state = recv},
    ?assert(nquic_protocol_streams_lifecycle:is_stream_terminal(2, client, Stream)).

is_stream_terminal_uni_peer_recv_done_test() ->
    Stream = #stream_state{stream_id = 2, type = uni, send_state = ready, recv_state = data_read},
    ?assert(nquic_protocol_streams_lifecycle:is_stream_terminal(2, server, Stream)).

is_stream_terminal_uni_peer_not_done_test() ->
    Stream = #stream_state{stream_id = 2, type = uni, send_state = ready, recv_state = recv},
    ?assertNot(nquic_protocol_streams_lifecycle:is_stream_terminal(2, server, Stream)).

maybe_cleanup_stream_removes_terminal_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = data_sent, recv_state = data_read
    },
    State = #conn_state{
        role = client,
        streams_state = #conn_streams{
            streams = #{0 => Stream}, local_max_streams_bidi = 100
        }
    },
    State1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(0, State),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual([], (State1#conn_state.flow)#conn_flow.pending_app_frames).

maybe_cleanup_stream_keeps_non_terminal_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = send, recv_state = recv
    },
    State = #conn_state{
        role = client, streams_state = #conn_streams{streams = #{0 => Stream}}
    },
    State1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(0, State),
    ?assert(maps:is_key(0, (State1#conn_state.streams_state)#conn_streams.streams)).

maybe_cleanup_stream_bumps_max_streams_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = data_sent, recv_state = data_read
    },
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            streams = #{0 => Stream},
            local_max_streams_bidi = 100,
            last_sent_max_streams_bidi = 100,
            opened_peer_bidi_count = 90
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    State1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(0, State),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual(101, (State1#conn_state.streams_state)#conn_streams.local_max_streams_bidi),
    ?assertMatch(
        [#max_streams{max_streams = 101, is_uni = false}],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(101, (State1#conn_state.streams_state)#conn_streams.last_sent_max_streams_bidi),
    ?assertEqual(0, (State1#conn_state.streams_state)#conn_streams.closed_peer_bidi_wm).

maybe_cleanup_stream_no_max_streams_for_local_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = data_sent, recv_state = data_read
    },
    State = #conn_state{
        role = client,
        streams_state = #conn_streams{
            streams = #{0 => Stream},
            local_max_streams_bidi = 100,
            next_bidi_stream = 4
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    State1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(0, State),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual([], (State1#conn_state.flow)#conn_flow.pending_app_frames),
    ?assertEqual(100, (State1#conn_state.streams_state)#conn_streams.local_max_streams_bidi),
    ?assertNot(maps:is_key(0, (State1#conn_state.streams_state)#conn_streams.closed_peer_streams)).

is_closed_stream_detected_test() ->
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{closed_peer_bidi_wm = 8}
    },
    ?assert(nquic_protocol_streams_lifecycle:is_closed_stream(0, State)),
    ?assert(nquic_protocol_streams_lifecycle:is_closed_stream(4, State)),
    ?assert(nquic_protocol_streams_lifecycle:is_closed_stream(8, State)).

is_closed_stream_unknown_test() ->
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{closed_peer_bidi_wm = 8}
    },
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(12, State)).

is_closed_stream_none_seen_test() ->
    State = #conn_state{role = server},
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(0, State)).

is_closed_stream_local_test() ->
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            next_bidi_stream = 1,
            closed_peer_bidi_wm = 8
        }
    },
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(1, State)).

is_closed_stream_local_initiated_test() ->
    State = #conn_state{
        role = client,
        streams_state = #conn_streams{next_bidi_stream = 8}
    },
    ?assert(nquic_protocol_streams_lifecycle:is_closed_stream(0, State)),
    ?assert(nquic_protocol_streams_lifecycle:is_closed_stream(4, State)),
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(8, State)).

is_closed_stream_local_still_active_test() ->
    Stream = #stream_state{
        send_state = ready,
        recv_state = recv,
        type = uni
    },
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            next_uni_stream = 15,
            streams = #{3 => Stream, 7 => Stream, 11 => Stream}
        }
    },
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(3, State)),
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(7, State)),
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(11, State)),
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(15, State)).

is_closed_stream_out_of_order_test() ->
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            max_peer_bidi_stream_id = 32,
            closed_peer_bidi_wm = 20,
            closed_peer_streams = #{32 => true}
        }
    },
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(24, State)),
    ?assertNot(nquic_protocol_streams_lifecycle:is_closed_stream(28, State)),
    ?assert(nquic_protocol_streams_lifecycle:is_closed_stream(32, State)),
    ?assert(nquic_protocol_streams_lifecycle:is_closed_stream(16, State)).

track_peer_stream_id_test() ->
    State = #conn_state{role = server},
    State1 = nquic_protocol_streams_send:track_peer_stream_id(0, State),
    ?assertEqual(0, (State1#conn_state.streams_state)#conn_streams.max_peer_bidi_stream_id),
    ?assertEqual(1, (State1#conn_state.streams_state)#conn_streams.opened_peer_bidi_count),
    State2 = nquic_protocol_streams_send:track_peer_stream_id(4, State1),
    ?assertEqual(4, (State2#conn_state.streams_state)#conn_streams.max_peer_bidi_stream_id),
    ?assertEqual(2, (State2#conn_state.streams_state)#conn_streams.opened_peer_bidi_count),
    State3 = nquic_protocol_streams_send:track_peer_stream_id(0, State2),
    ?assertEqual(4, (State3#conn_state.streams_state)#conn_streams.max_peer_bidi_stream_id),
    ?assertEqual(3, (State3#conn_state.streams_state)#conn_streams.opened_peer_bidi_count).

track_peer_stream_id_uni_test() ->
    State = #conn_state{role = server},
    State1 = nquic_protocol_streams_send:track_peer_stream_id(2, State),
    ?assertEqual(2, (State1#conn_state.streams_state)#conn_streams.max_peer_uni_stream_id),
    ?assertEqual(1, (State1#conn_state.streams_state)#conn_streams.opened_peer_uni_count),
    ?assertEqual(undefined, (State1#conn_state.streams_state)#conn_streams.max_peer_bidi_stream_id),
    ?assertEqual(0, (State1#conn_state.streams_state)#conn_streams.opened_peer_bidi_count).

track_peer_stream_id_local_noop_test() ->
    State = #conn_state{role = server},
    State1 = nquic_protocol_streams_send:track_peer_stream_id(1, State),
    ?assertEqual(undefined, (State1#conn_state.streams_state)#conn_streams.max_peer_bidi_stream_id),
    ?assertEqual(0, (State1#conn_state.streams_state)#conn_streams.opened_peer_bidi_count).

peer_consumed_counts_distinct_streams_not_max_id_test() ->
    State0 = #conn_state{role = server},
    State1 = nquic_protocol_streams_send:track_peer_stream_id(396, State0),
    ?assertEqual(1, nquic_protocol_streams_lifecycle:peer_consumed_bidi_streams(State1)),
    StateN = lists:foldl(
        fun(ID, Acc) -> nquic_protocol_streams_send:track_peer_stream_id(ID, Acc) end,
        State1,
        lists:seq(0, 392, 4)
    ),
    ?assertEqual(100, nquic_protocol_streams_lifecycle:peer_consumed_bidi_streams(StateN)),
    ?assertEqual(396, (StateN#conn_state.streams_state)#conn_streams.max_peer_bidi_stream_id).

peer_consumed_uni_counts_distinct_streams_not_max_id_test() ->
    State0 = #conn_state{role = server},
    State1 = nquic_protocol_streams_send:track_peer_stream_id(398, State0),
    ?assertEqual(1, nquic_protocol_streams_lifecycle:peer_consumed_uni_streams(State1)),
    StateN = lists:foldl(
        fun(ID, Acc) -> nquic_protocol_streams_send:track_peer_stream_id(ID, Acc) end,
        State1,
        lists:seq(2, 394, 4)
    ),
    ?assertEqual(100, nquic_protocol_streams_lifecycle:peer_consumed_uni_streams(StateN)).

max_streams_keeps_pace_with_out_of_order_opens_test() ->
    Base = #conn_state{
        role = server,
        streams_state = #conn_streams{
            local_max_streams_bidi = 100,
            last_sent_max_streams_bidi = 100
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    Final = lists:foldl(
        fun(ID, Acc) -> nquic_protocol_streams_send:track_peer_stream_id(ID, Acc) end,
        Base,
        lists:reverse(lists:seq(0, 396, 4))
    ),
    Opened = 100,
    ?assertEqual(
        Opened, nquic_protocol_streams_lifecycle:peer_consumed_bidi_streams(Final)
    ),
    ?assert(
        (Final#conn_state.streams_state)#conn_streams.local_max_streams_bidi >= Opened
    ).

read_stream_transitions_to_data_read_test() ->
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        send_state = data_sent,
        recv_state = size_known,
        app_buffer = <<"hello">>,
        app_buffer_size = 5
    },
    State = #conn_state{
        role = client,
        streams_state = #conn_streams{
            streams = #{0 => Stream}, local_max_streams_bidi = 100
        }
    },
    {ok, <<"hello">>, true, State1} = nquic_protocol:read_stream(0, State),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.streams).

max_streams_batching_no_frame_when_peer_below_threshold_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = data_sent, recv_state = data_read
    },
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            streams = #{0 => Stream},
            local_max_streams_bidi = 100,
            last_sent_max_streams_bidi = 100,
            opened_peer_bidi_count = 10
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    State1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(0, State),
    ?assertEqual(#{}, (State1#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual(101, (State1#conn_state.streams_state)#conn_streams.local_max_streams_bidi),
    ?assertEqual([], (State1#conn_state.flow)#conn_flow.pending_app_frames),
    ?assertEqual(100, (State1#conn_state.streams_state)#conn_streams.last_sent_max_streams_bidi).

max_streams_fires_at_threshold_test() ->
    Stream = #stream_state{
        stream_id = 0, type = bidi, send_state = data_sent, recv_state = data_read
    },
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            streams = #{0 => Stream},
            local_max_streams_bidi = 100,
            last_sent_max_streams_bidi = 100,
            opened_peer_bidi_count = 60
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    State1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(0, State),
    ?assertEqual(101, (State1#conn_state.streams_state)#conn_streams.local_max_streams_bidi),
    ?assertMatch(
        [#max_streams{max_streams = 101, is_uni = false}],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(101, (State1#conn_state.streams_state)#conn_streams.last_sent_max_streams_bidi).

max_streams_batching_many_cleanups_test() ->
    Base = #conn_state{
        role = server,
        streams_state = #conn_streams{
            local_max_streams_bidi = 100,
            last_sent_max_streams_bidi = 100,
            opened_peer_bidi_count = 10
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    Final = lists:foldl(
        fun(StreamID, Acc) ->
            nquic_protocol_streams_lifecycle:bump_max_streams(StreamID, Acc)
        end,
        Base,
        lists:seq(0, 196, 4)
    ),
    ?assertEqual(150, (Final#conn_state.streams_state)#conn_streams.local_max_streams_bidi),
    ?assertEqual([], (Final#conn_state.flow)#conn_flow.pending_app_frames),
    ?assertEqual(100, (Final#conn_state.streams_state)#conn_streams.last_sent_max_streams_bidi).

max_streams_large_initial_limit_test() ->
    Base = #conn_state{
        role = server,
        streams_state = #conn_streams{
            local_max_streams_bidi = 1000000,
            last_sent_max_streams_bidi = 1000000,
            opened_peer_bidi_count = 400000
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    Final = lists:foldl(
        fun(StreamID, Acc) -> nquic_protocol_streams_lifecycle:bump_max_streams(StreamID, Acc) end,
        Base,
        lists:seq(0, 396, 4)
    ),
    ?assertEqual(1000100, (Final#conn_state.streams_state)#conn_streams.local_max_streams_bidi),
    ?assertEqual([], (Final#conn_state.flow)#conn_flow.pending_app_frames).

max_streams_uni_threshold_test() ->
    Stream = #stream_state{
        stream_id = 2, type = uni, send_state = ready, recv_state = data_read
    },
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            streams = #{2 => Stream},
            local_max_streams_uni = 50,
            last_sent_max_streams_uni = 50,
            opened_peer_uni_count = 30
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    State1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(2, State),
    ?assertEqual(51, (State1#conn_state.streams_state)#conn_streams.local_max_streams_uni),
    ?assertMatch(
        [#max_streams{max_streams = 51, is_uni = true}],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ).

streams_blocked_triggers_update_test() ->
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            local_max_streams_bidi = 150,
            last_sent_max_streams_bidi = 100
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, [], State1} = nquic_protocol_recv:handle_frame(
        #streams_blocked{limit = 100, is_uni = false}, #short_header{}, State
    ),
    ?assertMatch(
        [#max_streams{max_streams = 150, is_uni = false}],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(150, (State1#conn_state.streams_state)#conn_streams.last_sent_max_streams_bidi).

streams_blocked_uni_triggers_update_test() ->
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            local_max_streams_uni = 75,
            last_sent_max_streams_uni = 50
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, [], State1} = nquic_protocol_recv:handle_frame(
        #streams_blocked{limit = 50, is_uni = true}, #short_header{}, State
    ),
    ?assertMatch(
        [#max_streams{max_streams = 75, is_uni = true}],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(75, (State1#conn_state.streams_state)#conn_streams.last_sent_max_streams_uni).

peer_consumed_bidi_streams_test() ->
    ?assertEqual(0, nquic_protocol_streams_lifecycle:peer_consumed_bidi_streams(#conn_state{})),
    ?assertEqual(
        1,
        nquic_protocol_streams_lifecycle:peer_consumed_bidi_streams(#conn_state{
            streams_state = #conn_streams{opened_peer_bidi_count = 1}
        })
    ),
    ?assertEqual(
        10,
        nquic_protocol_streams_lifecycle:peer_consumed_bidi_streams(#conn_state{
            streams_state = #conn_streams{opened_peer_bidi_count = 10}
        })
    ),
    ?assertEqual(
        100,
        nquic_protocol_streams_lifecycle:peer_consumed_bidi_streams(#conn_state{
            streams_state = #conn_streams{opened_peer_bidi_count = 100}
        })
    ).

peer_consumed_uni_streams_test() ->
    ?assertEqual(0, nquic_protocol_streams_lifecycle:peer_consumed_uni_streams(#conn_state{})),
    ?assertEqual(
        1,
        nquic_protocol_streams_lifecycle:peer_consumed_uni_streams(#conn_state{
            streams_state = #conn_streams{opened_peer_uni_count = 1}
        })
    ),
    ?assertEqual(
        10,
        nquic_protocol_streams_lifecycle:peer_consumed_uni_streams(#conn_state{
            streams_state = #conn_streams{opened_peer_uni_count = 10}
        })
    ).

max_streams_small_initial_limit_test() ->
    State = #conn_state{
        role = server,
        streams_state = #conn_streams{
            local_max_streams_bidi = 3,
            last_sent_max_streams_bidi = 2,
            opened_peer_bidi_count = 1
        },
        flow = #conn_flow{pending_app_frames = []}
    },
    State1 = nquic_protocol_streams_lifecycle:bump_max_streams(0, State),
    ?assertEqual(4, (State1#conn_state.streams_state)#conn_streams.local_max_streams_bidi),
    ?assertMatch(
        [#max_streams{max_streams = 4, is_uni = false}],
        (State1#conn_state.flow)#conn_flow.pending_app_frames
    ).

packet_payload_budget_test() ->
    State = #conn_state{dcid = <<1, 2, 3, 4, 5, 6, 7, 8>>},
    ?assertEqual(1171, nquic_protocol_send:packet_payload_budget(State)).

pre_encode(Frame) ->
    Enc = nquic_frame:encode(Frame),
    {iolist_size(Enc), Enc, Frame}.

pre_encode_list(Frames) ->
    [pre_encode(F) || F <- Frames].

frame_encoded_size_test_() ->
    [
        ?_assertEqual(1, element(1, pre_encode(#ping{}))),
        ?_assertEqual(1, element(1, pre_encode(#padding{}))),
        ?_assert(
            element(
                1,
                pre_encode(#stream{
                    stream_id = 0, offset = 0, length = 10, data = <<0:80>>
                })
            ) > 10
        )
    ].

take_frames_single_fits_test() ->
    Entry = pre_encode(#ping{}),
    {Batch, Rest} = nquic_protocol_send:take_frames_for_mtu_pre([Entry], 1000),
    ?assertEqual([Entry], Batch),
    ?assertEqual([], Rest).

take_frames_all_fit_test() ->
    Entries = pre_encode_list([#ping{}, #ping{}, #ping{}]),
    {Batch, Rest} = nquic_protocol_send:take_frames_for_mtu_pre(Entries, 1000),
    ?assertEqual(Entries, Batch),
    ?assertEqual([], Rest).

take_frames_split_at_budget_test() ->
    MkFrame = fun(ID) ->
        #stream{stream_id = ID, offset = 0, length = 60, data = <<0:480>>}
    end,
    Frames = [MkFrame(I * 4) || I <- lists:seq(0, 19)],
    Entries = pre_encode_list(Frames),
    {Batch, Rest} = nquic_protocol_send:take_frames_for_mtu_pre(Entries, 200),
    ?assert(length(Batch) >= 1),
    ?assert(length(Batch) =< 3),
    ?assertEqual(length(Entries), length(Batch) + length(Rest)).

take_frames_oversized_single_frame_test() ->
    BigFrame = #stream{stream_id = 0, offset = 0, length = 2000, data = <<0:16000>>},
    Entry = pre_encode(BigFrame),
    {Batch, Rest} = nquic_protocol_send:take_frames_for_mtu_pre([Entry], 100),
    ?assertEqual([Entry], Batch),
    ?assertEqual([], Rest).

take_frames_ack_first_test() ->
    Ack = #ack{largest_acknowledged = 10, delay = 0, first_ack_range = 5},
    StreamFrames = [
        #stream{stream_id = I * 4, offset = 0, length = 60, data = <<0:480>>}
     || I <- lists:seq(0, 19)
    ],
    Frames = nquic_protocol_send_queues:sort_frames([Ack | StreamFrames]),
    Entries = pre_encode_list(Frames),
    {Batch, _Rest} = nquic_protocol_send:take_frames_for_mtu_pre(Entries, 200),
    ?assertMatch([{_, _, #ack{}} | _], Batch).

take_frames_empty_test() ->
    {Batch, Rest} = nquic_protocol_send:take_frames_for_mtu_pre([], 1000),
    ?assertEqual([], Batch),
    ?assertEqual([], Rest).

%%%-------------------------------------------------------------------
%%% CRYPTO-in-0-RTT detection (RFC 9001 §8.3 / h3spec [TLS 8.3]).
%%%-------------------------------------------------------------------

crypto_in_zero_rtt_is_protocol_violation_test() ->
    State = #conn_state{role = server},
    Header = #long_header{type = rtt0, dcid = <<0:64>>, scid = <<0:64>>},
    Frame = #crypto{offset = 0, data = <<"unsolicited">>},
    ?assertMatch(
        {error, {transport_error, protocol_violation}, _},
        nquic_protocol_recv:handle_frame(Frame, Header, State)
    ).

crypto_in_zero_rtt_handle_frames_propagates_test() ->
    State = #conn_state{role = server},
    Header = #long_header{type = rtt0, dcid = <<0:64>>, scid = <<0:64>>},
    Frames = [#crypto{offset = 0, data = <<"unsolicited">>}],
    ?assertMatch(
        {error, {transport_error, protocol_violation}, _},
        nquic_protocol_recv:handle_frames(Frames, Header, State)
    ).

build_app_packet_no_keys_returns_error_test() ->
    State = #conn_state{
        role = client,
        crypto = #conn_crypto{keys = #{}, app_send_keys = undefined},
        pn_spaces = #{application => #{next_pn => 0}},
        loss_state = nquic_loss:init(),
        path = #conn_path_mgmt{address_validated = true}
    },
    ?assertMatch(
        {error, no_app_keys, _},
        nquic_protocol_send:build_app_packet([#ping{}], State)
    ).

build_app_packet_pre_no_keys_returns_error_test() ->
    State = make_app_send_state(undefined),
    Frame = #ping{},
    Enc = iolist_to_binary(nquic_frame:encode(Frame)),
    PreEncoded = [{byte_size(Enc), Enc, Frame}],
    Time = erlang:monotonic_time(microsecond),
    ?assertMatch(
        {error, no_app_keys, _},
        nquic_protocol_send:build_app_packet_pre(PreEncoded, Time, State)
    ).

build_app_packet_pre_happy_path_test() ->
    State = make_app_send_state(aes_128_gcm),
    Frame = #ping{},
    Enc = iolist_to_binary(nquic_frame:encode(Frame)),
    PreEncoded = [{byte_size(Enc), Enc, Frame}],
    Time = erlang:monotonic_time(microsecond),
    {ok, Packet, State1} =
        nquic_protocol_send:build_app_packet_pre(PreEncoded, Time, State),
    PacketBin = iolist_to_binary(Packet),
    ?assert(byte_size(PacketBin) > 0),
    ?assertEqual(State#conn_state.app_next_pn + 1, State1#conn_state.app_next_pn).

build_app_packet_pre_amplification_limited_test() ->
    State0 = make_app_send_state(aes_128_gcm),
    State = State0#conn_state{
        role = server,
        path = #conn_path_mgmt{
            address_validated = false,
            anti_amp_bytes_received = 0,
            anti_amp_bytes_sent = 0
        }
    },
    Frame = #ping{},
    Enc = iolist_to_binary(nquic_frame:encode(Frame)),
    PreEncoded = [{byte_size(Enc), Enc, Frame}],
    Time = erlang:monotonic_time(microsecond),
    ?assertMatch(
        {ok, <<>>, _},
        nquic_protocol_send:build_app_packet_pre(PreEncoded, Time, State)
    ).

build_packets_mtu_pre_happy_path_test() ->
    State = make_app_send_state(aes_128_gcm),
    Frame = #ping{},
    Enc = iolist_to_binary(nquic_frame:encode(Frame)),
    PreEncoded = [{byte_size(Enc), Enc, Frame}, {byte_size(Enc), Enc, Frame}],
    Time = erlang:monotonic_time(microsecond),
    {Packets, State1} =
        nquic_protocol_send:build_packets_mtu_pre(PreEncoded, 1200, Time, State, []),
    ?assert(length(Packets) >= 1),
    ?assertEqual(
        State#conn_state.app_next_pn + length(Packets),
        State1#conn_state.app_next_pn
    ).

build_packets_mtu_pre_empty_test() ->
    State = make_app_send_state(aes_128_gcm),
    Time = erlang:monotonic_time(microsecond),
    ?assertEqual(
        {[], State},
        nquic_protocol_send:build_packets_mtu_pre([], 1200, Time, State, [])
    ).

build_zero_rtt_packet_pre_no_keys_test() ->
    State = make_app_send_state(undefined),
    Frame = #ping{},
    Enc = iolist_to_binary(nquic_frame:encode(Frame)),
    PreEncoded = [{byte_size(Enc), Enc, Frame}],
    Time = erlang:monotonic_time(microsecond),
    ?assertMatch(
        {error, no_zero_rtt_keys, _},
        nquic_protocol_send:build_zero_rtt_packet_pre(PreEncoded, Time, State)
    ).

build_zero_rtt_packet_pre_happy_path_test() ->
    Cipher = aes_128_gcm,
    Secret = crypto:strong_rand_bytes(32),
    {K, IV, HP} = nquic_keys:derive_packet_protection(Secret, Cipher, 1),
    RoleKeys = nquic_keys:make_role_keys(Cipher, K, IV, HP),
    State0 = make_app_send_state(Cipher),
    Crypto0 = State0#conn_state.crypto,
    State = State0#conn_state{
        crypto = Crypto0#conn_crypto{
            keys = #{rtt0 => #{client => RoleKeys}},
            cipher = Cipher
        }
    },
    Frame = #ping{},
    Enc = iolist_to_binary(nquic_frame:encode(Frame)),
    PreEncoded = [{byte_size(Enc), Enc, Frame}],
    Time = erlang:monotonic_time(microsecond),
    {ok, Packet, State1} =
        nquic_protocol_send:build_zero_rtt_packet_pre(PreEncoded, Time, State),
    PacketBin = iolist_to_binary(Packet),
    ?assert(byte_size(PacketBin) > 0),
    ?assertEqual(State#conn_state.app_next_pn + 1, State1#conn_state.app_next_pn).

make_app_send_state(Cipher) ->
    Keys =
        case Cipher of
            undefined ->
                undefined;
            _ ->
                Secret = crypto:strong_rand_bytes(32),
                {K, IV, HP} = nquic_keys:derive_packet_protection(Secret, Cipher, 1),
                nquic_keys:make_role_keys(Cipher, K, IV, HP)
        end,
    #conn_state{
        role = client,
        version = 1,
        dcid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        scid = <<9, 10, 11, 12, 13, 14, 15, 16>>,
        crypto = #conn_crypto{
            cipher = Cipher,
            key_phase = false,
            app_send_keys = Keys,
            keys = #{}
        },
        app_next_pn = 0,
        pn_spaces = #{application => #{next_pn => 0}},
        loss_state = nquic_loss:init(),
        path = #conn_path_mgmt{address_validated = true},
        flow = #conn_flow{},
        gso_size = 0
    }.

build_handshake_packet_no_keys_returns_error_test() ->
    State = #conn_state{
        role = client,
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{},
        loss_state = nquic_loss:init(),
        path = #conn_path_mgmt{address_validated = true}
    },
    ?assertMatch(
        {error, no_handshake_keys, _},
        nquic_protocol_send:build_handshake_packet([#ping{}], State)
    ).

make_handshake_send_state(PeerMaxUdp) ->
    Cipher = aes_128_gcm,
    Secret = crypto:strong_rand_bytes(32),
    {K, IV, HP} = nquic_keys:derive_packet_protection(Secret, Cipher, 1),
    RoleKeys = nquic_keys:make_role_keys(Cipher, K, IV, HP),
    RemoteParams =
        case PeerMaxUdp of
            undefined -> undefined;
            _ -> #transport_params{max_udp_payload_size = PeerMaxUdp}
        end,
    #conn_state{
        role = server,
        version = 1,
        dcid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        scid = <<9, 10, 11, 12, 13, 14, 15, 16>>,
        max_payload_size = 1200,
        remote_params = RemoteParams,
        crypto = #conn_crypto{cipher = Cipher, keys = #{handshake => #{server => RoleKeys}}},
        pn_spaces = #{handshake => #{next_pn => 0}},
        loss_state = nquic_loss:init(),
        path = #conn_path_mgmt{address_validated = true},
        flow = #conn_flow{},
        gso_size = undefined
    }.

queue_handshake_flight(State0, Flight) ->
    Flow = State0#conn_state.flow,
    State0#conn_state{
        flow = Flow#conn_flow{pending_handshake_frames = [#crypto{offset = 0, data = Flight}]}
    }.

build_handshake_packets_small_flight_single_packet_test() ->
    State = queue_handshake_flight(make_handshake_send_state(1472), crypto:strong_rand_bytes(100)),
    {Packets, _State1} = nquic_protocol_send_queues:flush_handshake(State),
    ?assertEqual(1, length(Packets)).

build_handshake_packets_splits_large_flight_test() ->
    State = queue_handshake_flight(make_handshake_send_state(1472), crypto:strong_rand_bytes(4000)),
    {Packets, _State1} = nquic_protocol_send_queues:flush_handshake(State),
    ?assert(length(Packets) >= 4),
    lists:foreach(
        fun(P) -> ?assert(byte_size(iolist_to_binary(P)) =< 1200) end,
        Packets
    ).

build_handshake_packets_respects_peer_max_udp_payload_test() ->
    PeerMax = 1300,
    State0 = (make_handshake_send_state(PeerMax))#conn_state{max_payload_size = 9000},
    State = queue_handshake_flight(State0, crypto:strong_rand_bytes(6000)),
    {Packets, _State1} = nquic_protocol_send_queues:flush_handshake(State),
    ?assert(length(Packets) >= 2),
    lists:foreach(
        fun(P) -> ?assert(byte_size(iolist_to_binary(P)) =< PeerMax) end,
        Packets
    ).

build_handshake_packets_distinct_packet_numbers_test() ->
    State = queue_handshake_flight(make_handshake_send_state(1472), crypto:strong_rand_bytes(4000)),
    {Packets, State1} = nquic_protocol_send_queues:flush_handshake(State),
    HsSpace = maps:get(handshake, State1#conn_state.pn_spaces),
    ?assertEqual(length(Packets), maps:get(next_pn, HsSpace)).

build_initial_packet_no_keys_returns_error_test() ->
    State = #conn_state{
        role = client,
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{},
        loss_state = nquic_loss:init(),
        path = #conn_path_mgmt{address_validated = true}
    },
    ?assertMatch(
        {error, no_initial_keys, _},
        nquic_protocol_send:build_initial_packet([#ping{}], State)
    ).

build_initial_packet_arity3_no_keys_returns_error_test() ->
    State = #conn_state{
        role = client,
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{},
        loss_state = nquic_loss:init(),
        path = #conn_path_mgmt{address_validated = true}
    },
    ?assertMatch(
        {error, no_initial_keys, _},
        nquic_protocol_send:build_initial_packet([#ping{}], State, <<>>)
    ).

version_negotiation_no_common_returns_error_test() ->
    State = #conn_state{
        role = client,
        scid = <<1:64>>,
        dcid = <<2:64>>,
        version = 1,
        crypto = #conn_crypto{keys = #{}},
        pn_spaces = #{initial => #{next_pn => 0}},
        loss_state = nquic_loss:init(),
        path = #conn_path_mgmt{
            address_validated = true,
            path_state = nquic_path:new(undefined)
        }
    },
    VNHeader = #long_header{
        type = version_negotiation,
        version = 0,
        dcid = State#conn_state.scid,
        scid = State#conn_state.dcid,
        token = <<16#DEADBEEF:32>>
    },
    ?assertMatch(
        {error, {transport_error, version_negotiation_error}, _},
        nquic_protocol_recv:handle_version_negotiation(VNHeader, State)
    ).

version_negotiation_drops_on_server_test() ->
    State = #conn_state{role = server},
    Header = #long_header{type = version_negotiation, dcid = <<>>, scid = <<>>, token = <<>>},
    ?assertMatch({ok, [], _}, nquic_protocol_recv:handle_version_negotiation(Header, State)).

version_negotiation_drops_after_packet_processed_test() ->
    State = #conn_state{role = client, server_packet_processed = true},
    Header = #long_header{type = version_negotiation, dcid = <<>>, scid = <<>>, token = <<>>},
    ?assertMatch({ok, [], _}, nquic_protocol_recv:handle_version_negotiation(Header, State)).

version_negotiation_drops_on_cid_mismatch_test() ->
    State = #conn_state{
        role = client,
        scid = <<1:64>>,
        dcid = <<2:64>>
    },
    Header = #long_header{
        type = version_negotiation,
        dcid = <<99:64>>,
        scid = <<2:64>>,
        token = <<>>
    },
    ?assertMatch({ok, [], _}, nquic_protocol_recv:handle_version_negotiation(Header, State)).

version_negotiation_drops_when_listing_current_version_test() ->
    State = #conn_state{
        role = client,
        scid = <<1:64>>,
        dcid = <<2:64>>,
        version = 1
    },
    Header = #long_header{
        type = version_negotiation,
        dcid = State#conn_state.scid,
        scid = State#conn_state.dcid,
        token = <<1:32>>
    },
    ?assertMatch(
        {ok, [], _},
        nquic_protocol_recv:handle_version_negotiation(Header, State)
    ).

version_negotiation_malformed_list_test() ->
    State = #conn_state{
        role = client,
        scid = <<1:64>>,
        dcid = <<2:64>>,
        version = 1
    },
    Header = #long_header{
        type = version_negotiation,
        dcid = State#conn_state.scid,
        scid = State#conn_state.dcid,
        token = <<1, 2, 3>>
    },
    ?assertMatch(
        {ok, [], _},
        nquic_protocol_recv:handle_version_negotiation(Header, State)
    ).

version_negotiation_retries_with_supported_version_test() ->
    ssl:start(),
    State = #conn_state{
        role = client,
        scid = <<1:64>>,
        dcid = <<2:64>>,
        version = 1,
        local_params = #transport_params{initial_max_data = 1000},
        crypto = #conn_crypto{
            alpn = [<<"h3">>],
            hostname = "localhost",
            keys = #{}
        },
        pn_spaces = #{initial => #{next_pn => 0}},
        loss_state = nquic_loss:init(),
        path = #conn_path_mgmt{
            address_validated = true,
            path_state = nquic_path:new(undefined)
        }
    },
    VNHeader = #long_header{
        type = version_negotiation,
        version = 0,
        dcid = State#conn_state.scid,
        scid = State#conn_state.dcid,
        token = <<16#6b3343cf:32>>
    },
    ?assertMatch(
        {ok, [], #conn_state{version = 16#6b3343cf}},
        nquic_protocol_recv:handle_version_negotiation(VNHeader, State)
    ).

%%%-----------------------------------------------------------------------------
%% CONNECTION_CLOSE encryption-level selection (library-mode handshake closes)
%%%-----------------------------------------------------------------------------

close_during_handshake_uses_initial_and_handshake_spaces_test() ->
    State = #conn_state{
        crypto = #conn_crypto{keys = #{initial => #{}, handshake => #{}}},
        flow = #conn_flow{}
    },
    {ok, State1} = nquic_protocol:close(16#8, <<"transport_parameter_error">>, State),
    Flow = State1#conn_state.flow,
    ?assertMatch([#connection_close{error_code = 16#8}], Flow#conn_flow.pending_initial_frames),
    ?assertMatch([#connection_close{error_code = 16#8}], Flow#conn_flow.pending_handshake_frames),
    ?assertEqual([], Flow#conn_flow.pending_app_frames).

close_during_initial_only_uses_initial_space_test() ->
    State = #conn_state{
        crypto = #conn_crypto{keys = #{initial => #{}}},
        flow = #conn_flow{}
    },
    {ok, State1} = nquic_protocol:close(16#a, <<"protocol_violation">>, State),
    Flow = State1#conn_state.flow,
    ?assertMatch([#connection_close{error_code = 16#a}], Flow#conn_flow.pending_initial_frames),
    ?assertEqual([], Flow#conn_flow.pending_handshake_frames),
    ?assertEqual([], Flow#conn_flow.pending_app_frames).

close_established_uses_app_space_test() ->
    State = #conn_state{
        crypto = #conn_crypto{app_send_keys = #{}, keys = #{handshake => #{}, app => #{}}},
        flow = #conn_flow{}
    },
    {ok, State1} = nquic_protocol:close(0, <<>>, State),
    Flow = State1#conn_state.flow,
    ?assertMatch([#connection_close{}], Flow#conn_flow.pending_app_frames),
    ?assertEqual([], Flow#conn_flow.pending_initial_frames),
    ?assertEqual([], Flow#conn_flow.pending_handshake_frames).
