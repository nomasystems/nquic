%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_conn_statem}.
%%%-------------------------------------------------------------------
-module(nquic_conn_statem_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-include("nquic_transport.hrl").
check_congestion_control_test_() ->
    LossState = nquic_loss:init(),
    ConnState = #conn_state{loss_state = LossState},
    [
        ?_assertEqual(ok, nquic_protocol_send:check_congestion_control(ConnState, 1000)),
        ?_assertEqual(ok, nquic_protocol_send:check_congestion_control(ConnState, 12000)),
        ?_assertMatch({blocked, _}, nquic_protocol_send:check_congestion_control(ConnState, 15000))
    ].

get_packet_len_test_() ->
    LongHeader = #long_header{
        type = initial,
        version = 1,
        dcid = <<>>,
        scid = <<>>,
        token = <<>>,
        payload_len = 1200,
        packet_number = 0
    },
    ShortHeader = #short_header{dcid = <<1, 2, 3, 4>>, packet_number = 1, key_phase = false},
    [
        ?_assertEqual({ok, 1200}, nquic_protocol_send:get_packet_len(LongHeader, 1500)),
        ?_assertEqual({ok, 500}, nquic_protocol_send:get_packet_len(ShortHeader, 500))
    ].

maybe_update_dcid_test_() ->
    ServerInitialNoDCID = #conn_state{role = server, dcid = <<>>},
    ServerWithDCID = #conn_state{role = server, dcid = <<1, 2>>},
    ClientState = #conn_state{role = client, dcid = <<>>},
    InitHeader = #long_header{
        type = initial,
        scid = <<5, 6, 7, 8>>,
        version = 1,
        dcid = <<>>,
        token = <<>>,
        payload_len = 100,
        packet_number = 0
    },
    HSHeader = #long_header{
        type = handshake,
        scid = <<5, 6, 7, 8>>,
        version = 1,
        dcid = <<>>,
        token = <<>>,
        payload_len = 100,
        packet_number = 0
    },
    [
        ?_assertEqual(
            <<5, 6, 7, 8>>,
            (nquic_protocol_send:maybe_update_dcid(InitHeader, ServerInitialNoDCID))#conn_state.dcid
        ),
        ?_assertEqual(
            <<1, 2>>,
            (nquic_protocol_send:maybe_update_dcid(InitHeader, ServerWithDCID))#conn_state.dcid
        ),
        ?_assertEqual(
            <<5, 6, 7, 8>>,
            (nquic_protocol_send:maybe_update_dcid(InitHeader, ClientState))#conn_state.dcid
        ),
        ?_assertEqual(
            <<1, 2>>,
            (nquic_protocol_send:maybe_update_dcid(
                InitHeader,
                ClientState#conn_state{dcid = <<1, 2>>, server_packet_processed = true}
            ))#conn_state.dcid
        ),
        ?_assertEqual(
            <<>>,
            (nquic_protocol_send:maybe_update_dcid(HSHeader, ServerInitialNoDCID))#conn_state.dcid
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
        ?_assertEqual(
            <<"internal_error">>, nquic_protocol:error_to_reason_phrase(internal_error)
        ),
        ?_assertEqual(<<>>, nquic_protocol:error_to_reason_phrase({unknown, tuple}))
    ].

callback_mode_test() ->
    ?assertEqual(state_functions, nquic_conn_statem:callback_mode()).

ensure_stream_limits_already_init_test() ->
    StreamState = #stream_state{stream_id = 0, send_max_data = 1000, recv_window = 1000},
    ConnState = #conn_state{},
    Result = nquic_frame_handler:ensure_stream_limits(StreamState, ConnState),
    ?assertEqual(StreamState, Result).

ensure_stream_limits_needs_init_test() ->
    StreamState = #stream_state{stream_id = 0, send_max_data = 0, recv_window = 0},
    RemoteParams = #transport_params{
        initial_max_stream_data_bidi_remote = 5000,
        initial_max_stream_data_bidi_local = 3000
    },
    LocalParams = #transport_params{
        initial_max_stream_data_bidi_local = 4000
    },
    ConnState = #conn_state{
        role = client,
        remote_params = RemoteParams,
        local_params = LocalParams
    },
    Result = nquic_frame_handler:ensure_stream_limits(StreamState, ConnState),
    ?assert(Result#stream_state.send_max_data > 0 orelse Result#stream_state.recv_window > 0).

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

crypto_buffer_adversarial_fragments_test_() ->
    {timeout, 5, fun() ->
        N = 5000,
        Initial = {0, <<>>, []},
        Final = lists:foldl(
            fun(I, Acc) ->
                nquic_protocol_recv:crypto_buffer_add(I, <<I:8>>, Acc)
            end,
            Initial,
            lists:seq(0, N - 1)
        ),
        Bin = nquic_protocol_recv:crypto_buffer_data(Final),
        ?assertEqual(N, byte_size(Bin)),
        <<_:100/binary, Byte:8, _/binary>> = Bin,
        ?assertEqual(100, Byte)
    end}.

crypto_buffer_adversarial_out_of_order_test_() ->
    {timeout, 5, fun() ->
        N = 1000,
        Initial = {0, <<>>, []},
        Final = lists:foldl(
            fun(I, Acc) ->
                nquic_protocol_recv:crypto_buffer_add(I, <<I:8>>, Acc)
            end,
            Initial,
            lists:reverse(lists:seq(0, N - 1))
        ),
        Bin = nquic_protocol_recv:crypto_buffer_data(Final),
        ?assertEqual(N, byte_size(Bin)),
        Expected = list_to_binary([<<I:8>> || I <- lists:seq(0, N - 1)]),
        ?assertEqual(Expected, Bin)
    end}.

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

handle_packet_event_test() ->
    Self = self(),
    Event = {udp, socket, {127, 0, 0, 1}, 4433, <<"test">>},
    nquic_conn_statem:handle_packet_event(Self, Event),
    receive
        Msg -> ?assertEqual(Event, Msg)
    after 100 ->
        ?assert(false)
    end.

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
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}},
        flow = #conn_flow{data_received = 100, local_max_data = 10000}
    },
    {ok, _Events, NewData} = nquic_protocol_streams:handle_reset_stream(0, 500, 0, Stream, Data),
    NewStream = maps:get(0, (NewData#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual(reset_recvd, NewStream#stream_state.recv_state),
    ?assertEqual(500, NewStream#stream_state.recv_offset),
    ?assertEqual(500, NewStream#stream_state.recv_max_offset),
    ?assert(gb_trees:is_empty(NewStream#stream_state.recv_buffer)),
    ?assertEqual([], NewStream#stream_state.app_buffer),
    ?assertEqual(500, (NewData#conn_state.flow)#conn_flow.data_received).

handle_reset_stream_final_size_error_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = size_known,
        recv_max_offset = 200
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}},
        flow = #conn_flow{data_received = 200, local_max_data = 10000}
    },
    ?assertMatch(
        {error, {transport_error, final_size_error}, _},
        nquic_protocol_streams:handle_reset_stream(0, 300, 0, Stream, Data)
    ).

handle_reset_stream_flow_control_error_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = recv,
        recv_max_offset = 0
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}},
        flow = #conn_flow{data_received = 0, local_max_data = 100}
    },
    ?assertMatch(
        {error, {transport_error, flow_control_error}, _},
        nquic_protocol_streams:handle_reset_stream(0, 200, 0, Stream, Data)
    ).

handle_reset_stream_already_reset_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = reset_recvd,
        recv_max_offset = 100
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}},
        flow = #conn_flow{data_received = 100, local_max_data = 10000}
    },
    ?assertMatch({ok, _, _}, nquic_protocol_streams:handle_reset_stream(0, 100, 0, Stream, Data)).

handle_reset_stream_new_test() ->
    Data = #conn_state{flow = #conn_flow{data_received = 50, local_max_data = 1000}},
    {ok, _Events, NewData} = nquic_protocol_streams:handle_reset_stream_new(200, Data),
    ?assertEqual(250, (NewData#conn_state.flow)#conn_flow.data_received).

handle_stop_sending_test() ->
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        send_state = send,
        send_offset = 150
    },
    Data = #conn_state{
        role = client,
        streams_state = #conn_streams{streams = #{0 => Stream}},
        crypto = #conn_crypto{keys = #{}},
        socket = undefined,
        pn_spaces = #{},
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, _Events, NewData} = nquic_protocol_streams:handle_stop_sending(0, 42, Data),
    NewStream = maps:get(0, (NewData#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual(reset_sent, NewStream#stream_state.send_state).

handle_stop_sending_already_reset_test() ->
    Stream = #stream_state{
        stream_id = 0,
        send_state = reset_sent,
        send_offset = 100
    },
    Data = #conn_state{streams_state = #conn_streams{streams = #{0 => Stream}}},
    {ok, _Events, Data} = nquic_protocol_streams:handle_stop_sending(0, 42, Data).

handle_stop_sending_unknown_stream_test() ->
    Data = #conn_state{streams_state = #conn_streams{streams = #{}}},
    {ok, _Events, Data} = nquic_protocol_streams:handle_stop_sending(0, 42, Data).

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

build_ack_for_space_test() ->
    Data0 = #conn_state{pn_spaces = #{initial => #{next_pn => 0}}},
    ?assertEqual(none, nquic_protocol_ack:build_ack_for_space(initial, Data0)),
    Data1 = #conn_state{
        pn_spaces = #{
            initial => #{next_pn => 1, largest_received => 2, received_ranges => [{2, 0}]}
        }
    },
    {ok, Ack} = nquic_protocol_ack:build_ack_for_space(initial, Data1),
    ?assertEqual(2, Ack#ack.largest_acknowledged),
    ?assertEqual(2, Ack#ack.first_ack_range),
    ?assertEqual([], Ack#ack.ack_ranges).

maybe_drain_test_() ->
    BaseData = #conn_state{
        crypto = #conn_crypto{keys = #{initial => #{client => #{}}}},
        loss_state = nquic_loss:init(),
        connect_waiters = []
    },
    BaseEmpty = BaseData#conn_state{crypto = #conn_crypto{keys = #{}}},
    [
        ?_assertMatch(
            {next_state, draining, _, _},
            nquic_conn_close:maybe_drain(
                initial, {stop, {transport_error, protocol_violation}, BaseData}
            )
        ),
        ?_assertMatch(
            {stop, {transport_error, protocol_violation}, _},
            nquic_conn_close:maybe_drain(
                initial, {stop, {transport_error, protocol_violation}, BaseEmpty}
            )
        ),
        ?_assertEqual(
            {stop, normal, BaseData},
            nquic_conn_close:maybe_drain(initial, {stop, normal, BaseData})
        ),
        ?_assertEqual(
            {keep_state, BaseData},
            nquic_conn_close:maybe_drain(initial, {keep_state, BaseData})
        )
    ].

get_draining_timeout_test() ->
    Data = #conn_state{
        loss_state = nquic_loss:init(),
        remote_params = #transport_params{max_ack_delay = 25}
    },
    Timeout = nquic_protocol:get_draining_timeout(Data),
    ?assert(Timeout > 0),
    PtoUs = nquic_loss:get_pto_timeout(Data#conn_state.loss_state, 25_000),
    ExpectedMs = max(1, ((3 * PtoUs) + 999) div 1000),
    ?assertEqual(ExpectedMs, Timeout).

enter_draining_silent_test() ->
    Data = #conn_state{
        loss_state = nquic_loss:init(),
        remote_params = undefined,
        connect_waiters = []
    },
    {next_state, draining, _, Actions} = nquic_conn_close:enter_draining_silent(Data),
    ?assert(
        lists:any(
            fun
                ({{timeout, draining_timeout}, _, drain_expire}) -> true;
                (_) -> false
            end,
            Actions
        )
    ),
    assert_draining_cancellations(Actions).

enter_close_draining_cancels_other_timers_test() ->
    Data = #conn_state{
        loss_state = nquic_loss:init(),
        remote_params = undefined,
        connect_waiters = [],
        streams_state = #conn_streams{
            recv_waiters = #{},
            accept_stream_waiters = queue:new()
        }
    },
    From = {self(), make_ref()},
    {next_state, draining, _, Actions} = nquic_conn_close:enter_close_draining(From, Data),
    ?assert(
        lists:any(
            fun
                ({reply, F, ok}) when F =:= From -> true;
                (_) -> false
            end,
            Actions
        )
    ),
    ?assert(
        lists:any(
            fun
                ({{timeout, draining_timeout}, _, drain_expire}) -> true;
                (_) -> false
            end,
            Actions
        )
    ),
    assert_draining_cancellations(Actions).

assert_draining_cancellations(Actions) ->
    Cancellations = [idle_timeout, pto_timeout, ack_delay, path_validation],
    lists:foreach(
        fun(Name) ->
            ?assert(
                lists:member({{timeout, Name}, infinity, undefined}, Actions),
                {missing_cancellation, Name}
            )
        end,
        Cancellations
    ).

handle_recv_stream_with_data_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = recv,
        app_buffer = <<"hello">>,
        app_buffer_size = 5
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}, recv_waiters = #{}}
    },
    From = {self(), make_ref()},
    {reply, {ok, <<"hello">>, nofin}, NewData} =
        nquic_conn_streams:recv_stream(From, 0, Data),
    #{0 := NewStream} = (NewData#conn_state.streams_state)#conn_streams.streams,
    ?assertEqual([], NewStream#stream_state.app_buffer).

handle_recv_stream_fin_no_data_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = size_known,
        app_buffer = []
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}, recv_waiters = #{}}
    },
    From = {self(), make_ref()},
    {reply, {ok, <<>>, fin}, _, flush} =
        nquic_conn_streams:recv_stream(From, 0, Data).

handle_recv_stream_not_found_test() ->
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{}, recv_waiters = #{}}
    },
    From = {self(), make_ref()},
    {reply, {error, stream_not_found}, _} =
        nquic_conn_streams:recv_stream(From, 99, Data).

handle_recv_stream_waiter_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = recv,
        app_buffer = []
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}, recv_waiters = #{}}
    },
    From = {self(), make_ref()},
    {wait, NewData} = nquic_conn_streams:recv_stream(From, 0, Data),
    ?assert(maps:is_key(0, (NewData#conn_state.streams_state)#conn_streams.recv_waiters)).

handle_recv_stream_reset_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = reset_recvd,
        app_buffer = []
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}, recv_waiters = #{}}
    },
    From = {self(), make_ref()},
    {reply, {error, stream_reset}, _, flush} =
        nquic_conn_streams:recv_stream(From, 0, Data).

handle_accept_stream_with_pending_test() ->
    Data = #conn_state{
        streams_state = #conn_streams{
            pending_streams = queue:from_list([4, 8]),
            accept_stream_waiters = queue:new()
        }
    },
    From = {self(), make_ref()},
    {reply, {ok, 4}, NewData} =
        nquic_conn_streams:accept_stream(From, Data),
    ?assertEqual(
        [8], queue:to_list((NewData#conn_state.streams_state)#conn_streams.pending_streams)
    ).

handle_accept_stream_waiter_test() ->
    Data = #conn_state{
        streams_state = #conn_streams{
            pending_streams = queue:new(),
            accept_stream_waiters = queue:new()
        }
    },
    From = {self(), make_ref()},
    {wait, NewData} = nquic_conn_streams:accept_stream(From, Data),
    ?assertEqual(
        [From], queue:to_list((NewData#conn_state.streams_state)#conn_streams.accept_stream_waiters)
    ).

notify_or_queue_stream_no_waiter_test() ->
    Data = #conn_state{
        streams_state = #conn_streams{
            accept_stream_waiters = queue:new(),
            pending_streams = queue:new()
        }
    },
    NewData = nquic_conn_streams:notify_or_queue_stream(4, Data),
    ?assertEqual(
        [4], queue:to_list((NewData#conn_state.streams_state)#conn_streams.pending_streams)
    ).

handle_close_stream_test() ->
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        send_state = send,
        send_offset = 10
    },
    Data = #conn_state{
        role = client,
        streams_state = #conn_streams{streams = #{0 => Stream}},
        crypto = #conn_crypto{keys = #{}},
        socket = undefined,
        pn_spaces = #{}
    },
    {ok, NewData} = nquic_protocol:close_stream(0, Data),
    #{0 := NewStream} = (NewData#conn_state.streams_state)#conn_streams.streams,
    ?assertEqual(send, NewStream#stream_state.send_state),
    ?assert(NewStream#stream_state.pending_send_fin).

apply_peer_change_unchanged_test() ->
    Peer = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    Data = #conn_state{
        peer = Peer,
        path = #conn_path_mgmt{path_state = nquic_path:new(Peer)}
    },
    {unchanged, Data1} = nquic_conn_statem:apply_peer_change(Peer, Data),
    ?assertEqual(Peer, Data1#conn_state.peer),
    ?assert(nquic_path:is_validated((Data1#conn_state.path)#conn_path_mgmt.path_state)).

apply_peer_change_first_set_test() ->
    Data = #conn_state{
        peer = undefined,
        path = #conn_path_mgmt{path_state = nquic_path:new(undefined)}
    },
    Source = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    {changed, Data1} = nquic_conn_statem:apply_peer_change(Source, Data),
    ?assertEqual(Source, Data1#conn_state.peer),
    ?assert(nquic_path:is_validated((Data1#conn_state.path)#conn_path_mgmt.path_state)).

apply_peer_change_new_address_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    Data = #conn_state{
        peer = Old,
        path = #conn_path_mgmt{path_state = nquic_path:new(Old)}
    },
    {changed, Data1} = nquic_conn_statem:apply_peer_change(New, Data),
    ?assertEqual(New, Data1#conn_state.peer),
    ?assertNot(nquic_path:is_validated((Data1#conn_state.path)#conn_path_mgmt.path_state)).

path_validation_via_protocol_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{}} = nquic_path:initiate_validation(PS0, New),
    ?assert(nquic_path:is_validating(PS1)),
    ?assertNot(nquic_path:is_validated(PS1)),
    ?assertEqual(Old, nquic_path:get_previous_peer(PS1)).

migration_test_cids(CurrentDCID) ->
    SpareDCID = crypto:strong_rand_bytes(8),
    PeerCids = #{
        0 => #{cid => CurrentDCID, token => <<>>},
        1 => #{cid => SpareDCID, token => <<>>}
    },
    {PeerCids, SpareDCID}.

complete_migration_updates_peer_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{data = C}} = nquic_path:initiate_validation(PS0, New),
    {validated, PS2} = nquic_path:on_response(PS1, C),
    CurrentDCID = <<1, 2, 3, 4>>,
    {PeerCids, _} = migration_test_cids(CurrentDCID),
    Data = #conn_state{
        peer = New,
        path = #conn_path_mgmt{
            path_state = PS2,
            peer_cids = PeerCids,
            address_validated = false,
            anti_amp_bytes_sent = 100,
            anti_amp_bytes_received = 200
        },
        loss_state = nquic_loss:init(),
        dcid = CurrentDCID,
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, Data1} = nquic_protocol_migration:complete_migration(Data),
    ?assertEqual(New, Data1#conn_state.peer),
    ?assert((Data1#conn_state.path)#conn_path_mgmt.address_validated),
    ?assertEqual(0, (Data1#conn_state.path)#conn_path_mgmt.anti_amp_bytes_sent),
    ?assertEqual(0, (Data1#conn_state.path)#conn_path_mgmt.anti_amp_bytes_received).

complete_migration_resets_cc_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{data = C}} = nquic_path:initiate_validation(PS0, New),
    {validated, PS2} = nquic_path:on_response(PS1, C),
    OrigLoss = nquic_loss:init(),
    CurrentDCID = <<1, 2, 3, 4>>,
    {PeerCids, _} = migration_test_cids(CurrentDCID),
    Data = #conn_state{
        peer = New,
        path = #conn_path_mgmt{
            path_state = PS2,
            peer_cids = PeerCids,
            address_validated = false
        },
        loss_state = OrigLoss,
        dcid = CurrentDCID,
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, Data1} = nquic_protocol_migration:complete_migration(Data),
    ?assertEqual(0, nquic_loss:get_bytes_in_flight(Data1#conn_state.loss_state)).

complete_migration_preserves_streams_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{data = C}} = nquic_path:initiate_validation(PS0, New),
    {validated, PS2} = nquic_path:on_response(PS1, C),
    Stream = #stream_state{stream_id = 0, type = bidi},
    CurrentDCID = <<1, 2, 3, 4>>,
    {PeerCids, _} = migration_test_cids(CurrentDCID),
    Data = #conn_state{
        peer = New,
        path = #conn_path_mgmt{
            path_state = PS2,
            peer_cids = PeerCids,
            address_validated = false
        },
        loss_state = nquic_loss:init(),
        streams_state = #conn_streams{streams = #{0 => Stream}},
        flow = #conn_flow{
            data_sent = 500,
            data_received = 300,
            pending_app_frames = []
        },
        dcid = CurrentDCID
    },
    {ok, Data1} = nquic_protocol_migration:complete_migration(Data),
    ?assertEqual(#{0 => Stream}, (Data1#conn_state.streams_state)#conn_streams.streams),
    ?assertEqual(500, (Data1#conn_state.flow)#conn_flow.data_sent),
    ?assertEqual(300, (Data1#conn_state.flow)#conn_flow.data_received).

nat_rebinding_no_cc_reset_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 1}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{data = C}} = nquic_path:initiate_validation(PS0, New),
    {validated, PS2} = nquic_path:on_response(PS1, C),
    OrigLoss = nquic_loss:init(),
    CurrentDCID = <<1, 2, 3, 4>>,
    {PeerCids, _} = migration_test_cids(CurrentDCID),
    Data = #conn_state{
        peer = New,
        path = #conn_path_mgmt{
            path_state = PS2,
            peer_cids = PeerCids,
            address_validated = false
        },
        loss_state = OrigLoss,
        dcid = CurrentDCID,
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, Data1} = nquic_protocol_migration:complete_migration(Data),
    ?assertEqual(OrigLoss, Data1#conn_state.loss_state),
    ?assert((Data1#conn_state.path)#conn_path_mgmt.address_validated).

revert_migration_restores_peer_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, _} = nquic_path:initiate_validation(PS0, New),
    {retry, PS2, _} = nquic_path:on_timeout(PS1),
    {retry, PS3, _} = nquic_path:on_timeout(PS2),
    {retry, PS4, _} = nquic_path:on_timeout(PS3),
    {failed, PS5} = nquic_path:on_timeout(PS4),
    OrigLoss = nquic_loss:init(),
    Data = #conn_state{
        peer = New,
        path = #conn_path_mgmt{path_state = PS5},
        loss_state = OrigLoss
    },
    Data1 = nquic_protocol_migration:revert_migration(Data),
    ?assertEqual(Old, Data1#conn_state.peer),
    ?assert(nquic_path:is_validated((Data1#conn_state.path)#conn_path_mgmt.path_state)),
    ?assertNot(nquic_path:is_validating((Data1#conn_state.path)#conn_path_mgmt.path_state)),
    ?assertEqual(OrigLoss, Data1#conn_state.loss_state).

rotate_dcid_selects_unused_test() ->
    CurrentDCID = <<1, 2, 3, 4>>,
    Spare1 = <<5, 6, 7, 8>>,
    Spare2 = <<9, 10, 11, 12>>,
    PeerCids = #{
        0 => #{cid => CurrentDCID, token => <<>>},
        1 => #{cid => Spare1, token => <<>>},
        2 => #{cid => Spare2, token => <<>>}
    },
    Data = #conn_state{
        dcid = CurrentDCID,
        path = #conn_path_mgmt{peer_cids = PeerCids},
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, Data1} = nquic_protocol_cid:rotate_dcid(Data),
    ?assertEqual(Spare1, Data1#conn_state.dcid).

rotate_dcid_no_available_test() ->
    OnlyCID = <<1, 2, 3, 4>>,
    PeerCids = #{0 => #{cid => OnlyCID, token => <<>>}},
    Data = #conn_state{
        dcid = OnlyCID,
        path = #conn_path_mgmt{peer_cids = PeerCids}
    },
    ?assertEqual({error, no_available_cids}, nquic_protocol_cid:rotate_dcid(Data)).

rotate_dcid_empty_peer_cids_test() ->
    Data = #conn_state{
        dcid = <<1, 2, 3, 4>>,
        path = #conn_path_mgmt{peer_cids = #{}}
    },
    ?assertEqual({error, no_available_cids}, nquic_protocol_cid:rotate_dcid(Data)).

migration_uses_new_dcid_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{data = C}} = nquic_path:initiate_validation(PS0, New),
    {validated, PS2} = nquic_path:on_response(PS1, C),
    CurrentDCID = <<1, 2, 3, 4>>,
    SpareDCID = <<5, 6, 7, 8>>,
    PeerCids = #{
        0 => #{cid => CurrentDCID, token => <<>>},
        1 => #{cid => SpareDCID, token => <<>>}
    },
    Data = #conn_state{
        peer = New,
        path = #conn_path_mgmt{
            path_state = PS2,
            peer_cids = PeerCids,
            address_validated = false
        },
        loss_state = nquic_loss:init(),
        dcid = CurrentDCID,
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, Data1} = nquic_protocol_migration:complete_migration(Data),
    ?assertEqual(SpareDCID, Data1#conn_state.dcid),
    ?assertNotEqual(CurrentDCID, Data1#conn_state.dcid).

migration_aborts_without_cids_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{data = C}} = nquic_path:initiate_validation(PS0, New),
    {validated, PS2} = nquic_path:on_response(PS1, C),
    OnlyCID = <<1, 2, 3, 4>>,
    Data = #conn_state{
        peer = New,
        path = #conn_path_mgmt{
            path_state = PS2,
            peer_cids = #{0 => #{cid => OnlyCID, token => <<>>}},
            address_validated = false
        },
        loss_state = nquic_loss:init(),
        dcid = OnlyCID
    },
    ?assertEqual({error, no_available_cids}, nquic_protocol_migration:complete_migration(Data)).

rotate_dcid_retires_old_test() ->
    CurrentDCID = <<1, 2, 3, 4>>,
    SpareDCID = <<5, 6, 7, 8>>,
    PeerCids = #{
        0 => #{cid => CurrentDCID, token => <<>>},
        1 => #{cid => SpareDCID, token => <<>>}
    },
    Data = #conn_state{
        dcid = CurrentDCID,
        path = #conn_path_mgmt{peer_cids = PeerCids},
        flow = #conn_flow{pending_app_frames = []}
    },
    {ok, Data1} = nquic_protocol_cid:rotate_dcid(Data),
    Pending = (Data1#conn_state.flow)#conn_flow.pending_app_frames,
    RetireFrames = [F || #retire_connection_id{} = F <- Pending],
    ?assertEqual(1, length(RetireFrames)),
    [#retire_connection_id{seq_num = RetiredSeq}] = RetireFrames,
    ?assertEqual(0, RetiredSeq).

disable_migration_rejects_client_test() ->
    RemoteParams = #transport_params{disable_active_migration = true},
    Data = #conn_state{
        remote_params = RemoteParams,
        dcid = <<1, 2, 3, 4>>,
        path = #conn_path_mgmt{
            peer_cids = #{1 => #{cid => <<5, 6, 7, 8>>, token => <<>>}}
        }
    },
    ?assertEqual(
        {error, migration_disabled}, nquic_protocol_migration:check_migration_allowed(Data)
    ).

no_cids_rejects_migration_test() ->
    RemoteParams = #transport_params{disable_active_migration = false},
    CurrentDCID = <<1, 2, 3, 4>>,
    Data = #conn_state{
        remote_params = RemoteParams,
        dcid = CurrentDCID,
        path = #conn_path_mgmt{
            peer_cids = #{0 => #{cid => CurrentDCID, token => <<>>}}
        }
    },
    ?assertEqual(
        {error, no_available_cids}, nquic_protocol_migration:check_migration_allowed(Data)
    ).

migration_allowed_test() ->
    RemoteParams = #transport_params{disable_active_migration = false},
    CurrentDCID = <<1, 2, 3, 4>>,
    SpareCID = <<5, 6, 7, 8>>,
    Data = #conn_state{
        remote_params = RemoteParams,
        dcid = CurrentDCID,
        path = #conn_path_mgmt{
            peer_cids = #{
                0 => #{cid => CurrentDCID, token => <<>>},
                1 => #{cid => SpareCID, token => <<>>}
            }
        }
    },
    ?assertEqual(ok, nquic_protocol_migration:check_migration_allowed(Data)).

undefined_remote_params_allows_migration_test() ->
    CurrentDCID = <<1, 2, 3, 4>>,
    SpareCID = <<5, 6, 7, 8>>,
    Data = #conn_state{
        remote_params = undefined,
        dcid = CurrentDCID,
        path = #conn_path_mgmt{
            peer_cids = #{
                0 => #{cid => CurrentDCID, token => <<>>},
                1 => #{cid => SpareCID, token => <<>>}
            }
        }
    },
    ?assertEqual(ok, nquic_protocol_migration:check_migration_allowed(Data)).

client_migrate_rebinds_and_probes_test() ->
    {ok, Socket1} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    PS = nquic_path:new(Peer),
    Data = #conn_state{
        socket = Socket1,
        path = #conn_path_mgmt{path_state = PS},
        crypto = #conn_crypto{keys = #{}},
        flow = #conn_flow{pending_app_frames = []},
        pn_spaces = #{application => #{next_pn => 0}}
    },
    NewAddr = nquic_socket:make_sockaddr({127, 0, 0, 1}, 0),
    {ok, Data1} = nquic_conn_migration:initiate_client_migration(NewAddr, Data),
    ?assertNotEqual(Socket1, Data1#conn_state.socket),
    ?assert(nquic_path:is_validating((Data1#conn_state.path)#conn_path_mgmt.path_state)),
    nquic_socket:close(Data1#conn_state.socket).

preferred_address_installs_cid_test() ->
    PA = #{
        ipv4 => {{10, 0, 0, 1}, 4433},
        ipv6 => {{0, 0, 0, 0, 0, 0, 0, 1}, 4434},
        cid => <<9, 8, 7, 6>>,
        stateless_reset_token => <<0:128>>
    },
    Peer = nquic_socket:make_sockaddr({10, 0, 0, 1}, 5000),
    PS = nquic_path:new(Peer),
    Data = #conn_state{
        peer = Peer,
        path = #conn_path_mgmt{
            path_state = PS,
            peer_cids = #{0 => #{cid => <<1, 2, 3, 4>>, token => <<>>}}
        },
        crypto = #conn_crypto{keys = #{}},
        flow = #conn_flow{pending_app_frames = []},
        pn_spaces = #{application => #{next_pn => 0}},
        loss_state = nquic_loss:init(newreno),
        remote_params = #transport_params{max_ack_delay = 25}
    },
    {keep_state, Data1, _Actions} = nquic_conn_statem:handle_preferred_address_migration(PA, Data),
    ?assertEqual(
        #{cid => <<9, 8, 7, 6>>, token => <<0:128>>},
        maps:get(1, (Data1#conn_state.path)#conn_path_mgmt.peer_cids)
    ),
    ?assertEqual(nquic_socket:make_sockaddr({10, 0, 0, 1}, 4433), Data1#conn_state.peer),
    ?assert(nquic_path:is_validating((Data1#conn_state.path)#conn_path_mgmt.path_state)).

draining_timeout_test() ->
    Data = #conn_state{
        loss_state = nquic_loss:init(),
        connect_waiters = []
    },
    ?assertMatch(
        {stop, normal, _},
        nquic_conn_statem:draining({timeout, draining_timeout}, drain_expire, Data)
    ).

draining_rejects_calls_test() ->
    From = {self(), make_ref()},
    Data = #conn_state{},
    ?assertMatch(
        {keep_state_and_data, [{reply, From, {error, draining}}]},
        nquic_conn_statem:draining({call, From}, any_request, Data)
    ).

draining_ignores_info_test() ->
    Data = #conn_state{},
    ?assertEqual(keep_state_and_data, nquic_conn_statem:draining(info, some_message, Data)).

draining_ignores_cast_test() ->
    Data = #conn_state{},
    ?assertEqual(keep_state_and_data, nquic_conn_statem:draining(cast, some_cast, Data)).

get_peercert_present_test() ->
    DER = <<"fake_cert_der">>,
    Data = #conn_state{crypto = #conn_crypto{peer_cert = DER}},
    From = {self(), make_ref()},
    ?assertMatch(
        {keep_state_and_data, [{reply, From, {ok, DER}}]},
        nquic_conn_statem:handle_common({call, From}, get_peercert, established, Data)
    ).

get_peercert_absent_test() ->
    Data = #conn_state{crypto = #conn_crypto{peer_cert = undefined}},
    From = {self(), make_ref()},
    ?assertMatch(
        {keep_state_and_data, [{reply, _, {error, no_peercert}}]},
        nquic_conn_statem:handle_common({call, From}, get_peercert, established, Data)
    ).

get_peername_connected_test() ->
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Data = #conn_state{peer = Peer},
    From = {self(), make_ref()},
    {keep_state_and_data, [{reply, From, {ok, Result}}]} =
        nquic_conn_statem:handle_common({call, From}, get_peername, established, Data),
    ?assertMatch({_, _}, Result).

get_peername_not_connected_test() ->
    Data = #conn_state{peer = undefined},
    From = {self(), make_ref()},
    ?assertMatch(
        {keep_state_and_data, [{reply, From, {error, not_connected}}]},
        nquic_conn_statem:handle_common({call, From}, get_peername, established, Data)
    ).

get_streams_empty_test() ->
    Data = #conn_state{streams_state = #conn_streams{streams = #{}}},
    From = {self(), make_ref()},
    ?assertMatch(
        {keep_state_and_data, [{reply, From, {ok, []}}]},
        nquic_conn_statem:handle_common({call, From}, get_streams, established, Data)
    ).

get_streams_with_streams_test() ->
    Stream0 = #stream_state{stream_id = 0},
    Stream4 = #stream_state{stream_id = 4},
    Data = #conn_state{streams_state = #conn_streams{streams = #{0 => Stream0, 4 => Stream4}}},
    From = {self(), make_ref()},
    {keep_state_and_data, [{reply, From, {ok, StreamIds}}]} =
        nquic_conn_statem:handle_common({call, From}, get_streams, established, Data),
    ?assertEqual(lists:sort([0, 4]), lists:sort(StreamIds)).

wait_established_already_test() ->
    Data = #conn_state{connect_waiters = []},
    From = {self(), make_ref()},
    ?assertMatch(
        {keep_state_and_data, [{reply, From, ok}]},
        nquic_conn_statem:handle_common({call, From}, wait_established, established, Data)
    ).

wait_established_not_yet_test() ->
    Data = #conn_state{connect_waiters = []},
    From = {self(), make_ref()},
    {keep_state, NewData} =
        nquic_conn_statem:handle_common({call, From}, wait_established, handshake, Data),
    ?assertEqual([From], NewData#conn_state.connect_waiters).

handle_common_unknown_test() ->
    Data = #conn_state{},
    ?assertEqual(
        keep_state_and_data,
        nquic_conn_statem:handle_common(cast, unknown_message, established, Data)
    ).

timer_actions_to_statem_empty_test() ->
    ?assertEqual([], nquic_conn_timers:timer_actions_to_statem([])).

timer_actions_to_statem_set_timers_test() ->
    Actions = [
        {set_timer, idle, 30000},
        {set_timer, pto, 1000},
        {set_timer, path_validation, 5000},
        {set_timer, ack_delay, 25}
    ],
    Result = nquic_conn_timers:timer_actions_to_statem(Actions),
    ?assertEqual(4, length(Result)),
    ?assert(lists:member({{timeout, idle_timeout}, 30000, idle_fire}, Result)),
    ?assert(lists:member({{timeout, pto_timeout}, 1000, pto_fire}, Result)),
    ?assert(
        lists:member(
            {{timeout, path_validation}, 5000, path_validation_fire}, Result
        )
    ),
    ?assert(
        lists:member({{timeout, ack_delay}, 25, ack_delay_fire}, Result)
    ).

timer_actions_to_statem_cancel_pto_test() ->
    Actions = [{cancel_timer, pto}],
    Result = nquic_conn_timers:timer_actions_to_statem(Actions),
    ?assertEqual(
        [{{timeout, pto_timeout}, infinity, undefined}], Result
    ).

get_idle_timeout_both_zero_test() ->
    ?assertEqual(infinity, nquic_protocol:get_idle_timeout(0, 0)).

get_idle_timeout_local_zero_test() ->
    ?assertEqual(30000, nquic_protocol:get_idle_timeout(0, 30000)).

get_idle_timeout_remote_zero_test() ->
    ?assertEqual(15000, nquic_protocol:get_idle_timeout(15000, 0)).

get_idle_timeout_both_nonzero_test() ->
    ?assertEqual(10000, nquic_protocol:get_idle_timeout(10000, 20000)).

get_idle_timeout_remote_smaller_test() ->
    ?assertEqual(5000, nquic_protocol:get_idle_timeout(20000, 5000)).

set_idle_timer_both_zero_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 0},
        remote_params = #transport_params{max_idle_timeout = 0}
    },
    ?assertEqual([], nquic_conn_timers:set_idle_timer(Data)).

set_idle_timer_with_timeout_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 30000},
        remote_params = #transport_params{max_idle_timeout = 20000}
    },
    ?assertMatch(
        [{{timeout, idle_timeout}, 20000, idle_fire}],
        nquic_conn_timers:set_idle_timer(Data)
    ).

set_idle_timer_remote_undefined_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 30000},
        remote_params = undefined
    },
    ?assertMatch(
        [{{timeout, idle_timeout}, 30000, idle_fire}],
        nquic_conn_timers:set_idle_timer(Data)
    ).

set_pto_timer_no_inflight_test() ->
    LossState = nquic_loss:init(),
    Data = #conn_state{
        loss_state = LossState,
        remote_params = undefined
    },
    ?assertMatch(
        [{{timeout, pto_timeout}, infinity, undefined}],
        nquic_conn_timers:set_pto_timer(Data)
    ).

deliver_event_stream_reset_passive_test() ->
    Data = #conn_state{
        owner = self(),
        streams_state = #conn_streams{streams = #{}, recv_waiters = #{}}
    },
    Data1 = nquic_conn_events:deliver_protocol_event({stream_reset, 0, 42}, Data),
    ?assertEqual(Data, Data1).

deliver_event_stop_sending_test() ->
    Data = #conn_state{},
    ?assertEqual(Data, nquic_conn_events:deliver_protocol_event({stop_sending, 0, 0}, Data)).

deliver_event_stream_writable_passive_drops_test() ->
    Data = #conn_state{owner = self()},
    Data1 = nquic_conn_events:deliver_protocol_event({stream_writable, 0}, Data),
    ?assertEqual(Data, Data1),
    receive
        {nquic, _, {stream_writable, _}} -> ?assert(false)
    after 50 -> ok
    end.

deliver_event_connection_closed_test() ->
    Data = #conn_state{},
    ?assertEqual(
        Data, nquic_conn_events:deliver_protocol_event(connection_closed, Data)
    ).

deliver_protocol_events_empty_test() ->
    Data = #conn_state{},
    ?assertEqual(Data, nquic_conn_events:deliver_protocol_events([], Data)).

schedule_deferred_flush_already_pending_test() ->
    Data = #conn_state{deferred_flush_pending = true},
    ?assertEqual(Data, nquic_conn_statem:schedule_deferred_flush(Data)).

schedule_deferred_flush_sends_message_test() ->
    Data = #conn_state{deferred_flush_pending = false},
    Data1 = nquic_conn_statem:schedule_deferred_flush(Data),
    ?assertEqual(true, Data1#conn_state.deferred_flush_pending),
    receive
        deferred_flush -> ok
    after 100 -> ?assert(false)
    end.

is_ack_eliciting_empty_test() ->
    ?assertEqual(false, nquic_protocol_ack:is_ack_eliciting([])).

is_ack_eliciting_ack_only_test() ->
    ?assertEqual(false, nquic_protocol_ack:is_ack_eliciting([#ack{}])).

is_ack_eliciting_padding_only_test() ->
    ?assertEqual(false, nquic_protocol_ack:is_ack_eliciting([#padding{}])).

is_ack_eliciting_close_only_test() ->
    ?assertEqual(false, nquic_protocol_ack:is_ack_eliciting([#connection_close{}])).

is_ack_eliciting_non_ack_test() ->
    ?assertEqual(true, nquic_protocol_ack:is_ack_eliciting([#ping{}])).

is_ack_eliciting_mixed_test() ->
    ?assertEqual(true, nquic_protocol_ack:is_ack_eliciting([#ack{}, #padding{}, #ping{}])).

is_ack_eliciting_all_non_eliciting_test() ->
    ?assertEqual(
        false,
        nquic_protocol_ack:is_ack_eliciting([#ack{}, #padding{}, #connection_close{}])
    ).

handle_recv_stream_data_read_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = data_read,
        app_buffer = [],
        app_buffer_size = 0
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}, recv_waiters = #{}}
    },
    From = {self(), make_ref()},
    %% FIN already delivered + buffer drained: a further recv is EOF.
    {reply, {error, fin}, _, flush} =
        nquic_conn_streams:recv_stream(From, 0, Data).

handle_recv_stream_reset_read_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = reset_read,
        app_buffer = [],
        app_buffer_size = 0
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}, recv_waiters = #{}}
    },
    From = {self(), make_ref()},
    {reply, {error, stream_reset}, _, flush} =
        nquic_conn_streams:recv_stream(From, 0, Data).

handle_recv_stream_with_data_fin_test() ->
    Stream = #stream_state{
        stream_id = 0,
        recv_state = size_known,
        app_buffer = [<<"hello">>],
        app_buffer_size = 5
    },
    Data = #conn_state{
        streams_state = #conn_streams{streams = #{0 => Stream}, recv_waiters = #{}}
    },
    From = {self(), make_ref()},
    {reply, {ok, <<"hello">>, fin}, NewData} =
        nquic_conn_streams:recv_stream(From, 0, Data),
    #{0 := NewStream} = (NewData#conn_state.streams_state)#conn_streams.streams,
    ?assertEqual(data_read, NewStream#stream_state.recv_state).

scale_ack_delay_no_params_test() ->
    ?assertEqual(800, nquic_protocol:scale_ack_delay(100, undefined)).

scale_ack_delay_with_params_test() ->
    Params = #transport_params{
        ack_delay_exponent = 3,
        max_ack_delay = 25
    },
    ?assertEqual(800, nquic_protocol:scale_ack_delay(100, Params)).

scale_ack_delay_capped_test() ->
    Params = #transport_params{
        ack_delay_exponent = 3,
        max_ack_delay = 25
    },
    ?assertEqual(25000, nquic_protocol:scale_ack_delay(100000, Params)).

error_to_reason_phrase_atom_test() ->
    ?assertEqual(
        <<"flow_control_error">>, nquic_protocol:error_to_reason_phrase(flow_control_error)
    ).

handle_lost_frames_empty_test() ->
    Data = #conn_state{},
    ?assertEqual(Data, nquic_protocol_send:handle_lost_frames([], application, Data)).

handle_lost_frames_unknown_frame_test() ->
    Data = #conn_state{},
    ?assertEqual(
        Data,
        nquic_protocol_send:handle_lost_frames([#ping{}], application, Data)
    ).

handle_lost_max_data_requeues_current_test() ->
    Data = #conn_state{flow = #conn_flow{local_max_data = 4096}},
    Result = nquic_protocol_send:handle_lost_frames(
        [#max_data{max_data = 2048}], application, Data
    ),
    ?assertEqual(
        [#max_data{max_data = 4096}],
        (Result#conn_state.flow)#conn_flow.pending_app_frames
    ).

handle_lost_max_data_drops_if_window_shrank_test() ->
    Data = #conn_state{flow = #conn_flow{local_max_data = 1024}},
    Result = nquic_protocol_send:handle_lost_frames(
        [#max_data{max_data = 4096}], application, Data
    ),
    ?assertEqual([], (Result#conn_state.flow)#conn_flow.pending_app_frames).

handle_lost_max_stream_data_requeues_current_test() ->
    Stream = #stream_state{stream_id = 4, type = bidi, recv_window = 8192},
    SS = #conn_streams{streams = #{4 => Stream}},
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#max_stream_data{stream_id = 4, max_stream_data = 2048}], application, Data
    ),
    ?assertEqual(
        [#max_stream_data{stream_id = 4, max_stream_data = 8192}],
        (Result#conn_state.flow)#conn_flow.pending_app_frames
    ).

handle_lost_max_stream_data_drops_unknown_stream_test() ->
    Data = #conn_state{streams_state = #conn_streams{streams = #{}}},
    Result = nquic_protocol_send:handle_lost_frames(
        [#max_stream_data{stream_id = 4, max_stream_data = 2048}], application, Data
    ),
    ?assertEqual([], (Result#conn_state.flow)#conn_flow.pending_app_frames).

handle_lost_data_blocked_requeues_when_still_blocked_test() ->
    Flow = #conn_flow{remote_max_data = 4096, data_sent = 4096},
    Data = #conn_state{flow = Flow},
    Result = nquic_protocol_send:handle_lost_frames(
        [#data_blocked{limit = 4096}], application, Data
    ),
    ?assertEqual(
        [#data_blocked{limit = 4096}],
        (Result#conn_state.flow)#conn_flow.pending_app_frames
    ).

handle_lost_data_blocked_drops_when_window_advanced_test() ->
    Flow = #conn_flow{remote_max_data = 8192, data_sent = 4096},
    Data = #conn_state{flow = Flow},
    Result = nquic_protocol_send:handle_lost_frames(
        [#data_blocked{limit = 4096}], application, Data
    ),
    ?assertEqual([], (Result#conn_state.flow)#conn_flow.pending_app_frames).

handle_lost_stream_data_blocked_requeues_when_still_blocked_test() ->
    Stream = #stream_state{stream_id = 0, type = bidi, send_max_data = 1024, send_offset = 1024},
    SS = #conn_streams{streams = #{0 => Stream}},
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#stream_data_blocked{stream_id = 0, limit = 1024}], application, Data
    ),
    ?assertEqual(
        [#stream_data_blocked{stream_id = 0, limit = 1024}],
        (Result#conn_state.flow)#conn_flow.pending_app_frames
    ).

handle_lost_stream_data_blocked_drops_when_window_advanced_test() ->
    Stream = #stream_state{stream_id = 0, type = bidi, send_max_data = 2048, send_offset = 1024},
    SS = #conn_streams{streams = #{0 => Stream}},
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#stream_data_blocked{stream_id = 0, limit = 1024}], application, Data
    ),
    ?assertEqual([], (Result#conn_state.flow)#conn_flow.pending_app_frames).

handle_lost_max_streams_bidi_requeues_current_test() ->
    SS = #conn_streams{local_max_streams_bidi = 200, last_sent_max_streams_bidi = 100},
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#max_streams{max_streams = 100, is_uni = false}], application, Data
    ),
    ?assertEqual(
        [#max_streams{max_streams = 200, is_uni = false}],
        (Result#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(
        200, (Result#conn_state.streams_state)#conn_streams.last_sent_max_streams_bidi
    ).

handle_lost_max_streams_bidi_drops_if_limit_shrank_test() ->
    SS = #conn_streams{local_max_streams_bidi = 50, last_sent_max_streams_bidi = 50},
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#max_streams{max_streams = 100, is_uni = false}], application, Data
    ),
    ?assertEqual([], (Result#conn_state.flow)#conn_flow.pending_app_frames).

handle_lost_max_streams_uni_requeues_current_test() ->
    SS = #conn_streams{local_max_streams_uni = 300, last_sent_max_streams_uni = 100},
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#max_streams{max_streams = 100, is_uni = true}], application, Data
    ),
    ?assertEqual(
        [#max_streams{max_streams = 300, is_uni = true}],
        (Result#conn_state.flow)#conn_flow.pending_app_frames
    ),
    ?assertEqual(
        300, (Result#conn_state.streams_state)#conn_streams.last_sent_max_streams_uni
    ).

handle_lost_streams_blocked_bidi_requeues_when_still_blocked_test() ->
    SS = #conn_streams{
        peer_max_streams_bidi = 10,
        next_bidi_stream = 40
    },
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#streams_blocked{limit = 10, is_uni = false}], application, Data
    ),
    ?assertEqual(
        [#streams_blocked{limit = 10, is_uni = false}],
        (Result#conn_state.flow)#conn_flow.pending_app_frames
    ).

handle_lost_streams_blocked_bidi_drops_when_limit_lifted_test() ->
    SS = #conn_streams{
        peer_max_streams_bidi = 20,
        next_bidi_stream = 40
    },
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#streams_blocked{limit = 10, is_uni = false}], application, Data
    ),
    ?assertEqual([], (Result#conn_state.flow)#conn_flow.pending_app_frames).

handle_lost_streams_blocked_bidi_drops_when_opener_unblocked_test() ->
    SS = #conn_streams{
        peer_max_streams_bidi = 10,
        next_bidi_stream = 20
    },
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#streams_blocked{limit = 10, is_uni = false}], application, Data
    ),
    ?assertEqual([], (Result#conn_state.flow)#conn_flow.pending_app_frames).

handle_lost_streams_blocked_uni_requeues_when_still_blocked_test() ->
    SS = #conn_streams{
        peer_max_streams_uni = 5,
        next_uni_stream = 20
    },
    Data = #conn_state{streams_state = SS},
    Result = nquic_protocol_send:handle_lost_frames(
        [#streams_blocked{limit = 5, is_uni = true}], application, Data
    ),
    ?assertEqual(
        [#streams_blocked{limit = 5, is_uni = true}],
        (Result#conn_state.flow)#conn_flow.pending_app_frames
    ).

load_certs_undefined_test() ->
    ?assertEqual(
        {undefined, undefined}, nquic_protocol_handshake:load_certs(undefined, undefined)
    ).

load_certs_missing_file_test() ->
    ?assertEqual(
        {undefined, undefined},
        nquic_protocol_handshake:load_certs("/nonexistent/cert.pem", "/nonexistent/key.pem")
    ).

enter_close_draining_replies_waiters_test() ->
    RecvFrom = {self(), make_ref()},
    AccFrom = {self(), make_ref()},
    ConnFrom = {self(), make_ref()},
    CallerFrom = {self(), make_ref()},
    Data = #conn_state{
        loss_state = nquic_loss:init(),
        remote_params = #transport_params{max_ack_delay = 25},
        connect_waiters = [ConnFrom],
        streams_state = #conn_streams{
            recv_waiters = #{0 => RecvFrom},
            accept_stream_waiters = queue:from_list([AccFrom])
        }
    },
    {next_state, draining, NewData, Actions} =
        nquic_conn_close:enter_close_draining(CallerFrom, Data),
    ?assertEqual([], NewData#conn_state.connect_waiters),
    ?assertEqual(#{}, (NewData#conn_state.streams_state)#conn_streams.recv_waiters),
    ?assert(queue:is_empty((NewData#conn_state.streams_state)#conn_streams.accept_stream_waiters)),
    ?assert(lists:member({reply, CallerFrom, ok}, Actions)),
    ?assert(lists:member({reply, ConnFrom, {error, closed}}, Actions)),
    ?assert(lists:member({reply, RecvFrom, {error, closed}}, Actions)),
    ?assert(lists:member({reply, AccFrom, {error, closed}}, Actions)).

packet_space_from_header_initial_test() ->
    H = #long_header{type = initial, version = 1, dcid = <<>>, scid = <<>>},
    ?assertEqual(initial, nquic_protocol_send:packet_space_from_header(H)).

packet_space_from_header_handshake_test() ->
    H = #long_header{type = handshake, version = 1, dcid = <<>>, scid = <<>>},
    ?assertEqual(handshake, nquic_protocol_send:packet_space_from_header(H)).

packet_space_from_header_rtt0_test() ->
    H = #long_header{type = rtt0, version = 1, dcid = <<>>, scid = <<>>},
    ?assertEqual(application, nquic_protocol_send:packet_space_from_header(H)).

packet_space_from_header_short_test() ->
    H = #short_header{dcid = <<1, 2, 3, 4>>},
    ?assertEqual(application, nquic_protocol_send:packet_space_from_header(H)).

packet_number_from_long_header_test() ->
    H = #long_header{
        type = initial,
        version = 1,
        dcid = <<>>,
        scid = <<>>,
        packet_number = 42
    },
    ?assertEqual(42, nquic_protocol_send:packet_number_from_header(H)).

packet_number_from_short_header_test() ->
    H = #short_header{dcid = <<1, 2, 3, 4>>, packet_number = 99},
    ?assertEqual(99, nquic_protocol_send:packet_number_from_header(H)).

migrate_not_established_test() ->
    Data = #conn_state{},
    From = {self(), make_ref()},
    ?assertMatch(
        {keep_state_and_data, [{reply, From, {error, not_established}}]},
        nquic_conn_statem:handle_common(
            {call, From}, {migrate, {{0, 0, 0, 0}, 0}}, handshake, Data
        )
    ).

flush_pending_result_keep_state_actions_empty_test() ->
    Data = #conn_state{flow = #conn_flow{pending_app_frames = []}},
    Result = {keep_state, Data, [some_action]},
    ?assertEqual(Result, nquic_conn_statem:flush_pending_result(Result)).

flush_pending_result_next_state_empty_test() ->
    Data = #conn_state{flow = #conn_flow{pending_app_frames = []}},
    Result = {next_state, established, Data, [some_action]},
    ?assertEqual(Result, nquic_conn_statem:flush_pending_result(Result)).

flush_pending_result_stop_test() ->
    Data = #conn_state{flow = #conn_flow{pending_app_frames = [#ping{}]}},
    Result = {stop, normal, Data},
    ?assertEqual(Result, nquic_conn_statem:flush_pending_result(Result)).

sort_frames_empty_test() ->
    ?assertEqual([], nquic_protocol_send_queues:sort_frames([])).

sort_frames_acks_first_test() ->
    Frames = [#ping{}, #ack{}, #padding{}],
    [#ack{} | _] = nquic_protocol_send_queues:sort_frames(Frames).

sort_frames_no_acks_test() ->
    Frames = [#ping{}, #padding{}],
    ?assertEqual(Frames, nquic_protocol_send_queues:sort_frames(Frames)).

maybe_notify_recv_waiter_no_waiter_test() ->
    Data = #conn_state{
        streams_state = #conn_streams{recv_waiters = #{}, streams = #{}}
    },
    ?assertEqual(Data, nquic_conn_streams:maybe_notify_recv_waiter(0, Data)).

maybe_notify_recv_waiter_with_data_test() ->
    Stream = #stream_state{
        stream_id = 0,
        app_buffer = [<<"hello">>],
        app_buffer_size = 5,
        recv_state = recv
    },
    Data = #conn_state{
        streams_state = #conn_streams{recv_waiters = #{}, streams = #{0 => Stream}}
    },
    ?assertEqual(Data, nquic_conn_streams:maybe_notify_recv_waiter(0, Data)).

get_info_test() ->
    Data = #conn_state{
        role = client,
        scid = <<0:64>>,
        dcid = <<1:64>>,
        streams_state = #conn_streams{streams = #{}},
        loss_state = nquic_loss:init(),
        flow = #conn_flow{local_max_data = 16777216, remote_max_data = 16777216}
    },
    From = {self(), make_ref()},
    {keep_state_and_data, [{reply, From, {ok, Info}}]} =
        nquic_conn_statem:handle_common({call, From}, get_info, established, Data),
    ?assert(is_map(Info)).

get_sockname_no_socket_test() ->
    Data = #conn_state{socket = undefined},
    From = {self(), make_ref()},
    ?assertMatch(
        {keep_state_and_data, [{reply, From, {error, not_connected}}]},
        nquic_conn_statem:handle_common({call, From}, get_sockname, established, Data)
    ).

track_received_pn_new_space_test() ->
    Data = #conn_state{pn_spaces = #{}},
    Data1 = nquic_protocol_ack:track_received_pn(application, 0, Data),
    #{application := SpaceMap} = Data1#conn_state.pn_spaces,
    ?assertEqual(0, Data1#conn_state.app_largest_received),
    ?assertEqual([{0, 0}], maps:get(received_ranges, SpaceMap)).

track_received_pn_updates_largest_test() ->
    Data = #conn_state{
        app_largest_received = 5,
        pn_spaces = #{application => #{received_ranges => [{5, 0}]}}
    },
    Data1 = nquic_protocol_ack:track_received_pn(application, 10, Data),
    ?assertEqual(10, Data1#conn_state.app_largest_received).

deliver_event_stream_data_test() ->
    Stream = #stream_state{
        stream_id = 0,
        type = bidi,
        app_buffer = [<<"hi">>],
        app_buffer_size = 2,
        recv_state = recv
    },
    Ref = make_ref(),
    From = {self(), Ref},
    Data = #conn_state{
        owner = self(),
        streams_state = #conn_streams{
            streams = #{0 => Stream},
            recv_waiters = #{0 => From}
        }
    },
    _Data1 = nquic_conn_events:deliver_protocol_event({stream_data, 0}, Data),
    receive
        {Ref, {ok, <<"hi">>, nofin}} -> ok
    after 100 -> ?assert(false)
    end.

deliver_event_stream_opened_test() ->
    Ref = make_ref(),
    From = {self(), Ref},
    Data = #conn_state{
        owner = self(),
        streams_state = #conn_streams{
            accept_stream_waiters = queue:from_list([From]),
            pending_streams = queue:new()
        }
    },
    _Data1 = nquic_conn_events:deliver_protocol_event({stream_opened, 0}, Data),
    receive
        {Ref, {ok, 0}} -> ok
    after 100 -> ?assert(false)
    end.

enter_draining_common_replies_waiters_test() ->
    ConnFrom = {self(), make_ref()},
    RecvFrom = {self(), make_ref()},
    AccFrom = {self(), make_ref()},
    Data = #conn_state{
        loss_state = nquic_loss:init(),
        remote_params = undefined,
        connect_waiters = [ConnFrom],
        streams_state = #conn_streams{
            recv_waiters = #{0 => RecvFrom},
            accept_stream_waiters = queue:from_list([AccFrom])
        }
    },
    {next_state, draining, NewData, Actions} = nquic_conn_close:enter_draining_common(Data),
    ?assertEqual([], NewData#conn_state.connect_waiters),
    ?assertEqual(#{}, (NewData#conn_state.streams_state)#conn_streams.recv_waiters),
    ?assert(queue:is_empty((NewData#conn_state.streams_state)#conn_streams.accept_stream_waiters)),
    ?assert(lists:member({reply, ConnFrom, {error, closed}}, Actions)),
    ?assert(lists:member({reply, RecvFrom, {error, closed}}, Actions)),
    ?assert(lists:member({reply, AccFrom, {error, closed}}, Actions)).

crypto_buffer_data_test() ->
    ?assertEqual(<<"hello">>, nquic_protocol_recv:crypto_buffer_data({5, <<"hello">>, []})).

crypto_buffer_merge_gap_test() ->
    {5, <<>>, [{10, <<"gap">>}]} =
        nquic_protocol_recv:crypto_buffer_merge(5, <<>>, [{10, <<"gap">>}]).

crypto_buffer_merge_skip_covered_test() ->
    {10, <<"data">>, []} =
        nquic_protocol_recv:crypto_buffer_merge(10, <<"data">>, [{5, <<"old">>}]).

validate_retry_scid_no_retry_test() ->
    State = #conn_state{role = client, odcid = undefined, dcid = <<1, 2, 3, 4>>},
    Params = #transport_params{retry_source_connection_id = undefined},
    ?assertEqual(ok, nquic_protocol_handshake:validate_retry_scid(State, Params)).

validate_retry_scid_unexpected_test() ->
    State = #conn_state{role = client, odcid = undefined, dcid = <<1, 2, 3, 4>>},
    Params = #transport_params{retry_source_connection_id = <<5, 6, 7, 8>>},
    ?assertMatch(
        {error, {transport_parameter_error, unexpected_retry_scid}},
        nquic_protocol_handshake:validate_retry_scid(State, Params)
    ).

validate_retry_scid_match_test() ->
    RetrySCID = <<5, 6, 7, 8>>,
    State = #conn_state{
        role = client,
        odcid = <<1, 2, 3, 4>>,
        retry_scid = RetrySCID,
        dcid = <<9, 9, 9, 9>>
    },
    Params = #transport_params{retry_source_connection_id = RetrySCID},
    ?assertEqual(ok, nquic_protocol_handshake:validate_retry_scid(State, Params)).

validate_retry_scid_missing_test() ->
    State = #conn_state{
        role = client,
        odcid = <<1, 2, 3, 4>>,
        retry_scid = <<5, 6, 7, 8>>,
        dcid = <<9, 9, 9, 9>>
    },
    Params = #transport_params{retry_source_connection_id = undefined},
    ?assertMatch(
        {error, {transport_parameter_error, missing_retry_scid}},
        nquic_protocol_handshake:validate_retry_scid(State, Params)
    ).

validate_retry_scid_mismatch_test() ->
    State = #conn_state{
        role = client,
        odcid = <<1, 2, 3, 4>>,
        retry_scid = <<5, 6, 7, 8>>,
        dcid = <<9, 9, 9, 9>>
    },
    Params = #transport_params{retry_source_connection_id = <<9, 10, 11, 12>>},
    ?assertMatch(
        {error, {transport_parameter_error, retry_scid_mismatch}},
        nquic_protocol_handshake:validate_retry_scid(State, Params)
    ).

validate_retry_scid_server_skip_test() ->
    State = #conn_state{role = server, odcid = undefined, dcid = <<>>},
    Params = #transport_params{retry_source_connection_id = undefined},
    ?assertEqual(ok, nquic_protocol_handshake:validate_retry_scid(State, Params)).

validate_version_info_ok_test() ->
    State = #conn_state{role = client, version = 1, dcid = <<>>},
    VI = #{chosen_version => 1, other_versions => [1, 16#6b3343cf]},
    Params = #transport_params{version_information = VI},
    ?assertEqual(ok, nquic_protocol_handshake:validate_version_info(State, Params)).

validate_version_info_undefined_test() ->
    State = #conn_state{role = client, version = 1, dcid = <<>>},
    Params = #transport_params{version_information = undefined},
    ?assertEqual(ok, nquic_protocol_handshake:validate_version_info(State, Params)).

validate_version_info_chosen_mismatch_test() ->
    State = #conn_state{role = client, version = 1, dcid = <<>>},
    VI = #{chosen_version => 16#6b3343cf, other_versions => [1, 16#6b3343cf]},
    Params = #transport_params{version_information = VI},
    ?assertMatch(
        {error, {version_negotiation_error, chosen_version_mismatch}},
        nquic_protocol_handshake:validate_version_info(State, Params)
    ).

validate_version_info_not_in_others_test() ->
    State = #conn_state{role = client, version = 1, dcid = <<>>},
    VI = #{chosen_version => 1, other_versions => [16#6b3343cf]},
    Params = #transport_params{version_information = VI},
    ?assertMatch(
        {error, {version_negotiation_error, version_not_in_other_versions}},
        nquic_protocol_handshake:validate_version_info(State, Params)
    ).

validate_version_info_v2_ok_test() ->
    State = #conn_state{role = server, version = 16#6b3343cf, dcid = <<>>},
    VI = #{chosen_version => 16#6b3343cf, other_versions => [16#6b3343cf, 1]},
    Params = #transport_params{version_information = VI},
    ?assertEqual(ok, nquic_protocol_handshake:validate_version_info(State, Params)).
