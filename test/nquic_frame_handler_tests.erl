%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_frame_handler}.
%%%-------------------------------------------------------------------
-module(nquic_frame_handler_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
stream_initiator_test_() ->
    [
        ?_assertEqual(client, nquic_frame_handler:stream_initiator(0)),
        ?_assertEqual(server, nquic_frame_handler:stream_initiator(1)),
        ?_assertEqual(client, nquic_frame_handler:stream_initiator(2)),
        ?_assertEqual(server, nquic_frame_handler:stream_initiator(3)),
        ?_assertEqual(client, nquic_frame_handler:stream_initiator(4)),
        ?_assertEqual(server, nquic_frame_handler:stream_initiator(5))
    ].

stream_is_unidirectional_test_() ->
    [
        ?_assertEqual(false, nquic_frame_handler:stream_is_unidirectional(0)),
        ?_assertEqual(false, nquic_frame_handler:stream_is_unidirectional(1)),
        ?_assertEqual(true, nquic_frame_handler:stream_is_unidirectional(2)),
        ?_assertEqual(true, nquic_frame_handler:stream_is_unidirectional(3)),
        ?_assertEqual(false, nquic_frame_handler:stream_is_unidirectional(4)),
        ?_assertEqual(true, nquic_frame_handler:stream_is_unidirectional(6))
    ].

peer_can_send_test_() ->
    [
        ?_assertEqual(true, nquic_frame_handler:peer_can_send(0, client)),
        ?_assertEqual(true, nquic_frame_handler:peer_can_send(0, server)),
        ?_assertEqual(true, nquic_frame_handler:peer_can_send(1, client)),
        ?_assertEqual(false, nquic_frame_handler:peer_can_send(2, client)),
        ?_assertEqual(true, nquic_frame_handler:peer_can_send(2, server)),
        ?_assertEqual(true, nquic_frame_handler:peer_can_send(3, client)),
        ?_assertEqual(false, nquic_frame_handler:peer_can_send(3, server))
    ].

i_can_send_test_() ->
    [
        ?_assertEqual(true, nquic_frame_handler:i_can_send(0, client)),
        ?_assertEqual(true, nquic_frame_handler:i_can_send(1, server)),
        ?_assertEqual(true, nquic_frame_handler:i_can_send(2, client)),
        ?_assertEqual(false, nquic_frame_handler:i_can_send(2, server)),
        ?_assertEqual(false, nquic_frame_handler:i_can_send(3, client)),
        ?_assertEqual(true, nquic_frame_handler:i_can_send(3, server))
    ].

is_locally_initiated_test_() ->
    [
        ?_assertEqual(true, nquic_frame_handler:is_locally_initiated(0, client)),
        ?_assertEqual(false, nquic_frame_handler:is_locally_initiated(0, server)),
        ?_assertEqual(false, nquic_frame_handler:is_locally_initiated(1, client)),
        ?_assertEqual(true, nquic_frame_handler:is_locally_initiated(1, server)),
        ?_assertEqual(true, nquic_frame_handler:is_locally_initiated(2, client)),
        ?_assertEqual(false, nquic_frame_handler:is_locally_initiated(3, client))
    ].

validate_stream_for_reset_test_() ->
    [
        ?_assertEqual(ok, nquic_frame_handler:validate_stream_for_reset(0, client)),
        ?_assertEqual(ok, nquic_frame_handler:validate_stream_for_reset(2, server)),
        ?_assertEqual(
            {error, stream_state_error}, nquic_frame_handler:validate_stream_for_reset(2, client)
        ),
        ?_assertEqual(
            {error, stream_state_error}, nquic_frame_handler:validate_stream_for_reset(3, server)
        )
    ].

validate_stream_for_stop_sending_test_() ->
    Streams = #{0 => #stream_state{}},
    [
        ?_assertEqual(
            ok, nquic_frame_handler:validate_stream_for_stop_sending(0, client, Streams)
        ),
        ?_assertEqual(
            ok, nquic_frame_handler:validate_stream_for_stop_sending(0, server, Streams)
        ),
        ?_assertEqual(
            {error, stream_state_error},
            nquic_frame_handler:validate_stream_for_stop_sending(2, server, #{})
        ),
        ?_assertEqual(
            {error, stream_state_error},
            nquic_frame_handler:validate_stream_for_stop_sending(3, server, #{})
        ),
        ?_assertEqual(ok, nquic_frame_handler:validate_stream_for_stop_sending(1, client, #{})),
        ?_assertEqual(
            {error, stream_state_error},
            nquic_frame_handler:validate_stream_for_stop_sending(4, client, #{})
        )
    ].

validate_stream_for_recv_test_() ->
    Streams = #{0 => #stream_state{}},
    [
        ?_assertEqual(ok, nquic_frame_handler:validate_stream_for_recv(0, client, Streams)),
        ?_assertEqual(ok, nquic_frame_handler:validate_stream_for_recv(1, client, #{})),
        ?_assertEqual(ok, nquic_frame_handler:validate_stream_for_recv(2, server, #{})),
        ?_assertEqual(
            {error, stream_state_error},
            nquic_frame_handler:validate_stream_for_recv(2, client, #{})
        ),
        ?_assertEqual(
            {error, stream_state_error},
            nquic_frame_handler:validate_stream_for_recv(4, client, #{})
        )
    ].

validate_stream_for_max_stream_data_test_() ->
    Streams = #{0 => #stream_state{}},
    [
        ?_assertEqual(
            ok, nquic_frame_handler:validate_stream_for_max_stream_data(0, client, Streams)
        ),
        ?_assertEqual(ok, nquic_frame_handler:validate_stream_for_max_stream_data(1, client, #{})),
        ?_assertEqual(
            {error, stream_state_error},
            nquic_frame_handler:validate_stream_for_max_stream_data(2, server, #{})
        ),
        ?_assertEqual(
            {error, stream_state_error},
            nquic_frame_handler:validate_stream_for_max_stream_data(4, client, #{})
        )
    ].

check_handshake_crypto_test_() ->
    ValidMsg = <<11, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
    EarlyData = <<5, 0, 0, 0>>,
    KeyUpdate = <<24, 0, 0, 1, 0>>,
    [
        ?_assertEqual(ok, nquic_frame_handler:check_handshake_crypto(<<>>)),
        ?_assertEqual(ok, nquic_frame_handler:check_handshake_crypto(ValidMsg)),
        ?_assertEqual(
            {error, {tls_alert, unexpected_message}},
            nquic_frame_handler:check_handshake_crypto(EarlyData)
        ),
        ?_assertEqual(
            {error, {tls_alert, unexpected_message}},
            nquic_frame_handler:check_handshake_crypto(KeyUpdate)
        )
    ].

check_post_handshake_crypto_test_() ->
    ValidMsg = <<4, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
    KeyUpdate = <<24, 0, 0, 1, 0>>,
    [
        ?_assertEqual(ok, nquic_frame_handler:check_post_handshake_crypto(<<>>)),
        ?_assertEqual(ok, nquic_frame_handler:check_post_handshake_crypto(ValidMsg)),
        ?_assertEqual(
            {error, {tls_alert, unexpected_message}},
            nquic_frame_handler:check_post_handshake_crypto(KeyUpdate)
        )
    ].

decode_ack_ranges_test_() ->
    [
        ?_assertEqual([{8, 10}], nquic_frame_handler:decode_ack_ranges(10, 2, [])),
        ?_assertEqual(
            [{3, 6}, {8, 10}],
            nquic_frame_handler:decode_ack_ranges(10, 2, [#ack_range{gap = 0, length = 3}])
        )
    ].
