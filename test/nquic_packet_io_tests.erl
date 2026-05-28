%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_packet_io}.
%%%-------------------------------------------------------------------
-module(nquic_packet_io_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_frame.hrl").
find_highest_key_level_test_() ->
    [
        ?_assertEqual(
            application,
            nquic_packet_io:find_highest_key_level(#{
                application => #{}, handshake => #{}, initial => #{}
            })
        ),
        ?_assertEqual(
            handshake,
            nquic_packet_io:find_highest_key_level(#{handshake => #{}, initial => #{}})
        ),
        ?_assertEqual(
            initial, nquic_packet_io:find_highest_key_level(#{initial => #{}})
        )
    ].

test_initial_keys(DCID) ->
    {_CSecret, SSecret} = nquic_keys:initial_secrets(DCID),
    {Key, IV, HP} = nquic_keys:derive_packet_protection(SSecret, aes_128_gcm, 1),
    #{key => Key, iv => IV, hp => HP}.

test_role_keys(DCID) ->
    {CSecret, SSecret} = nquic_keys:initial_secrets(DCID),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(CSecret, aes_128_gcm, 1),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(SSecret, aes_128_gcm, 1),
    #{
        client => #{key => CKey, iv => CIV, hp => CHP},
        server => #{key => SKey, iv => SIV, hp => SHP}
    }.

send_initial_packet_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    Keys = test_initial_keys(DCID),
    Frame = #ping{},
    {ok, _Packet, Size} =
        nquic_packet_io:send_initial_packet(SendSock, Peer, DCID, SCID, Keys, {0, [Frame]}),
    ?assert(Size >= 1200),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).

send_handshake_packet_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    Keys = test_initial_keys(DCID),
    Frame = #ping{},
    {ok, _Packet, Size} =
        nquic_packet_io:send_handshake_packet(SendSock, Peer, DCID, SCID, Keys, {0, [Frame]}),
    ?assert(Size < 1200),
    ?assert(Size > 0),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).

send_app_packet_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Keys = test_initial_keys(DCID),
    Frame = #ping{},
    {ok, _Packet, Size} =
        nquic_packet_io:send_app_packet(SendSock, Peer, DCID, Keys, {0, Frame}),
    ?assert(Size > 0),
    ?assert(Size < 1200),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).

send_close_frame_app_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    RoleKeys = test_role_keys(DCID),
    Keys = #{application => RoleKeys, handshake => RoleKeys, initial => RoleKeys},
    PnSpaces = #{
        application => #{next_pn => 0},
        handshake => #{next_pn => 0},
        initial => #{next_pn => 0}
    },
    Frame = #connection_close{error_code = 0, reason_phrase = <<>>},
    Params = #{
        dcid => DCID,
        scid => SCID,
        keys => Keys,
        pn_spaces => PnSpaces,
        role => client,
        frame => Frame
    },
    ?assertEqual(ok, nquic_packet_io:send_close_frame(SendSock, Peer, Params)),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).

send_close_frame_handshake_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    RoleKeys = test_role_keys(DCID),
    Keys = #{handshake => RoleKeys, initial => RoleKeys},
    PnSpaces = #{handshake => #{next_pn => 0}, initial => #{next_pn => 0}},
    Frame = #connection_close{error_code = 1, reason_phrase = <<"bye">>},
    Params = #{
        dcid => DCID,
        scid => SCID,
        keys => Keys,
        pn_spaces => PnSpaces,
        role => server,
        frame => Frame
    },
    ?assertEqual(ok, nquic_packet_io:send_close_frame(SendSock, Peer, Params)),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).

send_close_frame_initial_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    RoleKeys = test_role_keys(DCID),
    Keys = #{initial => RoleKeys},
    PnSpaces = #{initial => #{next_pn => 0}},
    Frame = #connection_close{error_code = 0, reason_phrase = <<>>},
    Params = #{
        dcid => DCID,
        scid => SCID,
        keys => Keys,
        pn_spaces => PnSpaces,
        role => client,
        frame => Frame
    },
    ?assertEqual(ok, nquic_packet_io:send_close_frame(SendSock, Peer, Params)),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).

send_close_frame_initial_no_pn_space_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    RoleKeys = test_role_keys(DCID),
    Keys = #{initial => RoleKeys},
    PnSpaces = #{},
    Frame = #connection_close{error_code = 0, reason_phrase = <<>>},
    Params = #{
        dcid => DCID,
        scid => SCID,
        keys => Keys,
        pn_spaces => PnSpaces,
        role => client,
        frame => Frame
    },
    ?assertEqual(ok, nquic_packet_io:send_close_frame(SendSock, Peer, Params)),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).

hp_sample_large_ciphertext_test() ->
    Large = crypto:strong_rand_bytes(32),
    Tag = crypto:strong_rand_bytes(16),
    Sample = nquic_packet_io:hp_sample(Large, Tag, 0),
    ?assertEqual(16, byte_size(Sample)),
    <<Expected:16/binary, _/binary>> = Large,
    ?assertEqual(Expected, Sample).

hp_sample_small_ciphertext_test() ->
    Small = <<1, 2, 3, 4, 5>>,
    Tag = crypto:strong_rand_bytes(16),
    Sample = nquic_packet_io:hp_sample(Small, Tag, 0),
    ?assertEqual(16, byte_size(Sample)),
    Combined = <<Small/binary, Tag/binary>>,
    <<Expected:16/binary, _/binary>> = Combined,
    ?assertEqual(Expected, Sample).

hp_sample_with_offset_test() ->
    Ciphertext = crypto:strong_rand_bytes(32),
    Tag = crypto:strong_rand_bytes(16),
    Sample = nquic_packet_io:hp_sample(Ciphertext, Tag, 4),
    ?assertEqual(16, byte_size(Sample)),
    <<_:4/binary, Expected:16/binary, _/binary>> = Ciphertext,
    ?assertEqual(Expected, Sample).

send_initial_packet_multiple_frames_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    Keys = test_initial_keys(DCID),
    Frames = [#ping{}, #padding{}, #ping{}],
    {ok, _Packet, Size} =
        nquic_packet_io:send_initial_packet(SendSock, Peer, DCID, SCID, Keys, {0, Frames}),
    ?assert(Size >= 1200),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).

send_app_packet_stream_frame_test() ->
    {ok, RecvSock} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(RecvSock),
    {ok, SendSock} = nquic_socket:open(#{}),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, RecvPort),
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Keys = test_initial_keys(DCID),
    Frame = #stream{
        stream_id = 0,
        offset = 0,
        length = 5,
        fin = false,
        data = <<"hello">>
    },
    {ok, _Packet, Size} =
        nquic_packet_io:send_app_packet(SendSock, Peer, DCID, Keys, {0, Frame}),
    ?assert(Size > 0),
    nquic_socket:close(RecvSock),
    nquic_socket:close(SendSock).
