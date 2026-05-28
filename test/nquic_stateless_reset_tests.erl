%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_stateless_reset}.
%%%-------------------------------------------------------------------
-module(nquic_stateless_reset_tests).

-include_lib("eunit/include/eunit.hrl").

generate_token_deterministic_test() ->
    Key = crypto:strong_rand_bytes(32),
    CID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    T1 = nquic_stateless_reset:generate_token(Key, CID),
    T2 = nquic_stateless_reset:generate_token(Key, CID),
    ?assertEqual(T1, T2),
    ?assertEqual(16, byte_size(T1)).

generate_token_different_cids_test() ->
    Key = crypto:strong_rand_bytes(32),
    T1 = nquic_stateless_reset:generate_token(Key, <<1, 2, 3, 4>>),
    T2 = nquic_stateless_reset:generate_token(Key, <<5, 6, 7, 8>>),
    ?assertNotEqual(T1, T2).

generate_token_different_keys_test() ->
    CID = <<1, 2, 3, 4>>,
    T1 = nquic_stateless_reset:generate_token(<<0:256>>, CID),
    T2 = nquic_stateless_reset:generate_token(<<1:256>>, CID),
    ?assertNotEqual(T1, T2).

build_packet_format_test() ->
    Token = crypto:strong_rand_bytes(16),
    Packet = nquic_stateless_reset:build_packet(Token),
    ?assert(byte_size(Packet) >= 21),
    PacketLen = byte_size(Packet),
    ?assertEqual(Token, binary:part(Packet, PacketLen - 16, 16)),
    <<B7:1, B6:1, _:6>> = <<(binary:first(Packet))>>,
    ?assertEqual(0, B7),
    ?assertEqual(1, B6).

detect_valid_test() ->
    Token = crypto:strong_rand_bytes(16),
    Packet = nquic_stateless_reset:build_packet(Token),
    ?assert(nquic_stateless_reset:detect(Packet, Token)).

detect_invalid_token_test() ->
    Token = crypto:strong_rand_bytes(16),
    WrongToken = crypto:strong_rand_bytes(16),
    Packet = nquic_stateless_reset:build_packet(Token),
    ?assertNot(nquic_stateless_reset:detect(Packet, WrongToken)).

detect_packet_too_short_test() ->
    Token = crypto:strong_rand_bytes(16),
    ?assertNot(nquic_stateless_reset:detect(<<0:160>>, Token)).

detect_constant_time_wrong_token_size_test() ->
    ?assertNot(nquic_stateless_reset:detect(<<0:168>>, <<0:120>>)).
