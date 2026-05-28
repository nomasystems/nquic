%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_retry}.
%%%
%%% The `TOKEN_LIFETIME_SECS' macro mirrors the production default in
%%% `src/nquic_retry.erl'; if that default changes, update the value
%%% below to keep the regression tests in sync.
%%%-------------------------------------------------------------------
-module(nquic_retry_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TOKEN_LIFETIME_SECS, 30).

generate_validate_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Token = nquic_retry:generate_token(Key, ODCID, Peer, ?TOKEN_LIFETIME_SECS),
    ?assertMatch({ok, ODCID}, nquic_retry:validate_token(Token, Key, Peer, ?TOKEN_LIFETIME_SECS)).

validate_wrong_key_test() ->
    Key1 = crypto:strong_rand_bytes(32),
    Key2 = crypto:strong_rand_bytes(32),
    ODCID = <<1, 2, 3, 4>>,
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Token = nquic_retry:generate_token(Key1, ODCID, Peer, ?TOKEN_LIFETIME_SECS),
    ?assertEqual(
        {error, invalid_retry_token},
        nquic_retry:validate_token(Token, Key2, Peer, ?TOKEN_LIFETIME_SECS)
    ).

validate_wrong_addr_test() ->
    Key = crypto:strong_rand_bytes(32),
    ODCID = <<1, 2, 3, 4>>,
    Peer1 = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Peer2 = nquic_socket:make_sockaddr({10, 0, 0, 1}, 4433),
    Token = nquic_retry:generate_token(Key, ODCID, Peer1, ?TOKEN_LIFETIME_SECS),
    ?assertEqual(
        {error, invalid_retry_token},
        nquic_retry:validate_token(Token, Key, Peer2, ?TOKEN_LIFETIME_SECS)
    ).

validate_truncated_token_test() ->
    ?assertEqual({error, invalid_retry_token}, nquic_retry:validate_token(<<0:64>>, <<>>, #{}, 30)).

validate_malformed_token_test() ->
    ?assertEqual({error, invalid_retry_token}, nquic_retry:validate_token(<<>>, <<>>, #{}, 30)).

integrity_tag_roundtrip_test() ->
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    DCID = <<10, 11, 12, 13>>,
    SCID = <<20, 21, 22, 23, 24, 25, 26, 27>>,
    Token = <<"test_token">>,
    Unused = 5,
    FirstByte = 16#F0 bor Unused,
    PacketNoTag = <<
        FirstByte:8,
        1:32,
        (byte_size(DCID)):8,
        DCID/binary,
        (byte_size(SCID)):8,
        SCID/binary,
        Token/binary
    >>,
    Tag = nquic_retry:compute_integrity_tag(ODCID, PacketNoTag),
    ?assertEqual(16, byte_size(Tag)),
    ?assertEqual(ok, nquic_retry:verify_integrity_tag(ODCID, PacketNoTag, Tag)).

integrity_tag_wrong_odcid_test() ->
    ODCID1 = <<1, 2, 3, 4>>,
    ODCID2 = <<5, 6, 7, 8>>,
    PacketNoTag = <<16#F0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, "token">>,
    Tag = nquic_retry:compute_integrity_tag(ODCID1, PacketNoTag),
    ?assertMatch({error, _}, nquic_retry:verify_integrity_tag(ODCID2, PacketNoTag, Tag)).

encode_retry_packet_test() ->
    DCID = <<1, 2, 3, 4>>,
    SCID = <<5, 6, 7, 8, 9, 10, 11, 12>>,
    ODCID = <<13, 14, 15, 16>>,
    Token = <<"retry_token_data">>,
    Packet = nquic_retry:encode_retry_packet(DCID, SCID, ODCID, Token, 1),
    <<First:8, 1:32, DCIDLen:8, DCID2:DCIDLen/binary, SCIDLen:8, SCID2:SCIDLen/binary, Rest/binary>> =
        Packet,
    ?assertEqual(1, (First bsr 7) band 1),
    ?assertEqual(1, (First bsr 6) band 1),
    ?assertEqual(3, (First bsr 4) band 3),
    ?assertEqual(DCID, DCID2),
    ?assertEqual(SCID, SCID2),
    TokenLen = byte_size(Rest) - 16,
    <<ExtractedToken:TokenLen/binary, IntegrityTag:16/binary>> = Rest,
    ?assertEqual(Token, ExtractedToken),
    PacketNoTag = binary:part(Packet, 0, byte_size(Packet) - 16),
    ?assertEqual(ok, nquic_retry:verify_integrity_tag(ODCID, PacketNoTag, IntegrityTag)).

encode_addr_ipv4_test() ->
    Addr = nquic_socket:make_sockaddr({192, 168, 1, 1}, 8080),
    Bin = nquic_retry:encode_addr(Addr),
    ?assertEqual(<<192, 168, 1, 1, 8080:16>>, Bin).

hmac_equal_same_test() ->
    A = crypto:strong_rand_bytes(32),
    ?assert(nquic_retry:hmac_equal(A, A)).

hmac_equal_different_test() ->
    A = crypto:strong_rand_bytes(32),
    B = crypto:strong_rand_bytes(32),
    ?assertNot(nquic_retry:hmac_equal(A, B)).

hmac_equal_different_size_test() ->
    ?assertNot(nquic_retry:hmac_equal(<<1, 2, 3>>, <<1, 2>>)).
