%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_packet}.
%%%-------------------------------------------------------------------
-module(nquic_packet_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_packet.hrl").
long_header_initial_test() ->
    DCID = <<1, 2, 3, 4>>,
    SCID = <<5, 6, 7, 8>>,
    Token = <<9, 10>>,
    PayloadLen = 100,
    Version = 1,
    FirstByte = 2#11000000,
    Bin =
        <<FirstByte, Version:32, (byte_size(DCID)):8, DCID/binary, (byte_size(SCID)):8, SCID/binary,
            (nquic_varint:encode(byte_size(Token)))/binary, Token/binary,
            (nquic_varint:encode(PayloadLen))/binary, "packet_number_and_payload">>,
    ?assertMatch(
        {ok,
            #long_header{
                type = initial, dcid = DCID, scid = SCID, token = Token, payload_len = PayloadLen
            },
            _},
        nquic_packet:parse_header(Bin)
    ).

short_header_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    FirstByte = 2#01000000,
    Bin = <<FirstByte, DCID/binary, "packet_number_and_payload">>,
    ?assertMatch({ok, #short_header{dcid = DCID}, _}, nquic_packet:parse_header(Bin, 8)).

retry_parse_header_test() ->
    DCID = <<1, 2, 3, 4>>,
    SCID = <<5, 6, 7, 8, 9, 10, 11, 12>>,
    ODCID = <<13, 14, 15, 16>>,
    Token = <<"retry_token_data">>,
    Packet = nquic_retry:encode_retry_packet(DCID, SCID, ODCID, Token, 1),
    {ok, Header, <<>>} = nquic_packet:parse_header(Packet),
    ?assertEqual(retry, Header#long_header.type),
    ?assertEqual(DCID, Header#long_header.dcid),
    ?assertEqual(SCID, Header#long_header.scid),
    ?assertEqual(1, Header#long_header.version).

retry_parse_retry_roundtrip_test() ->
    DCID = <<1, 2, 3, 4>>,
    SCID = <<5, 6, 7, 8, 9, 10, 11, 12>>,
    ODCID = <<13, 14, 15, 16>>,
    Token = <<"retry_token_data">>,
    Packet = nquic_retry:encode_retry_packet(DCID, SCID, ODCID, Token, 1),
    {ok, Header, <<>>} = nquic_packet:parse_header(Packet),
    RawToken = Header#long_header.token,
    {ok, ExtractedToken, PacketNoTag, IntegrityTag} = nquic_packet:parse_retry(RawToken, Packet),
    ?assertEqual(Token, ExtractedToken),
    ?assertEqual(16, byte_size(IntegrityTag)),
    ?assertEqual(ok, nquic_retry:verify_integrity_tag(ODCID, PacketNoTag, IntegrityTag)).

parse_retry_too_short_test() ->
    ?assertEqual({error, retry_token_too_short}, nquic_packet:parse_retry(<<0:128>>, <<>>)).

v1_type_bits_test() ->
    ?assertEqual(0, nquic_packet:packet_type_bits(initial, 1)),
    ?assertEqual(1, nquic_packet:packet_type_bits(rtt0, 1)),
    ?assertEqual(2, nquic_packet:packet_type_bits(handshake, 1)),
    ?assertEqual(3, nquic_packet:packet_type_bits(retry, 1)).

v2_type_bits_test() ->
    V2 = 16#6b3343cf,
    ?assertEqual(1, nquic_packet:packet_type_bits(initial, V2)),
    ?assertEqual(2, nquic_packet:packet_type_bits(rtt0, V2)),
    ?assertEqual(3, nquic_packet:packet_type_bits(handshake, V2)),
    ?assertEqual(0, nquic_packet:packet_type_bits(retry, V2)).

v1_bits_to_type_test() ->
    ?assertEqual(initial, nquic_packet:bits_to_packet_type(0, 1)),
    ?assertEqual(rtt0, nquic_packet:bits_to_packet_type(1, 1)),
    ?assertEqual(handshake, nquic_packet:bits_to_packet_type(2, 1)),
    ?assertEqual(retry, nquic_packet:bits_to_packet_type(3, 1)).

v2_bits_to_type_test() ->
    V2 = 16#6b3343cf,
    ?assertEqual(initial, nquic_packet:bits_to_packet_type(1, V2)),
    ?assertEqual(rtt0, nquic_packet:bits_to_packet_type(2, V2)),
    ?assertEqual(handshake, nquic_packet:bits_to_packet_type(3, V2)),
    ?assertEqual(retry, nquic_packet:bits_to_packet_type(0, V2)).

v2_roundtrip_type_bits_test() ->
    V2 = 16#6b3343cf,
    Types = [initial, rtt0, handshake, retry],
    lists:foreach(
        fun(T) ->
            ?assertEqual(
                T, nquic_packet:bits_to_packet_type(nquic_packet:packet_type_bits(T, V2), V2)
            )
        end,
        Types
    ).

supported_versions_test() ->
    Versions = nquic_packet:supported_versions(),
    ?assert(lists:member(1, Versions)),
    ?assert(lists:member(16#6b3343cf, Versions)),
    ?assertEqual(16#6b3343cf, hd(Versions)).
