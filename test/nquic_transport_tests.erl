%%%-------------------------------------------------------------------
%%% @doc Unit tests for nquic_transport
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_transport_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_transport.hrl").
encode_decode_test() ->
    Params = #transport_params{
        original_destination_connection_id = <<1, 2, 3, 4>>,
        max_idle_timeout = 30000,
        stateless_reset_token = <<0:128>>,
        max_udp_payload_size = 1400,
        initial_max_data = 100000,
        initial_max_stream_data_bidi_local = 50000,
        initial_max_stream_data_bidi_remote = 50000,
        initial_max_stream_data_uni = 50000,
        initial_max_streams_bidi = 100,
        initial_max_streams_uni = 100,
        ack_delay_exponent = 3,
        max_ack_delay = 25,
        disable_active_migration = true,
        active_connection_id_limit = 4,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },

    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),

    ?assertEqual(Params, Decoded).

defaults_test() ->
    ?assertMatch(
        {error, {transport_parameter_error, missing_initial_source_cid}},
        nquic_transport:decode(<<>>, client)
    ).

unknown_param_test() ->
    InitialSrcCid = <<16#0f, 8, 1, 2, 3, 4, 5, 6, 7, 8>>,
    KnownParam = <<16#01, 1, 10>>,
    UnknownParam = <<16#7F, 16#FF, 1, 123>>,
    Bin = <<InitialSrcCid/binary, KnownParam/binary, UnknownParam/binary>>,

    {ok, Decoded} = nquic_transport:decode(Bin, client),
    ?assertEqual(10, Decoded#transport_params.max_idle_timeout),
    ?assertEqual(<<1, 2, 3, 4, 5, 6, 7, 8>>, Decoded#transport_params.initial_source_connection_id).

zero_valued_params_test() ->
    Params = #transport_params{
        max_idle_timeout = 0,
        initial_max_data = 0,
        initial_max_stream_data_bidi_local = 0,
        initial_max_stream_data_bidi_remote = 0,
        initial_max_stream_data_uni = 0,
        initial_max_streams_bidi = 0,
        initial_max_streams_uni = 0,
        ack_delay_exponent = 0,
        max_ack_delay = 0,
        active_connection_id_limit = 2,
        initial_source_connection_id = <<1, 2, 3, 4>>,
        original_destination_connection_id = <<5, 6, 7, 8>>
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),
    ?assertEqual(0, Decoded#transport_params.ack_delay_exponent),
    ?assertEqual(0, Decoded#transport_params.initial_max_data),
    ?assertEqual(0, Decoded#transport_params.initial_max_streams_bidi),
    ?assertEqual(0, Decoded#transport_params.max_ack_delay),
    ?assertEqual(2, Decoded#transport_params.active_connection_id_limit).

active_connection_id_limit_validation_test() ->
    Params = #transport_params{
        active_connection_id_limit = 1,
        initial_source_connection_id = <<1, 2, 3, 4>>,
        original_destination_connection_id = <<5, 6, 7, 8>>
    },
    Encoded = nquic_transport:encode(Params),
    ?assertMatch(
        {error, {transport_parameter_error, invalid_active_cid_limit}},
        nquic_transport:decode(Encoded, server)
    ).

parse_preferred_address_test() ->
    PA = #{
        ipv4 => {{10, 0, 0, 1}, 4433},
        ipv6 => {{0, 0, 0, 0, 0, 0, 0, 1}, 4434},
        cid => <<1, 2, 3, 4, 5, 6, 7, 8>>,
        stateless_reset_token => <<0:128>>
    },
    Params = #transport_params{
        preferred_address = PA,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        stateless_reset_token = <<0:128>>,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),
    ?assertEqual(PA, Decoded#transport_params.preferred_address).

preferred_address_undefined_roundtrip_test() ->
    Params = #transport_params{
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),
    ?assertEqual(undefined, Decoded#transport_params.preferred_address).

preferred_address_client_sends_error_test() ->
    PA = #{
        ipv4 => {{10, 0, 0, 1}, 4433},
        ipv6 => {{0, 0, 0, 0, 0, 0, 0, 1}, 4434},
        cid => <<1, 2, 3, 4>>,
        stateless_reset_token => <<0:128>>
    },
    Params = #transport_params{
        preferred_address = PA,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    Encoded = nquic_transport:encode(Params),
    ?assertMatch({error, transport_parameter_error}, nquic_transport:decode(Encoded, client)).

version_information_roundtrip_test() ->
    VI = #{chosen_version => 1, other_versions => [1, 16#6b3343cf]},
    Params = #transport_params{
        version_information = VI,
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),
    ?assertEqual(VI, Decoded#transport_params.version_information).

version_information_v2_roundtrip_test() ->
    VI = #{chosen_version => 16#6b3343cf, other_versions => [16#6b3343cf, 1]},
    Params = #transport_params{
        version_information = VI,
        initial_source_connection_id = <<1, 2, 3, 4>>
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, client),
    ?assertEqual(VI, Decoded#transport_params.version_information).

version_information_undefined_test() ->
    Params = #transport_params{
        original_destination_connection_id = <<1, 2, 3, 4>>,
        initial_source_connection_id = <<5, 6, 7, 8>>
    },
    Encoded = nquic_transport:encode(Params),
    {ok, Decoded} = nquic_transport:decode(Encoded, server),
    ?assertEqual(undefined, Decoded#transport_params.version_information).

%% Pure decode error-path contract (RFC 9000 §18 validation arms).
tlv(ID, Val) ->
    <<(nquic_varint:encode(ID))/binary, (nquic_varint:encode(byte_size(Val)))/binary, Val/binary>>.

decode_error_paths_test_() ->
    Cases = [
        {"orig_dcid from client", tlv(16#00, <<"ab">>), client, transport_parameter_error},
        {"reset_token from client", tlv(16#02, <<"ab">>), client, transport_parameter_error},
        {"reset_token bad size", tlv(16#02, <<"ab">>), server, transport_parameter_error},
        {"max_udp_payload < 1200", tlv(16#03, nquic_varint:encode(100)), server,
            transport_parameter_error},
        {"ack_delay_exponent > 20", tlv(16#0a, nquic_varint:encode(21)), server,
            transport_parameter_error},
        {"max_ack_delay >= 16384", tlv(16#0b, nquic_varint:encode(16384)), server,
            transport_parameter_error},
        {"retry_scid from client", tlv(16#10, <<"cid">>), client, transport_parameter_error},
        {"preferred_address from client", tlv(16#0d, <<"x">>), client, transport_parameter_error},
        {"truncated value", <<16#04, 8, 1, 2>>, server, truncated_param_value}
    ],
    [
        {Name, fun() -> ?assertEqual({error, R}, nquic_transport:decode(Bin, Role)) end}
     || {Name, Bin, Role, R} <- Cases
    ].

decode_error_tagged_paths_test_() ->
    Cases = [
        {"bad preferred_address", tlv(16#0d, <<"bad">>), server,
            {transport_parameter_error, malformed_preferred_address}},
        {"bad version_information", tlv(16#11, <<1, 2, 3>>), server,
            {transport_parameter_error, malformed_version_information}},
        {"active_cid_limit < 2", tlv(16#0e, nquic_varint:encode(1)), server,
            {transport_parameter_error, invalid_active_cid_limit}}
    ],
    [
        {Name, fun() -> ?assertEqual({error, R}, nquic_transport:decode(Bin, Role)) end}
     || {Name, Bin, Role, R} <- Cases
    ].
