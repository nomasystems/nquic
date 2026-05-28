%%%-------------------------------------------------------------------
%%% @doc Unit tests for nquic_tls
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_tls_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_transport.hrl").
-record(server_hello_versions, {
    versions
}).

make_client_hello_test() ->
    ssl:start(),
    Params = #transport_params{
        initial_max_data = 1000
    },

    {ok, Bin, State} = nquic_tls_client:make_client_hello(Params, [<<"h3">>], undefined),

    <<Type:8, Len:24, Body:Len/binary>> = Bin,
    ?assertEqual(1, Type),

    Pattern = <<0, 57>>,
    ?assert(binary:match(Body, Pattern) =/= nomatch),

    #{priv_key := PrivKey} = State,
    ?assert(is_binary(PrivKey)).

process_server_hello_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, CHBin, State} = nquic_tls_client:make_client_hello(Params, [<<"h3">>], undefined),

    {ServerPub, ServerPriv} = crypto:generate_key(ecdh, x25519),

    LegacyVer = <<3, 3>>,
    Random = crypto:strong_rand_bytes(32),
    SessionID = <<0>>,
    CipherSuite = <<19, 1>>,
    CompMethod = 0,

    KeyShareData = <<16#001d:16, 32:16, ServerPub/binary>>,
    KeyShareExt = <<16#0033:16, (byte_size(KeyShareData)):16, KeyShareData/binary>>,

    ExtData = KeyShareExt,
    ExtLen = byte_size(ExtData),

    Body =
        <<LegacyVer/binary, Random/binary, SessionID/binary, CipherSuite/binary, CompMethod:8,
            ExtLen:16, ExtData/binary>>,

    SHBin = <<2:8, (byte_size(Body)):24, Body/binary>>,

    {ok, Keys} = nquic_tls_client:process_server_hello(SHBin, CHBin, State),

    ?assert(maps:is_key(client_secret, Keys)),
    ?assert(maps:is_key(server_secret, Keys)),
    ?assert(maps:is_key(client_key, Keys)),
    ?assert(maps:is_key(client_iv, Keys)),
    ?assert(maps:is_key(client_hp, Keys)),

    #{pub_key := ClientPub} = State,
    SharedSecret = crypto:compute_key(ecdh, ClientPub, ServerPriv, x25519),
    Transcript = <<CHBin/binary, SHBin/binary>>,
    TranscriptHash = crypto:hash(sha256, Transcript),

    {ExpectedClientSecret, _, _} = nquic_keys:handshake_secrets(SharedSecret, TranscriptHash),

    ?assertEqual(ExpectedClientSecret, maps:get(client_secret, Keys)).

parse_vec8_test() ->
    {<<1, 2, 3>>, <<4, 5>>} = nquic_tls:parse_vec8(<<3, 1, 2, 3, 4, 5>>),
    {<<>>, <<1>>} = nquic_tls:parse_vec8(<<0, 1>>).

parse_vec16_test() ->
    {<<1, 2, 3, 4>>, <<5>>} = nquic_tls:parse_vec16(<<0, 4, 1, 2, 3, 4, 5>>),
    {<<>>, <<>>} = nquic_tls:parse_vec16(<<0, 0>>).

parse_extensions_recursive_test() ->
    ?assertEqual(#{}, nquic_tls:parse_extensions_recursive(<<>>)),

    Ext = <<0, 51, 0, 2, 1, 2>>,
    ?assertEqual(#{51 => <<1, 2>>}, nquic_tls:parse_extensions_recursive(Ext)),
    Ext2 = <<0, 10, 0, 1, 5, 0, 20, 0, 2, 6, 7>>,
    ?assertEqual(#{10 => <<5>>, 20 => <<6, 7>>}, nquic_tls:parse_extensions_recursive(Ext2)).

find_alpn_none_test() ->
    ?assertEqual(undefined, nquic_tls_server:find_alpn(#{})).

find_alpn_present_test() ->
    ALPNData = <<0, 3, 2, 104, 51>>,
    ?assertEqual([<<"h3">>], nquic_tls_server:find_alpn(#{16 => ALPNData})).

select_alpn_no_server_protos_test() ->
    ?assertEqual({ok, undefined}, nquic_tls_server:select_alpn([<<"h3">>], undefined)).

select_alpn_match_test() ->
    ?assertEqual(
        {ok, <<"h3">>}, nquic_tls_server:select_alpn([<<"h2">>, <<"h3">>], [<<"h3">>, <<"hq">>])
    ).

encode_extensions_empty_test() ->
    ?assertEqual(<<>>, nquic_tls_server:encode_extensions(#{})).

encode_extensions_version_only_test() ->
    Exts = #{server_hello_versions => #server_hello_versions{versions = {3, 4}}},
    Result = nquic_tls_server:encode_extensions(Exts),
    ?assertEqual(<<0, 43, 0, 2, 3, 4>>, Result).

decode_cipher_suite_aes128_test() ->
    ?assertEqual({ok, aes_128_gcm}, nquic_tls:decode_cipher_suite(<<19, 1>>)).

decode_cipher_suite_aes256_test() ->
    ?assertEqual({ok, aes_256_gcm}, nquic_tls:decode_cipher_suite(<<19, 2>>)).

decode_cipher_suite_chacha_test() ->
    ?assertEqual({ok, chacha20_poly1305}, nquic_tls:decode_cipher_suite(<<19, 3>>)).

decode_cipher_suite_unsupported_test() ->
    ?assertEqual(
        {error, {unsupported_cipher_suite, <<99, 99>>}},
        nquic_tls:decode_cipher_suite(<<99, 99>>)
    ).

encode_cipher_suite_test() ->
    ?assertEqual(<<19, 1>>, nquic_tls:encode_cipher_suite(aes_128_gcm)),
    ?assertEqual(<<19, 2>>, nquic_tls:encode_cipher_suite(aes_256_gcm)),
    ?assertEqual(<<19, 3>>, nquic_tls:encode_cipher_suite(chacha20_poly1305)).

parse_cipher_suites_empty_test() ->
    ?assertEqual([], nquic_tls_server:parse_cipher_suites(<<>>)).

parse_cipher_suites_all_test() ->
    ?assertEqual(
        [aes_128_gcm, aes_256_gcm, chacha20_poly1305],
        nquic_tls_server:parse_cipher_suites(<<19, 1, 19, 2, 19, 3>>)
    ).

parse_cipher_suites_skips_unknown_test() ->
    ?assertEqual(
        [aes_128_gcm],
        nquic_tls_server:parse_cipher_suites(<<0, 0, 19, 1, 255, 255>>)
    ).

select_cipher_prefers_aes128_test() ->
    ?assertEqual(
        {ok, aes_128_gcm}, nquic_tls_server:select_cipher([chacha20_poly1305, aes_128_gcm])
    ).

select_cipher_fallback_test() ->
    ?assertEqual({ok, aes_256_gcm}, nquic_tls_server:select_cipher([aes_256_gcm])).

select_cipher_default_preference_test() ->
    ?assertEqual(
        {ok, aes_128_gcm},
        nquic_tls_server:select_cipher(
            [chacha20_poly1305, aes_128_gcm], undefined
        )
    ).

select_cipher_explicit_preference_picks_chacha_test() ->
    ?assertEqual(
        {ok, chacha20_poly1305},
        nquic_tls_server:select_cipher(
            [aes_128_gcm, aes_256_gcm, chacha20_poly1305],
            [chacha20_poly1305]
        )
    ).

select_cipher_explicit_preference_no_match_test() ->
    ?assertEqual(
        {error, {tls_alert, handshake_failure}},
        nquic_tls_server:select_cipher([aes_128_gcm], [chacha20_poly1305])
    ).

make_client_hello_chacha20_only_test() ->
    ssl:start(),
    Params = #transport_params{
        initial_max_data = 1000,
        initial_max_streams_bidi = 100
    },
    {ok, Bin, _State} =
        nquic_tls_client:make_client_hello(
            Params, [<<"h3">>], <<"localhost">>, [chacha20_poly1305]
        ),
    ?assertNotEqual(nomatch, binary:match(Bin, <<19, 3>>)),
    ?assertEqual(nomatch, binary:match(Bin, <<19, 1>>)).

make_client_hello_aes128_only_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, Bin, _State} =
        nquic_tls_client:make_client_hello(
            Params, [<<"h3">>], <<"localhost">>, [aes_128_gcm]
        ),
    ?assertNotEqual(nomatch, binary:match(Bin, <<19, 1>>)),
    ?assertEqual(nomatch, binary:match(Bin, <<19, 3>>)).

make_client_hello_aes256_only_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, Bin, _State} =
        nquic_tls_client:make_client_hello(
            Params, [<<"h3">>], <<"localhost">>, [aes_256_gcm]
        ),
    ?assertNotEqual(nomatch, binary:match(Bin, <<19, 2>>)),
    ?assertEqual(nomatch, binary:match(Bin, <<19, 1>>)).

make_client_hello_empty_alpn_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, _Bin, _State} =
        nquic_tls_client:make_client_hello(Params, [], <<"localhost">>).

make_client_hello_undefined_hostname_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, _Bin, _State} =
        nquic_tls_client:make_client_hello(Params, [<<"h3">>], undefined).

make_client_hello_list_hostname_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, _Bin, _State} =
        nquic_tls_client:make_client_hello(Params, [<<"h3">>], "example.org").

find_message_found_test() ->
    Msg = <<2, 0, 0, 5, 1, 2, 3, 4, 5>>,
    ?assertEqual(Msg, nquic_tls_client:find_message(2, [<<1, 0, 0, 0>>, Msg])).

find_message_not_found_test() ->
    ?assertEqual(undefined, nquic_tls_client:find_message(99, [<<1, 0, 0, 0>>])).

find_message_empty_test() ->
    ?assertEqual(undefined, nquic_tls_client:find_message(1, [])).

take_through_type_found_test() ->
    M1 = <<1, 0, 0, 0>>,
    M2 = <<2, 0, 0, 0>>,
    M3 = <<3, 0, 0, 0>>,
    ?assertEqual([M1, M2], nquic_tls_client:take_through_type(2, [M1, M2, M3])).

take_through_type_not_found_test() ->
    M1 = <<1, 0, 0, 0>>,
    ?assertEqual([M1], nquic_tls_client:take_through_type(99, [M1])).

parse_cert_entries_single_test() ->
    Cert = <<"cert_data">>,
    CertLen = byte_size(Cert),
    Entry = <<CertLen:24, Cert/binary, 0:16>>,
    {Cert, []} = nquic_tls_client:parse_cert_entries(Entry).

parse_remaining_cert_entries_empty_test() ->
    ?assertEqual([], nquic_tls_client:parse_remaining_cert_entries(<<>>)).

parse_remaining_cert_entries_two_test() ->
    C1 = <<"c1">>,
    C2 = <<"c2">>,
    Entry = <<2:24, C1/binary, 0:16, 2:24, C2/binary, 0:16>>,
    ?assertEqual([C1, C2], nquic_tls_client:parse_remaining_cert_entries(Entry)).

select_alpn_no_match_test() ->
    ?assertEqual(
        {error, {tls_alert, no_application_protocol}},
        nquic_tls_server:select_alpn([<<"h2">>], [<<"h3">>])
    ).

select_alpn_client_empty_test() ->
    ?assertEqual(
        {error, {tls_alert, no_application_protocol}},
        nquic_tls_server:select_alpn([], [<<"h3">>])
    ).

select_alpn_client_no_alpn_test() ->
    ?assertEqual(
        {error, {tls_alert, no_application_protocol}},
        nquic_tls_server:select_alpn(undefined, [<<"h3">>])
    ).

parse_alpn_items_empty_test() ->
    ?assertEqual([], nquic_tls_server:parse_alpn_items(<<>>)).

parse_alpn_items_multi_test() ->
    ?assertEqual([<<"h3">>, <<"h2">>], nquic_tls_server:parse_alpn_items(<<2, "h3", 2, "h2">>)).

find_match_empty_test() ->
    ?assertEqual(undefined, nquic_tls_server:find_match([], [<<"h3">>])).

find_match_found_test() ->
    ?assertEqual(<<"h3">>, nquic_tls_server:find_match([<<"h2">>, <<"h3">>], [<<"h3">>])).

hash_length_sha256_test() ->
    ?assertEqual(32, nquic_tls:hash_length(sha256)).

hash_length_sha384_test() ->
    ?assertEqual(48, nquic_tls:hash_length(sha384)).

update_transcript_ctx_empty_test() ->
    Ctx = crypto:hash_init(sha256),
    Ctx2 = nquic_tls_client:update_transcript_ctx(Ctx, []),
    ?assertEqual(crypto:hash_final(Ctx), crypto:hash_final(Ctx2)).

update_transcript_ctx_with_data_test() ->
    Ctx = crypto:hash_init(sha256),
    Ctx2 = nquic_tls_client:update_transcript_ctx(Ctx, [<<"hello">>, <<"world">>]),
    Expected = crypto:hash(sha256, <<"helloworld">>),
    ?assertEqual(Expected, crypto:hash_final(Ctx2)).

make_certificate_message_test() ->
    Leaf = <<"leaf_cert">>,
    Chain = [<<"inter_cert">>],
    Msg = nquic_tls_server:make_certificate_message(Leaf, Chain),
    <<11, _Len:24, 0, _Rest/binary>> = Msg.

find_cipher_match_empty_test() ->
    ?assertEqual(undefined, nquic_tls_server:find_cipher_match([], [aes_128_gcm])).

find_cipher_match_found_test() ->
    ?assertEqual(
        aes_256_gcm, nquic_tls_server:find_cipher_match([aes_256_gcm], [aes_128_gcm, aes_256_gcm])
    ).

encode_decode_nst_test() ->
    Ticket = #{
        lifetime => 7200,
        age_add => 12345,
        nonce => <<1, 2, 3, 4>>,
        ticket => <<"my_ticket_value">>
    },
    Encoded = nquic_tls:encode_new_session_ticket(Ticket),
    {ok, Decoded} = nquic_tls:decode_new_session_ticket(Encoded),
    ?assertEqual(7200, maps:get(lifetime, Decoded)),
    ?assertEqual(12345, maps:get(age_add, Decoded)),
    ?assertEqual(<<1, 2, 3, 4>>, maps:get(nonce, Decoded)),
    ?assertEqual(<<"my_ticket_value">>, maps:get(ticket, Decoded)),
    ?assertEqual(undefined, maps:get(max_early_data, Decoded)).

encode_decode_nst_with_early_data_test() ->
    Ticket = #{
        lifetime => 3600,
        age_add => 99999,
        nonce => <<42>>,
        ticket => <<"ticket">>,
        max_early_data => 16#FFFFFFFF
    },
    Encoded = nquic_tls:encode_new_session_ticket(Ticket),
    {ok, Decoded} = nquic_tls:decode_new_session_ticket(Encoded),
    ?assertEqual(3600, maps:get(lifetime, Decoded)),
    ?assertEqual(16#FFFFFFFF, maps:get(max_early_data, Decoded)).

decode_nst_invalid_test() ->
    ?assertEqual({error, not_new_session_ticket}, nquic_tls:decode_new_session_ticket(<<>>)),
    ?assertEqual(
        {error, not_new_session_ticket}, nquic_tls:decode_new_session_ticket(<<5, 0, 0, 1, 0>>)
    ).

derive_resumption_secret_test() ->
    Ctx = crypto:hash_init(sha256),
    FinBin = <<20, 0, 0, 32, 0:256>>,
    HSSecret = crypto:strong_rand_bytes(32),
    S1 = nquic_tls:derive_resumption_secret(HSSecret, Ctx, FinBin, aes_128_gcm),
    S2 = nquic_tls:derive_resumption_secret(HSSecret, Ctx, FinBin, aes_128_gcm),
    ?assertEqual(32, byte_size(S1)),
    ?assertEqual(S1, S2).

encode_psk_ke_modes_extension_test() ->
    Bin = nquic_tls_client:encode_psk_ke_modes_extension(),
    ?assertEqual(<<0, 45, 0, 2, 1, 1>>, Bin).

encode_early_data_extension_test() ->
    Bin = nquic_tls_client:encode_early_data_extension(),
    ?assertEqual(<<0, 42, 0, 0>>, Bin).

encode_psk_identity_test() ->
    Identity = <<"ticket_value">>,
    Age = 12345,
    Bin = nquic_tls_client:encode_psk_identity(Identity, Age),
    IdentityLen = byte_size(Identity),
    ExpectedEntryLen = 2 + IdentityLen + 4,
    <<ListLen:16, EntryIdentityLen:16, Id:IdentityLen/binary, EntryAge:32>> = Bin,
    ?assertEqual(ExpectedEntryLen, ListLen),
    ?assertEqual(IdentityLen, EntryIdentityLen),
    ?assertEqual(Identity, Id),
    ?assertEqual(Age, EntryAge).

compute_psk_binder_test() ->
    PSK = crypto:strong_rand_bytes(32),
    PartialCH = <<"partial_client_hello_data">>,
    B1 = nquic_tls:compute_psk_binder(PSK, PartialCH, sha256, 32),
    B2 = nquic_tls:compute_psk_binder(PSK, PartialCH, sha256, 32),
    ?assertEqual(32, byte_size(B1)),
    ?assertEqual(B1, B2),
    PSK2 = crypto:strong_rand_bytes(32),
    B3 = nquic_tls:compute_psk_binder(PSK2, PartialCH, sha256, 32),
    ?assertNotEqual(B1, B3).

compute_ticket_age_test() ->
    ?assertEqual(0, nquic_tls_client:compute_ticket_age(#{})),
    Now = erlang:system_time(millisecond),
    Age = nquic_tls_client:compute_ticket_age(#{received_at => Now - 1000}),
    ?assert(Age >= 1000),
    ?assert(Age < 2000).

make_client_hello_psk_test() ->
    TP = #transport_params{
        initial_source_connection_id = <<1, 2, 3, 4, 5, 6, 7, 8>>
    },
    PSK = crypto:strong_rand_bytes(32),
    TicketData = #{
        lifetime => 7200,
        age_add => 12345,
        nonce => <<1, 2, 3, 4>>,
        ticket => <<"test_ticket_value">>,
        received_at => erlang:system_time(millisecond) - 500
    },
    PSKInfo = #{psk => PSK, ticket => TicketData, cipher => aes_128_gcm},
    {ok, CHBin, State} = nquic_tls_client:make_client_hello_psk(
        TP, [<<"h3">>], "localhost", PSKInfo
    ),
    <<1:8, Len:24, _Body:Len/binary>> = CHBin,
    ?assertEqual(PSK, maps:get(psk, State)),
    ?assertEqual(aes_128_gcm, maps:get(cipher, State)),
    <<1:8, _:24, Body/binary>> = CHBin,
    <<_:2/binary, _:32/binary, Rest1/binary>> = Body,
    {_SessID, Rest2} = nquic_tls:parse_vec8(Rest1),
    {_Ciphers, Rest3} = nquic_tls:parse_vec16(Rest2),
    {_Comp, Rest4} = nquic_tls:parse_vec8(Rest3),
    <<ExtLen:16, ExtData:ExtLen/binary>> = Rest4,
    LastExtType = find_last_extension_type(ExtData),
    ?assertEqual(41, LastExtType).

find_last_extension_type(<<Type:16, Len:16, _Val:Len/binary>>) ->
    Type;
find_last_extension_type(<<_Type:16, Len:16, _Val:Len/binary, Rest/binary>>) ->
    find_last_extension_type(Rest).

parse_psk_extension_absent_test() ->
    ?assertEqual(undefined, nquic_tls:parse_psk_extension(#{})).

parse_psk_extension_present_test() ->
    Identity = <<"my_ticket">>,
    IdLen = byte_size(Identity),
    Age = 42,
    IdentityEntry = <<IdLen:16, Identity/binary, Age:32>>,
    IdentitiesBin = <<(byte_size(IdentityEntry)):16, IdentityEntry/binary>>,
    Binder = crypto:strong_rand_bytes(32),
    BindersBin = <<33:16, 32:8, Binder/binary>>,
    ExtVal = <<IdentitiesBin/binary, BindersBin/binary>>,
    {ok, Identities, Binders} = nquic_tls:parse_psk_extension(#{41 => ExtVal}),
    ?assertEqual([{Identity, Age}], Identities),
    ?assertEqual([Binder], Binders).

has_psk_dhe_ke_mode_test() ->
    ?assertNot(nquic_tls:has_psk_dhe_ke_mode(#{})),
    ?assertNot(nquic_tls:has_psk_dhe_ke_mode(#{45 => <<1, 0>>})),
    ?assert(nquic_tls:has_psk_dhe_ke_mode(#{45 => <<1, 1>>})),
    ?assert(nquic_tls:has_psk_dhe_ke_mode(#{45 => <<2, 0, 1>>})).

verify_psk_binder_test() ->
    PSK = crypto:strong_rand_bytes(32),
    PartialCH = <<"partial_client_hello">>,
    Binder = nquic_tls:compute_psk_binder(PSK, PartialCH, sha256, 32),
    ?assertEqual(ok, nquic_tls:verify_psk_binder(PSK, PartialCH, Binder, sha256, 32)),
    BadBinder = crypto:strong_rand_bytes(32),
    ?assertEqual(
        {error, binder_mismatch},
        nquic_tls:verify_psk_binder(PSK, PartialCH, BadBinder, sha256, 32)
    ).

extract_partial_client_hello_test() ->
    Full = <<"hello_world_binders">>,
    BindersLen = 7,
    Partial = nquic_tls:extract_partial_client_hello(Full, BindersLen),
    ?assertEqual(<<"hello_world_">>, Partial).

process_server_hello_invalid_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, CHBin, State} = nquic_tls_client:make_client_hello(Params, [<<"h3">>], undefined),
    Bogus = <<99:8, 0:24>>,
    ?assertEqual(
        {error, invalid_server_hello},
        nquic_tls_client:process_server_hello(Bogus, CHBin, State)
    ).

process_server_hello_no_key_share_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, CHBin, State} = nquic_tls_client:make_client_hello(Params, [<<"h3">>], undefined),
    SHBin = build_server_hello(<<19, 1>>, <<>>),
    ?assertEqual(
        {error, key_share_not_found},
        nquic_tls_client:process_server_hello(SHBin, CHBin, State)
    ).

process_server_hello_unsupported_group_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, CHBin, State} = nquic_tls_client:make_client_hello(Params, [<<"h3">>], undefined),
    BogusKey = crypto:strong_rand_bytes(32),
    Secp256r1Group = 16#0017,
    KeyShareData = <<Secp256r1Group:16, (byte_size(BogusKey)):16, BogusKey/binary>>,
    KeyShareExt = <<16#0033:16, (byte_size(KeyShareData)):16, KeyShareData/binary>>,
    SHBin = build_server_hello(<<19, 1>>, KeyShareExt),
    ?assertMatch(
        {error, {unsupported_group, Secp256r1Group}},
        nquic_tls_client:process_server_hello(SHBin, CHBin, State)
    ).

process_server_hello_unknown_cipher_test() ->
    ssl:start(),
    Params = #transport_params{initial_max_data = 1000},
    {ok, CHBin, State} = nquic_tls_client:make_client_hello(Params, [<<"h3">>], undefined),
    {ServerPub, _} = crypto:generate_key(ecdh, x25519),
    KeyShareData = <<16#001d:16, 32:16, ServerPub/binary>>,
    KeyShareExt = <<16#0033:16, (byte_size(KeyShareData)):16, KeyShareData/binary>>,
    UnknownCipher = <<255, 255>>,
    SHBin = build_server_hello(UnknownCipher, KeyShareExt),
    ?assertMatch(
        {error, _},
        nquic_tls_client:process_server_hello(SHBin, CHBin, State)
    ).

build_server_hello(CipherSuite, ExtData) ->
    LegacyVer = <<3, 3>>,
    Random = crypto:strong_rand_bytes(32),
    SessionID = <<0>>,
    CompMethod = 0,
    ExtLen = byte_size(ExtData),
    Body =
        <<LegacyVer/binary, Random/binary, SessionID/binary, CipherSuite/binary, CompMethod:8,
            ExtLen:16, ExtData/binary>>,
    <<2:8, (byte_size(Body)):24, Body/binary>>.
