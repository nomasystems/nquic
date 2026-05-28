%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_keys}.
%%%-------------------------------------------------------------------
-module(nquic_keys_tests).

-include_lib("eunit/include/eunit.hrl").

initial_secrets_test() ->
    DestCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#51, 16#0b>>,
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DestCID),
    ?assertEqual(32, byte_size(ClientSecret)),
    ?assertEqual(32, byte_size(ServerSecret)).

update_traffic_secret_aes128_test() ->
    DestCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ClientSecret, _} = nquic_keys:initial_secrets(DestCID),
    {NewSecret, Key, IV} = nquic_keys:update_traffic_secret(ClientSecret, aes_128_gcm, 1),
    ?assertEqual(32, byte_size(NewSecret)),
    ?assertEqual(16, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertNotEqual(ClientSecret, NewSecret).

update_traffic_secret_deterministic_test() ->
    Secret = crypto:strong_rand_bytes(32),
    {S1, K1, IV1} = nquic_keys:update_traffic_secret(Secret, aes_128_gcm, 1),
    {S2, K2, IV2} = nquic_keys:update_traffic_secret(Secret, aes_128_gcm, 1),
    ?assertEqual(S1, S2),
    ?assertEqual(K1, K2),
    ?assertEqual(IV1, IV2).

qhkdf_expand_hash_param_test() ->
    PRK = crypto:strong_rand_bytes(32),
    R4 = nquic_keys:qhkdf_expand(PRK, <<"test">>, <<>>, 16),
    R5 = nquic_keys:qhkdf_expand(PRK, <<"test">>, <<>>, 16, sha256),
    ?assertEqual(R4, R5).

early_secrets_no_psk_test() ->
    ClientHelloHash = crypto:hash(sha256, <<"fake_client_hello">>),
    Secret = nquic_keys:early_secrets(ClientHelloHash, sha256),
    ?assertEqual(32, byte_size(Secret)).

early_secrets_with_psk_test() ->
    ClientHelloHash = crypto:hash(sha256, <<"fake_client_hello">>),
    PSK = crypto:strong_rand_bytes(32),
    SecretNoPSK = nquic_keys:early_secrets(ClientHelloHash, sha256),
    SecretPSK = nquic_keys:early_secrets(PSK, ClientHelloHash, sha256),
    ?assertEqual(32, byte_size(SecretPSK)),
    ?assertNotEqual(SecretNoPSK, SecretPSK).

early_secrets_deterministic_test() ->
    ClientHelloHash = crypto:hash(sha256, <<"same_input">>),
    S1 = nquic_keys:early_secrets(ClientHelloHash, sha256),
    S2 = nquic_keys:early_secrets(ClientHelloHash, sha256),
    ?assertEqual(S1, S2).

handshake_secrets_psk_test() ->
    SharedSecret = crypto:strong_rand_bytes(32),
    TranscriptHash = crypto:hash(sha256, <<"test transcript">>),
    PSK = crypto:strong_rand_bytes(32),
    {C1, S1, HS1} = nquic_keys:handshake_secrets(SharedSecret, TranscriptHash, sha256),
    {C2, S2, HS2} = nquic_keys:handshake_secrets(SharedSecret, TranscriptHash, sha256, PSK),
    ?assertNotEqual(C1, C2),
    ?assertNotEqual(S1, S2),
    ?assertNotEqual(HS1, HS2),
    {C3, S3, HS3} = nquic_keys:handshake_secrets(SharedSecret, TranscriptHash, sha256, undefined),
    ?assertEqual(C1, C3),
    ?assertEqual(S1, S3),
    ?assertEqual(HS1, HS3).

make_role_keys_aes128_test() ->
    Secret = crypto:strong_rand_bytes(32),
    {Key, IV, HP} = nquic_keys:derive_packet_protection(Secret, aes_128_gcm, 1),
    RoleKeys = nquic_keys:make_role_keys(aes_128_gcm, Key, IV, HP),
    ?assertEqual(Key, maps:get(key, RoleKeys)),
    ?assertEqual(IV, maps:get(iv, RoleKeys)),
    ?assertEqual(HP, maps:get(hp, RoleKeys)),
    ?assert(maps:is_key(hp_ctx, RoleKeys)).

make_role_keys_chacha_test() ->
    Secret = crypto:strong_rand_bytes(32),
    {Key, IV, HP} = nquic_keys:derive_packet_protection(Secret, chacha20_poly1305, 1),
    RoleKeys = nquic_keys:make_role_keys(chacha20_poly1305, Key, IV, HP),
    ?assertEqual(Key, maps:get(key, RoleKeys)),
    ?assertNot(maps:is_key(hp_ctx, RoleKeys)).

local_peer_keys_test() ->
    CKeys = #{key => <<"client-k">>, iv => <<"client-i">>, hp => <<"client-h">>},
    SKeys = #{key => <<"server-k">>, iv => <<"server-i">>, hp => <<"server-h">>},
    Roles = #{client => CKeys, server => SKeys},
    ?assertEqual(CKeys, nquic_keys:local_keys(client, Roles)),
    ?assertEqual(SKeys, nquic_keys:local_keys(server, Roles)),
    ?assertEqual(SKeys, nquic_keys:peer_keys(client, Roles)),
    ?assertEqual(CKeys, nquic_keys:peer_keys(server, Roles)).
