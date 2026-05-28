%%%-------------------------------------------------------------------
%%% @doc Cryptography Verification Suite (RFC 9001)
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_crypto_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-export([all/0]).
-export([test_initial_secrets_v1/1, test_packet_protection_roundtrip/1]).

all() ->
    [test_initial_secrets_v1, test_packet_protection_roundtrip].

test_initial_secrets_v1(_Config) ->
    DestCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#51, 16#0b>>,
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DestCID),

    ExpectedClientSecret =
        <<16#8b, 16#d0, 16#b0, 16#55, 16#e1, 16#18, 16#04, 16#f3, 16#1b, 16#b9, 16#af, 16#bf, 16#0f,
            16#64, 16#71, 16#ba, 16#d1, 16#a2, 16#a6, 16#46, 16#b1, 16#47, 16#76, 16#0f, 16#72,
            16#f9, 16#d6, 16#b2, 16#56, 16#0a, 16#ca, 16#90>>,

    ExpectedServerSecret =
        <<16#5e, 16#dc, 16#45, 16#72, 16#d1, 16#9e, 16#6e, 16#00, 16#22, 16#8a, 16#7d, 16#8e, 16#d2,
            16#87, 16#fa, 16#59, 16#7f, 16#fb, 16#3a, 16#50, 16#2c, 16#3d, 16#f3, 16#bd, 16#68,
            16#17, 16#ef, 16#d6, 16#f7, 16#87, 16#eb, 16#2d>>,

    ?assertEqual(ExpectedClientSecret, ClientSecret),
    ?assertEqual(ExpectedServerSecret, ServerSecret),

    {ClientKey, ClientIV, ClientHP} = nquic_keys:derive_packet_protection(
        ClientSecret, aes_128_gcm, 1
    ),

    ?assertEqual(16, byte_size(ClientKey)),
    ?assertEqual(12, byte_size(ClientIV)),
    ?assertEqual(16, byte_size(ClientHP)).

test_packet_protection_roundtrip(_Config) ->
    Secret = crypto:strong_rand_bytes(32),
    Cipher = aes_128_gcm,
    {Key, IV, HP} = nquic_keys:derive_packet_protection(Secret, Cipher, 1),

    PN = 12345,

    P0 = 2#11000001,
    Version = <<1, 0, 0, 0>>,
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<8, 7, 6, 5, 4, 3, 2, 1>>,
    LengthField = <<16#40, 16#22>>,

    HeaderMiddle = <<Version/binary, 8, DCID/binary, 8, SCID/binary, 0, LengthField/binary>>,

    PnOffset = 1 + byte_size(HeaderMiddle),

    AAD = <<P0, HeaderMiddle/binary, PN:16>>,

    Payload = <<"Test Payload 16 bytes long">>,

    {Ciphertext, Tag} = nquic_crypto:encrypt(Cipher, Key, IV, PN, AAD, Payload),

    FullPacket = <<P0, HeaderMiddle/binary, PN:16, Ciphertext/binary, Tag/binary>>,

    SampleStart = PnOffset + 4,
    Sample = binary:part(FullPacket, SampleStart, 16),
    ProtectedPacket = nquic_hp:mask(Cipher, HP, Sample, FullPacket, PnOffset),

    SampleRecv = binary:part(ProtectedPacket, SampleStart, 16),
    UnmaskedPacket = nquic_hp:unmask(Cipher, HP, SampleRecv, ProtectedPacket, PnOffset),

    HeaderLen = byte_size(HeaderMiddle),
    <<RecvP0, _:HeaderLen/binary, RecvPN:16, ProtectedPayload/binary>> = UnmaskedPacket,

    ?assertEqual(P0, RecvP0),
    ?assertEqual(PN, RecvPN),

    DecryptedPayload = nquic_crypto:decrypt(Cipher, Key, IV, RecvPN, AAD, ProtectedPayload),
    ?assertEqual(Payload, DecryptedPayload).
