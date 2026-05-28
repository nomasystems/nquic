%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_hp}.
%%%-------------------------------------------------------------------
-module(nquic_hp_tests).

-include_lib("eunit/include/eunit.hrl").

generate_mask_aes_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Sample = crypto:strong_rand_bytes(16),
    Mask = nquic_hp:generate_mask(aes_128_gcm, HPKey, Sample),
    ?assertEqual(5, byte_size(Mask)).

generate_mask_aes256_test() ->
    HPKey = crypto:strong_rand_bytes(32),
    Sample = crypto:strong_rand_bytes(16),
    Mask = nquic_hp:generate_mask(aes_256_gcm, HPKey, Sample),
    ?assertEqual(5, byte_size(Mask)).

generate_mask_chacha_test() ->
    HPKey = crypto:strong_rand_bytes(32),
    Sample = crypto:strong_rand_bytes(16),
    Mask = nquic_hp:generate_mask(chacha20_poly1305, HPKey, Sample),
    ?assertEqual(5, byte_size(Mask)).

mask_unmask_roundtrip_chacha_test() ->
    HPKey = crypto:strong_rand_bytes(32),
    Packet =
        <<16#40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Masked = nquic_hp:mask(chacha20_poly1305, HPKey, Sample, Packet, PnOffset),
    Unmasked = nquic_hp:unmask(chacha20_poly1305, HPKey, Sample, Masked, PnOffset),
    ?assertEqual(Packet, Unmasked).

mask_unmask_roundtrip_long_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Packet =
        <<16#C0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Masked = nquic_hp:mask(aes_128_gcm, HPKey, Sample, Packet, PnOffset),
    Unmasked = nquic_hp:unmask(aes_128_gcm, HPKey, Sample, Masked, PnOffset),
    ?assertEqual(Packet, Unmasked).

mask_unmask_roundtrip_short_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Packet =
        <<16#40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Masked = nquic_hp:mask(aes_128_gcm, HPKey, Sample, Packet, PnOffset),
    Unmasked = nquic_hp:unmask(aes_128_gcm, HPKey, Sample, Masked, PnOffset),
    ?assertEqual(Packet, Unmasked).

mask_header_short_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Packet =
        <<16#40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    PnLen = (16#40 band 16#03) + 1,
    HeaderBin = binary:part(Packet, 0, PnOffset + PnLen),
    Ciphertext = binary:part(Packet, PnOffset + PnLen, byte_size(Packet) - PnOffset - PnLen),
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Mask = nquic_hp:generate_mask(aes_128_gcm, HPKey, Sample),
    {MaskedHeader, RetPnLen} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, false),
    ?assertEqual(PnLen, RetPnLen),
    FullMasked = nquic_hp:mask(aes_128_gcm, HPKey, Sample, Packet, PnOffset),
    ExpectedHeader = binary:part(FullMasked, 0, byte_size(MaskedHeader)),
    ?assertEqual(ExpectedHeader, MaskedHeader),
    ExpectedCiphertext = binary:part(FullMasked, byte_size(MaskedHeader), byte_size(Ciphertext)),
    ?assertEqual(ExpectedCiphertext, Ciphertext).

mask_header_long_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Packet =
        <<16#C0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    PnLen = (16#C0 band 16#03) + 1,
    HeaderBin = binary:part(Packet, 0, PnOffset + PnLen),
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Mask = nquic_hp:generate_mask(aes_128_gcm, HPKey, Sample),
    {MaskedHeader, RetPnLen} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, true),
    ?assertEqual(PnLen, RetPnLen),
    FullMasked = nquic_hp:mask(aes_128_gcm, HPKey, Sample, Packet, PnOffset),
    ExpectedHeader = binary:part(FullMasked, 0, byte_size(MaskedHeader)),
    ?assertEqual(ExpectedHeader, MaskedHeader).

unmask_header_short_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Packet =
        <<16#40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Masked = nquic_hp:mask(aes_128_gcm, HPKey, Sample, Packet, PnOffset),
    FullUnmasked = nquic_hp:unmask(aes_128_gcm, HPKey, Sample, Masked, PnOffset),
    {UnmaskedFirst, PnLen, TruncatedPN, UnmaskedHeader} =
        nquic_hp:unmask_header(aes_128_gcm, HPKey, Sample, PnOffset, Masked),
    <<ExpFirst:8, _/binary>> = FullUnmasked,
    ?assertEqual(ExpFirst, UnmaskedFirst),
    HeaderLen = PnOffset + PnLen,
    ExpHeader = binary:part(FullUnmasked, 0, HeaderLen),
    ?assertEqual(ExpHeader, UnmaskedHeader),
    PnBits = PnLen * 8,
    <<_:PnOffset/binary, ExpPN:PnBits>> = UnmaskedHeader,
    ?assertEqual(ExpPN, TruncatedPN).

unmask_header_long_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Packet =
        <<16#C0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Masked = nquic_hp:mask(aes_128_gcm, HPKey, Sample, Packet, PnOffset),
    FullUnmasked = nquic_hp:unmask(aes_128_gcm, HPKey, Sample, Masked, PnOffset),
    {UnmaskedFirst, PnLen, TruncatedPN, UnmaskedHeader} =
        nquic_hp:unmask_header(aes_128_gcm, HPKey, Sample, PnOffset, Masked),
    <<ExpFirst:8, _/binary>> = FullUnmasked,
    ?assertEqual(ExpFirst, UnmaskedFirst),
    HeaderLen = PnOffset + PnLen,
    ExpHeader = binary:part(FullUnmasked, 0, HeaderLen),
    ?assertEqual(ExpHeader, UnmaskedHeader),
    PnBits = PnLen * 8,
    <<_:PnOffset/binary, ExpPN:PnBits>> = UnmaskedHeader,
    ?assertEqual(ExpPN, TruncatedPN).

generate_mask_ctx_aes128_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Sample = crypto:strong_rand_bytes(16),
    Ctx = nquic_hp:init_hp_ctx(aes_128_gcm, HPKey),
    MaskOneShot = nquic_hp:generate_mask(aes_128_gcm, HPKey, Sample),
    MaskCached = nquic_hp:generate_mask_ctx(Ctx, Sample),
    ?assertEqual(MaskOneShot, MaskCached).

generate_mask_ctx_aes256_test() ->
    HPKey = crypto:strong_rand_bytes(32),
    Sample = crypto:strong_rand_bytes(16),
    Ctx = nquic_hp:init_hp_ctx(aes_256_gcm, HPKey),
    MaskOneShot = nquic_hp:generate_mask(aes_256_gcm, HPKey, Sample),
    MaskCached = nquic_hp:generate_mask_ctx(Ctx, Sample),
    ?assertEqual(MaskOneShot, MaskCached).

generate_mask_ctx_reuse_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Ctx = nquic_hp:init_hp_ctx(aes_128_gcm, HPKey),
    S1 = crypto:strong_rand_bytes(16),
    S2 = crypto:strong_rand_bytes(16),
    ?assertEqual(
        nquic_hp:generate_mask(aes_128_gcm, HPKey, S1), nquic_hp:generate_mask_ctx(Ctx, S1)
    ),
    ?assertEqual(
        nquic_hp:generate_mask(aes_128_gcm, HPKey, S2), nquic_hp:generate_mask_ctx(Ctx, S2)
    ).

unmask_header_mask_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Packet =
        <<16#40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Masked = nquic_hp:mask(aes_128_gcm, HPKey, Sample, Packet, PnOffset),
    Result1 = nquic_hp:unmask_header(aes_128_gcm, HPKey, Sample, PnOffset, Masked),
    Mask = nquic_hp:generate_mask(aes_128_gcm, HPKey, Sample),
    Result2 = nquic_hp:unmask_header_mask(Mask, PnOffset, Masked),
    ?assertEqual(Result1, Result2).

unmask_header_mask_ctx_test() ->
    HPKey = crypto:strong_rand_bytes(16),
    Packet =
        <<16#C0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30>>,
    PnOffset = 5,
    Sample = binary:part(Packet, PnOffset + 4, 16),
    Masked = nquic_hp:mask(aes_128_gcm, HPKey, Sample, Packet, PnOffset),
    Ctx = nquic_hp:init_hp_ctx(aes_128_gcm, HPKey),
    CachedMask = nquic_hp:generate_mask_ctx(Ctx, Sample),
    ResultCached = nquic_hp:unmask_header_mask(CachedMask, PnOffset, Masked),
    ResultOneShot = nquic_hp:unmask_header(aes_128_gcm, HPKey, Sample, PnOffset, Masked),
    ?assertEqual(ResultOneShot, ResultCached).
