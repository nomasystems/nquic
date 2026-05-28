-module(nquic_hp).

-moduledoc """
QUIC header protection per RFC 9001 Section 5.4.

Masks and unmasks the first byte and packet number bytes of QUIC packets.
Supports AES-128-ECB, AES-256-ECB, and ChaCha20 mask generation.
The 5-byte mask protects 1 byte of flags and up to 4 bytes of packet number.
""".

-export([generate_mask/3, mask/5, mask_header/4, unmask/5, unmask_header/5]).
-export([generate_mask_ctx/2, generate_mask_from_keys/3, init_hp_ctx/2, unmask_header_mask/3]).

-spec apply_mask(<<_:40>>, binary(), non_neg_integer()) -> binary().
apply_mask(<<HP0:8, HP1_4:4/binary>>, Packet, PnOffset) ->
    <<P0:8, _/binary>> = Packet,
    IsLong = (P0 band 16#80) /= 0,
    BitMask =
        if
            IsLong -> 16#0F;
            true -> 16#1F
        end,
    NewP0 = P0 bxor (HP0 band BitMask),
    PnLen = (P0 band 16#03) + 1,
    MiddleLen = PnOffset - 1,
    <<_:1/binary, Middle:MiddleLen/binary, Pn:PnLen/binary, Payload/binary>> = Packet,
    NewPn = xor_pn(Pn, HP1_4),
    <<NewP0, Middle/binary, NewPn/binary, Payload/binary>>.

-spec apply_unmask(<<_:40>>, binary(), non_neg_integer()) -> binary().
apply_unmask(<<HP0:8, HP1_4:4/binary>>, Packet, PnOffset) ->
    <<P0:8, _/binary>> = Packet,
    IsLong = (P0 band 16#80) /= 0,
    BitMask =
        if
            IsLong -> 16#0F;
            true -> 16#1F
        end,
    UnmaskedP0 = P0 bxor (HP0 band BitMask),
    PnLen = (UnmaskedP0 band 16#03) + 1,
    MiddleLen = PnOffset - 1,
    <<_:1/binary, Middle:MiddleLen/binary, Pn:PnLen/binary, Payload/binary>> = Packet,
    UnmaskedPn = xor_pn(Pn, HP1_4),
    <<UnmaskedP0, Middle/binary, UnmaskedPn/binary, Payload/binary>>.

-doc "Generate the 5-byte HP mask from the cipher, HP key, and 16-byte sample.".
-spec generate_mask(
    aes_128_gcm | aes_256_gcm | chacha20_poly1305, binary(), binary()
) ->
    binary().
generate_mask(aes_128_gcm, HPKey, Sample) ->
    Ciphertext = crypto:crypto_one_time(aes_128_ecb, HPKey, Sample, true),
    <<Mask:5/binary, _/binary>> = Ciphertext,
    Mask;
generate_mask(aes_256_gcm, HPKey, Sample) ->
    Ciphertext = crypto:crypto_one_time(aes_256_ecb, HPKey, Sample, true),
    <<Mask:5/binary, _/binary>> = Ciphertext,
    Mask;
generate_mask(chacha20_poly1305, HPKey, Sample) ->
    Ciphertext = crypto:crypto_one_time(chacha20, HPKey, Sample, <<0, 0, 0, 0, 0>>, true),
    <<Mask:5/binary, _/binary>> = Ciphertext,
    Mask.

-doc "Generate the 5-byte HP mask using a cached cipher context.".
-spec generate_mask_ctx(crypto:crypto_state(), binary()) -> binary().
generate_mask_ctx(HpCtx, Sample) ->
    <<Mask:5/binary, _/binary>> = crypto:crypto_update(HpCtx, Sample),
    Mask.

-doc """
Generate the 5-byte HP mask from a role key map.
Uses cached cipher context (`hp_ctx`) when present, falls back to one-shot.
""".
-spec generate_mask_from_keys(
    #{hp := term(), hp_ctx => crypto:crypto_state(), atom() => term()},
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    binary()
) -> binary().
generate_mask_from_keys(#{hp_ctx := HpCtx}, _Cipher, Sample) ->
    generate_mask_ctx(HpCtx, Sample);
generate_mask_from_keys(#{hp := HP}, Cipher, Sample) ->
    generate_mask(Cipher, HP, Sample).

-doc """
Create a cached AES-ECB cipher context for header protection.
Avoids per-packet EVP_CIPHER_CTX alloc/destroy (~200-400ns savings per packet).
Only works for AES ciphers; ChaCha20 uses a different IV per packet.
""".
-spec init_hp_ctx(aes_128_gcm | aes_256_gcm, binary()) -> crypto:crypto_state().
init_hp_ctx(aes_128_gcm, HPKey) ->
    crypto:crypto_init(aes_128_ecb, HPKey, true);
init_hp_ctx(aes_256_gcm, HPKey) ->
    crypto:crypto_init(aes_256_ecb, HPKey, true).

-doc "Apply header protection to a packet.".
-spec mask(
    aes_128_gcm | aes_256_gcm | chacha20_poly1305, binary(), binary(), binary(), non_neg_integer()
) ->
    binary().
mask(Cipher, HPKey, Sample, Packet, PnOffset) ->
    Mask = generate_mask(Cipher, HPKey, Sample),
    apply_mask(Mask, Packet, PnOffset).

-doc """
Apply header protection to just the header bytes (send path optimization).
Returns `{MaskedHeader, PnLen}`. The caller assembles
`[MaskedHeader, Ciphertext, Tag]` as an iolist, avoiding a full packet copy.
Inlines the PN XOR per PnLen so the masked header is built in a single
binary allocation (no `xor_pn` intermediate). Mirrors `unmask_header_mask/3`.
""".
-spec mask_header(binary(), binary(), non_neg_integer(), boolean()) ->
    {binary(), 1..4}.
mask_header(<<HP0:8, M1:8, M2:8, M3:8, M4:8>>, HeaderBin, PnOffset, IsLong) ->
    <<P0:8, _/binary>> = HeaderBin,
    BitMask =
        case IsLong of
            true -> 16#0F;
            false -> 16#1F
        end,
    NewP0 = P0 bxor (HP0 band BitMask),
    PnLen = (P0 band 16#03) + 1,
    MiddleLen = PnOffset - 1,
    case PnLen of
        1 ->
            <<_:1/binary, Middle:MiddleLen/binary, P:8>> = HeaderBin,
            U = P bxor M1,
            {<<NewP0:8, Middle/binary, U:8>>, 1};
        2 ->
            <<_:1/binary, Middle:MiddleLen/binary, P:16>> = HeaderBin,
            U = P bxor ((M1 bsl 8) bor M2),
            {<<NewP0:8, Middle/binary, U:16>>, 2};
        3 ->
            <<_:1/binary, Middle:MiddleLen/binary, P:24>> = HeaderBin,
            U = P bxor ((M1 bsl 16) bor (M2 bsl 8) bor M3),
            {<<NewP0:8, Middle/binary, U:24>>, 3};
        4 ->
            <<_:1/binary, Middle:MiddleLen/binary, P:32>> = HeaderBin,
            U = P bxor ((M1 bsl 24) bor (M2 bsl 16) bor (M3 bsl 8) bor M4),
            {<<NewP0:8, Middle/binary, U:32>>, 4}
    end.

-doc "Remove header protection from a packet.".
-spec unmask(
    aes_128_gcm | aes_256_gcm | chacha20_poly1305, binary(), binary(), binary(), non_neg_integer()
) ->
    binary().
unmask(Cipher, HPKey, Sample, Packet, PnOffset) ->
    Mask = generate_mask(Cipher, HPKey, Sample),
    apply_unmask(Mask, Packet, PnOffset).

-doc """
Unmask just the header of a protected packet (recv path optimization).
Returns `{UnmaskedFirstByte, PnLen, TruncatedPN, UnmaskedHeader}`
without rebuilding the full packet. CiphertextAndTag can be extracted
as a zero-copy sub-binary of the original packet.
""".
-spec unmask_header(
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    binary(),
    binary(),
    non_neg_integer(),
    binary()
) ->
    {non_neg_integer(), 1..4, non_neg_integer(), binary()}.
unmask_header(Cipher, HPKey, Sample, PnOffset, Packet) ->
    Mask = generate_mask(Cipher, HPKey, Sample),
    unmask_header_mask(Mask, PnOffset, Packet).

-doc """
Unmask header using a pre-computed 5-byte mask (recv path optimization).
Callers generate the mask via `generate_mask_ctx/2` or `generate_mask/3`,
then pass it here. Avoids coupling mask generation to header unmasking.
Returns `{UnmaskedFirstByte, PnLen, TruncatedPN, UnmaskedHeader}`.
The truncated packet number is also returned as an integer so the
recv path can hand it to `nquic_packet_number:decode/3` without a
second binary slice.
""".
-spec unmask_header_mask(binary(), non_neg_integer(), binary()) ->
    {non_neg_integer(), 1..4, non_neg_integer(), binary()}.
unmask_header_mask(<<HP0:8, M1:8, M2:8, M3:8, M4:8>>, PnOffset, Packet) ->
    <<P0:8, _/binary>> = Packet,
    BitMask =
        case P0 band 16#80 of
            0 -> 16#1F;
            _ -> 16#0F
        end,
    UnmaskedP0 = P0 bxor (HP0 band BitMask),
    PnLen = (UnmaskedP0 band 16#03) + 1,
    MiddleLen = PnOffset - 1,
    case PnLen of
        1 ->
            <<_:1/binary, Middle:MiddleLen/binary, P:8, _/binary>> = Packet,
            U = P bxor M1,
            {UnmaskedP0, 1, U, <<UnmaskedP0:8, Middle/binary, U:8>>};
        2 ->
            <<_:1/binary, Middle:MiddleLen/binary, P:16, _/binary>> = Packet,
            U = P bxor ((M1 bsl 8) bor M2),
            {UnmaskedP0, 2, U, <<UnmaskedP0:8, Middle/binary, U:16>>};
        3 ->
            <<_:1/binary, Middle:MiddleLen/binary, P:24, _/binary>> = Packet,
            U = P bxor ((M1 bsl 16) bor (M2 bsl 8) bor M3),
            {UnmaskedP0, 3, U, <<UnmaskedP0:8, Middle/binary, U:24>>};
        4 ->
            <<_:1/binary, Middle:MiddleLen/binary, P:32, _/binary>> = Packet,
            U = P bxor ((M1 bsl 24) bor (M2 bsl 16) bor (M3 bsl 8) bor M4),
            {UnmaskedP0, 4, U, <<UnmaskedP0:8, Middle/binary, U:32>>}
    end.

-spec xor_pn(binary(), binary()) -> binary().
xor_pn(<<P:8>>, <<M:8, _:3/binary>>) -> <<(P bxor M):8>>;
xor_pn(<<P:16>>, <<M:16, _:2/binary>>) -> <<(P bxor M):16>>;
xor_pn(<<P:24>>, <<M:24, _:1/binary>>) -> <<(P bxor M):24>>;
xor_pn(<<P:32>>, <<M:32>>) -> <<(P bxor M):32>>.
