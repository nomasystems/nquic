-module(nquic_packet).
-moduledoc """
QUIC packet parsing and encoding per RFC 9000 Section 17.

Handles long headers (Initial, Handshake, 0-RTT, Retry), short headers
(1-RTT), and version negotiation packets. Provides the combined
unmask-and-decrypt pipeline for received packets.
""".

-include("nquic_packet.hrl").
-export([encode_header/1, parse_header/1, parse_header/2, unmask_and_decrypt/6]).
-export([encode_version_negotiation/3, is_supported_version/1]).
-export([parse_retry/2]).
-export([bits_to_packet_type/2, packet_type_bits/2]).
-export([supported_versions/0]).
-export([decrypt_unmasked/5, unmask_header/6]).
-export([maybe_extract_key_phase/2]).

-export_type([header/0, space/0]).

-type space() :: initial | handshake | application.
-type header() :: #long_header{} | #short_header{}.

-define(QUIC_V1, 16#00000001).
-define(QUIC_V2, 16#6b3343cf).
-define(SUPPORTED_VERSIONS, [?QUIC_V2, ?QUIC_V1]).

-doc "Map header bits to packet type atom for the given QUIC version.".
-spec bits_to_packet_type(0..3, non_neg_integer()) -> initial | rtt0 | handshake | retry.
bits_to_packet_type(Bits, ?QUIC_V2) ->
    case Bits of
        1 -> initial;
        2 -> rtt0;
        3 -> handshake;
        0 -> retry
    end;
bits_to_packet_type(Bits, _V1) ->
    case Bits of
        0 -> initial;
        1 -> rtt0;
        2 -> handshake;
        3 -> retry
    end.

-spec check_reserved_bits(header(), non_neg_integer()) ->
    ok | {error, protocol_violation}.
check_reserved_bits(#short_header{}, First) when First band 16#18 =:= 0 -> ok;
check_reserved_bits(#long_header{}, First) when First band 16#0C =:= 0 -> ok;
check_reserved_bits(_, _) -> {error, protocol_violation}.

-spec classify_decrypt(binary() | {error, nquic_error:any_reason()}) ->
    {ok, binary()} | {error, nquic_error:any_reason()}.
classify_decrypt({error, Reason}) -> {error, {decrypt_failed, Reason}};
classify_decrypt(<<>>) -> {error, protocol_violation};
classify_decrypt(Plain) -> {ok, Plain}.

-spec decode_all_frames(binary()) -> {ok, [nquic_frame:t()]} | {error, nquic_error:any_reason()}.
decode_all_frames(Bin) ->
    decode_all_frames(Bin, []).

-spec decode_all_frames(binary(), [nquic_frame:t()]) ->
    {ok, [nquic_frame:t()]} | {error, nquic_error:any_reason()}.
decode_all_frames(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_all_frames(Bin, Acc) ->
    case skip_padding(Bin) of
        <<>> ->
            {ok, lists:reverse(Acc)};
        NoPad ->
            case nquic_frame:decode(NoPad) of
                {ok, Frame, Rest} ->
                    decode_all_frames(Rest, [Frame | Acc]);
                {error, Reason} ->
                    {error, Reason}
            end
    end.

-spec decrypt_payload(
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    map(),
    non_neg_integer(),
    binary(),
    binary()
) -> {ok, binary()} | {error, term()}.
decrypt_payload(Cipher, #{key := Key, iv := IV}, PN, AAD, CT) ->
    classify_decrypt(nquic_crypto:decrypt(Cipher, Key, IV, PN, AAD, CT)).

-doc """
Phase 2 of the receive pipeline: AEAD-decrypt and decode frames.
Pair with unmask_header/6.
""".
-spec decrypt_unmasked(
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    map(),
    non_neg_integer(),
    binary(),
    binary()
) ->
    {ok, [nquic_frame:t()]} | {error, term()}.
decrypt_unmasked(Cipher, Keys, PN, AAD, CT) ->
    maybe
        {ok, Plaintext} ?= decrypt_payload(Cipher, Keys, PN, AAD, CT),
        decode_all_frames(Plaintext)
    end.

-doc "Encode a QUIC packet header to binary.".
-spec encode_header(header()) -> binary().
encode_header(#long_header{
    type = Type,
    version = Ver,
    dcid = DCID,
    scid = SCID,
    token = Token,
    payload_len = PayLen,
    packet_number = PN,
    pn_len = PnLenOpt
}) ->
    TypeBits = packet_type_bits(Type, Ver),

    PnLen =
        case PnLenOpt of
            undefined -> 4;
            _ -> PnLenOpt
        end,
    PnLenVal = PnLen - 1,

    TokenBin =
        case Type of
            initial ->
                T =
                    if
                        Token =:= undefined -> <<>>;
                        true -> Token
                    end,
                <<(nquic_varint:encode(byte_size(T)))/binary, T/binary>>;
            _ ->
                <<>>
        end,

    LenField = PayLen + PnLen,
    PnBits = PnLen * 8,

    <<1:1, 1:1, TypeBits:2, 0:2, PnLenVal:2, Ver:32, (byte_size(DCID)):8, DCID/binary,
        (byte_size(SCID)):8, SCID/binary, TokenBin/binary, (nquic_varint:encode(LenField))/binary,
        PN:PnBits>>;
encode_header(#short_header{
    dcid = DCID, packet_number = PN, key_phase = KP, spin = Spin, pn_len = PnLenOpt
}) ->
    PnLen =
        case PnLenOpt of
            undefined -> 4;
            _ -> PnLenOpt
        end,
    PnLenVal = PnLen - 1,
    KPBit =
        case KP of
            true -> 1;
            false -> 0
        end,
    PnBits = PnLen * 8,
    <<0:1, 1:1, Spin:1, 0:2, KPBit:1, PnLenVal:2, DCID/binary, PN:PnBits>>.

-doc "Encode a Version Negotiation packet with DCID/SCID swapped per RFC 9000 Section 17.2.1.".
-spec encode_version_negotiation(nquic:connection_id(), nquic:connection_id(), [non_neg_integer()]) ->
    binary().
encode_version_negotiation(DCID, SCID, SupportedVersions) ->
    FirstByte = 16#80 bor (rand:uniform(128) - 1),
    VersionsBin = <<<<V:32>> || V <- SupportedVersions>>,
    <<FirstByte:8, 0:32, (byte_size(DCID)):8, DCID/binary, (byte_size(SCID)):8, SCID/binary,
        VersionsBin/binary>>.

-doc "Check whether a QUIC version is supported.".
-spec is_supported_version(non_neg_integer()) -> boolean().
is_supported_version(Version) ->
    lists:member(Version, ?SUPPORTED_VERSIONS).

-spec maybe_extract_key_phase(header(), non_neg_integer()) -> header().
maybe_extract_key_phase(#short_header{} = H, First) ->
    SpinBit =
        case First band 16#20 of
            0 -> 0;
            _ -> 1
        end,
    H#short_header{key_phase = (First band 16#04) =/= 0, spin = SpinBit};
maybe_extract_key_phase(H, _) ->
    H.

-doc "Map packet type atom to header bits for the given QUIC version.".
-spec packet_type_bits(atom(), non_neg_integer()) -> 0..3.
packet_type_bits(Type, ?QUIC_V2) ->
    case Type of
        initial -> 1;
        rtt0 -> 2;
        handshake -> 3;
        retry -> 0
    end;
packet_type_bits(Type, _V1) ->
    case Type of
        initial -> 0;
        rtt0 -> 1;
        handshake -> 2;
        retry -> 3
    end.

-doc "Parse a QUIC packet header from binary.".
-spec parse_header(binary()) -> {ok, header(), binary()} | {error, nquic_error:any_reason()}.
parse_header(Bin) ->
    parse_header(Bin, 0).

-doc "Parse a QUIC packet header with a known DCID length for short headers.".
-spec parse_header(binary(), non_neg_integer()) ->
    {ok, header(), binary()} | {error, nquic_error:any_reason()}.
parse_header(
    <<1:1, _:7, 0:32, DCIDLen:8, DCID:DCIDLen/binary, SCIDLen:8, SCID:SCIDLen/binary, Rest/binary>>,
    _
) ->
    Versions = parse_version_list(Rest, []),
    VersionsBin = <<<<V:32>> || V <- Versions>>,
    {ok,
        #long_header{
            type = version_negotiation,
            version = 0,
            dcid = DCID,
            scid = SCID,
            token = VersionsBin
        },
        <<>>};
parse_header(
    <<1:1, 1:1, TypeBits:2, _Protected:4, Version:32, DCIDLen:8, DCID:DCIDLen/binary, SCIDLen:8,
        SCID:SCIDLen/binary, Rest/binary>>,
    _KnownDCIDLen
) ->
    Type = bits_to_packet_type(TypeBits, Version),
    case Type of
        retry ->
            {ok,
                #long_header{
                    type = retry,
                    version = Version,
                    dcid = DCID,
                    scid = SCID,
                    token = Rest
                },
                <<>>};
        _ ->
            maybe
                {ok, Rest1, Token} ?= parse_initial_token(Type, Rest),
                {ok, PayloadLen, Rest2} ?= nquic_varint:decode(Rest1),
                {ok,
                    #long_header{
                        type = Type,
                        version = Version,
                        dcid = DCID,
                        scid = SCID,
                        token = Token,
                        payload_len = PayloadLen
                    },
                    Rest2}
            else
                {error, _} = Err -> Err
            end
    end;
parse_header(<<0:1, 1:1, _Protected:6, Rest/binary>>, DCIDLen) ->
    <<_Spin:1, _Prot:5>> = <<_Protected:6>>,
    case Rest of
        <<DCID:DCIDLen/binary, Rest1/binary>> ->
            {ok, #short_header{dcid = DCID, key_phase = false}, Rest1};
        _ ->
            {error, incomplete_binary}
    end;
parse_header(_, _) ->
    {error, invalid_packet}.

-spec parse_initial_token(atom(), binary()) ->
    {ok, binary(), binary() | undefined} | {error, incomplete_binary}.
parse_initial_token(initial, Rest) ->
    maybe
        {ok, TLen, R} ?= nquic_varint:decode(Rest),
        true ?= byte_size(R) >= TLen orelse {error, incomplete_binary},
        <<Token:TLen/binary, R1/binary>> = R,
        {ok, R1, Token}
    else
        {error, _} = Err -> Err
    end;
parse_initial_token(_, Rest) ->
    {ok, Rest, undefined}.

-doc """
Parse a Retry packet's token payload into {RetryToken, IntegrityTag}.
The raw token field from parse_header contains both the retry token
and the 16-byte integrity tag appended at the end.
""".
-spec parse_retry(binary(), binary()) ->
    {ok, binary(), nquic:connection_id(), binary()} | {error, term()}.
parse_retry(RawToken, FullPacket) when byte_size(RawToken) > 16 ->
    TokenLen = byte_size(RawToken) - 16,
    <<RetryToken:TokenLen/binary, IntegrityTag:16/binary>> = RawToken,
    PacketNoTag = binary:part(FullPacket, 0, byte_size(FullPacket) - 16),
    {ok, RetryToken, PacketNoTag, IntegrityTag};
parse_retry(_, _) ->
    {error, retry_token_too_short}.

-spec parse_version_list(binary(), [non_neg_integer()]) -> [non_neg_integer()].
parse_version_list(<<V:32, Rest/binary>>, Acc) ->
    parse_version_list(Rest, [V | Acc]);
parse_version_list(_, Acc) ->
    lists:reverse(Acc).

-spec set_packet_number(header(), non_neg_integer(), 1..4) -> header().
set_packet_number(#long_header{} = H, PN, PnLen) ->
    H#long_header{packet_number = PN, pn_len = PnLen};
set_packet_number(#short_header{} = H, PN, PnLen) ->
    H#short_header{packet_number = PN, pn_len = PnLen}.

-spec skip_padding(binary()) -> binary().
skip_padding(<<0:64, Rest/binary>>) ->
    skip_padding(Rest);
skip_padding(<<0, Rest/binary>>) ->
    skip_padding(Rest);
skip_padding(Bin) ->
    Bin.

-doc "Return the list of supported QUIC versions (preferred first).".
-spec supported_versions() -> [non_neg_integer()].
supported_versions() ->
    ?SUPPORTED_VERSIONS.

-doc "Remove header protection and decrypt a QUIC packet in one pass.".
-spec unmask_and_decrypt(
    binary(),
    binary(),
    header(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    map(),
    non_neg_integer()
) ->
    {ok, header(), [nquic_frame:t()]} | {error, term()}.
unmask_and_decrypt(Packet, Rest, Header, Cipher, Keys, LargestRecv) ->
    maybe
        {ok, Header1, PN, AAD, CT} ?=
            unmask_header(Packet, Rest, Header, Cipher, Keys, LargestRecv),
        {ok, Frames} ?= decrypt_unmasked(Cipher, Keys, PN, AAD, CT),
        {ok, Header1, Frames}
    end.

-doc """
Phase 1 of the receive pipeline: strip header protection and recover
the full packet number, returning the unmasked header alongside the
recovered packet number, AAD, and ciphertext+tag. The caller is
responsible for choosing AEAD keys (e.g. based on the unmasked
short-header key_phase) and then calling decrypt_unmasked/5 to finish
the AEAD step.
""".
-spec unmask_header(
    binary(),
    binary(),
    header(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    map(),
    non_neg_integer()
) ->
    {ok, header(), non_neg_integer(), binary(), binary()} | {error, term()}.
unmask_header(Packet, Rest, Header, Cipher, Keys, LargestRecv) ->
    PnOffset = byte_size(Packet) - byte_size(Rest),
    SampleOffset = PnOffset + 4,
    case Packet of
        <<_:SampleOffset/binary, Sample:16/binary, _/binary>> ->
            Mask = nquic_hp:generate_mask_from_keys(Keys, Cipher, Sample),
            {UnmaskedFirst, PnLen, TruncatedPN, UnmaskedAAD} =
                nquic_hp:unmask_header_mask(Mask, PnOffset, Packet),
            maybe
                ok ?= check_reserved_bits(Header, UnmaskedFirst),
                Header1 = maybe_extract_key_phase(Header, UnmaskedFirst),
                PacketNumber = nquic_packet_number:decode(LargestRecv, TruncatedPN, PnLen),
                HeaderLen = PnOffset + PnLen,
                <<_:HeaderLen/binary, CiphertextAndTag/binary>> = Packet,
                {ok, set_packet_number(Header1, PacketNumber, PnLen), PacketNumber, UnmaskedAAD,
                    CiphertextAndTag}
            end;
        _ ->
            {error, packet_too_short}
    end.
