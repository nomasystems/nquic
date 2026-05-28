-module(nquic_retry).

-moduledoc """
Server-side Retry packet support per RFC 9000 Section 8.1.2.

Retry allows a server to validate a client's address before allocating
connection state. The server sends a Retry packet containing an opaque
token. The client must resend its Initial with this token. The server
validates the token (HMAC of original DCID, client address, timestamp)
before accepting the connection.
""".

-export([
    compute_integrity_tag/2,
    compute_integrity_tag/3,
    encode_retry_packet/5,
    generate_token/4,
    retry_key/1,
    retry_nonce/1,
    validate_token/4,
    verify_integrity_tag/3,
    verify_integrity_tag/4
]).

-export([encode_addr/1, hmac_equal/2]).

-define(RETRY_KEY_V1,
    <<16#be, 16#0c, 16#69, 16#0b, 16#9f, 16#66, 16#57, 16#5a, 16#1d, 16#76, 16#6b, 16#54, 16#e3,
        16#68, 16#c8, 16#4e>>
).
-define(RETRY_NONCE_V1,
    <<16#46, 16#15, 16#99, 16#d3, 16#5d, 16#63, 16#2b, 16#f2, 16#23, 16#98, 16#25, 16#bb>>
).

-define(RETRY_KEY_V2,
    <<16#8f, 16#b4, 16#b0, 16#1b, 16#56, 16#ac, 16#48, 16#e2, 16#60, 16#fb, 16#cb, 16#ce, 16#ad,
        16#7c, 16#cc, 16#92>>
).
-define(RETRY_NONCE_V2,
    <<16#d8, 16#69, 16#69, 16#bc, 16#2d, 16#7c, 16#6d, 16#99, 16#90, 16#ef, 16#b0, 16#4a>>
).

-doc "Compute the Retry Integrity Tag (v1 default).".
-spec compute_integrity_tag(nquic:connection_id(), binary()) -> binary().
compute_integrity_tag(ODCID, RetryPacketNoTag) ->
    compute_integrity_tag(ODCID, RetryPacketNoTag, 1).

-doc """
Compute the Retry Integrity Tag per RFC 9000/9369.
Version selects the fixed key and nonce (v1 vs v2).
""".
-spec compute_integrity_tag(nquic:connection_id(), binary(), non_neg_integer()) -> binary().
compute_integrity_tag(ODCID, RetryPacketNoTag, Version) ->
    ODCIDLen = byte_size(ODCID),
    AAD = <<ODCIDLen:8, ODCID/binary, RetryPacketNoTag/binary>>,
    {_Ciphertext, Tag} = crypto:crypto_one_time_aead(
        aes_128_gcm, retry_key(Version), retry_nonce(Version), <<>>, AAD, 16, true
    ),
    Tag.

-doc """
Encode a complete Retry packet with integrity tag.
DCID/SCID are from the server's perspective (DCID = client's SCID,
SCID = server's new CID).
""".
-spec encode_retry_packet(
    nquic:connection_id(), nquic:connection_id(), nquic:connection_id(), binary(), non_neg_integer()
) -> binary().
encode_retry_packet(DCID, SCID, ODCID, RetryToken, Version) ->
    TypeBits = nquic_packet:packet_type_bits(retry, Version),
    Unused = rand:uniform(16) - 1,
    FirstByte = (1 bsl 7) bor (1 bsl 6) bor (TypeBits bsl 4) bor Unused,
    PacketNoTag = <<
        FirstByte:8,
        Version:32,
        (byte_size(DCID)):8,
        DCID/binary,
        (byte_size(SCID)):8,
        SCID/binary,
        RetryToken/binary
    >>,
    Tag = compute_integrity_tag(ODCID, PacketNoTag, Version),
    <<PacketNoTag/binary, Tag/binary>>.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec encode_addr(nquic_socket:sockaddr()) -> binary().
encode_addr(#{family := inet, addr := {A, B, C, D}, port := Port}) ->
    <<A, B, C, D, Port:16>>;
encode_addr(#{family := inet6, addr := {A, B, C, D, E, F, G, H}, port := Port}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16, Port:16>>.

-doc """
Generate a Retry token containing the original DCID, client address, and
timestamp. HMAC-SHA256 provides integrity and authentication.
Token format: <<HMAC:32/binary, Timestamp:64, ODCIDLen:8, ODCID/binary, AddrBin/binary>>
""".
-spec generate_token(binary(), nquic:connection_id(), nquic_socket:sockaddr(), non_neg_integer()) ->
    binary().
generate_token(StaticKey, ODCID, PeerAddr, TokenLifetime) ->
    Now = erlang:system_time(second),
    AddrBin = encode_addr(PeerAddr),
    ODCIDLen = byte_size(ODCID),
    Payload = <<Now:64, ODCIDLen:8, ODCID/binary, AddrBin/binary>>,
    HMAC = crypto:mac(hmac, sha256, StaticKey, <<TokenLifetime:32, Payload/binary>>),
    <<HMAC/binary, Payload/binary>>.

-spec hmac_equal(binary(), binary()) -> boolean().
hmac_equal(A, B) ->
    nquic_crypto:constant_time_equal(A, B).

-doc "Return the retry integrity key for a given QUIC version.".
-spec retry_key(non_neg_integer()) -> binary().
retry_key(16#6b3343cf) -> ?RETRY_KEY_V2;
retry_key(_) -> ?RETRY_KEY_V1.

-doc "Return the retry integrity nonce for a given QUIC version.".
-spec retry_nonce(non_neg_integer()) -> binary().
retry_nonce(16#6b3343cf) -> ?RETRY_NONCE_V2;
retry_nonce(_) -> ?RETRY_NONCE_V1.

-doc """
Validate a Retry token. Returns `{ok, ODCID}` if the token is valid
(correct HMAC, not expired, matching client address), or `{error, Reason}`.
""".
-spec validate_token(binary(), binary(), nquic_socket:sockaddr(), non_neg_integer()) ->
    {ok, nquic:connection_id()} | {error, term()}.
validate_token(
    <<HMAC:32/binary, Now0:64, ODCIDLen:8, Rest/binary>>,
    StaticKey,
    PeerAddr,
    TokenLifetime
) ->
    case Rest of
        <<ODCID:ODCIDLen/binary, AddrBin/binary>> ->
            Payload = <<Now0:64, ODCIDLen:8, ODCID/binary, AddrBin/binary>>,
            Expected = crypto:mac(hmac, sha256, StaticKey, <<TokenLifetime:32, Payload/binary>>),
            CurrentTime = erlang:system_time(second),
            Expired = (CurrentTime - Now0) > TokenLifetime,
            AddrMatch = (AddrBin =:= encode_addr(PeerAddr)),
            maybe
                true ?= hmac_equal(HMAC, Expected),
                true ?= not Expired,
                true ?= AddrMatch,
                {ok, ODCID}
            else
                false -> {error, invalid_retry_token}
            end;
        _ ->
            {error, invalid_retry_token}
    end;
validate_token(_, _, _, _) ->
    {error, invalid_retry_token}.

-spec verify_integrity_tag(nquic:connection_id(), binary(), binary()) ->
    ok | {error, integrity_check_failed}.
verify_integrity_tag(ODCID, RetryPacketNoTag, IntegrityTag) ->
    verify_integrity_tag(ODCID, RetryPacketNoTag, IntegrityTag, 1).

-doc """
Verify the Retry Integrity Tag on a received Retry packet.
""".
-spec verify_integrity_tag(nquic:connection_id(), binary(), binary(), non_neg_integer()) ->
    ok | {error, integrity_check_failed}.
verify_integrity_tag(ODCID, RetryPacketNoTag, IntegrityTag, Version) ->
    Expected = compute_integrity_tag(ODCID, RetryPacketNoTag, Version),
    case hmac_equal(IntegrityTag, Expected) of
        true -> ok;
        false -> {error, integrity_check_failed}
    end.
