-module(nquic_tls).
-moduledoc """
Shared TLS 1.3 codec for QUIC per RFC 9001.

Holds the wire-format parse/encode helpers used by both
`nquic_tls_client` and `nquic_tls_server`, plus the PSK and
NewSessionTicket helpers that straddle the two roles. Role-specific
flows (ClientHello / ServerHello construction, handshake-flight
generation, Finished verification, certificate-chain validation) live
in the role modules.
""".

-export([
    decode_cipher_suite/1,
    encode_cipher_suite/1,
    find_quic_params/2,
    hash_length/1,
    parse_extensions_recursive/1,
    parse_vec16/1,
    parse_vec8/1
]).
-export([decode_new_session_ticket/1, encode_new_session_ticket/1]).
-export([derive_resumption_secret/4]).
-export([has_psk_dhe_ke_mode/1, parse_psk_extension/1]).
-export([compute_psk_binder/4, extract_partial_client_hello/2, verify_psk_binder/5]).
-export([decrypt_ticket/2]).

%%%-----------------------------------------------------------------------------
%% WIRE-FORMAT CODEC
%%%-----------------------------------------------------------------------------
-spec decode_cipher_suite(binary()) ->
    {ok, aes_128_gcm | aes_256_gcm | chacha20_poly1305}
    | {error, {unsupported_cipher_suite, binary()}}.
decode_cipher_suite(<<19, 1>>) -> {ok, aes_128_gcm};
decode_cipher_suite(<<19, 2>>) -> {ok, aes_256_gcm};
decode_cipher_suite(<<19, 3>>) -> {ok, chacha20_poly1305};
decode_cipher_suite(Other) -> {error, {unsupported_cipher_suite, Other}}.

-spec encode_cipher_suite(aes_128_gcm | aes_256_gcm | chacha20_poly1305) -> binary().
encode_cipher_suite(aes_128_gcm) -> <<19, 1>>;
encode_cipher_suite(aes_256_gcm) -> <<19, 2>>;
encode_cipher_suite(chacha20_poly1305) -> <<19, 3>>.

-spec find_quic_params(#{non_neg_integer() => binary()}, client | server) ->
    {ok, nquic_transport:params()} | {error, term()}.
find_quic_params(ExtMap, SenderRole) ->
    case maps:get(57, ExtMap, undefined) of
        undefined ->
            {error, {tls_alert, missing_extension}};
        Bin ->
            nquic_transport:decode(Bin, SenderRole)
    end.

-spec hash_length(sha256 | sha384) -> pos_integer().
hash_length(sha256) -> 32;
hash_length(sha384) -> 48.

-spec parse_extensions_recursive(binary()) -> #{non_neg_integer() => binary()}.
parse_extensions_recursive(<<>>) ->
    #{};
parse_extensions_recursive(<<Type:16, Len:16, Val:Len/binary, Rest/binary>>) ->
    Exts = parse_extensions_recursive(Rest),
    Exts#{Type => Val}.

-spec parse_vec16(binary()) -> {binary(), binary()}.
parse_vec16(<<Len:16, Data:Len/binary, Rest/binary>>) -> {Data, Rest}.

-spec parse_vec8(binary()) -> {binary(), binary()}.
parse_vec8(<<Len:8, Data:Len/binary, Rest/binary>>) -> {Data, Rest}.

%%%-----------------------------------------------------------------------------
%% SERVER PSK TICKET VALIDATION
%%%-----------------------------------------------------------------------------
-doc """
Decrypt a ticket value using the server's static key.
Returns {ok, PSK, Cipher} on success, {error, Reason} on failure.
""".
-spec decrypt_ticket(binary(), binary()) ->
    {ok, binary(), atom()} | {error, term()}.
decrypt_ticket(TicketValue, StaticKey) ->
    try
        case byte_size(TicketValue) of
            Sz when Sz < 28 ->
                {error, ticket_too_short};
            _ ->
                <<IV:12/binary, Tag:16/binary, Ct/binary>> = TicketValue,
                case
                    crypto:crypto_one_time_aead(
                        aes_256_gcm, StaticKey, IV, Ct, <<>>, Tag, false
                    )
                of
                    error ->
                        {error, ticket_decrypt_failed};
                    Plain ->
                        parse_ticket_plain(Plain)
                end
        end
    catch
        error:_ -> {error, ticket_decrypt_failed}
    end.

-spec parse_cipher_atom(binary()) -> {ok, atom()} | error.
parse_cipher_atom(<<"aes_128_gcm">>) -> {ok, aes_128_gcm};
parse_cipher_atom(<<"aes_256_gcm">>) -> {ok, aes_256_gcm};
parse_cipher_atom(<<"chacha20_poly1305">>) -> {ok, chacha20_poly1305};
parse_cipher_atom(_) -> error.

-spec parse_ticket_plain(binary()) ->
    {ok, binary(), atom()} | {error, invalid_ticket_cipher | invalid_ticket_format}.
parse_ticket_plain(Plain) ->
    case Plain of
        <<PSK:48/binary, CipherBin/binary>> ->
            case parse_cipher_atom(CipherBin) of
                {ok, Cipher} -> {ok, PSK, Cipher};
                error -> try_32byte_psk(Plain)
            end;
        <<PSK:32/binary, CipherBin/binary>> ->
            case parse_cipher_atom(CipherBin) of
                {ok, Cipher} -> {ok, PSK, Cipher};
                error -> {error, invalid_ticket_cipher}
            end;
        _ ->
            {error, invalid_ticket_format}
    end.

-spec try_32byte_psk(binary()) ->
    {ok, binary(), atom()} | {error, invalid_ticket_cipher | invalid_ticket_format}.
try_32byte_psk(<<PSK:32/binary, CipherBin/binary>>) ->
    case parse_cipher_atom(CipherBin) of
        {ok, Cipher} -> {ok, PSK, Cipher};
        error -> {error, invalid_ticket_cipher}
    end;
try_32byte_psk(_) ->
    {error, invalid_ticket_format}.

%%%-----------------------------------------------------------------------------
%% PSK EXTENSION PARSING (RFC 8446 S4 2 11)
%%%-----------------------------------------------------------------------------
-spec compute_psk_binder(binary(), binary(), sha256 | sha384, pos_integer()) ->
    binary().
compute_psk_binder(PSK, PartialCH, Hash, HashLen) ->
    Zero = <<0:(HashLen * 8)>>,
    EarlySecret = hkdf_extract(Hash, Zero, PSK),
    EmptyHash = crypto:hash(Hash, <<>>),
    BinderKey = nquic_keys:qhkdf_expand(
        EarlySecret, <<"res binder">>, EmptyHash, HashLen, Hash
    ),
    FinishedKey = nquic_keys:qhkdf_expand(
        BinderKey, <<"finished">>, <<>>, HashLen, Hash
    ),
    TranscriptHash = crypto:hash(Hash, PartialCH),
    crypto:mac(hmac, Hash, FinishedKey, TranscriptHash).

-doc """
Extract the partial ClientHello for binder verification.
The partial CH is the full ClientHello minus the binders list at the end.
BindersLen is the length of the binders field (including the 2-byte length prefix).
""".
-spec extract_partial_client_hello(binary(), non_neg_integer()) -> binary().
extract_partial_client_hello(CHBin, BindersLen) ->
    Offset = byte_size(CHBin) - BindersLen,
    binary:part(CHBin, 0, Offset).

-doc """
Check if the psk_key_exchange_modes extension includes psk_dhe_ke (mode 1).
Returns true if present, false otherwise.
""".
-spec has_psk_dhe_ke_mode(map()) -> boolean().
has_psk_dhe_ke_mode(ExtMap) ->
    case maps:get(45, ExtMap, undefined) of
        undefined ->
            false;
        <<ModesLen:8, Modes:ModesLen/binary>> ->
            lists:member(1, binary_to_list(Modes));
        _ ->
            false
    end.

-spec hkdf_extract(sha256 | sha384, binary(), binary()) -> binary().
hkdf_extract(Hash, Salt, IKM) ->
    crypto:mac(hmac, Hash, Salt, IKM).

-spec parse_psk_binders(binary()) -> [binary()].
parse_psk_binders(<<>>) ->
    [];
parse_psk_binders(<<Len:8, Binder:Len/binary, Rest/binary>>) ->
    [Binder | parse_psk_binders(Rest)].

-spec parse_psk_ext_body(binary()) ->
    {ok, [{binary(), non_neg_integer()}], [binary()]}.
parse_psk_ext_body(Bin) ->
    <<IdentitiesLen:16, IdentitiesBin:IdentitiesLen/binary, Rest/binary>> = Bin,
    Identities = parse_psk_identities(IdentitiesBin),
    <<BindersLen:16, BindersBin:BindersLen/binary>> = Rest,
    Binders = parse_psk_binders(BindersBin),
    {ok, Identities, Binders}.

-doc """
Parse a pre_shared_key extension from a ClientHello extension map.
Returns {ok, Identities, Binders} or undefined if not present.
Identities: [{Identity, ObfuscatedAge}], Binders: [binary()].
""".
-spec parse_psk_extension(map()) ->
    {ok, [{binary(), non_neg_integer()}], [binary()]} | undefined.
parse_psk_extension(ExtMap) ->
    case maps:get(41, ExtMap, undefined) of
        undefined ->
            undefined;
        Bin ->
            parse_psk_ext_body(Bin)
    end.

-spec parse_psk_identities(binary()) -> [{binary(), non_neg_integer()}].
parse_psk_identities(<<>>) ->
    [];
parse_psk_identities(<<Len:16, Identity:Len/binary, Age:32, Rest/binary>>) ->
    [{Identity, Age} | parse_psk_identities(Rest)].

-doc """
Verify a PSK binder against the partial ClientHello transcript.
The partial CH is everything in the ClientHello up to (but not including)
the binders list in the pre_shared_key extension.
""".
-spec verify_psk_binder(
    binary(), binary(), binary(), sha256 | sha384, pos_integer()
) -> ok | {error, term()}.
verify_psk_binder(PSK, PartialCH, Binder, Hash, HashLen) ->
    Expected = compute_psk_binder(PSK, PartialCH, Hash, HashLen),
    case Binder =:= Expected of
        true -> ok;
        false -> {error, binder_mismatch}
    end.

%%%-----------------------------------------------------------------------------
%% SESSION RESUMPTION NEWSESSIONTICKET (RFC 8446 S4 6 1)
%%%-----------------------------------------------------------------------------
-doc "Decode a NewSessionTicket TLS message.".
-spec decode_new_session_ticket(binary()) ->
    {ok, map()} | {error, term()}.
decode_new_session_ticket(<<4:8, Len:24, Body:Len/binary>>) ->
    case Body of
        <<Lifetime:32, AgeAdd:32, NonceLen:8, Nonce:NonceLen/binary, TicketLen:16,
            Ticket:TicketLen/binary, ExtData/binary>> ->
            MaxEarlyData = parse_nst_extensions(ExtData),
            {ok, #{
                lifetime => Lifetime,
                age_add => AgeAdd,
                nonce => Nonce,
                ticket => Ticket,
                max_early_data => MaxEarlyData
            }};
        _ ->
            {error, malformed_new_session_ticket}
    end;
decode_new_session_ticket(_) ->
    {error, not_new_session_ticket}.

-doc "Derive the resumption_master_secret after client Finished is verified.".
-spec derive_resumption_secret(
    binary(), crypto:hash_state(), binary(), aes_128_gcm | aes_256_gcm | chacha20_poly1305
) -> binary().
derive_resumption_secret(HandshakeSecret, TranscriptCtx, ClientFinishedBin, Cipher) ->
    Hash = nquic_keys:cipher_to_hash(Cipher),
    HashLen = hash_length(Hash),
    EmptyHash = crypto:hash(Hash, <<>>),
    DerivedSecret = nquic_keys:qhkdf_expand(
        HandshakeSecret, <<"derived">>, EmptyHash, HashLen, Hash
    ),
    MasterSecret = crypto:mac(hmac, Hash, DerivedSecret, <<0:(HashLen * 8)>>),
    Ctx = crypto:hash_update(TranscriptCtx, ClientFinishedBin),
    TranscriptHash = crypto:hash_final(Ctx),
    nquic_keys:qhkdf_expand(MasterSecret, <<"res master">>, TranscriptHash, HashLen, Hash).

-doc """
Encode a NewSessionTicket message (RFC 8446 S4.6.1).
Ticket map keys: lifetime, age_add, nonce, ticket, max_early_data (optional).
""".
-spec encode_new_session_ticket(map()) -> binary().
encode_new_session_ticket(
    #{
        lifetime := Lifetime,
        age_add := AgeAdd,
        nonce := Nonce,
        ticket := Ticket
    } = Params
) ->
    NonceLen = byte_size(Nonce),
    TicketLen = byte_size(Ticket),
    Extensions =
        case maps:get(max_early_data, Params, undefined) of
            undefined ->
                <<0:16>>;
            MaxEarlyData ->
                ExtBody = <<MaxEarlyData:32>>,
                <<8:16, 42:16, 4:16, ExtBody/binary>>
        end,
    Body = <<
        Lifetime:32,
        AgeAdd:32,
        NonceLen:8,
        Nonce/binary,
        TicketLen:16,
        Ticket/binary,
        Extensions/binary
    >>,
    <<4:8, (byte_size(Body)):24, Body/binary>>.

-spec parse_nst_ext_loop(binary()) -> non_neg_integer() | undefined.
parse_nst_ext_loop(<<>>) ->
    undefined;
parse_nst_ext_loop(<<42:16, 4:16, MaxEarlyData:32, _Rest/binary>>) ->
    MaxEarlyData;
parse_nst_ext_loop(<<_Type:16, ELen:16, _EVal:ELen/binary, Rest/binary>>) ->
    parse_nst_ext_loop(Rest);
parse_nst_ext_loop(_) ->
    undefined.

-spec parse_nst_extensions(binary()) -> non_neg_integer() | undefined.
parse_nst_extensions(<<ExtLen:16, ExtData:ExtLen/binary>>) ->
    parse_nst_ext_loop(ExtData);
parse_nst_extensions(_) ->
    undefined.
