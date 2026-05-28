-module(nquic_tls_client).
-moduledoc """
Client-side TLS 1.3 handshake flow for QUIC per RFC 9001.

Builds ClientHello (full and PSK-resumption variants), processes
ServerHello, drives the post-ServerHello handshake (EncryptedExtensions,
Certificate, CertificateVerify, Finished) for both fresh and PSK
handshakes, and emits the client Finished. Certificate-chain
validation against a trust store lives here too because only the
client validates server certificates today. Codec helpers shared with
the server live in `nquic_tls`; the binder / NewSessionTicket helpers
remain there because they straddle both roles.
""".

-include("nquic_tls.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    make_client_finished/2,
    make_client_hello/3,
    make_client_hello/4,
    make_client_hello_psk/4,
    make_client_hello_psk/5,
    process_handshake_messages/3,
    process_handshake_messages_psk/3,
    process_server_hello/3
]).

-export([
    compute_ticket_age/1,
    encode_early_data_extension/0,
    encode_psk_identity/2,
    encode_psk_ke_modes_extension/0,
    find_message/2,
    parse_cert_entries/1,
    parse_remaining_cert_entries/1,
    take_through_type/2,
    update_transcript_ctx/2
]).
-record(client_hello, {
    client_version,
    random,
    session_id,
    cookie,
    cipher_suites,
    extensions
}).

-record(key_share_client_hello, {
    client_shares
}).

-record(client_hello_versions, {
    versions
}).

-record(signature_algorithms, {
    signature_scheme_list
}).

-record(supported_groups, {
    supported_groups
}).

-doc "Construct the client Finished message and derive application keys.".
-spec make_client_finished(binary(), map()) ->
    {ok, binary(), map(), map()} | {error, nquic_error:any_reason()}.
make_client_finished(HandshakeSecret, Keys) ->
    try
        Ctx = maps:get(transcript_ctx, Keys),
        ClientSecret = maps:get(client_secret, Keys),
        Cipher = maps:get(cipher, Keys, aes_128_gcm),
        Version = maps:get(quic_version, Keys, 1),
        Hash = nquic_keys:cipher_to_hash(Cipher),
        HashLen = nquic_tls:hash_length(Hash),

        FinishedKey = nquic_keys:qhkdf_expand(ClientSecret, <<"finished">>, <<>>, HashLen),
        TranscriptHash = crypto:hash_final(Ctx),
        VerifyData = crypto:mac(hmac, Hash, FinishedKey, TranscriptHash),

        FinLen = byte_size(VerifyData),
        FinBody = <<FinLen:24, VerifyData/binary>>,
        FinHeader = <<20, FinBody/binary>>,
        FinBin = FinHeader,

        {ClientAppSecret, ServerAppSecret} = nquic_keys:master_secrets(
            HandshakeSecret, TranscriptHash, Hash
        ),

        Ctx1 = crypto:hash_update(Ctx, FinBin),

        {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientAppSecret, Cipher, Version),
        {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerAppSecret, Cipher, Version),

        AppKeys0 = #{
            client_secret => ClientAppSecret,
            server_secret => ServerAppSecret,
            client_key => CKey,
            client_iv => CIV,
            client_hp => CHP,
            server_key => SKey,
            server_iv => SIV,
            server_hp => SHP,
            transcript_ctx => Ctx1,
            quic_version => Version
        },

        AppKeys =
            case maps:get(remote_params, Keys, undefined) of
                undefined -> AppKeys0;
                RP -> AppKeys0#{remote_params => RP}
            end,

        NewState = Keys#{transcript_ctx => Ctx1},

        {ok, FinBin, AppKeys, NewState}
    catch
        error:Reason -> {error, {client_finished_failed, Reason}}
    end.

-doc "Construct a TLS 1.3 ClientHello message with the default cipher suites.".
-spec make_client_hello(
    nquic_transport:params(), [binary()] | undefined, string() | binary() | undefined
) ->
    {ok, binary(), map()} | {error, term()}.
make_client_hello(TransportParams, ALPNProtos, Hostname) ->
    make_client_hello(TransportParams, ALPNProtos, Hostname, undefined).

-doc """
Construct a TLS 1.3 ClientHello message with an explicit cipher suite
list. `undefined` advertises all three RFC 8446 TLS 1.3 suites.
""".
-spec make_client_hello(
    nquic_transport:params(),
    [binary()] | undefined,
    string() | binary() | undefined,
    [aes_128_gcm | aes_256_gcm | chacha20_poly1305] | undefined
) ->
    {ok, binary(), map()} | {error, term()}.
make_client_hello(TransportParams, ALPNProtos, Hostname, CipherSuites) ->
    {PubKey, PrivKey} = crypto:generate_key(ecdh, x25519),

    BaseExtensions = #{
        client_hello_versions => #client_hello_versions{versions = [{3, 4}]},
        supported_groups => #supported_groups{supported_groups = [x25519]},
        key_share => #key_share_client_hello{
            client_shares = [#key_share_entry{group = x25519, key_exchange = PubKey}]
        },
        signature_algs => #signature_algorithms{
            signature_scheme_list = [
                eddsa_ed25519,
                rsa_pss_rsae_sha256,
                rsa_pkcs1_sha256,
                ecdsa_secp256r1_sha256
            ]
        }
    },

    Extensions = BaseExtensions,

    CH = #client_hello{
        client_version = {3, 3},
        random = crypto:strong_rand_bytes(32),
        session_id = <<>>,
        cookie = undefined,
        cipher_suites = encode_cipher_suites(CipherSuites),
        extensions = Extensions
    },

    try
        EncodedList = tls_handshake:encode_handshake(CH, {3, 4}),
        EncodedBin = iolist_to_binary(EncodedList),

        TPBin = nquic_transport:encode(TransportParams),
        ExtraExtensions = [
            encode_sni_extension(Hostname),
            encode_alpn_extension(ALPNProtos),
            encode_quic_params_extension(TPBin)
        ],
        FinalBin = inject_extensions(EncodedBin, ExtraExtensions),

        State = #{
            priv_key => PrivKey,
            pub_key => PubKey
        },

        {ok, FinalBin, State}
    catch
        error:Reason ->
            {error, {encoding_failed, Reason}}
    end.

-doc """
Build a ClientHello with PSK extensions for session resumption, using
the default cipher suites.
""".
-spec make_client_hello_psk(
    nquic_transport:params(),
    [binary()] | undefined,
    string() | binary() | undefined,
    #{psk := binary(), ticket := map(), cipher := atom()}
) ->
    {ok, binary(), map()} | {error, term()}.
make_client_hello_psk(TransportParams, ALPNProtos, Hostname, PSKInfo) ->
    make_client_hello_psk(TransportParams, ALPNProtos, Hostname, PSKInfo, undefined).

-doc """
Build a ClientHello with PSK extensions for session resumption.
TicketData is the map received from a prior NewSessionTicket message.
PSK is the pre-shared key derived from the resumption master secret.
The pre_shared_key extension MUST be the last extension (RFC 8446 S4.2.11).
`CipherSuites` controls which suites are advertised; `undefined` keeps
the default of all three RFC 8446 TLS 1.3 suites.
""".
-spec make_client_hello_psk(
    nquic_transport:params(),
    [binary()] | undefined,
    string() | binary() | undefined,
    #{psk := binary(), ticket := map(), cipher := atom()},
    [aes_128_gcm | aes_256_gcm | chacha20_poly1305] | undefined
) ->
    {ok, binary(), map()} | {error, term()}.
make_client_hello_psk(TransportParams, ALPNProtos, Hostname, PSKInfo, CipherSuites) ->
    #{psk := PSK, ticket := TicketData, cipher := Cipher} = PSKInfo,
    Hash = nquic_keys:cipher_to_hash(Cipher),
    HashLen = nquic_tls:hash_length(Hash),

    {PubKey, PrivKey} = crypto:generate_key(ecdh, x25519),

    BaseExtensions = #{
        client_hello_versions => #client_hello_versions{versions = [{3, 4}]},
        supported_groups => #supported_groups{supported_groups = [x25519]},
        key_share => #key_share_client_hello{
            client_shares = [
                #key_share_entry{group = x25519, key_exchange = PubKey}
            ]
        },
        signature_algs => #signature_algorithms{
            signature_scheme_list = [
                eddsa_ed25519,
                rsa_pss_rsae_sha256,
                rsa_pkcs1_sha256,
                ecdsa_secp256r1_sha256
            ]
        }
    },

    CH = #client_hello{
        client_version = {3, 3},
        random = crypto:strong_rand_bytes(32),
        session_id = <<>>,
        cookie = undefined,
        cipher_suites = encode_cipher_suites(CipherSuites),
        extensions = BaseExtensions
    },

    try
        EncodedList = tls_handshake:encode_handshake(CH, {3, 4}),
        EncodedBin = iolist_to_binary(EncodedList),

        TPBin = nquic_transport:encode(TransportParams),
        ExtraExtensions = [
            encode_sni_extension(Hostname),
            encode_alpn_extension(ALPNProtos),
            encode_quic_params_extension(TPBin),
            encode_psk_ke_modes_extension(),
            encode_early_data_extension()
        ],
        CHWithExts = inject_extensions(EncodedBin, ExtraExtensions),

        #{ticket := TicketValue, age_add := AgeAdd} = TicketData,
        TicketAge = compute_ticket_age(TicketData),
        ObfuscatedAge = (TicketAge + AgeAdd) band 16#FFFFFFFF,
        IdentityBin = encode_psk_identity(TicketValue, ObfuscatedAge),
        BinderPlaceholder = <<0:(HashLen * 8)>>,
        BindersBin = <<(HashLen + 1):16, HashLen:8, BinderPlaceholder/binary>>,
        PSKExtBody = <<IdentityBin/binary, BindersBin/binary>>,
        PSKExt = <<0, 41, (byte_size(PSKExtBody)):16, PSKExtBody/binary>>,

        CHWithPSK = inject_extensions(CHWithExts, [PSKExt]),

        BindersOffset = byte_size(CHWithPSK) - byte_size(BindersBin),
        PartialCH = binary:part(CHWithPSK, 0, BindersOffset),
        Binder = nquic_tls:compute_psk_binder(PSK, PartialCH, Hash, HashLen),

        <<Prefix:BindersOffset/binary, _OldBinders/binary>> = CHWithPSK,
        FinalBindersBin = <<(HashLen + 1):16, HashLen:8, Binder/binary>>,
        FinalBin = <<Prefix/binary, FinalBindersBin/binary>>,

        State = #{
            priv_key => PrivKey,
            pub_key => PubKey,
            psk => PSK,
            cipher => Cipher
        },

        {ok, FinalBin, State}
    catch
        error:Reason ->
            {error, {encoding_failed, Reason}}
    end.

-doc "Process handshake messages (EncryptedExtensions, Certificate, CertificateVerify, Finished).".
-spec process_handshake_messages(binary(), binary(), map()) ->
    {ok, map()} | {error, nquic_error:any_reason()}.
process_handshake_messages(Data, HandshakeSecret, State) ->
    try
        Ctx0 = maps:get(transcript_ctx, State),
        ServerSecret = maps:get(server_secret, State),
        Cipher = maps:get(cipher, State, aes_128_gcm),
        Version = maps:get(quic_version, State, 1),
        Hash = nquic_keys:cipher_to_hash(Cipher),
        HashLen = nquic_tls:hash_length(Hash),

        maybe
            {ok, Messages} ?= parse_handshake_msgs(Data),

            RemoteTP =
                case find_encrypted_extensions(Messages) of
                    {ok, EEMsg} ->
                        case parse_encrypted_extensions(EEMsg) of
                            {ok, TP} -> TP;
                            _ -> undefined
                        end;
                    _ ->
                        undefined
                end,

            {ok, {MsgsBefore, FinishedMsg}} ?= split_finished(Messages),

            {ok, PeerCertDER} ?= verify_certificate_chain(MsgsBefore, Ctx0, State),

            Ctx1 = update_transcript_ctx(Ctx0, MsgsBefore),

            ok ?= verify_finished(FinishedMsg, ServerSecret, Ctx1, Hash, HashLen),

            Ctx2 = crypto:hash_update(Ctx1, FinishedMsg),
            TranscriptHash = crypto:hash_final(Ctx2),

            {ClientAppSecret, ServerAppSecret} = nquic_keys:master_secrets(
                HandshakeSecret, TranscriptHash, Hash
            ),

            {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(
                ClientAppSecret, Cipher, Version
            ),
            {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(
                ServerAppSecret, Cipher, Version
            ),

            {ok, #{
                client_secret => ClientAppSecret,
                server_secret => ServerAppSecret,
                client_key => CKey,
                client_iv => CIV,
                client_hp => CHP,
                server_key => SKey,
                server_iv => SIV,
                server_hp => SHP,
                transcript_ctx => Ctx2,
                remote_params => RemoteTP,
                cipher => Cipher,
                peer_cert => PeerCertDER,
                quic_version => Version
            }}
        end
    catch
        error:Reason -> {error, {handshake_failed, Reason}}
    end.

-doc """
Process PSK handshake messages (EncryptedExtensions + Finished only).
No Certificate or CertificateVerify in PSK mode (RFC 8446 S2.3).
""".
-spec process_handshake_messages_psk(binary(), binary(), map()) ->
    {ok, map()} | {error, term()}.
process_handshake_messages_psk(Data, HandshakeSecret, State) ->
    try
        Ctx0 = maps:get(transcript_ctx, State),
        ServerSecret = maps:get(server_secret, State),
        Cipher = maps:get(cipher, State, aes_128_gcm),
        Version = maps:get(quic_version, State, 1),
        Hash = nquic_keys:cipher_to_hash(Cipher),
        HashLen = nquic_tls:hash_length(Hash),

        maybe
            {ok, Messages} ?= parse_handshake_msgs(Data),

            RemoteTP =
                case find_encrypted_extensions(Messages) of
                    {ok, EEMsg} ->
                        case parse_encrypted_extensions(EEMsg) of
                            {ok, TP} -> TP;
                            _ -> undefined
                        end;
                    _ ->
                        undefined
                end,

            ZeroRTTAccepted = check_early_data_in_ee(Messages),

            {ok, {MsgsBefore, FinishedMsg}} ?= split_finished(Messages),

            Ctx1 = update_transcript_ctx(Ctx0, MsgsBefore),

            ok ?= verify_finished(FinishedMsg, ServerSecret, Ctx1, Hash, HashLen),

            Ctx2 = crypto:hash_update(Ctx1, FinishedMsg),
            TranscriptHash = crypto:hash_final(Ctx2),

            {ClientAppSecret, ServerAppSecret} = nquic_keys:master_secrets(
                HandshakeSecret, TranscriptHash, Hash
            ),

            {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(
                ClientAppSecret, Cipher, Version
            ),
            {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(
                ServerAppSecret, Cipher, Version
            ),

            {ok, #{
                client_secret => ClientAppSecret,
                server_secret => ServerAppSecret,
                client_key => CKey,
                client_iv => CIV,
                client_hp => CHP,
                server_key => SKey,
                server_iv => SIV,
                server_hp => SHP,
                transcript_ctx => Ctx2,
                remote_params => RemoteTP,
                cipher => Cipher,
                peer_cert => undefined,
                zero_rtt_accepted => ZeroRTTAccepted,
                quic_version => Version
            }}
        end
    catch
        error:Reason -> {error, {handshake_failed, Reason}}
    end.

-doc "Process a ServerHello, extract the key share, and derive handshake secrets.".
-spec process_server_hello(binary(), binary(), map()) ->
    {ok, map()} | {error, nquic_error:any_reason()}.
process_server_hello(ServerHelloBin, ClientHelloBin, State) ->
    #{priv_key := ClientPrivKey} = State,
    Version = maps:get(quic_version, State, 1),

    try
        maybe
            {ok, ServerKeyShare, Cipher, PSKAccepted} ?=
                parse_server_hello_full(ServerHelloBin),
            Hash = nquic_keys:cipher_to_hash(Cipher),

            SharedSecret = crypto:compute_key(ecdh, ServerKeyShare, ClientPrivKey, x25519),

            Ctx0 = crypto:hash_init(Hash),
            Ctx1 = crypto:hash_update(Ctx0, ClientHelloBin),
            Ctx2 = crypto:hash_update(Ctx1, ServerHelloBin),
            TranscriptHash = crypto:hash_final(Ctx2),

            ClientPSK =
                case PSKAccepted of
                    true -> maps:get(psk, State, undefined);
                    false -> undefined
                end,
            {ClientHSSecret, ServerHSSecret, HandshakeSecret} = nquic_keys:handshake_secrets(
                SharedSecret, TranscriptHash, Hash, ClientPSK
            ),

            {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(
                ClientHSSecret, Cipher, Version
            ),
            {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(
                ServerHSSecret, Cipher, Version
            ),

            {ok, #{
                client_secret => ClientHSSecret,
                server_secret => ServerHSSecret,
                client_key => CKey,
                client_iv => CIV,
                client_hp => CHP,
                server_key => SKey,
                server_iv => SIV,
                server_hp => SHP,
                handshake_secret => HandshakeSecret,
                transcript_ctx => Ctx2,
                cipher => Cipher,
                psk_accepted => PSKAccepted,
                quic_version => Version
            }}
        end
    catch
        error:Reason -> {error, {processing_failed, Reason}}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL CLIENTHELLO EXTENSIONS
%%%-----------------------------------------------------------------------------
-spec cipher_suite_to_wire(aes_128_gcm | aes_256_gcm | chacha20_poly1305) -> binary().
cipher_suite_to_wire(aes_128_gcm) -> <<19, 1>>;
cipher_suite_to_wire(aes_256_gcm) -> <<19, 2>>;
cipher_suite_to_wire(chacha20_poly1305) -> <<19, 3>>.

-spec encode_alpn_extension([binary()] | undefined) -> binary().
encode_alpn_extension(undefined) ->
    <<>>;
encode_alpn_extension([]) ->
    <<>>;
encode_alpn_extension(Protos) when is_list(Protos) ->
    ProtoList = iolist_to_binary([<<(byte_size(P)):8, P/binary>> || P <- Protos]),
    ListLen = byte_size(ProtoList),
    ExtData = <<ListLen:16, ProtoList/binary>>,
    <<16:16, (byte_size(ExtData)):16, ExtData/binary>>.

-spec encode_cipher_suites(
    [aes_128_gcm | aes_256_gcm | chacha20_poly1305] | undefined
) -> [binary()].
encode_cipher_suites(undefined) ->
    [<<19, 1>>, <<19, 2>>, <<19, 3>>];
encode_cipher_suites(Suites) when is_list(Suites), Suites =/= [] ->
    [cipher_suite_to_wire(S) || S <- Suites].

-spec encode_quic_params_extension(binary()) -> binary().
encode_quic_params_extension(TPBin) ->
    <<57:16, (byte_size(TPBin)):16, TPBin/binary>>.

-spec encode_sni_extension(string() | binary() | undefined) -> binary().
encode_sni_extension(undefined) ->
    <<>>;
encode_sni_extension(Hostname) when is_list(Hostname) ->
    encode_sni_extension(list_to_binary(Hostname));
encode_sni_extension(Hostname) when is_binary(Hostname), byte_size(Hostname) > 0 ->
    NameLen = byte_size(Hostname),
    ServerName = <<0:8, NameLen:16, Hostname/binary>>,
    ServerNameList = <<(byte_size(ServerName)):16, ServerName/binary>>,
    <<0:16, (byte_size(ServerNameList)):16, ServerNameList/binary>>;
encode_sni_extension(_) ->
    <<>>.

-spec inject_extensions(binary(), [binary()]) -> binary().
inject_extensions(CHBin, ExtraExts) ->
    <<Type:8, Len:24, Body:Len/binary>> = CHBin,
    1 = Type,

    <<Version:2/binary, Random:32/binary, Rest1/binary>> = Body,

    {SessionID, Rest2} = nquic_tls:parse_vec8(Rest1),
    {CipherSuites, Rest3} = nquic_tls:parse_vec16(Rest2),
    {CompMethods, Rest4} = nquic_tls:parse_vec8(Rest3),

    <<ExtLen:16, ExtData:ExtLen/binary>> = Rest4,

    ExtraExtsBin = iolist_to_binary(ExtraExts),
    NewExtData = <<ExtData/binary, ExtraExtsBin/binary>>,
    NewExtLen = byte_size(NewExtData),

    NewBody =
        <<Version/binary, Random/binary, (byte_size(SessionID)):8, SessionID/binary,
            (byte_size(CipherSuites)):16, CipherSuites/binary, (byte_size(CompMethods)):8,
            CompMethods/binary, NewExtLen:16, NewExtData/binary>>,

    NewLen = byte_size(NewBody),
    <<Type, NewLen:24, NewBody/binary>>.

%%%-----------------------------------------------------------------------------
%% INTERNAL PSK CLIENTHELLO EXTENSIONS
%%%-----------------------------------------------------------------------------
-spec compute_ticket_age(map()) -> non_neg_integer().
compute_ticket_age(TicketData) ->
    case maps:get(received_at, TicketData, undefined) of
        ReceivedAt when is_integer(ReceivedAt) ->
            Now = erlang:system_time(millisecond),
            erlang:max(0, Now - ReceivedAt);
        _ ->
            0
    end.

-spec encode_early_data_extension() -> binary().
encode_early_data_extension() ->
    <<0, 42, 0, 0>>.

-spec encode_psk_identity(binary(), non_neg_integer()) -> binary().
encode_psk_identity(Identity, ObfuscatedAge) ->
    IdentityLen = byte_size(Identity),
    Entry = <<IdentityLen:16, Identity/binary, ObfuscatedAge:32>>,
    EntryListLen = byte_size(Entry),
    <<EntryListLen:16, Entry/binary>>.

-spec encode_psk_ke_modes_extension() -> binary().
encode_psk_ke_modes_extension() ->
    <<0, 45, 0, 2, 1, 1>>.

%%%-----------------------------------------------------------------------------
%% INTERNAL SERVERHELLO / HANDSHAKE-FLIGHT PARSING
%%%-----------------------------------------------------------------------------
-spec check_early_data_in_ee([binary()]) -> boolean().
check_early_data_in_ee([]) ->
    false;
check_early_data_in_ee([<<8:8, Len:24, Body:Len/binary>> | _]) ->
    <<ExtLen:16, ExtData:ExtLen/binary>> = Body,
    ExtMap = nquic_tls:parse_extensions_recursive(ExtData),
    maps:is_key(42, ExtMap);
check_early_data_in_ee([_ | Rest]) ->
    check_early_data_in_ee(Rest).

-spec find_encrypted_extensions([binary()]) -> {ok, binary()} | undefined.
find_encrypted_extensions([]) -> undefined;
find_encrypted_extensions([<<8:8, _:24, _/binary>> = Msg | _]) -> {ok, Msg};
find_encrypted_extensions([_ | Rest]) -> find_encrypted_extensions(Rest).

-spec parse_encrypted_extensions(binary()) ->
    {ok, nquic_transport:params()} | {error, nquic_error:any_reason()}.
parse_encrypted_extensions(<<8:8, _Len:24, Body/binary>>) ->
    <<ExtListLen:16, Exts:ExtListLen/binary>> = Body,
    ExtMap = nquic_tls:parse_extensions_recursive(Exts),
    nquic_tls:find_quic_params(ExtMap, server).

-spec parse_handshake_msgs(binary()) ->
    {ok, [binary()]} | {error, nquic_error:any_reason()}.
parse_handshake_msgs(Bin) ->
    parse_handshake_msgs(Bin, []).

-spec parse_handshake_msgs(binary(), [binary()]) ->
    {ok, [binary()]} | {error, nquic_error:any_reason()}.
parse_handshake_msgs(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
parse_handshake_msgs(<<Type:8, Len:24, Body:Len/binary, Rest/binary>>, Acc) ->
    case Type of
        5 -> {error, {tls_alert, unexpected_message}};
        24 -> {error, {tls_alert, unexpected_message}};
        _ -> parse_handshake_msgs(Rest, [<<Type:8, Len:24, Body/binary>> | Acc])
    end;
parse_handshake_msgs(_, _Acc) ->
    {error, incomplete_handshake_message}.

-spec parse_server_hello_full(binary()) ->
    {ok, binary(), atom(), boolean()} | {error, nquic_error:any_reason()}.
parse_server_hello_full(<<2:8, Len:24, Body:Len/binary>>) ->
    <<_Version:2/binary, _Random:32/binary, Rest1/binary>> = Body,
    {_SessionID, Rest2} = nquic_tls:parse_vec8(Rest1),
    <<CipherSuite:2/binary, _CompMethod:8, Rest3/binary>> = Rest2,
    maybe
        {ok, Cipher} ?= nquic_tls:decode_cipher_suite(CipherSuite),
        <<ExtLen:16, ExtData:ExtLen/binary>> = Rest3,
        ExtMap = nquic_tls:parse_extensions_recursive(ExtData),
        {ok, Key} ?= server_hello_key_share(maps:get(51, ExtMap, undefined)),
        PSKAccepted = maps:is_key(41, ExtMap),
        {ok, Key, Cipher, PSKAccepted}
    end;
parse_server_hello_full(_) ->
    {error, invalid_server_hello}.

-spec server_hello_key_share(binary() | undefined) ->
    {ok, binary()} | {error, nquic_error:any_reason()}.
server_hello_key_share(undefined) ->
    {error, key_share_not_found};
server_hello_key_share(<<Group:16, _KLen:16, K/binary>>) ->
    case Group of
        16#001d -> {ok, K};
        _ -> {error, {unsupported_group, Group}}
    end.

-spec split_finished([binary()]) ->
    {ok, {[binary()], binary()}} | {error, nquic_error:any_reason()}.
split_finished(Messages) ->
    case lists:last(Messages) of
        <<20:8, _/binary>> = Fin ->
            {ok, {lists:droplast(Messages), Fin}};
        _ ->
            {error, finished_not_found}
    end.

-spec update_transcript_ctx(crypto:hash_state(), [binary()]) -> crypto:hash_state().
update_transcript_ctx(Ctx, Messages) ->
    lists:foldl(fun(Msg, C) -> crypto:hash_update(C, Msg) end, Ctx, Messages).

-spec verify_finished(binary(), binary(), crypto:hash_state(), atom(), pos_integer()) ->
    ok | {error, nquic_error:any_reason()}.
verify_finished(
    <<20:8, _Len:24, VerifyData/binary>>, ServerSecret, TranscriptCtx, Hash, HashLen
) ->
    FinishedKey = nquic_keys:qhkdf_expand(ServerSecret, <<"finished">>, <<>>, HashLen),
    TranscriptHash = crypto:hash_final(TranscriptCtx),
    ExpectedData = crypto:mac(hmac, Hash, FinishedKey, TranscriptHash),

    if
        VerifyData =:= ExpectedData -> ok;
        true -> {error, finished_verification_failed}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL CERTIFICATE-CHAIN VALIDATION
%%%-----------------------------------------------------------------------------
-spec extract_public_key(#'OTPCertificate'{}) -> #'OTPSubjectPublicKeyInfo'{}.
extract_public_key(#'OTPCertificate'{tbsCertificate = TBS}) ->
    TBS#'OTPTBSCertificate'.subjectPublicKeyInfo.

-spec find_issuer([binary()], [#'OTPCertificate'{}]) ->
    {ok, #'OTPCertificate'{}} | error.
find_issuer([], _TrustedCerts) ->
    error;
find_issuer([CertDER | Rest], TrustedCerts) ->
    Cert = public_key:pkix_decode_cert(CertDER, otp),
    case
        lists:search(
            fun(TC) -> public_key:pkix_is_issuer(Cert, TC) end,
            TrustedCerts
        )
    of
        {value, Issuer} -> {ok, Issuer};
        false -> find_issuer(Rest, TrustedCerts)
    end.

-spec find_message(non_neg_integer(), [binary()]) -> binary() | undefined.
find_message(_Type, []) -> undefined;
find_message(Type, [<<Type:8, _/binary>> = Msg | _]) -> Msg;
find_message(Type, [_ | Rest]) -> find_message(Type, Rest).

-spec find_trusted_root([binary()], [#'OTPCertificate'{}]) ->
    {ok, #'OTPCertificate'{}} | error.
find_trusted_root(Chain, TrustedCerts) ->
    find_issuer(lists:reverse(Chain), TrustedCerts).

-spec parse_cert_entries(binary()) -> {binary(), [binary()]}.
parse_cert_entries(
    <<CertLen:24, CertDER:CertLen/binary, ExtLen:16, _Ext:ExtLen/binary, Rest/binary>>
) ->
    ChainCerts = parse_remaining_cert_entries(Rest),
    {CertDER, ChainCerts}.

-spec parse_certificate_chain(binary()) -> {binary(), [binary()]}.
parse_certificate_chain(<<11:8, _Len:24, Body/binary>>) ->
    <<CtxLen:8, _Ctx:CtxLen/binary, ListLen:24, Entries:ListLen/binary>> = Body,
    parse_cert_entries(Entries).

-spec parse_remaining_cert_entries(binary()) -> [binary()].
parse_remaining_cert_entries(<<>>) ->
    [];
parse_remaining_cert_entries(
    <<CertLen:24, CertDER:CertLen/binary, ExtLen:16, _Ext:ExtLen/binary, Rest/binary>>
) ->
    [CertDER | parse_remaining_cert_entries(Rest)].

-spec sig_result(boolean()) -> ok | {error, {tls_alert, decrypt_error}}.
sig_result(true) ->
    ok;
sig_result(false) ->
    {error, {tls_alert, decrypt_error}}.

-spec take_through_type(non_neg_integer(), [binary()]) -> [binary()].
take_through_type(Type, Messages) ->
    take_through_type(Type, Messages, []).

-spec take_through_type(non_neg_integer(), [binary()], [binary()]) -> [binary()].
take_through_type(_Type, [], Acc) ->
    lists:reverse(Acc);
take_through_type(Type, [<<Type:8, _/binary>> = Msg | _], Acc) ->
    lists:reverse([Msg | Acc]);
take_through_type(Type, [Msg | Rest], Acc) ->
    take_through_type(Type, Rest, [Msg | Acc]).

-spec validate_chain(binary(), [binary()], [binary()], inet:hostname() | binary() | undefined) ->
    ok | {error, nquic_error:any_reason()}.
validate_chain(_LeafDER, _ChainDERs, [], _Hostname) ->
    {error, {tls_alert, unknown_ca}};
validate_chain(LeafDER, ChainDERs, CACerts, Hostname) ->
    Chain = [LeafDER | ChainDERs],
    TrustedCerts = [public_key:pkix_decode_cert(CA, otp) || CA <- CACerts],
    LeafOTP = public_key:pkix_decode_cert(LeafDER, otp),
    ChainOTP = [public_key:pkix_decode_cert(C, otp) || C <- ChainDERs],
    case find_trusted_root(Chain, TrustedCerts) of
        {ok, TrustedCert} ->
            PathChain = lists:reverse([LeafOTP | ChainOTP]),
            case public_key:pkix_path_validation(TrustedCert, PathChain, []) of
                {ok, _} ->
                    verify_hostname(LeafOTP, Hostname);
                {error, {bad_cert, Reason}} ->
                    {error, {tls_alert, {bad_certificate, Reason}}}
            end;
        error ->
            {error, {tls_alert, unknown_ca}}
    end.

-spec validate_chain_opts(verify_none | verify_peer, binary(), [binary()], map()) ->
    ok | {error, nquic_error:any_reason()}.
validate_chain_opts(verify_none, _LeafDER, _ChainDERs, _VerifyOpts) ->
    ok;
validate_chain_opts(verify_peer, LeafDER, ChainDERs, VerifyOpts) ->
    CACerts = maps:get(cacerts, VerifyOpts, []),
    Hostname = maps:get(hostname, VerifyOpts, undefined),
    validate_chain(LeafDER, ChainDERs, CACerts, Hostname).

-spec verify_certificate_chain([binary()], crypto:hash_state(), map()) ->
    {ok, binary() | undefined} | {error, nquic_error:any_reason()}.
verify_certificate_chain(Messages, TranscriptCtx, VerifyOpts) ->
    CertMsg = find_message(11, Messages),
    CVMsg = find_message(15, Messages),
    case {CertMsg, CVMsg} of
        {undefined, undefined} ->
            {ok, undefined};
        {undefined, _} ->
            {error, {tls_alert, certificate_required}};
        {_, undefined} ->
            {error, {tls_alert, certificate_required}};
        {CertBin, CVBin} ->
            {LeafDER, ChainDERs} = parse_certificate_chain(CertBin),

            MsgsUpToCert = take_through_type(11, Messages),
            CtxForCV = update_transcript_ctx(TranscriptCtx, MsgsUpToCert),
            TranscriptHashCV = crypto:hash_final(CtxForCV),

            maybe
                ok ?= verify_certificate_verify(CVBin, LeafDER, TranscriptHashCV),
                ok ?=
                    validate_chain_opts(
                        maps:get(verify, VerifyOpts, verify_none),
                        LeafDER,
                        ChainDERs,
                        VerifyOpts
                    ),
                {ok, LeafDER}
            end
    end.

-spec verify_certificate_verify(binary(), binary(), binary()) ->
    ok | {error, nquic_error:any_reason()}.
verify_certificate_verify(
    <<15:8, _Len:24, Alg:16, SigLen:16, Sig:SigLen/binary>>, LeafCertDER, TranscriptHash
) ->
    Pad = binary:copy(<<16#20>>, 64),
    Context = <<"TLS 1.3, server CertificateVerify">>,
    Input = <<Pad/binary, Context/binary, 0:8, TranscriptHash/binary>>,

    Cert = public_key:pkix_decode_cert(LeafCertDER, otp),
    PubKey = extract_public_key(Cert),

    verify_sig(Alg, Sig, Input, PubKey).

-spec verify_hostname(#'OTPCertificate'{}, inet:hostname() | binary() | undefined) ->
    ok | {error, nquic_error:any_reason()}.
verify_hostname(_Cert, undefined) ->
    ok;
verify_hostname(Cert, Hostname) when is_list(Hostname) ->
    verify_hostname(Cert, list_to_binary(Hostname));
verify_hostname(Cert, Hostname) when is_binary(Hostname) ->
    HostStr = binary_to_list(Hostname),
    ReferenceIDs =
        case inet:parse_address(HostStr) of
            {ok, _IP} -> [{ip, HostStr}];
            {error, _} -> [{dns_id, HostStr}]
        end,
    case public_key:pkix_verify_hostname(Cert, ReferenceIDs) of
        true -> ok;
        false -> {error, {tls_alert, {bad_certificate, hostname_mismatch}}}
    end.

-spec verify_sig(non_neg_integer(), binary(), binary(), #'OTPSubjectPublicKeyInfo'{}) ->
    ok | {error, nquic_error:any_reason()}.
verify_sig(16#0804, Sig, Input, #'OTPSubjectPublicKeyInfo'{
    algorithm = #'PublicKeyAlgorithm'{algorithm = ?'rsaEncryption'},
    subjectPublicKey = RSAKey
}) ->
    sig_result(
        public_key:verify(Input, sha256, Sig, RSAKey, [
            {rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}
        ])
    );
verify_sig(16#0403, Sig, Input, #'OTPSubjectPublicKeyInfo'{
    algorithm = #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey', parameters = Params},
    subjectPublicKey = ECPoint
}) ->
    sig_result(public_key:verify(Input, sha256, Sig, {ECPoint, Params}));
verify_sig(_, _, _, _) ->
    {error, {tls_alert, handshake_failure}}.
