-module(nquic_tls_server).
-moduledoc """
Server-side TLS 1.3 handshake flow for QUIC per RFC 9001.

Processes ClientHello, builds the server handshake flight
(EncryptedExtensions, Certificate, CertificateVerify, Finished) for
full handshakes and the abbreviated EE+Finished flight for PSK
resumption, and verifies the client Finished. Codec helpers shared
with the client live in `nquic_tls`; PSK / NewSessionTicket helpers
remain there too because they straddle both roles.
""".

-include("nquic_tls.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    make_server_handshake_flight/6,
    make_server_handshake_flight_psk/4,
    process_client_hello/3,
    process_client_hello/4,
    validate_psk_offer/4,
    verify_client_finished/3,
    verify_client_finished/4
]).

-export([
    encode_extensions/1,
    find_alpn/1,
    find_cipher_match/2,
    find_match/2,
    make_certificate_message/2,
    parse_alpn_items/1,
    parse_cipher_suites/1,

    select_alpn/2,
    select_cipher/1, select_cipher/2
]).
-record(server_hello, {
    server_version,
    random,
    session_id,
    cipher_suite,
    compression_method,
    extensions
}).

-record(key_share_server_hello, {
    server_share
}).

-doc "Build the server handshake flight (EncryptedExtensions, Certificate, CertificateVerify, Finished).".
-spec make_server_handshake_flight(
    binary(), map(), map(), binary(), [binary()], public_key:private_key()
) ->
    {ok, binary(), map(), map()} | {error, nquic_error:any_reason()}.
make_server_handshake_flight(HandshakeSecret, Keys, State, CertDER, CertChain, PrivKey) ->
    try
        maybe
            Ctx0 = maps:get(transcript_ctx, Keys),
            ServerSecret = maps:get(server_secret, Keys),
            TransportParams = maps:get(transport_params, State),
            Cipher = maps:get(cipher, State, aes_128_gcm),
            Version = maps:get(quic_version, State, 1),
            Hash = nquic_keys:cipher_to_hash(Cipher),
            HashLen = nquic_tls:hash_length(Hash),

            TPBin = nquic_transport:encode(TransportParams),

            ExtID = 57,
            ExtLen = byte_size(TPBin),
            ExtData0 = <<ExtID:16, ExtLen:16, TPBin/binary>>,

            ExtData =
                case maps:get(selected_alpn, State, undefined) of
                    undefined ->
                        ExtData0;
                    Proto ->
                        P = <<(byte_size(Proto)):8, Proto/binary>>,
                        ALPNData = <<(byte_size(P)):16, P/binary>>,
                        ALPNBin = <<16:16, (byte_size(ALPNData)):16, ALPNData/binary>>,
                        <<ExtData0/binary, ALPNBin/binary>>
                end,

            EELen = byte_size(ExtData),
            EEBody = <<EELen:16, ExtData/binary>>,
            EEHeader = <<8, (byte_size(EEBody)):24>>,
            EEBin = <<EEHeader/binary, EEBody/binary>>,

            CertMsg = make_certificate_message(CertDER, CertChain),

            Ctx1 = crypto:hash_update(Ctx0, EEBin),
            Ctx2 = crypto:hash_update(Ctx1, CertMsg),
            TranscriptHashCV = crypto:hash_final(Ctx2),
            {ok, CertVerifyMsg} ?= make_certificate_verify_message(PrivKey, TranscriptHashCV),

            Ctx3 = crypto:hash_update(Ctx2, CertVerifyMsg),

            FinishedKey = nquic_keys:qhkdf_expand(ServerSecret, <<"finished">>, <<>>, HashLen),
            TranscriptHashFin = crypto:hash_final(Ctx3),
            VerifyData = crypto:mac(hmac, Hash, FinishedKey, TranscriptHashFin),

            FinLen = byte_size(VerifyData),
            FinBody = <<FinLen:24, VerifyData/binary>>,
            FinHeader = <<20, FinBody/binary>>,
            FinBin = FinHeader,

            Ctx4 = crypto:hash_update(Ctx3, FinBin),
            TranscriptHashFinal = crypto:hash_final(Ctx4),

            {ClientAppSecret, ServerAppSecret} = nquic_keys:master_secrets(
                HandshakeSecret, TranscriptHashFinal, Hash
            ),

            {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(
                ClientAppSecret, Cipher, Version
            ),
            {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(
                ServerAppSecret, Cipher, Version
            ),

            AppKeys = #{
                client_secret => ClientAppSecret,
                server_secret => ServerAppSecret,
                client_key => CKey,
                client_iv => CIV,
                client_hp => CHP,
                server_key => SKey,
                server_iv => SIV,
                server_hp => SHP,
                transcript_ctx => Ctx4,
                quic_version => Version
            },

            FlightBin = <<EEBin/binary, CertMsg/binary, CertVerifyMsg/binary, FinBin/binary>>,
            ClientHSSecret = maps:get(client_secret, Keys),
            NewState = State#{transcript_ctx => Ctx4, client_secret => ClientHSSecret},

            {ok, FlightBin, AppKeys, NewState}
        end
    catch
        error:Reason -> {error, {flight_generation_failed, Reason}}
    end.

-doc """
Build the server handshake flight for PSK resumption (no Certificate/CertificateVerify).
EncryptedExtensions + Finished only. Optionally includes early_data extension
to signal 0-RTT acceptance.
""".
-spec make_server_handshake_flight_psk(
    binary(), map(), map(), boolean()
) -> {ok, binary(), map(), map()} | {error, term()}.
make_server_handshake_flight_psk(HandshakeSecret, Keys, State, AcceptEarlyData) ->
    try
        Ctx0 = maps:get(transcript_ctx, Keys),
        ServerSecret = maps:get(server_secret, Keys),
        Cipher = maps:get(cipher, State, aes_128_gcm),
        Version = maps:get(quic_version, State, 1),
        Hash = nquic_keys:cipher_to_hash(Cipher),
        HashLen = nquic_tls:hash_length(Hash),

        TransportParams = maps:get(transport_params, State),
        TPBin = nquic_transport:encode(TransportParams),
        ExtID = 57,
        ExtLen = byte_size(TPBin),
        ExtData0 = <<ExtID:16, ExtLen:16, TPBin/binary>>,

        ExtData1 =
            case maps:get(selected_alpn, State, undefined) of
                undefined ->
                    ExtData0;
                Proto ->
                    P = <<(byte_size(Proto)):8, Proto/binary>>,
                    ALPNData = <<(byte_size(P)):16, P/binary>>,
                    ALPNBin = <<16:16, (byte_size(ALPNData)):16, ALPNData/binary>>,
                    <<ExtData0/binary, ALPNBin/binary>>
            end,

        ExtData =
            case AcceptEarlyData of
                true -> <<ExtData1/binary, 0, 42, 0, 0>>;
                false -> ExtData1
            end,

        EELen = byte_size(ExtData),
        EEBody = <<EELen:16, ExtData/binary>>,
        EEHeader = <<8, (byte_size(EEBody)):24>>,
        EEBin = <<EEHeader/binary, EEBody/binary>>,

        Ctx1 = crypto:hash_update(Ctx0, EEBin),
        FinishedKey = nquic_keys:qhkdf_expand(ServerSecret, <<"finished">>, <<>>, HashLen),
        TranscriptHashFin = crypto:hash_final(Ctx1),
        VerifyData = crypto:mac(hmac, Hash, FinishedKey, TranscriptHashFin),

        FinLen = byte_size(VerifyData),
        FinBody = <<FinLen:24, VerifyData/binary>>,
        FinBin = <<20, FinBody/binary>>,

        Ctx2 = crypto:hash_update(Ctx1, FinBin),
        TranscriptHashFinal = crypto:hash_final(Ctx2),

        {ClientAppSecret, ServerAppSecret} = nquic_keys:master_secrets(
            HandshakeSecret, TranscriptHashFinal, Hash
        ),

        {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientAppSecret, Cipher, Version),
        {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerAppSecret, Cipher, Version),

        AppKeys = #{
            client_secret => ClientAppSecret,
            server_secret => ServerAppSecret,
            client_key => CKey,
            client_iv => CIV,
            client_hp => CHP,
            server_key => SKey,
            server_iv => SIV,
            server_hp => SHP,
            transcript_ctx => Ctx2,
            quic_version => Version
        },

        FlightBin = <<EEBin/binary, FinBin/binary>>,
        ClientHSSecret = maps:get(client_secret, Keys),
        NewState = State#{transcript_ctx => Ctx2, client_secret => ClientHSSecret},

        {ok, FlightBin, AppKeys, NewState}
    catch
        error:Reason -> {error, {psk_flight_generation_failed, Reason}}
    end.

-doc "Process a ClientHello, generate a ServerHello, and derive handshake secrets.".
-spec process_client_hello(binary(), nquic_transport:params(), [binary()] | undefined) ->
    {ok, binary(), map(), map()} | {error, term()}.
process_client_hello(ClientHelloBin, TransportParams, SupportedALPNs) ->
    process_client_hello(ClientHelloBin, TransportParams, SupportedALPNs, #{}).

-doc """
Process a ClientHello with options.
Opts may include `psk_selected => Index` to include pre_shared_key in ServerHello.
""".
-spec process_client_hello(binary(), nquic_transport:params(), [binary()] | undefined, map()) ->
    {ok, binary(), map(), map()} | {error, term()}.
process_client_hello(ClientHelloBin, TransportParams, SupportedALPNs, Opts) ->
    try
        maybe
            {ok, SessionID, ClientKeyShare, RemoteTP, ClientALPNs, ClientCiphers, PSKInfo} ?=
                parse_client_hello(ClientHelloBin),

            {ok, SelectedALPN} ?= select_alpn(ClientALPNs, SupportedALPNs),

            Preferred = maps:get(cipher_suites, Opts, undefined),
            {ok, Cipher} ?= select_cipher(ClientCiphers, Preferred),
            Hash = nquic_keys:cipher_to_hash(Cipher),

            {ServerPubKey, ServerPrivKey} = crypto:generate_key(ecdh, x25519),

            BaseExtensions = #{
                server_hello_versions => #server_hello_versions{versions = {3, 4}},
                key_share => #key_share_server_hello{
                    server_share = #key_share_entry{group = x25519, key_exchange = ServerPubKey}
                }
            },

            Extensions =
                case maps:get(psk_selected, Opts, undefined) of
                    undefined -> BaseExtensions;
                    Index -> BaseExtensions#{pre_shared_key => Index}
                end,

            SH = #server_hello{
                server_version = {3, 3},
                random = crypto:strong_rand_bytes(32),
                session_id = SessionID,
                cipher_suite = nquic_tls:encode_cipher_suite(Cipher),
                compression_method = 0,
                extensions = Extensions
            },

            ServerHelloBin = manual_encode_server_hello(SH),

            SharedSecret = crypto:compute_key(ecdh, ClientKeyShare, ServerPrivKey, x25519),

            Ctx0 = crypto:hash_init(Hash),
            Ctx1 = crypto:hash_update(Ctx0, ClientHelloBin),
            Ctx2 = crypto:hash_update(Ctx1, ServerHelloBin),
            TranscriptHash = crypto:hash_final(Ctx2),

            PSKValue = maps:get(psk_value, Opts, undefined),
            {ClientHSSecret, ServerHSSecret, HandshakeSecret} = nquic_keys:handshake_secrets(
                SharedSecret, TranscriptHash, Hash, PSKValue
            ),

            Version = maps:get(quic_version, Opts, 1),
            {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientHSSecret, Cipher, Version),
            {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerHSSecret, Cipher, Version),

            Keys = #{
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
                remote_params => RemoteTP,
                cipher => Cipher,
                quic_version => Version
            },

            State0 = #{
                priv_key => ServerPrivKey,
                role => server,
                transport_params => TransportParams,
                client_secret => ClientHSSecret,
                server_secret => ServerHSSecret,
                handshake_secret => HandshakeSecret,
                transcript_ctx => Ctx2,
                remote_params => RemoteTP,
                selected_alpn => SelectedALPN,
                cipher => Cipher,
                quic_version => Version
            },

            State =
                case PSKInfo of
                    undefined ->
                        State0;
                    _ ->
                        State0#{
                            psk_info => PSKInfo,
                            client_hello_bin => ClientHelloBin
                        }
                end,

            {ok, ServerHelloBin, Keys, State}
        end
    catch
        error:Reason -> {error, {processing_failed, Reason}}
    end.

-doc """
Validate a PSK offer from a ClientHello against the server's ticket.
Decrypts the first matching identity, verifies the binder, and returns
the PSK and whether 0-RTT should be accepted.
StaticKey is the server's ticket encryption key.
ClientHelloBin is the raw ClientHello (needed for binder verification).
""".
-spec validate_psk_offer(map(), binary(), binary(), atom()) ->
    {ok, binary(), atom(), boolean(), binary()} | {error, term()}.
validate_psk_offer(PSKInfo, ClientHelloBin, StaticKey, NegCipher) ->
    #{identities := Identities, binders := Binders, early_data := HasEarlyData} = PSKInfo,
    validate_psk_identities(
        Identities, Binders, ClientHelloBin, StaticKey, NegCipher, HasEarlyData
    ).

-doc "Verify the client Finished message using the client handshake traffic secret.".
-spec verify_client_finished(binary(), binary(), crypto:hash_state()) ->
    ok | {error, nquic_error:any_reason()}.
verify_client_finished(Data, ClientSecret, TranscriptCtx) ->
    verify_client_finished(Data, ClientSecret, TranscriptCtx, aes_128_gcm).

-doc "Verify the client Finished message with an explicit cipher suite.".
-spec verify_client_finished(
    binary(), binary(), crypto:hash_state(), aes_128_gcm | aes_256_gcm | chacha20_poly1305
) -> ok | {error, term()}.
verify_client_finished(Data, ClientSecret, TranscriptCtx, Cipher) ->
    try
        Hash = nquic_keys:cipher_to_hash(Cipher),
        HashLen = nquic_tls:hash_length(Hash),

        <<20:8, Len:24, VerifyData:Len/binary>> = Data,

        FinishedKey = nquic_keys:qhkdf_expand(ClientSecret, <<"finished">>, <<>>, HashLen),
        TranscriptHash = crypto:hash_final(TranscriptCtx),
        ExpectedData = crypto:mac(hmac, Hash, FinishedKey, TranscriptHash),

        if
            VerifyData =:= ExpectedData -> ok;
            true -> {error, client_finished_verification_failed}
        end
    catch
        error:{badmatch, _} -> {error, malformed_finished}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL SERVERHELLO ENCODING
%%%-----------------------------------------------------------------------------
-spec encode_extensions(map()) -> binary().
encode_extensions(Exts) ->
    V =
        case maps:get(server_hello_versions, Exts, undefined) of
            #server_hello_versions{versions = {Maj, Min}} ->
                <<0, 43, 0, 2, Maj, Min>>;
            _ ->
                <<>>
        end,

    K =
        case maps:get(key_share, Exts, undefined) of
            #key_share_server_hello{
                server_share = #key_share_entry{group = x25519, key_exchange = Key}
            } ->
                Group = 16#001d,
                KLen = byte_size(Key),
                Entry = <<Group:16, KLen:16, Key/binary>>,
                ExtLen = byte_size(Entry),
                <<0, 51, ExtLen:16, Entry/binary>>;
            _ ->
                <<>>
        end,

    PSK =
        case maps:get(pre_shared_key, Exts, undefined) of
            undefined ->
                <<>>;
            SelectedIndex when is_integer(SelectedIndex) ->
                <<0, 41, 0, 2, SelectedIndex:16>>
        end,

    <<V/binary, K/binary, PSK/binary>>.

-spec manual_encode_server_hello(#server_hello{}) -> binary().
manual_encode_server_hello(SH) ->
    #server_hello{
        server_version = {Major, Minor},
        random = Random,
        session_id = SessionID,
        cipher_suite = CipherSuite,
        compression_method = CompMethod,
        extensions = ExtensionsMap
    } = SH,

    VerBin = <<Major, Minor>>,

    SIDLen = byte_size(SessionID),
    SIDBin = <<SIDLen:8, SessionID/binary>>,

    CSBin = CipherSuite,

    CompBin = <<CompMethod:8>>,

    ExtsBin = encode_extensions(ExtensionsMap),
    ExtsLen = byte_size(ExtsBin),
    ExtsLenBin = <<ExtsLen:16>>,

    Body =
        <<VerBin/binary, Random/binary, SIDBin/binary, CSBin/binary, CompBin/binary,
            ExtsLenBin/binary, ExtsBin/binary>>,

    Type = 2,
    Len = byte_size(Body),
    <<Type:8, Len:24, Body/binary>>.

%%%-----------------------------------------------------------------------------
%% INTERNAL CERTIFICATE / CERTIFICATEVERIFY
%%%-----------------------------------------------------------------------------
-spec encode_cert_entries([binary()]) -> iolist().
encode_cert_entries([]) ->
    [];
encode_cert_entries([CertDER | Rest]) ->
    CertLen = byte_size(CertDER),
    [<<CertLen:24, CertDER/binary, 0:16>> | encode_cert_entries(Rest)].

-spec make_certificate_message(binary(), [binary()]) -> binary().
make_certificate_message(LeafDER, ChainDERs) ->
    Entries = encode_cert_entries([LeafDER | ChainDERs]),
    ListLen = iolist_size(Entries),
    Body = [<<0:8, ListLen:24>>, Entries],
    BodyBin = iolist_to_binary(Body),
    MsgLen = byte_size(BodyBin),
    <<11:8, MsgLen:24, BodyBin/binary>>.

-spec make_certificate_verify_message(public_key:private_key(), binary()) ->
    {ok, binary()} | {error, nquic_error:any_reason()}.
make_certificate_verify_message(PrivKey, Hash) ->
    Pad = binary:copy(<<16#20>>, 64),
    Context = <<"TLS 1.3, server CertificateVerify">>,
    Input = <<Pad/binary, Context/binary, 0:8, Hash/binary>>,
    maybe
        {ok, {Alg, Sig}} ?= sign(PrivKey, Input),
        SigLen = byte_size(Sig),
        Body = <<Alg:16, SigLen:16, Sig/binary>>,
        MsgLen = byte_size(Body),
        {ok, <<15:8, MsgLen:24, Body/binary>>}
    end.

-spec sign(public_key:private_key(), binary()) ->
    {ok, {non_neg_integer(), binary()}} | {error, nquic_error:any_reason()}.
sign(#'RSAPrivateKey'{} = Key, Data) ->
    Sig = public_key:sign(Data, sha256, Key, [
        {rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}
    ]),
    {ok, {16#0804, Sig}};
sign(#'ECPrivateKey'{parameters = {namedCurve, {1, 2, 840, 10045, 3, 1, 7}}} = Key, Data) ->
    Sig = public_key:sign(Data, sha256, Key),
    {ok, {16#0403, Sig}};
sign(_, _) ->
    {error, unsupported_key_type}.

%%%-----------------------------------------------------------------------------
%% INTERNAL CLIENTHELLO PARSING
%%%-----------------------------------------------------------------------------
-spec client_hello_key_share(binary() | undefined) ->
    {ok, binary()} | {error, nquic_error:any_reason()}.
client_hello_key_share(undefined) ->
    {error, key_share_not_found};
client_hello_key_share(Bin) ->
    find_x25519(Bin).

-spec client_hello_quic_params(
    {ok, nquic_transport:params()} | {error, nquic_error:any_reason()}
) ->
    {ok, nquic_transport:params()} | {error, nquic_error:any_reason()}.
client_hello_quic_params({ok, P}) ->
    {ok, P};
client_hello_quic_params({error, {tls_alert, _} = Alert}) ->
    {error, Alert};
client_hello_quic_params({error, Reason}) ->
    {error, {transport_parameter_error, Reason}}.

-spec find_alpn(map()) -> [binary()] | undefined.
find_alpn(ExtMap) ->
    case maps:get(16, ExtMap, undefined) of
        undefined -> undefined;
        Bin -> parse_alpn_list(Bin)
    end.

-spec find_cipher_match([atom()], [atom()]) -> atom() | undefined.
find_cipher_match([], _) ->
    undefined;
find_cipher_match([C | Rest], ClientCiphers) ->
    case lists:member(C, ClientCiphers) of
        true -> C;
        false -> find_cipher_match(Rest, ClientCiphers)
    end.

-spec find_match([binary()], [binary()]) -> binary() | undefined.
find_match([], _) ->
    undefined;
find_match([P | Rest], ServerProtos) ->
    case lists:member(P, ServerProtos) of
        true -> P;
        false -> find_match(Rest, ServerProtos)
    end.

-spec find_x25519(binary()) ->
    {ok, binary()} | {error, nquic_error:any_reason()}.
find_x25519(<<VecLen:16, Rest/binary>>) when byte_size(Rest) == VecLen ->
    find_x25519_in_vector(Rest);
find_x25519(_) ->
    {error, invalid_key_share_format}.

-spec find_x25519_in_vector(binary()) ->
    {ok, binary()} | {error, nquic_error:any_reason()}.
find_x25519_in_vector(<<>>) ->
    {error, x25519_not_found};
find_x25519_in_vector(<<Group:16, Len:16, Key:Len/binary, Rest/binary>>) ->
    case Group of
        16#001d -> {ok, Key};
        _ -> find_x25519_in_vector(Rest)
    end.

-spec parse_alpn_items(binary()) -> [binary()].
parse_alpn_items(<<>>) -> [];
parse_alpn_items(<<Len:8, Proto:Len/binary, Rest/binary>>) -> [Proto | parse_alpn_items(Rest)].

-spec parse_alpn_list(binary()) -> [binary()].
parse_alpn_list(<<Len:16, Rest/binary>>) when byte_size(Rest) == Len ->
    parse_alpn_items(Rest).

-spec parse_cipher_suites(binary()) -> [aes_128_gcm | aes_256_gcm | chacha20_poly1305].
parse_cipher_suites(<<>>) ->
    [];
parse_cipher_suites(<<Suite:2/binary, Rest/binary>>) ->
    case Suite of
        <<19, 1>> -> [aes_128_gcm | parse_cipher_suites(Rest)];
        <<19, 2>> -> [aes_256_gcm | parse_cipher_suites(Rest)];
        <<19, 3>> -> [chacha20_poly1305 | parse_cipher_suites(Rest)];
        _ -> parse_cipher_suites(Rest)
    end.

-spec parse_client_hello(binary()) ->
    {ok, binary(), binary(), nquic_transport:params(), [binary()] | undefined,
        [aes_128_gcm | aes_256_gcm | chacha20_poly1305], map() | undefined}
    | {error, nquic_error:any_reason()}.
parse_client_hello(<<Type:8, Len:24, Body:Len/binary>>) when Type =:= 1 ->
    <<_Version:2/binary, _Random:32/binary, Rest1/binary>> = Body,
    {SessionID, Rest2} = nquic_tls:parse_vec8(Rest1),
    {CipherSuitesBin, Rest3} = nquic_tls:parse_vec16(Rest2),
    {_CompMethods, Rest4} = nquic_tls:parse_vec8(Rest3),
    <<ExtLen:16, ExtData:ExtLen/binary>> = Rest4,
    ExtMap = nquic_tls:parse_extensions_recursive(ExtData),

    maybe
        {ok, KeyShare} ?= client_hello_key_share(maps:get(51, ExtMap, undefined)),
        {ok, TP} ?= client_hello_quic_params(nquic_tls:find_quic_params(ExtMap, client)),

        ALPN = find_alpn(ExtMap),

        Ciphers = parse_cipher_suites(CipherSuitesBin),

        PSKData = nquic_tls:parse_psk_extension(ExtMap),
        HasDHEKE = nquic_tls:has_psk_dhe_ke_mode(ExtMap),
        HasEarlyData = maps:is_key(42, ExtMap),

        PSKInfo =
            case {PSKData, HasDHEKE} of
                {{ok, Identities, Binders}, true} ->
                    #{identities => Identities, binders => Binders, early_data => HasEarlyData};
                _ ->
                    undefined
            end,

        {ok, SessionID, KeyShare, TP, ALPN, Ciphers, PSKInfo}
    end;
parse_client_hello(_) ->
    {error, invalid_client_hello}.

-spec select_alpn([binary()] | undefined, [binary()] | undefined) ->
    {ok, binary() | undefined} | {error, nquic_error:any_reason()}.
select_alpn(_, undefined) ->
    {ok, undefined};
select_alpn(undefined, _ServerProtos) ->
    {error, {tls_alert, no_application_protocol}};
select_alpn([], _ServerProtos) ->
    {error, {tls_alert, no_application_protocol}};
select_alpn(ClientProtos, ServerProtos) ->
    case find_match(ClientProtos, ServerProtos) of
        undefined ->
            {error, {tls_alert, no_application_protocol}};
        Match ->
            {ok, Match}
    end.

-spec select_cipher([aes_128_gcm | aes_256_gcm | chacha20_poly1305]) ->
    {ok, aes_128_gcm | aes_256_gcm | chacha20_poly1305}
    | {error, nquic_error:any_reason()}.
select_cipher(ClientCiphers) ->
    select_cipher(ClientCiphers, undefined).

-spec select_cipher(
    [aes_128_gcm | aes_256_gcm | chacha20_poly1305],
    [aes_128_gcm | aes_256_gcm | chacha20_poly1305] | undefined
) ->
    {ok, aes_128_gcm | aes_256_gcm | chacha20_poly1305}
    | {error, nquic_error:any_reason()}.
select_cipher(ClientCiphers, undefined) ->
    select_cipher(ClientCiphers, [aes_128_gcm, aes_256_gcm, chacha20_poly1305]);
select_cipher(ClientCiphers, Preferred) when is_list(Preferred), Preferred =/= [] ->
    case find_cipher_match(Preferred, ClientCiphers) of
        undefined -> {error, {tls_alert, handshake_failure}};
        Cipher -> {ok, Cipher}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL PSK IDENTITY VALIDATION
%%%-----------------------------------------------------------------------------
-spec compute_binders_wire_len([binary()]) -> non_neg_integer().
compute_binders_wire_len(Binders) ->
    ContentLen = lists:foldl(fun(B, Acc) -> Acc + 1 + byte_size(B) end, 0, Binders),
    erlang:floor(2 + ContentLen).

-spec validate_psk_identities(
    [{binary(), non_neg_integer()}],
    [binary()],
    binary(),
    binary(),
    atom(),
    boolean()
) -> {ok, binary(), atom(), boolean(), binary()} | {error, term()}.
validate_psk_identities([], _, _, _, _, _) ->
    {error, no_matching_psk};
validate_psk_identities(
    [{Identity, _ObfAge} | RestIds],
    [Binder | RestBinders],
    ClientHelloBin,
    StaticKey,
    NegCipher,
    HasEarlyData
) ->
    case nquic_tls:decrypt_ticket(Identity, StaticKey) of
        {ok, PSK, TicketCipher} ->
            case TicketCipher =:= NegCipher of
                false ->
                    validate_psk_identities(
                        RestIds,
                        RestBinders,
                        ClientHelloBin,
                        StaticKey,
                        NegCipher,
                        HasEarlyData
                    );
                true ->
                    Hash = nquic_keys:cipher_to_hash(NegCipher),
                    HashLen = nquic_tls:hash_length(Hash),
                    BindersLen = compute_binders_wire_len(
                        [Binder | RestBinders]
                    ),
                    PartialCH = nquic_tls:extract_partial_client_hello(
                        ClientHelloBin, BindersLen
                    ),
                    case nquic_tls:verify_psk_binder(PSK, PartialCH, Binder, Hash, HashLen) of
                        ok ->
                            {ok, PSK, TicketCipher, HasEarlyData, Identity};
                        {error, _} ->
                            {error, binder_verification_failed}
                    end
            end;
        {error, _} ->
            validate_psk_identities(
                RestIds,
                RestBinders,
                ClientHelloBin,
                StaticKey,
                NegCipher,
                HasEarlyData
            )
    end;
validate_psk_identities(_, _, _, _, _, _) ->
    {error, psk_identity_binder_mismatch}.
