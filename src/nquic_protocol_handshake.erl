-module(nquic_protocol_handshake).
-moduledoc """
TLS 1.3 handshake driver for the QUIC protocol state.

Pure functions over `#conn_state{}` covering the QUIC half of the
handshake (RFC 9001 §4 client initiation, §6 secret installation,
§4.1 CRYPTO buffering and dispatch, §8.3 0-RTT acceptance, RFC 8446
§4.6.1 NewSessionTicket emission). The TLS 1.3 message construction
itself lives in `nquic_tls_client` / `nquic_tls_server` (with shared
codec helpers in `nquic_tls`); this module owns the QUIC-side wiring:
key installation, transport-parameter validation, packet number space
initialisation, CRYPTO fragment reassembly, and event emission.

Extracted from `nquic_protocol` as part of REVIEW_PLAN.md Phase 4.4.
The trunk still owns Version Negotiation and Retry orchestration, plus
the public dispatchers; both call back into this module.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
-export([start_client_handshake/1]).

-export([
    buffer_crypto/4,
    discard_handshake_keys/1,
    discard_initial_keys/1,
    process_handshake_crypto_client/2,
    process_handshake_crypto_server/2,
    process_initial_crypto_client/2,
    process_initial_crypto_server/2
]).

-export([
    install_app_keys/3,
    install_handshake_keys/3
]).

-export([
    apply_server_compat_version_switch/2,
    select_server_compat_version/3,
    validate_retry_scid/2,
    validate_version_info/2
]).

-export([
    gate_zero_rtt_replay/2,
    queue_new_session_ticket/4,
    try_psk_resumption/3
]).

-export([preferred_address_event/1]).

-export([load_certs/2]).

-export([make_client_hello_maybe_psk/4, make_client_hello_maybe_psk/5]).

%%%-----------------------------------------------------------------------------
%% CLIENT-SIDE HANDSHAKE INITIATION (RFC 9001 4)
%%%-----------------------------------------------------------------------------
-spec make_client_hello_maybe_psk(
    #transport_params{},
    [binary()] | undefined,
    string() | binary() | undefined,
    map() | undefined
) -> {ok, binary(), map()} | {error, term()}.
make_client_hello_maybe_psk(Params, ALPN, Hostname, Ticket) ->
    make_client_hello_maybe_psk(Params, ALPN, Hostname, Ticket, undefined).

-spec make_client_hello_maybe_psk(
    #transport_params{},
    [binary()] | undefined,
    string() | binary() | undefined,
    map() | undefined,
    [aes_128_gcm | aes_256_gcm | chacha20_poly1305] | undefined
) -> {ok, binary(), map()} | {error, term()}.
make_client_hello_maybe_psk(Params, ALPN, Hostname, undefined, CipherSuites) ->
    nquic_tls_client:make_client_hello(Params, ALPN, Hostname, CipherSuites);
make_client_hello_maybe_psk(Params, ALPN, Hostname, Ticket, CipherSuites) ->
    #{psk := PSK, cipher := Cipher} = Ticket,
    PSKInfo = #{psk => PSK, ticket => Ticket, cipher => Cipher},
    nquic_tls_client:make_client_hello_psk(Params, ALPN, Hostname, PSKInfo, CipherSuites).

-spec maybe_seed_remote_params(map() | undefined, nquic_protocol:state()) ->
    nquic_protocol:state().
maybe_seed_remote_params(undefined, State) ->
    State;
maybe_seed_remote_params(Ticket, State) when is_map(Ticket) ->
    case maps:get(remote_params, Ticket, undefined) of
        undefined ->
            State;
        #transport_params{} = Cached ->
            Sanitised = sanitise_remembered_params(Cached),
            State1 = State#conn_state{remote_params = Sanitised},
            nquic_flow:init_conn_limits(State1)
    end.

-spec sanitise_remembered_params(#transport_params{}) -> #transport_params{}.
sanitise_remembered_params(#transport_params{} = TP) ->
    TP#transport_params{
        original_destination_connection_id = undefined,
        initial_source_connection_id = undefined,
        retry_source_connection_id = undefined,
        preferred_address = undefined,
        stateless_reset_token = undefined
    }.

-doc """
Begin a client handshake.
Generates the ClientHello (with optional PSK / 0-RTT material when a
session ticket is configured), derives Initial-space packet protection
keys, optionally installs 0-RTT keys, initialises the Initial packet
number space, and queues the ClientHello as an Initial-space CRYPTO
frame for the next `flush/1`. The caller is responsible for flushing
the queue and transmitting the resulting datagram.
Used by the gen_statem wrapper at handshake start, and re-used by the
Version Negotiation handler in `nquic_protocol` when restarting under
a new version.
""".
-spec start_client_handshake(nquic_protocol:state()) -> {ok, nquic_protocol:state()}.
start_client_handshake(State) ->
    #conn_state{
        dcid = DCID,
        local_params = Params,
        version = Version,
        crypto = #conn_crypto{
            alpn = ALPN,
            hostname = Hostname,
            session_ticket = SessionTicket,
            cipher_suites = CipherSuites
        }
    } = State,
    {ok, CHBin, TLSState} = make_client_hello_maybe_psk(
        Params, ALPN, Hostname, SessionTicket, CipherSuites
    ),
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DCID, Version),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientSecret, aes_128_gcm, Version),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerSecret, aes_128_gcm, Version),
    ClientRoleKeys = nquic_keys:make_role_keys(aes_128_gcm, CKey, CIV, CHP),
    ServerRoleKeys = nquic_keys:make_role_keys(aes_128_gcm, SKey, SIV, SHP),
    Keys0 = #{
        initial => #{
            client => ClientRoleKeys,
            server => ServerRoleKeys
        }
    },
    {Keys, Cipher} =
        case maps:get(psk, TLSState, undefined) of
            undefined ->
                {Keys0, aes_128_gcm};
            PSK ->
                PSKCipher = maps:get(cipher, TLSState, aes_128_gcm),
                Hash = nquic_keys:cipher_to_hash(PSKCipher),
                CHHash = crypto:hash(Hash, CHBin),
                EarlySecret = nquic_keys:early_secrets(PSK, CHHash, Hash),
                {EKey, EIV, EHP} = nquic_keys:derive_packet_protection(
                    EarlySecret, PSKCipher, Version
                ),
                ZeroRTTKeys = #{
                    client => nquic_keys:make_role_keys(PSKCipher, EKey, EIV, EHP)
                },
                {Keys0#{rtt0 => ZeroRTTKeys}, PSKCipher}
        end,
    Crypto0 = State#conn_state.crypto,
    NewCrypto = Crypto0#conn_crypto{
        tls_state = TLSState#{client_hello => CHBin, quic_version => Version},
        keys = Keys,
        cipher = Cipher
    },
    State1 = State#conn_state{
        crypto = NewCrypto,
        pn_spaces = #{initial => #{next_pn => 0}}
    },
    State2 = maybe_seed_remote_params(SessionTicket, State1),
    nquic_protocol_send_queues:queue_initial_frame(#crypto{offset = 0, data = CHBin}, State2).

%%%-----------------------------------------------------------------------------
%% CRYPTO BUFFERING AND PROCESSING (RFC 9001 4 1, 6)
%%%-----------------------------------------------------------------------------
-spec buffer_crypto(nquic_packet:space(), non_neg_integer(), binary(), nquic_protocol:state()) ->
    {binary(), nquic_protocol:state()}.
buffer_crypto(Space, Offset, CryptoData, State) ->
    #conn_state{crypto = Crypto0} = State,
    Buffers = Crypto0#conn_crypto.crypto_buffer,
    CurrentBuf = maps:get(Space, Buffers, {0, <<>>, []}),
    NewBufEntry = nquic_protocol_recv:crypto_buffer_add(Offset, CryptoData, CurrentBuf),
    NewBuf = nquic_protocol_recv:crypto_buffer_data(NewBufEntry),
    NewBuffers = Buffers#{Space => NewBufEntry},
    State1 = State#conn_state{crypto = Crypto0#conn_crypto{crypto_buffer = NewBuffers}},
    {NewBuf, State1}.

-spec build_server_flight(
    boolean(),
    {ok, binary(), atom(), boolean(), binary()} | term(),
    binary(),
    map(),
    map(),
    nquic_protocol:state()
) -> {ok, binary(), map(), map()} | {error, term()}.
build_server_flight(true, {ok, _PSK, _Cipher, AcceptEarlyData, _Id}, HSSecret, Keys, TLS, _State) ->
    nquic_tls_server:make_server_handshake_flight_psk(HSSecret, Keys, TLS, AcceptEarlyData);
build_server_flight(_IsPSK, _PSKResult, HSSecret, Keys, TLS, State) ->
    Crypto = State#conn_state.crypto,
    nquic_tls_server:make_server_handshake_flight(
        HSSecret,
        Keys,
        TLS,
        Crypto#conn_crypto.cert,
        Crypto#conn_crypto.cert_chain,
        Crypto#conn_crypto.key
    ).

-spec classify_check_handshake(
    ok | {error, nquic_error:any_reason()}, binary(), nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, nquic_error:any_reason(), nquic_protocol:state()}.
classify_check_handshake({error, TLSError}, _NewBuf, State) ->
    {error, {transport_error, TLSError}, State};
classify_check_handshake(ok, NewBuf, State) ->
    #conn_state{crypto = #conn_crypto{tls_state = TLSState, cipher = VerifyCipher}} = State,
    ClientSecret = maps:get(client_secret, TLSState),
    TranscriptCtx = maps:get(transcript_ctx, TLSState),
    classify_verify_finished(
        nquic_tls_server:verify_client_finished(
            NewBuf, ClientSecret, TranscriptCtx, VerifyCipher
        ),
        NewBuf,
        TranscriptCtx,
        TLSState,
        State
    ).

-spec classify_client_hello(
    {ok, binary(), map(), map()} | {error, term()}, binary(), nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
classify_client_hello({ok, ServerHelloBin, Keys, TLSState1}, NewBuf, State) ->
    process_initial_crypto_server_step1(NewBuf, ServerHelloBin, Keys, TLSState1, State);
classify_client_hello({error, {transport_parameter_error, _}}, _NewBuf, State) ->
    {error, {transport_error, transport_parameter_error}, State};
classify_client_hello({error, {tls_alert, _} = TLSError}, _NewBuf, State) ->
    {error, {transport_error, TLSError}, State};
classify_client_hello({error, _Reason}, _NewBuf, State) ->
    {ok, [], State}.

-spec classify_handshake_messages(
    {ok, map()} | {error, term()}, binary() | undefined, map(), nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
classify_handshake_messages({ok, IntermediateKeys}, HandshakeSecret, TLSState, State) ->
    process_handshake_crypto_client_finalize(IntermediateKeys, HandshakeSecret, TLSState, State);
classify_handshake_messages({error, {transport_parameter_error, _}}, _, _, State) ->
    {error, {transport_error, transport_parameter_error}, State};
classify_handshake_messages({error, {tls_alert, _} = TLSError}, _, _, State) ->
    {error, {transport_error, TLSError}, State};
classify_handshake_messages({error, Reason}, _, _, State) when
    Reason =:= finished_not_found; Reason =:= incomplete_handshake_message
->
    {ok, [], State};
classify_handshake_messages({error, Reason}, _, _, State) ->
    {error, {handshake_error, Reason}, State}.

-spec classify_verify_finished(
    ok | {error, term()}, binary(), crypto:hash_state(), map(), nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
classify_verify_finished(ok, NewBuf, TranscriptCtx, TLSState, State) ->
    process_handshake_crypto_server_finalize(NewBuf, TranscriptCtx, TLSState, State);
classify_verify_finished({error, malformed_finished}, _, _, _, State) ->
    {ok, [], State};
classify_verify_finished({error, Reason}, _, _, _, State) ->
    {error, {handshake_error, Reason}, State}.

-doc """
Discard Handshake-level keys and state once the handshake is confirmed.
RFC 9001 §4.9.2 / RFC 9000 §4.1.2: the client confirms the handshake on
receipt of a HANDSHAKE_DONE frame, after which Handshake keys MUST be
discarded. Dropping the keyring entry makes any retransmitted
Handshake-level packet fail to decrypt and be dropped, rather than
re-entering TLS handshake processing with a torn-down `tls_state`.
""".
-spec discard_handshake_keys(nquic_protocol:state()) -> nquic_protocol:state().
discard_handshake_keys(#conn_state{crypto = Crypto} = State) ->
    NewCrypto = Crypto#conn_crypto{
        keys = maps:remove(handshake, Crypto#conn_crypto.keys),
        crypto_buffer = maps:remove(handshake, Crypto#conn_crypto.crypto_buffer)
    },
    LossState = nquic_loss:clear_handshake_spaces(State#conn_state.loss_state),
    State#conn_state{crypto = NewCrypto, loss_state = LossState}.

-doc """
Discard Initial-level keys and state.
RFC 9001 §4.9.1: the client MUST discard Initial keys when it first
sends a Handshake packet. The server MUST discard Initial keys when
it first successfully processes a Handshake packet. After discard,
the endpoint MUST NOT send or process Initial packets. Dropping the
keyring entry makes any later Initial packet fail to decrypt and be
silently dropped via the existing decrypt-error path.
""".
-spec discard_initial_keys(nquic_protocol:state()) -> nquic_protocol:state().
discard_initial_keys(#conn_state{crypto = Crypto, pn_spaces = PnSpaces} = State) ->
    NewCrypto = Crypto#conn_crypto{
        keys = maps:remove(initial, Crypto#conn_crypto.keys),
        crypto_buffer = maps:remove(initial, Crypto#conn_crypto.crypto_buffer)
    },
    LossState = nquic_loss:clear_initial_space(State#conn_state.loss_state),
    State#conn_state{
        crypto = NewCrypto,
        loss_state = LossState,
        pn_spaces = maps:remove(initial, PnSpaces)
    }.

-spec dispatch_after_compat_version(
    binary(), binary(), map(), map(), #transport_params{} | undefined, nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
dispatch_after_compat_version(NewBuf, ServerHelloBin, Keys, TLSState1, RemoteParams, State) ->
    Selection = select_server_compat_version(
        RemoteParams,
        State#conn_state.version_preference,
        State#conn_state.version
    ),
    case Selection of
        no_switch ->
            dispatch_version_check(
                ok, NewBuf, ServerHelloBin, Keys, TLSState1, RemoteParams, State
            );
        {switch, NewVersion} ->
            State1 = apply_server_compat_version_switch(NewVersion, State),
            replay_after_compat_version_switch(NewBuf, RemoteParams, State1)
    end.

-spec dispatch_version_check(
    ok | {error, term()},
    binary(),
    binary(),
    map(),
    map(),
    #transport_params{} | undefined,
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
dispatch_version_check({error, _}, _NewBuf, _SHBin, _Keys, _TLSState, _RemoteParams, State) ->
    {error, {transport_error, version_negotiation_error}, State};
dispatch_version_check(ok, NewBuf, ServerHelloBin, Keys, TLSState1, RemoteParams, State) ->
    NegCipher = maps:get(cipher, Keys, aes_128_gcm),
    PSKResult = gate_zero_rtt_replay(try_psk_resumption(TLSState1, State, NegCipher), State),
    {SHBin, FinalKeys, FinalTLS, IsPSK} = pick_server_flight_inputs(
        PSKResult, NewBuf, ServerHelloBin, Keys, TLSState1, State
    ),
    process_initial_crypto_server_step2(
        NewBuf, SHBin, FinalKeys, FinalTLS, IsPSK, NegCipher, RemoteParams, PSKResult, State
    ).

-spec finalize_client_established(binary(), boolean(), nquic_protocol:state()) ->
    nquic_protocol:state().
finalize_client_established(ResSecret, ZeroRTTOk, State) ->
    Crypto = State#conn_state.crypto,
    NewCrypto = Crypto#conn_crypto{
        tls_state = undefined,
        zero_rtt_accepted = ZeroRTTOk,
        resumption_secret = ResSecret,
        crypto_buffer = #{}
    },
    Path = State#conn_state.path,
    LossState = nquic_loss:clear_handshake_spaces(State#conn_state.loss_state),
    State#conn_state{
        crypto = NewCrypto,
        path = Path#conn_path_mgmt{address_validated = true},
        loss_state = LossState
    }.

-spec finalize_server_established(nquic_protocol:state()) -> nquic_protocol:state().
finalize_server_established(State) ->
    Crypto = State#conn_state.crypto,
    NewCrypto = Crypto#conn_crypto{crypto_buffer = #{}, tls_state = undefined},
    Path = State#conn_state.path,
    LossState = nquic_loss:clear_handshake_spaces(State#conn_state.loss_state),
    State#conn_state{
        crypto = NewCrypto,
        path = Path#conn_path_mgmt{address_validated = true},
        loss_state = LossState
    }.

-spec finalize_server_step2(
    {ok, binary(), map(), map()} | {error, term()},
    binary(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    {ok, binary(), atom(), boolean(), binary()} | term(),
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
finalize_server_step2({ok, FlightBin, AppKeys, TLSState2}, NewBuf, NegCipher, PSKResult, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_handshake_frame(
        #crypto{offset = 0, data = FlightBin}, State
    ),
    State2 = maybe_install_zero_rtt_psk(PSKResult, NewBuf, NegCipher, State1),
    State3 = install_server_app_keys(AppKeys, NegCipher, TLSState2, PSKResult, State2),
    {ok, [{state_transition, handshake}], State3};
finalize_server_step2(Error, _NewBuf, _NegCipher, _PSKResult, State) ->
    {error, Error, State}.

-spec handle_client_finished(
    {ok, binary(), map(), map()} | {error, term()},
    map(),
    binary() | undefined,
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_client_finished({ok, FinBin, AppKeys, _TLSState2}, IntermediateKeys, HandshakeSecret, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_handshake_frame(
        #crypto{offset = 0, data = FinBin}, State
    ),
    Buffers = (State1#conn_state.crypto)#conn_crypto.crypto_buffer,
    install_client_app_state(
        install_app_keys(AppKeys, State1, Buffers),
        FinBin,
        IntermediateKeys,
        HandshakeSecret,
        State1
    );
handle_client_finished(Error, _IntermediateKeys, _HandshakeSecret, State) ->
    {error, Error, State}.

-spec handle_initial_client(boolean(), binary(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_initial_client(true, _NewBuf, State) ->
    {ok, [], State};
handle_initial_client(false, NewBuf, State) ->
    #conn_state{crypto = #conn_crypto{tls_state = TLSState, crypto_buffer = Buffers}} = State,
    ClientHello = maps:get(client_hello, TLSState, undefined),
    case nquic_tls_client:process_server_hello(NewBuf, ClientHello, TLSState) of
        {ok, Keys} ->
            {ok, State1} = install_handshake_keys(Keys, State, Buffers),
            {ok, [], State1};
        {error, _} ->
            {ok, [], State}
    end.

-spec handle_initial_server(boolean(), binary(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_initial_server(true, _NewBuf, State) ->
    {ok, [], State};
handle_initial_server(false, NewBuf, State) ->
    #conn_state{
        crypto = #conn_crypto{alpn = ALPN, cipher_suites = CipherSuites},
        local_params = Params,
        version = Version
    } = State,
    Opts = (cipher_opts(CipherSuites))#{quic_version => Version},
    classify_client_hello(
        nquic_tls_server:process_client_hello(NewBuf, Params, ALPN, Opts),
        NewBuf,
        State
    ).

-spec install_client_app_state(
    {ok, nquic_protocol:state()} | {error, term()},
    binary(),
    map(),
    binary() | undefined,
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
install_client_app_state({error, Reason}, _FinBin, _IK, _HSSecret, State) ->
    {error, {handshake_error, Reason}, State};
install_client_app_state({ok, State}, FinBin, IntermediateKeys, HandshakeSecret, _Prev) ->
    PreClientFinCtx = maps:get(transcript_ctx, IntermediateKeys),
    ResSecret = nquic_tls:derive_resumption_secret(
        HandshakeSecret,
        PreClientFinCtx,
        FinBin,
        (State#conn_state.crypto)#conn_crypto.cipher
    ),
    ZeroRTTOk = maps:get(zero_rtt_accepted, IntermediateKeys, false),
    State1 = finalize_client_established(ResSecret, ZeroRTTOk, State),
    {ok, State2} = maybe_issue_spare_cids(State1),
    Events = [connected, {state_transition, established} | preferred_address_event(State2)],
    {ok, Events, State2}.

-spec install_server_app_keys(
    map(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    map(),
    {ok, binary(), atom(), boolean(), binary()} | term(),
    nquic_protocol:state()
) -> nquic_protocol:state().
install_server_app_keys(AppKeys, NegCipher, TLSState2, PSKResult, State) ->
    Crypto = State#conn_state.crypto,
    AppRoleKeys = nquic_handshake:format_keys(AppKeys, NegCipher),
    {SendKeys, RecvKeys} = nquic_keys:resolve_role_keys(server, AppRoleKeys),
    NewCrypto = Crypto#conn_crypto{
        tls_state = TLSState2,
        keys = (Crypto#conn_crypto.keys)#{application => AppRoleKeys},
        app_send_keys = SendKeys,
        app_recv_keys = RecvKeys,
        client_app_secret = maps:get(client_secret, AppKeys, undefined),
        server_app_secret = maps:get(server_secret, AppKeys, undefined),
        zero_rtt_accepted = zero_rtt_accepted(PSKResult)
    },
    State#conn_state{
        crypto = NewCrypto,
        pn_spaces = (State#conn_state.pn_spaces)#{application => #{}}
    }.

-spec install_server_handshake_state(
    map(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    map(),
    #transport_params{} | undefined,
    nquic_protocol:state()
) -> nquic_protocol:state().
install_server_handshake_state(FinalTLS, NegCipher, FinalKeys, RemoteParams, State) ->
    Crypto0 = State#conn_state.crypto,
    Buffers = Crypto0#conn_crypto.crypto_buffer,
    CryptoPre = Crypto0#conn_crypto{
        tls_state = FinalTLS,
        cipher = NegCipher,
        keys = (Crypto0#conn_crypto.keys)#{
            handshake => nquic_handshake:format_keys(FinalKeys, NegCipher)
        },
        crypto_buffer = Buffers#{initial => {0, <<>>, []}}
    },
    State2pre = State#conn_state{
        remote_params = RemoteParams,
        crypto = CryptoPre,
        pn_spaces = (State#conn_state.pn_spaces)#{handshake => #{next_pn => 0}}
    },
    nquic_flow:init_conn_limits(State2pre).

-spec maybe_install_zero_rtt_psk(
    {ok, binary(), atom(), boolean(), binary()} | term(),
    binary(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    nquic_protocol:state()
) -> nquic_protocol:state().
maybe_install_zero_rtt_psk({ok, PSK, _Cipher, _AcceptEarlyData, _Id}, NewBuf, NegCipher, State) ->
    Hash = nquic_keys:cipher_to_hash(NegCipher),
    CHHash = crypto:hash(Hash, NewBuf),
    nquic_protocol_zero_rtt:install_zero_rtt_keys_psk(PSK, CHHash, NegCipher, State);
maybe_install_zero_rtt_psk(_PSKResult, _NewBuf, _NegCipher, State) ->
    State.

-spec maybe_issue_spare_cids(nquic_protocol:state()) -> {ok, nquic_protocol:state()}.
maybe_issue_spare_cids(#conn_state{proactive_cids = true} = State) ->
    nquic_protocol_cid:issue_spare_cids(State);
maybe_issue_spare_cids(State) ->
    {ok, State}.

-spec pick_server_flight_inputs(
    {ok, binary(), atom(), boolean(), binary()} | term(),
    binary(),
    binary(),
    map(),
    map(),
    nquic_protocol:state()
) -> {binary(), map(), map(), boolean()}.
pick_server_flight_inputs(
    {ok, PSKVal, _Cipher, _AcceptEarlyData, _Identity},
    NewBuf,
    _ServerHelloBin,
    _Keys,
    _TLSState1,
    State
) ->
    #conn_state{
        local_params = Params,
        crypto = #conn_crypto{alpn = ALPN, cipher_suites = CipherSuites},
        version = Version
    } = State,
    Opts = (cipher_opts(CipherSuites))#{
        psk_selected => 0, psk_value => PSKVal, quic_version => Version
    },
    {ok, SH2, K2, T2} = nquic_tls_server:process_client_hello(NewBuf, Params, ALPN, Opts),
    {SH2, K2, T2, true};
pick_server_flight_inputs(_NotAccepted, _NewBuf, ServerHelloBin, Keys, TLSState1, _State) ->
    {ServerHelloBin, Keys, TLSState1, false}.

-spec preferred_address_event(nquic_protocol:state()) -> [nquic_protocol:event()].
preferred_address_event(#conn_state{role = client, remote_params = RP}) when
    RP =/= undefined
->
    case RP#transport_params.preferred_address of
        undefined -> [];
        PA -> [{migrate_to_preferred, PA}]
    end;
preferred_address_event(_) ->
    [].

-spec process_handshake_crypto_client(binary(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_handshake_crypto_client(
    _NewBuf, #conn_state{crypto = #conn_crypto{tls_state = undefined}} = State
) ->
    {ok, [], State};
process_handshake_crypto_client(NewBuf, State) ->
    #conn_state{crypto = #conn_crypto{tls_state = TLSState}} = State,
    HandshakeSecret = maps:get(handshake_secret, TLSState, undefined),
    TLSStateWithVerify = tls_state_with_verify(State, TLSState),
    PSKAccepted = maps:get(psk_accepted, TLSState, false),
    Result = process_handshake_messages(PSKAccepted, NewBuf, HandshakeSecret, TLSStateWithVerify),
    classify_handshake_messages(Result, HandshakeSecret, TLSState, State).

-spec process_handshake_crypto_client_finalize(
    map(), binary() | undefined, map(), nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_handshake_crypto_client_finalize(
    IntermediateKeys, HandshakeSecret, TLSState, State
) ->
    State1 = store_peer_cert(IntermediateKeys, State),
    ClientSecret = maps:get(client_secret, TLSState),
    InputKeys = IntermediateKeys#{client_secret => ClientSecret},
    handle_client_finished(
        nquic_tls_client:make_client_finished(HandshakeSecret, InputKeys),
        IntermediateKeys,
        HandshakeSecret,
        State1
    ).

-spec process_handshake_crypto_server(binary(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_handshake_crypto_server(
    _NewBuf, #conn_state{crypto = #conn_crypto{tls_state = undefined}} = State
) ->
    {ok, [], State};
process_handshake_crypto_server(NewBuf, State) ->
    classify_check_handshake(nquic_frame_handler:check_handshake_crypto(NewBuf), NewBuf, State).

-spec process_handshake_crypto_server_finalize(
    binary(), crypto:hash_state(), map(), nquic_protocol:state()
) -> {ok, [nquic_protocol:event()], nquic_protocol:state()}.
process_handshake_crypto_server_finalize(NewBuf, TranscriptCtx, TLSState, State) ->
    State1 = queue_handshake_ack(
        nquic_protocol_ack:build_ack_for_space(handshake, State), State
    ),
    {ok, State2} = nquic_protocol_send_queues:queue_app_frame(#handshake_done{}, State1),
    HSSecret = maps:get(handshake_secret, TLSState),
    State3 = queue_new_session_ticket(HSSecret, TranscriptCtx, NewBuf, State2),
    State3a = queue_new_token(State3),
    State4 = finalize_server_established(State3a),
    {ok, State5} = nquic_protocol_cid:issue_spare_cids(State4),
    Events = [listener_established, connected, {state_transition, established}],
    {ok, Events, State5}.

-spec process_handshake_messages(boolean(), binary(), binary() | undefined, map()) ->
    {ok, map()} | {error, term()}.
process_handshake_messages(true, NewBuf, HandshakeSecret, TLSState) ->
    nquic_tls_client:process_handshake_messages_psk(NewBuf, HandshakeSecret, TLSState);
process_handshake_messages(false, NewBuf, HandshakeSecret, TLSState) ->
    nquic_tls_client:process_handshake_messages(NewBuf, HandshakeSecret, TLSState).

-spec process_initial_crypto_client(binary(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_initial_crypto_client(NewBuf, State) ->
    #conn_state{crypto = #conn_crypto{keys = KeyRing}} = State,
    handle_initial_client(maps:is_key(handshake, KeyRing), NewBuf, State).

-spec process_initial_crypto_server(binary(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_initial_crypto_server(NewBuf, State) ->
    #conn_state{crypto = #conn_crypto{keys = KeyRing}} = State,
    handle_initial_server(maps:is_key(handshake, KeyRing), NewBuf, State).

-spec process_initial_crypto_server_step1(
    binary(), binary(), map(), map(), nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_initial_crypto_server_step1(NewBuf, ServerHelloBin, Keys, TLSState1, State) ->
    RemoteParams = maps:get(remote_params, TLSState1, undefined),
    case validate_version_info(State, RemoteParams) of
        {error, _} = Err ->
            dispatch_version_check(
                Err, NewBuf, ServerHelloBin, Keys, TLSState1, RemoteParams, State
            );
        ok ->
            dispatch_after_compat_version(
                NewBuf, ServerHelloBin, Keys, TLSState1, RemoteParams, State
            )
    end.

-spec process_initial_crypto_server_step2(
    binary(),
    binary(),
    map(),
    map(),
    boolean(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    #transport_params{} | undefined,
    {ok, binary(), atom(), boolean(), binary()} | {error, term()},
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_initial_crypto_server_step2(
    NewBuf, SHBin, FinalKeys, FinalTLS, IsPSK, NegCipher, RemoteParams, PSKResult, State
) ->
    State2 = install_server_handshake_state(
        FinalTLS, NegCipher, FinalKeys, RemoteParams, State
    ),
    {ok, State2a} = nquic_protocol_send_queues:queue_initial_frame(
        #crypto{offset = 0, data = SHBin}, State2
    ),
    HSSecret = maps:get(handshake_secret, FinalKeys),
    FlightResult = build_server_flight(IsPSK, PSKResult, HSSecret, FinalKeys, FinalTLS, State),
    finalize_server_step2(FlightResult, NewBuf, NegCipher, PSKResult, State2a).

-spec queue_handshake_ack({ok, #ack{}} | none, nquic_protocol:state()) -> nquic_protocol:state().
queue_handshake_ack(none, State) ->
    State;
queue_handshake_ack({ok, AckFrame}, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_handshake_frame(AckFrame, State),
    State1.

-spec queue_new_token(nquic_protocol:state()) -> nquic_protocol:state().
queue_new_token(#conn_state{new_token_enabled = false} = State) ->
    State;
queue_new_token(#conn_state{crypto = #conn_crypto{static_key = undefined}} = State) ->
    State;
queue_new_token(
    #conn_state{
        crypto = #conn_crypto{static_key = StaticKey},
        peer = PeerAddr,
        new_token_lifetime = Lifetime
    } = State
) ->
    Token = nquic_new_token:generate(StaticKey, PeerAddr, Lifetime),
    {ok, State1} = nquic_protocol_send_queues:queue_app_frame(#new_token{token = Token}, State),
    State1.

-spec replay_after_compat_version_switch(
    binary(), #transport_params{} | undefined, nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
replay_after_compat_version_switch(NewBuf, RemoteParams, State) ->
    #conn_state{
        crypto = #conn_crypto{alpn = ALPN, cipher_suites = CipherSuites},
        local_params = Params,
        version = Version
    } = State,
    Opts = (cipher_opts(CipherSuites))#{quic_version => Version},
    case nquic_tls_server:process_client_hello(NewBuf, Params, ALPN, Opts) of
        {ok, SH2, K2, T2} ->
            dispatch_version_check(ok, NewBuf, SH2, K2, T2, RemoteParams, State);
        Err ->
            classify_client_hello(Err, NewBuf, State)
    end.

-spec store_peer_cert(map(), nquic_protocol:state()) -> nquic_protocol:state().
store_peer_cert(IntermediateKeys, State) ->
    PeerCert = maps:get(peer_cert, IntermediateKeys, undefined),
    Crypto = State#conn_state.crypto,
    State#conn_state{crypto = Crypto#conn_crypto{peer_cert = PeerCert}}.

-spec tls_state_with_verify(nquic_protocol:state(), map()) -> map().
tls_state_with_verify(
    #conn_state{
        crypto = #conn_crypto{verify = Verify, cacerts = CACerts, hostname = Hostname}
    },
    TLSState
) ->
    TLSState#{verify => Verify, cacerts => CACerts, hostname => Hostname}.

-spec zero_rtt_accepted({ok, binary(), atom(), boolean(), binary()} | dynamic()) -> boolean().
zero_rtt_accepted({ok, _, _, true, _}) -> true;
zero_rtt_accepted(_) -> false.

%%%-----------------------------------------------------------------------------
%% HANDSHAKE KEY INSTALLATION (RFC 9001 SECTIONS 4 6, 5)
%%%-----------------------------------------------------------------------------
-doc """
Install 1-RTT (application) packet protection keys.
Client-side also validates the peer's `retry_source_connection_id`
(RFC 9000 §7.3) and `version_information` (RFC 9369 §3) transport
parameters, initialises connection-level flow limits, and updates the
loss detector's max-datagram budget.
""".
-spec install_app_keys(map(), nquic_protocol:state(), map()) ->
    {ok, nquic_protocol:state()}
    | {error, {transport_parameter_error | version_negotiation_error, term()}}.
install_app_keys(Keys, State, Buffers) ->
    #{
        client_key := CK,
        client_iv := CIV,
        client_hp := CHP,
        server_key := SK,
        server_iv := SIV,
        server_hp := SHP,
        transcript_ctx := Trans
    } = Keys,

    ClientAppSecret = maps:get(client_secret, Keys, undefined),
    ServerAppSecret = maps:get(server_secret, Keys, undefined),

    Cipher = (State#conn_state.crypto)#conn_crypto.cipher,
    AppKeys = #{
        client => nquic_keys:make_role_keys(Cipher, CK, CIV, CHP),
        server => nquic_keys:make_role_keys(Cipher, SK, SIV, SHP)
    },

    NewKeys = ((State#conn_state.crypto)#conn_crypto.keys)#{application => AppKeys},

    {AppSendKeys, AppRecvKeys} = nquic_keys:resolve_role_keys(client, AppKeys),

    State2 =
        case maps:get(remote_params, Keys, undefined) of
            undefined ->
                State;
            RemoteParams ->
                maybe
                    ok ?= validate_retry_scid(State, RemoteParams),
                    ok ?= validate_version_info(State, RemoteParams),
                    D = State#conn_state{remote_params = RemoteParams},
                    D1 = nquic_flow:init_conn_limits(D),
                    MaxSize = RemoteParams#transport_params.max_udp_payload_size,
                    NewLoss = nquic_loss:set_max_datagram_size(
                        D1#conn_state.loss_state, MaxSize
                    ),
                    D1#conn_state{loss_state = NewLoss}
                end
        end,

    case State2 of
        {error, _} = RetryErr ->
            RetryErr;
        _ ->
            Crypto2 = State2#conn_state.crypto,
            NewCrypto = Crypto2#conn_crypto{
                keys = NewKeys,
                app_send_keys = AppSendKeys,
                app_recv_keys = AppRecvKeys,
                client_app_secret = ClientAppSecret,
                server_app_secret = ServerAppSecret,
                tls_state = (Crypto2#conn_crypto.tls_state)#{
                    transcript_ctx => Trans
                },
                crypto_buffer = Buffers#{handshake => {0, <<>>, []}}
            },
            State3 = State2#conn_state{
                crypto = NewCrypto,
                pn_spaces = (State#conn_state.pn_spaces)#{
                    application => #{}
                }
            },
            {ok, State3}
    end.

-doc """
Install Handshake-space packet protection keys derived from the TLS
handshake secret. Server-side also extracts the peer's transport
parameters (`remote_params`), initialises connection-level flow
limits, and updates the loss detector's max-datagram budget.
""".
-spec install_handshake_keys(map(), nquic_protocol:state(), map()) -> {ok, nquic_protocol:state()}.
install_handshake_keys(Keys, State, Buffers) ->
    #{
        client_key := CK,
        client_iv := CIV,
        client_hp := CHP,
        server_key := SK,
        server_iv := SIV,
        server_hp := SHP,
        handshake_secret := HS,
        server_secret := SS,
        client_secret := CS,
        transcript_ctx := Trans
    } = Keys,

    Cipher = maps:get(cipher, Keys, aes_128_gcm),

    HandshakeKeys = #{
        client => nquic_keys:make_role_keys(Cipher, CK, CIV, CHP),
        server => nquic_keys:make_role_keys(Cipher, SK, SIV, SHP)
    },

    NewKeys = ((State#conn_state.crypto)#conn_crypto.keys)#{handshake => HandshakeKeys},

    State2 =
        case maps:get(remote_params, Keys, undefined) of
            undefined ->
                State;
            RemoteParams ->
                D = State#conn_state{remote_params = RemoteParams},
                D1 = nquic_flow:init_conn_limits(D),
                MaxSize = RemoteParams#transport_params.max_udp_payload_size,
                NewLoss = nquic_loss:set_max_datagram_size(D1#conn_state.loss_state, MaxSize),
                D1#conn_state{loss_state = NewLoss}
        end,

    PSKAccepted = maps:get(psk_accepted, Keys, false),
    Crypto2 = State2#conn_state.crypto,
    NewCrypto = Crypto2#conn_crypto{
        cipher = Cipher,
        keys = NewKeys,
        tls_state = (Crypto2#conn_crypto.tls_state)#{
            handshake_secret => HS,
            server_secret => SS,
            client_secret => CS,
            transcript_ctx => Trans,
            cipher => Cipher,
            psk_accepted => PSKAccepted
        },
        crypto_buffer = Buffers#{initial => {0, <<>>, []}}
    },
    State3 = State2#conn_state{
        crypto = NewCrypto,
        pn_spaces = (State#conn_state.pn_spaces)#{
            handshake => #{next_pn => 0}
        }
    },
    {ok, State3}.

%%%-----------------------------------------------------------------------------
%% TRANSPORT PARAMETER VALIDATION
%%%-----------------------------------------------------------------------------
-doc """
Apply a Compatible Version Negotiation switch on the server side.
Rederives Initial-space packet protection keys against the wire DCID
used for the client's most recent Initial (the original DCID, or the
Retry-rewritten one when a Retry was issued), updates
`conn_state.version`, propagates the new version into the TLS state's
`quic_version` so subsequent handshake/app key derivations pick the
RFC 9369 labels, and rewrites the server's own
`version_information.chosen_version` so the outgoing EncryptedExtensions
TPs reflect the switch (RFC 9368 §4).
""".
-spec apply_server_compat_version_switch(
    non_neg_integer(), nquic_protocol:state()
) -> nquic_protocol:state().
apply_server_compat_version_switch(NewVersion, State) ->
    DCID = server_initial_key_dcid(State),
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DCID, NewVersion),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(
        ClientSecret, aes_128_gcm, NewVersion
    ),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(
        ServerSecret, aes_128_gcm, NewVersion
    ),
    NewInitial = #{
        client => nquic_keys:make_role_keys(aes_128_gcm, CKey, CIV, CHP),
        server => nquic_keys:make_role_keys(aes_128_gcm, SKey, SIV, SHP)
    },
    Crypto0 = State#conn_state.crypto,
    NewKeys = (Crypto0#conn_crypto.keys)#{initial => NewInitial},
    NewTLSState =
        case Crypto0#conn_crypto.tls_state of
            undefined -> undefined;
            TS -> TS#{quic_version => NewVersion}
        end,
    LocalParams0 = State#conn_state.local_params,
    OldVI = LocalParams0#transport_params.version_information,
    NewVI =
        case OldVI of
            undefined ->
                #{
                    chosen_version => NewVersion,
                    other_versions => State#conn_state.version_preference
                };
            #{} ->
                OldVI#{chosen_version => NewVersion}
        end,
    NewLocalParams = LocalParams0#transport_params{version_information = NewVI},
    State#conn_state{
        version = NewVersion,
        crypto = Crypto0#conn_crypto{keys = NewKeys, tls_state = NewTLSState},
        local_params = NewLocalParams
    }.

-spec compatible_versions(non_neg_integer(), non_neg_integer()) -> boolean().
compatible_versions(V, V) -> true;
compatible_versions(16#00000001, 16#6b3343cf) -> true;
compatible_versions(16#6b3343cf, 16#00000001) -> true;
compatible_versions(_, _) -> false.

-spec first_compat_version(
    [non_neg_integer()], [non_neg_integer()], non_neg_integer()
) -> non_neg_integer() | undefined.
first_compat_version([], _Others, _VInitial) ->
    undefined;
first_compat_version([V | Rest], Others, VInitial) ->
    Eligible =
        nquic_packet:is_supported_version(V) andalso
            lists:member(V, Others) andalso
            compatible_versions(V, VInitial),
    case Eligible of
        true -> V;
        false -> first_compat_version(Rest, Others, VInitial)
    end.

-doc """
Pure selection of a Compatible Version Negotiation target (RFC 9368 §4.1).
Walks the server's preference list and returns the first version that
is in the client's advertised `other_versions`, is supported locally,
and is compatible with `VInitial` (the version on the wire of the
client's first Initial). If that first match equals `VInitial`, or if
no version qualifies, the result is `no_switch`. The server MUST NOT
pick a version the client did not list.
`Preference` semantics: list order is preference order, first match
wins. The default `[1]` is the only-v1 / no-switch configuration.
""".
-spec select_server_compat_version(
    #transport_params{} | undefined,
    [non_neg_integer()],
    non_neg_integer()
) -> no_switch | {switch, non_neg_integer()}.
select_server_compat_version(undefined, _Pref, _VInitial) ->
    no_switch;
select_server_compat_version(#transport_params{version_information = undefined}, _Pref, _VInitial) ->
    no_switch;
select_server_compat_version(
    #transport_params{version_information = #{other_versions := Others}}, Pref, VInitial
) ->
    case first_compat_version(Pref, Others, VInitial) of
        undefined -> no_switch;
        VInitial -> no_switch;
        Picked -> {switch, Picked}
    end.

-spec server_initial_key_dcid(nquic_protocol:state()) -> nquic:connection_id() | undefined.
server_initial_key_dcid(#conn_state{
    local_params = #transport_params{retry_source_connection_id = RetrySCID}
}) when RetrySCID =/= undefined ->
    RetrySCID;
server_initial_key_dcid(#conn_state{odcid = ODCID}) ->
    ODCID.

-spec validate_retry_scid(nquic_protocol:state(), #transport_params{}) ->
    ok | {error, nquic_error:any_reason()}.
validate_retry_scid(#conn_state{role = client, retry_scid = undefined}, RemoteParams) ->
    case RemoteParams#transport_params.retry_source_connection_id of
        undefined -> ok;
        _ -> {error, {transport_parameter_error, unexpected_retry_scid}}
    end;
validate_retry_scid(#conn_state{role = client, retry_scid = RetrySCID}, RemoteParams) ->
    case RemoteParams#transport_params.retry_source_connection_id of
        RetrySCID -> ok;
        undefined -> {error, {transport_parameter_error, missing_retry_scid}};
        _ -> {error, {transport_parameter_error, retry_scid_mismatch}}
    end;
validate_retry_scid(_, _) ->
    ok.

-spec validate_version_info(nquic_protocol:state(), #transport_params{}) ->
    ok | {error, nquic_error:any_reason()}.
validate_version_info(_State, #transport_params{version_information = undefined}) ->
    ok;
validate_version_info(State, #transport_params{version_information = VI}) ->
    #{chosen_version := Chosen, other_versions := Others} = VI,
    ConnVersion = State#conn_state.version,
    case Chosen =:= ConnVersion of
        false ->
            {error, {version_negotiation_error, chosen_version_mismatch}};
        true ->
            case lists:member(ConnVersion, Others) of
                true -> ok;
                false -> {error, {version_negotiation_error, version_not_in_other_versions}}
            end
    end.

%%%-----------------------------------------------------------------------------
%% PSK RESUMPTION / 0-RTT ACCEPTANCE / NEWSESSIONTICKET
%%%-----------------------------------------------------------------------------
-spec gate_zero_rtt_replay(
    {ok, binary(), atom(), boolean(), binary()} | {error, term()},
    nquic_protocol:state()
) ->
    {ok, binary(), atom(), boolean(), binary()} | {error, term()}.
gate_zero_rtt_replay({ok, _PSK, _Cipher, false, _Identity} = Result, _State) ->
    Result;
gate_zero_rtt_replay({ok, PSK, Cipher, true, Identity}, State) ->
    case
        nquic_zero_rtt:check(
            (State#conn_state.crypto)#conn_crypto.replay_protection,
            Identity,
            State#conn_state.peer
        )
    of
        accept -> {ok, PSK, Cipher, true, Identity};
        reject -> {ok, PSK, Cipher, false, Identity}
    end;
gate_zero_rtt_replay(Other, _State) ->
    Other.

-spec queue_new_session_ticket(binary(), crypto:hash_state(), binary(), nquic_protocol:state()) ->
    nquic_protocol:state().
queue_new_session_ticket(HSSecret, TranscriptCtx, ClientFinBin, State) ->
    Cipher = (State#conn_state.crypto)#conn_crypto.cipher,
    ResSecret = nquic_tls:derive_resumption_secret(
        HSSecret, TranscriptCtx, ClientFinBin, Cipher
    ),
    Nonce = crypto:strong_rand_bytes(8),
    Hash = nquic_keys:cipher_to_hash(Cipher),
    HashLen =
        case Hash of
            sha256 -> 32;
            sha384 -> 48
        end,
    PSK = nquic_keys:qhkdf_expand(ResSecret, <<"resumption">>, Nonce, HashLen, Hash),
    StaticKey = (State#conn_state.crypto)#conn_crypto.static_key,
    TicketPlain = <<PSK/binary, (atom_to_binary(Cipher))/binary>>,
    TicketValue =
        case StaticKey of
            undefined ->
                TicketPlain;
            _ ->
                TicketIV = crypto:strong_rand_bytes(12),
                {Ct, Tag} = crypto:crypto_one_time_aead(
                    aes_256_gcm, StaticKey, TicketIV, TicketPlain, <<>>, true
                ),
                <<TicketIV/binary, Tag/binary, Ct/binary>>
        end,
    AgeAdd = rand:uniform(16#FFFFFFFF),
    NSTMsg = nquic_tls:encode_new_session_ticket(#{
        lifetime => 7200,
        age_add => AgeAdd,
        nonce => Nonce,
        ticket => TicketValue,
        max_early_data => 16#FFFFFFFF
    }),
    CryptoFrame = #crypto{offset = 0, data = NSTMsg},
    {ok, State1} = nquic_protocol_send_queues:queue_app_frame(CryptoFrame, State),
    Crypto1 = State1#conn_state.crypto,
    State1#conn_state{crypto = Crypto1#conn_crypto{resumption_secret = ResSecret}}.

-spec try_psk_resumption(map(), nquic_protocol:state(), atom()) ->
    {ok, binary(), atom(), boolean(), binary()} | {error, term()}.
try_psk_resumption(TLSState, State, NegCipher) ->
    case maps:get(psk_info, TLSState, undefined) of
        undefined ->
            {error, no_psk};
        PSKInfo ->
            case (State#conn_state.crypto)#conn_crypto.static_key of
                undefined ->
                    {error, no_static_key};
                StaticKey ->
                    CHBin = maps:get(client_hello_bin, TLSState, <<>>),
                    nquic_tls_server:validate_psk_offer(PSKInfo, CHBin, StaticKey, NegCipher)
            end
    end.

%%%-----------------------------------------------------------------------------
%% CERTIFICATE LOADING
%%%-----------------------------------------------------------------------------
-spec cipher_opts(
    [aes_128_gcm | aes_256_gcm | chacha20_poly1305] | undefined
) -> map().
cipher_opts(undefined) -> #{};
cipher_opts(CipherSuites) -> #{cipher_suites => CipherSuites}.

-doc """
Load a leaf certificate (DER) and private key from PEM files.
Used by the gen_statem wrapper at conn startup when the listener has
not pre-loaded certificates. Returns `{undefined, undefined}` when no
file is configured or the file cannot be read; the caller treats that
as "no local cert", which is fine for clients that do not require
client authentication and for tests that drive the handshake without
real certs.
The listener has its own preload path (`nquic_listener_sup:preload_certs/1`)
that supports chains and CA certificates.
""".
-spec load_certs(file:filename() | undefined, file:filename() | undefined) ->
    {binary() | undefined, term() | undefined}.
load_certs(undefined, _) ->
    {undefined, undefined};
load_certs(CertF, KeyF) ->
    case file:read_file(CertF) of
        {ok, CBin} ->
            [CEntry | _] = public_key:pem_decode(CBin),
            {_, CertDER, _} = CEntry,
            {ok, KBin} = file:read_file(KeyF),
            [KEntry | _] = public_key:pem_decode(KBin),
            PrivKey = public_key:pem_entry_decode(KEntry),
            {CertDER, PrivKey};
        {error, _} ->
            {undefined, undefined}
    end.
