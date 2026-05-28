-module(nquic_protocol_recv).
-moduledoc """
Inbound side of the QUIC protocol state.

Pure functions over `#conn_state{}` covering datagram parsing
(`process_datagram/3`), per-packet dispatch (`handle_single_packet/4`,
`decrypt_and_process/4`), Version Negotiation and Retry handling
(RFC 9000 §6, §17.2.5), stateless-reset detection (RFC 9000 §10.3.1),
the per-frame handler dispatch table (`handle_frame/3` for every
RFC 9000 / 9221 frame type), and CRYPTO fragment reassembly
(RFC 9001 §4.1.3).

Extracted from `nquic_protocol` as part of REVIEW_PLAN.md Phase 4.4.
The trunk's public dispatchers (`handle_packet/3,4`,
`handle_packet_notimers/3,4`) call into `process_datagram/3` here;
stream-frame and stream-cleanup helpers live in `nquic_protocol`
until slice 7 moves them out.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-include("nquic_transport.hrl").
-export([
    process_datagram/3
]).

-export([
    check_stateless_reset/2,
    handle_single_packet/4
]).

-export([
    handle_retry_packet/3,
    handle_version_negotiation/2
]).

-export([
    handle_frame/3,
    handle_frames/3,
    maybe_update_peer_spin/4
]).

-export([
    crypto_buffer_add/3,
    crypto_buffer_data/1,
    crypto_buffer_merge/3
]).

-export_type([crypto_buffer_entry/0]).

-type crypto_buffer_entry() ::
    {non_neg_integer(), iodata(), [{non_neg_integer(), binary()}]}.

%%%-----------------------------------------------------------------------------
%% DATAGRAM PARSING
%%%-----------------------------------------------------------------------------
-spec process_datagram(binary(), nquic_protocol:state(), [nquic_protocol:event()]) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_datagram(<<>>, State, Events) ->
    {ok, lists:reverse(Events), State};
process_datagram(Bin, State, EventsAcc) ->
    SCIDLen = byte_size(State#conn_state.scid),
    case nquic_packet:parse_header(Bin, SCIDLen) of
        {ok, #long_header{type = version_negotiation} = Header, _} ->
            case handle_version_negotiation(Header, State) of
                {ok, _Events, NewState} ->
                    {ok, lists:reverse(EventsAcc), NewState};
                {error, _, _} = Error ->
                    Error
            end;
        {ok, #short_header{} = Header, Rest} ->
            case handle_single_packet(Bin, Rest, Header, State) of
                {ok, NewEvents, NewState} ->
                    {ok, lists:reverse(EventsAcc, NewEvents), NewState};
                {error, Reason, NewState} ->
                    {error, Reason, NewState}
            end;
        {ok, Header, Rest} ->
            HeaderLen = byte_size(Bin) - byte_size(Rest),
            {ok, PayloadLen} = nquic_protocol_send:get_packet_len(Header, byte_size(Rest)),
            case byte_size(Rest) >= PayloadLen of
                true ->
                    PacketLen = HeaderLen + PayloadLen,
                    <<CurrentPacket:PacketLen/binary, NextPackets/binary>> = Bin,
                    SlicedRest = binary:part(Rest, 0, PayloadLen),
                    case handle_single_packet(CurrentPacket, SlicedRest, Header, State) of
                        {ok, [], NewState} ->
                            process_datagram(NextPackets, NewState, EventsAcc);
                        {ok, NewEvents, NewState} ->
                            process_datagram(
                                NextPackets, NewState, lists:reverse(NewEvents, EventsAcc)
                            );
                        {error, Reason, NewState} ->
                            {error, Reason, NewState}
                    end;
                false ->
                    {ok, lists:reverse(EventsAcc), State}
            end;
        {error, _} ->
            {ok, lists:reverse(EventsAcc), State}
    end.

%%%-----------------------------------------------------------------------------
%% VERSION NEGOTIATION (RFC 9000 6)
%%%-----------------------------------------------------------------------------
-spec choose_negotiated_version([non_neg_integer()], nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
choose_negotiated_version(Offered, State) ->
    Supported = nquic_packet:supported_versions(),
    Common = [V || V <- Supported, lists:member(V, Offered)],
    case Common of
        [NewVersion | _] ->
            retry_with_version(NewVersion, State);
        [] ->
            {error, {transport_error, version_negotiation_error}, State}
    end.

-doc """
Handle a Version Negotiation packet.
RFC 9000 §6 governs acceptance:
  * a client MUST discard VN packets that arrive after any other
    server packet has been successfully decrypted (the
    `server_packet_processed` flag latches once that happens),
  * VN must echo the client's chosen connection IDs (DCID = our SCID,
    SCID = the DCID we used on the Initial that triggered the VN);
    mismatched echoes look like injected VN and are dropped,
  * a VN that lists the version the client was attempting MUST be
    discarded (RFC 9000 §6.2),
  * servers MUST NOT receive VN; drop for robustness.
When negotiation succeeds the function picks the highest-priority
version that both peers support and re-runs the client handshake on
that version (resetting Initial-space keys and the Initial PN space,
queueing a fresh ClientHello via `start_client_handshake/1`). When
no common version exists the function returns
`{error, {transport_error, version_negotiation_error}, State}` and
the wrapper drives the connection into the draining state.
""".
-spec handle_version_negotiation(#long_header{}, nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_version_negotiation(_Header, #conn_state{role = server} = State) ->
    {ok, [], State};
handle_version_negotiation(
    _Header,
    #conn_state{role = client, server_packet_processed = true} = State
) ->
    {ok, [], State};
handle_version_negotiation(#long_header{dcid = VNDCID, scid = VNSCID}, State) when
    VNDCID =/= State#conn_state.scid orelse VNSCID =/= State#conn_state.dcid
->
    {ok, [], State};
handle_version_negotiation(#long_header{token = VersionsBin}, State) ->
    CurrentVersion = State#conn_state.version,
    case byte_size(VersionsBin) rem 4 of
        0 ->
            Versions = [V || <<V:32>> <= VersionsBin],
            case lists:member(CurrentVersion, Versions) of
                true ->
                    {ok, [], State};
                false ->
                    choose_negotiated_version(Versions, State)
            end;
        _ ->
            {ok, [], State}
    end.

-spec retry_with_version(non_neg_integer(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
retry_with_version(NewVersion, State) ->
    Crypto0 = State#conn_state.crypto,
    NewCrypto = Crypto0#conn_crypto{keys = #{}, tls_state = undefined},
    State1 = State#conn_state{
        version = NewVersion,
        crypto = NewCrypto,
        pn_spaces = #{},
        app_next_pn = 0,
        app_largest_received = -1
    },
    {ok, State2} = nquic_protocol_handshake:start_client_handshake(State1),
    {ok, [], State2}.

%%%-----------------------------------------------------------------------------
%% RETRY PACKET HANDLING (RFC 9000 17 2 5)
%%%-----------------------------------------------------------------------------
-doc """
Handle a Retry packet (RFC 9000 §17.2.5).
A client that has not yet processed a Retry verifies the integrity
tag, adopts the server's SCID as the new DCID, stashes the original
DCID as `odcid` and the Retry token on `#conn_state.retry_token`,
re-derives Initial-space keys against the new DCID, resets the
Initial PN space and loss detector, and queues a fresh ClientHello
via `queue_initial_frame/2`. Subsequent Initial packets (queued
retransmits, PTO probes) carry the token through
`build_initial_packet/2`.
A Retry that fails any check (server role, second Retry, parse
error, integrity-tag mismatch) is silently dropped per RFC 9000
§17.2.5.1.
""".
-spec handle_retry_packet(binary(), #long_header{}, nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
handle_retry_packet(_Bin, _Header, #conn_state{role = server} = State) ->
    {ok, [], State};
handle_retry_packet(_Bin, _Header, #conn_state{odcid = ODCID} = State) when
    ODCID =/= undefined
->
    {ok, [], State};
handle_retry_packet(Bin, #long_header{scid = ServerSCID, token = RawToken}, State) ->
    ODCID = State#conn_state.dcid,
    Version = State#conn_state.version,
    case nquic_packet:parse_retry(RawToken, Bin) of
        {ok, RetryToken, PacketNoTag, IntegrityTag} ->
            case nquic_retry:verify_integrity_tag(ODCID, PacketNoTag, IntegrityTag, Version) of
                ok ->
                    resend_initial_after_retry(ServerSCID, ODCID, RetryToken, State);
                {error, _} ->
                    {ok, [], State}
            end;
        {error, _} ->
            {ok, [], State}
    end.

-spec resend_initial_after_retry(
    nquic:connection_id(), nquic:connection_id(), binary(), nquic_protocol:state()
) -> {ok, [nquic_protocol:event()], nquic_protocol:state()}.
resend_initial_after_retry(NewDCID, ODCID, RetryToken, State) ->
    Version = State#conn_state.version,
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(NewDCID, Version),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientSecret, aes_128_gcm, Version),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerSecret, aes_128_gcm, Version),
    ClientRoleKeys = nquic_keys:make_role_keys(aes_128_gcm, CKey, CIV, CHP),
    ServerRoleKeys = nquic_keys:make_role_keys(aes_128_gcm, SKey, SIV, SHP),
    NewKeys = #{
        initial => #{
            client => ClientRoleKeys,
            server => ServerRoleKeys
        }
    },
    CHBin = maps:get(client_hello, (State#conn_state.crypto)#conn_crypto.tls_state),
    Crypto0 = State#conn_state.crypto,
    State1 = State#conn_state{
        dcid = NewDCID,
        odcid = ODCID,
        retry_scid = NewDCID,
        retry_token = RetryToken,
        crypto = Crypto0#conn_crypto{keys = NewKeys},
        pn_spaces = #{initial => #{next_pn => 0}},
        app_next_pn = 0,
        app_largest_received = -1,
        loss_state = nquic_loss:init(
            nquic_loss:get_cc_algorithm(State#conn_state.loss_state),
            nquic_loss:pacer_config(State#conn_state.loss_state)
        )
    },
    {ok, State2} = nquic_protocol_send_queues:queue_initial_frame(
        #crypto{offset = 0, data = CHBin}, State1
    ),
    {ok, [], State2}.

%%%-----------------------------------------------------------------------------
%% PER-PACKET HANDLER (DECRYPT FRAME DISPATCH ACK QUEUING)
%%%-----------------------------------------------------------------------------
-spec check_stateless_reset(binary(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
check_stateless_reset(Packet, #conn_state{path = #conn_path_mgmt{peer_cids = PeerCids}} = State) ->
    case byte_size(Packet) >= 21 of
        false ->
            {ok, [], State};
        true ->
            Tokens = [
                maps:get(token, Entry, <<>>)
             || Entry <- maps:values(PeerCids),
                is_map(Entry)
            ],
            case lists:any(fun(T) -> nquic_stateless_reset:detect(Packet, T) end, Tokens) of
                true -> {ok, [connection_closed], State};
                false -> {ok, [], State}
            end
    end.

-spec decrypt_and_process(binary(), binary(), nquic_packet:header(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
decrypt_and_process(Packet, Rest, #short_header{} = Header, State) ->
    LargestRecv = max(0, State#conn_state.app_largest_received),
    case decrypt_short_with_key_update(Packet, Rest, Header, LargestRecv, State) of
        {ok, DecHeader, Frames, State1} ->
            handle_decrypt_result({ok, DecHeader, Frames}, Header, Packet, State1);
        {error, _} = Err ->
            handle_decrypt_result(Err, Header, Packet, State)
    end;
decrypt_and_process(Packet, Rest, Header, State) ->
    Space = nquic_protocol_send:packet_space_from_header(Header),
    LargestRecv = largest_received_for(Space, State),
    handle_decrypt_result(
        decrypt_packet(Header, Packet, Rest, LargestRecv, State), Header, Packet, State
    ).

-spec decrypt_packet(
    #long_header{}, binary(), binary(), non_neg_integer(), nquic_protocol:state()
) ->
    {ok, nquic_packet:header(), [nquic_frame:t()]} | {error, term()}.
decrypt_packet(#long_header{type = initial} = Header, Packet, Rest, LargestRecv, State) ->
    #conn_state{role = Role, crypto = #conn_crypto{keys = #{initial := InitKeys}}} = State,
    nquic_packet:unmask_and_decrypt(
        Packet,
        Rest,
        Header,
        aes_128_gcm,
        nquic_keys:peer_keys(Role, InitKeys),
        LargestRecv
    );
decrypt_packet(#long_header{type = handshake} = Header, Packet, Rest, LargestRecv, State) ->
    #conn_state{role = Role, crypto = #conn_crypto{cipher = Cipher, keys = Keys}} = State,
    decrypt_with_keys(
        maps:get(handshake, Keys, undefined),
        no_handshake_keys,
        Packet,
        Rest,
        Header,
        Cipher,
        Role,
        LargestRecv
    );
decrypt_packet(#long_header{type = rtt0} = Header, Packet, Rest, LargestRecv, State) ->
    #conn_state{crypto = #conn_crypto{cipher = Cipher, keys = Keys}} = State,
    decrypt_zero_rtt(maps:get(rtt0, Keys, undefined), Packet, Rest, Header, Cipher, LargestRecv).

-spec decrypt_short_phase_mismatch(
    #short_header{},
    binary(),
    binary(),
    non_neg_integer(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    nquic_protocol:state()
) ->
    {ok, nquic_packet:header(), [nquic_frame:t()], nquic_protocol:state()} | {error, term()}.
decrypt_short_phase_mismatch(DecHeader, AAD, CT, PN, Cipher, State) ->
    #conn_crypto{old_read_keys = OldReadKeys} = State#conn_state.crypto,
    case try_old_read_keys(OldReadKeys, Cipher, PN, AAD, CT) of
        {ok, Frames} ->
            {ok, DecHeader, Frames, State};
        none ->
            try_rotated_read_keys(DecHeader, AAD, CT, PN, Cipher, State)
    end.

-spec decrypt_short_with_key_update(
    binary(), binary(), #short_header{}, non_neg_integer(), nquic_protocol:state()
) ->
    {ok, nquic_packet:header(), [nquic_frame:t()], nquic_protocol:state()} | {error, term()}.
decrypt_short_with_key_update(Packet, Rest, Header, LargestRecv, State) ->
    #conn_state{crypto = Crypto} = State,
    #conn_crypto{cipher = Cipher, key_phase = CurrentKP, app_recv_keys = RecvKeys} = Crypto,
    case RecvKeys of
        undefined ->
            {error, no_app_keys};
        CurrentPeerKeys ->
            case
                nquic_packet:unmask_header(
                    Packet, Rest, Header, Cipher, CurrentPeerKeys, LargestRecv
                )
            of
                {error, _} = Err ->
                    Err;
                {ok, #short_header{key_phase = KP} = DecHeader, PN, AAD, CT} when
                    KP =:= CurrentKP
                ->
                    case nquic_packet:decrypt_unmasked(Cipher, CurrentPeerKeys, PN, AAD, CT) of
                        {ok, Frames} -> {ok, DecHeader, Frames, State};
                        {error, _} = Err -> Err
                    end;
                {ok, #short_header{} = DecHeader, PN, AAD, CT} ->
                    decrypt_short_phase_mismatch(DecHeader, AAD, CT, PN, Cipher, State)
            end
    end.

-spec decrypt_with_keys(
    map() | undefined,
    atom(),
    binary(),
    binary(),
    nquic_packet:header(),
    atom(),
    client | server,
    non_neg_integer()
) -> {ok, nquic_packet:header(), [nquic_frame:t()]} | {error, term()}.
decrypt_with_keys(undefined, MissingTag, _Packet, _Rest, _Header, _Cipher, _Role, _LargestRecv) ->
    {error, MissingTag};
decrypt_with_keys(Keys, _MissingTag, Packet, Rest, Header, Cipher, Role, LargestRecv) ->
    nquic_packet:unmask_and_decrypt(
        Packet, Rest, Header, Cipher, nquic_keys:peer_keys(Role, Keys), LargestRecv
    ).

-spec decrypt_zero_rtt(
    map() | undefined, binary(), binary(), nquic_packet:header(), atom(), non_neg_integer()
) -> {ok, nquic_packet:header(), [nquic_frame:t()]} | {error, term()}.
decrypt_zero_rtt(undefined, _Packet, _Rest, _Header, _Cipher, _LargestRecv) ->
    {error, no_zero_rtt_keys};
decrypt_zero_rtt(#{client := CKeys}, Packet, Rest, Header, Cipher, LargestRecv) ->
    nquic_packet:unmask_and_decrypt(Packet, Rest, Header, Cipher, CKeys, LargestRecv).

-spec filter_zero_rtt_frames(nquic_packet:header(), nquic_protocol:state(), [nquic_frame:t()]) ->
    [nquic_frame:t()].
filter_zero_rtt_frames(
    #long_header{type = rtt0},
    #conn_state{crypto = #conn_crypto{zero_rtt_accepted = false}},
    Frames
) ->
    [F || F <- Frames, is_record(F, crypto)];
filter_zero_rtt_frames(_Header, _State, Frames) ->
    Frames.

-spec finalize_frames(
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()},
    nquic_packet:header(),
    [nquic_frame:t()]
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
finalize_frames({ok, Events, State}, DecHeader, Frames) ->
    {ok, Events, nquic_protocol_ack:maybe_queue_ack(DecHeader, Frames, State)};
finalize_frames({error, _, _} = Error, _DecHeader, _Frames) ->
    Error.

-spec handle_decrypt_result(
    {ok, nquic_packet:header(), [nquic_frame:t()]} | {error, term()},
    nquic_packet:header(),
    binary(),
    nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_decrypt_result({ok, DecHeader, Frames}, _Header, _Packet, State) ->
    process_decrypted(DecHeader, Frames, State);
handle_decrypt_result({error, frame_encoding_error}, _Header, _Packet, State) ->
    {error, {transport_error, frame_encoding_error}, State};
handle_decrypt_result({error, protocol_violation}, _Header, _Packet, State) ->
    {error, {transport_error, protocol_violation}, State};
handle_decrypt_result(_Error, #short_header{}, Packet, State) ->
    check_stateless_reset(Packet, State);
handle_decrypt_result(_Error, _Header, _Packet, State) ->
    {ok, [], State}.

-spec handle_single_packet(binary(), binary(), nquic_packet:header(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_single_packet(Packet, Rest, Header, State) ->
    case maybe_compatible_version_negotiation(Header, State) of
        {ok, State0} ->
            case nquic_protocol_send:ensure_initial_keys(Header, State0) of
                {ok, State1} ->
                    State2 = nquic_protocol_send:maybe_update_dcid(Header, State1),
                    decrypt_and_process(Packet, Rest, Header, State2);
                _Error ->
                    {ok, [], State0}
            end;
        {error, _Reason} ->
            {ok, [], State}
    end.

-spec largest_received_for(nquic_packet:space(), nquic_protocol:state()) ->
    non_neg_integer().
largest_received_for(application, #conn_state{app_largest_received = LR}) ->
    max(0, LR);
largest_received_for(Space, #conn_state{pn_spaces = PnSpaces}) ->
    SpaceMap = maps:get(Space, PnSpaces, #{next_pn => 0}),
    maps:get(largest_received, SpaceMap, 0).

-spec mark_server_packet_processed(nquic_protocol:state()) -> nquic_protocol:state().
mark_server_packet_processed(#conn_state{server_packet_processed = true} = State) ->
    State;
mark_server_packet_processed(#conn_state{role = client} = State) ->
    State#conn_state{server_packet_processed = true};
mark_server_packet_processed(State) ->
    State.

-doc """
RFC 9368 Compatible Version Negotiation (client side).
When the client receives the first Initial packet from the server with a
QUIC version different from the one originally sent, and that version is
listed in the client's advertised `other_versions`, switch to it: rederive
Initial keys with the new version's salt and HKDF labels, and update the
connection's negotiated version. Subsequent packets, including the just-
arrived Initial, are then processed with the chosen version's keys.
The check is gated on `server_packet_processed = false` so a peer cannot
flip the version after the handshake has begun making progress on the
original version.
""".
-spec maybe_compatible_version_negotiation(nquic_packet:header(), nquic_protocol:state()) ->
    {ok, nquic_protocol:state()} | {error, term()}.
maybe_compatible_version_negotiation(
    #long_header{type = initial, version = HeaderVer},
    #conn_state{
        role = client,
        version = CurVer,
        server_packet_processed = false,
        local_params = #transport_params{
            version_information = #{other_versions := Others}
        }
    } = State
) when HeaderVer =/= CurVer, HeaderVer =/= 0 ->
    case lists:member(HeaderVer, Others) andalso nquic_packet:is_supported_version(HeaderVer) of
        true -> {ok, switch_compat_version(HeaderVer, State)};
        false -> {error, version_negotiation_error}
    end;
maybe_compatible_version_negotiation(_Header, State) ->
    {ok, State}.

-spec maybe_discard_initial_on_server_handshake_received(
    nquic_packet:space(), nquic_protocol:state()
) -> nquic_protocol:state().
maybe_discard_initial_on_server_handshake_received(
    handshake, #conn_state{role = server, crypto = #conn_crypto{keys = Keys}} = State
) ->
    case maps:is_key(initial, Keys) of
        true -> nquic_protocol_handshake:discard_initial_keys(State);
        false -> State
    end;
maybe_discard_initial_on_server_handshake_received(_Space, State) ->
    State.

-spec maybe_update_peer_spin(
    nquic_packet:header(), nquic_packet:space(), nquic_packet_number:t(), nquic_protocol:state()
) ->
    nquic_protocol:state().
maybe_update_peer_spin(
    #short_header{spin = Spin},
    application,
    PN,
    #conn_state{spin_enabled = true, app_largest_received = Prev} = State
) when PN > Prev ->
    State#conn_state{peer_spin = Spin};
maybe_update_peer_spin(_Header, _Space, _PN, State) ->
    State.

-spec process_decrypted(nquic_packet:header(), [nquic_frame:t()], nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
process_decrypted(DecHeader, Frames, State) ->
    State1 = nquic_protocol_key_update:maybe_handle_key_update(DecHeader, State),
    State2 = mark_server_packet_processed(State1),
    Space = nquic_protocol_send:packet_space_from_header(DecHeader),
    PN = nquic_protocol_send:packet_number_from_header(DecHeader),
    State2a = maybe_update_peer_spin(DecHeader, Space, PN, State2),
    State2b = qlog_packet_received(State2a, Space, PN),
    State3 = nquic_protocol_ack:track_received_pn_and_ecn(
        Space, PN, State2b#conn_state.recv_ecn, State2b
    ),
    State4 = maybe_discard_initial_on_server_handshake_received(Space, State3),
    Filtered = filter_zero_rtt_frames(DecHeader, State4, Frames),
    finalize_frames(handle_frames(Filtered, DecHeader, State4), DecHeader, Filtered).

-spec qlog_packet_received(nquic_protocol:state(), nquic_packet:space(), nquic_packet_number:t()) ->
    nquic_protocol:state().
qlog_packet_received(#conn_state{qlog = undefined} = State, _Space, _PN) ->
    State;
qlog_packet_received(#conn_state{qlog = QLog} = State, Space, PN) ->
    Data = #{packet_type => Space, packet_number => PN},
    State#conn_state{qlog = nquic_qlog:event(QLog, transport_packet_received, Data)}.

-spec switch_compat_version(non_neg_integer(), nquic_protocol:state()) ->
    nquic_protocol:state().
switch_compat_version(NewVersion, State) ->
    DCID = State#conn_state.dcid,
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
    State#conn_state{
        version = NewVersion,
        crypto = Crypto0#conn_crypto{keys = NewKeys, tls_state = NewTLSState}
    }.

-spec try_old_read_keys(
    map() | undefined,
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    non_neg_integer(),
    binary(),
    binary()
) -> {ok, [nquic_frame:t()]} | none.
try_old_read_keys(undefined, _Cipher, _PN, _AAD, _CT) ->
    none;
try_old_read_keys(OldReadKeys, Cipher, PN, AAD, CT) ->
    case nquic_packet:decrypt_unmasked(Cipher, OldReadKeys, PN, AAD, CT) of
        {ok, _} = Ok -> Ok;
        {error, _} -> none
    end.

-spec try_rotated_read_keys(
    #short_header{},
    binary(),
    binary(),
    non_neg_integer(),
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    nquic_protocol:state()
) ->
    {ok, nquic_packet:header(), [nquic_frame:t()], nquic_protocol:state()} | {error, term()}.
try_rotated_read_keys(DecHeader, AAD, CT, PN, Cipher, State) ->
    Rotated = nquic_protocol_key_update:perform_key_update(State),
    NewPeerKeys = (Rotated#conn_state.crypto)#conn_crypto.app_recv_keys,
    case nquic_packet:decrypt_unmasked(Cipher, NewPeerKeys, PN, AAD, CT) of
        {ok, Frames} -> {ok, DecHeader, Frames, Rotated};
        {error, _} = Err -> Err
    end.

%%%-----------------------------------------------------------------------------
%% FRAME HANDLING
%%%-----------------------------------------------------------------------------
-spec apply_max_stream_data(
    nquic:stream_id(), non_neg_integer(), map(), #conn_streams{}, nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
apply_max_stream_data(StreamID, MaxData, Streams, SS, State) ->
    case maps:find(StreamID, Streams) of
        {ok, S} ->
            CurrentMax = S#stream_state.send_max_data,
            NewMax = max(CurrentMax, MaxData),
            S1 = S#stream_state{send_max_data = NewMax},
            SS1 = SS#conn_streams{streams = Streams#{StreamID => S1}},
            State1 = State#conn_state{streams_state = SS1},
            case NewMax > CurrentMax of
                true ->
                    {Events, State2} = nquic_protocol_streams_send:scan_blocked_stream(
                        StreamID, State1
                    ),
                    {ok, Events, State2};
                false ->
                    {ok, [], State1}
            end;
        error ->
            {ok, [], State}
    end.

-spec crypto_buffer_add(
    non_neg_integer(), binary(), crypto_buffer_entry()
) -> crypto_buffer_entry().
crypto_buffer_add(Offset, FragData, {NextOffset, Buf, Pending}) ->
    DataEnd = Offset + byte_size(FragData),
    if
        Offset =:= NextOffset ->
            crypto_buffer_merge(DataEnd, [Buf, FragData], Pending);
        Offset < NextOffset, DataEnd > NextOffset ->
            Skip = NextOffset - Offset,
            <<_:Skip/binary, Useful/binary>> = FragData,
            crypto_buffer_merge(DataEnd, [Buf, Useful], Pending);
        Offset =< NextOffset ->
            {NextOffset, Buf, Pending};
        true ->
            NewPending = lists:sort(
                fun({A, _}, {B, _}) -> A =< B end,
                [{Offset, FragData} | Pending]
            ),
            {NextOffset, Buf, NewPending}
    end.

-spec crypto_buffer_data(crypto_buffer_entry()) -> binary().
crypto_buffer_data({_NextOffset, Data, _Pending}) ->
    iolist_to_binary(Data).

-spec crypto_buffer_merge(
    non_neg_integer(), iodata(), [{non_neg_integer(), binary()}]
) -> crypto_buffer_entry().
crypto_buffer_merge(NextOffset, Buf, []) ->
    {NextOffset, Buf, []};
crypto_buffer_merge(NextOffset, Buf, [{Offset, FragData} | Rest]) ->
    DataEnd = Offset + byte_size(FragData),
    if
        Offset =< NextOffset, DataEnd > NextOffset ->
            Skip = NextOffset - Offset,
            <<_:Skip/binary, Useful/binary>> = FragData,
            crypto_buffer_merge(DataEnd, [Buf, Useful], Rest);
        Offset =< NextOffset ->
            crypto_buffer_merge(NextOffset, Buf, Rest);
        true ->
            {NextOffset, Buf, [{Offset, FragData} | Rest]}
    end.

-spec handle_ack_frame(#ack{}, nquic_packet:header(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
handle_ack_frame(
    #ack{
        largest_acknowledged = LargestAcked,
        delay = Delay,
        first_ack_range = FirstRange,
        ack_ranges = Ranges,
        ecn_counts = ECNCounts
    },
    Header,
    State
) ->
    #conn_state{loss_state = LossState, remote_params = RemoteParams} = State,
    Space = nquic_protocol_send:packet_space_from_header(Header),
    AckedRanges = nquic_frame_handler:decode_ack_ranges(LargestAcked, FirstRange, Ranges),
    Now = erlang:monotonic_time(microsecond),
    AckDelay = nquic_protocol:scale_ack_delay(Delay, RemoteParams),
    MaxAckDelayUs =
        case RemoteParams of
            #transport_params{max_ack_delay = MAD} -> MAD * 1000;
            undefined -> 25_000
        end,
    InFlightBefore = nquic_loss:get_bytes_in_flight(LossState),
    {ok, NewLossState, AckedFrames, LostFrames} = nquic_loss:on_ack_received(
        LossState, Space, AckedRanges, AckDelay, Now, MaxAckDelayUs
    ),
    NewLossState2 = nquic_loss:process_ecn_counts(NewLossState, Space, ECNCounts),
    InFlightAfter = nquic_loss:get_bytes_in_flight(NewLossState2),
    State1 = State#conn_state{loss_state = NewLossState2},
    State1a = nquic_protocol_ack:apply_received_ranges_prune(Space, AckedFrames, State1),
    State2 = nquic_protocol_send:handle_lost_frames(LostFrames, Space, State1a),
    case InFlightAfter < InFlightBefore of
        true ->
            {WritableEvents, State3} = nquic_protocol_streams_send:scan_blocked_streams(State2),
            {ok, WritableEvents, State3};
        false ->
            {ok, [], State2}
    end.

-spec handle_cid_frame(nquic_frame:t(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
handle_cid_frame(
    #new_connection_id{
        seq_num = SeqNum,
        retire_prior_to = RetirePriorTo,
        cid = CID,
        stateless_reset_token = Token
    },
    State
) ->
    {ok, State1} = nquic_protocol_cid:handle_new_connection_id(
        SeqNum, RetirePriorTo, CID, Token, State
    ),
    {ok, [], State1};
handle_cid_frame(#retire_connection_id{seq_num = SeqNum}, State) ->
    {ok, State1} = nquic_protocol_cid:handle_retire_connection_id(SeqNum, State),
    {ok, [], State1}.

-spec handle_crypto_frame(#crypto{}, nquic_packet:header(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_crypto_frame(#crypto{}, #long_header{type = rtt0}, State) ->
    {error, {transport_error, protocol_violation}, State};
handle_crypto_frame(
    #crypto{offset = Offset, data = CryptoData},
    #long_header{type = initial},
    #conn_state{role = Role} = State
) ->
    {NewBuf, State1} = nquic_protocol_handshake:buffer_crypto(
        initial, Offset, CryptoData, State
    ),
    case Role of
        client -> nquic_protocol_handshake:process_initial_crypto_client(NewBuf, State1);
        server -> nquic_protocol_handshake:process_initial_crypto_server(NewBuf, State1)
    end;
handle_crypto_frame(
    #crypto{offset = Offset, data = CryptoData},
    #long_header{type = handshake},
    #conn_state{role = Role} = State
) ->
    {NewBuf, State1} = nquic_protocol_handshake:buffer_crypto(
        handshake, Offset, CryptoData, State
    ),
    case Role of
        client -> nquic_protocol_handshake:process_handshake_crypto_client(NewBuf, State1);
        server -> nquic_protocol_handshake:process_handshake_crypto_server(NewBuf, State1)
    end;
handle_crypto_frame(#crypto{data = CryptoData}, _Header, State) ->
    case nquic_frame_handler:check_post_handshake_crypto(CryptoData) of
        ok ->
            Events =
                case CryptoData of
                    <<4:8, _/binary>> -> [{new_session_ticket, CryptoData}];
                    _ -> []
                end,
            {ok, Events, State};
        {error, TLSError} ->
            {error, {transport_error, TLSError}, State}
    end.

-spec handle_flow_control_frame(nquic_frame:t(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_flow_control_frame(#max_data{max_data = MaxData}, State) ->
    Flow0 = State#conn_state.flow,
    CurrentMax = Flow0#conn_flow.remote_max_data,
    NewMax = max(CurrentMax, MaxData),
    State1 = State#conn_state{flow = Flow0#conn_flow{remote_max_data = NewMax}},
    case NewMax > CurrentMax of
        true ->
            {Events, State2} = nquic_protocol_streams_send:scan_blocked_streams(State1),
            {ok, Events, State2};
        false ->
            {ok, [], State1}
    end;
handle_flow_control_frame(
    #max_stream_data{stream_id = StreamID, max_stream_data = MaxData}, State
) ->
    #conn_state{streams_state = SS, role = Role} = State,
    #conn_streams{streams = Streams} = SS,
    case nquic_frame_handler:validate_stream_for_max_stream_data(StreamID, Role, Streams) of
        ok ->
            apply_max_stream_data(StreamID, MaxData, Streams, SS, State);
        {error, stream_state_error} ->
            case nquic_protocol_streams_lifecycle:is_closed_stream(StreamID, State) of
                true -> {ok, [], State};
                false -> {error, {transport_error, stream_state_error}, State}
            end
    end;
handle_flow_control_frame(#max_streams{max_streams = Max, is_uni = false}, State) ->
    SS0 = State#conn_state.streams_state,
    NewSS = SS0#conn_streams{
        peer_max_streams_bidi = max(SS0#conn_streams.peer_max_streams_bidi, Max)
    },
    {ok, [], State#conn_state{streams_state = NewSS}};
handle_flow_control_frame(#max_streams{max_streams = Max, is_uni = true}, State) ->
    SS0 = State#conn_state.streams_state,
    NewSS = SS0#conn_streams{
        peer_max_streams_uni = max(SS0#conn_streams.peer_max_streams_uni, Max)
    },
    {ok, [], State#conn_state{streams_state = NewSS}};
handle_flow_control_frame(#streams_blocked{is_uni = false}, State) ->
    Current = (State#conn_state.streams_state)#conn_streams.local_max_streams_bidi,
    Frame = #max_streams{max_streams = Current, is_uni = false},
    {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
    SS1 = (State1#conn_state.streams_state)#conn_streams{last_sent_max_streams_bidi = Current},
    {ok, [], State1#conn_state{streams_state = SS1}};
handle_flow_control_frame(#streams_blocked{is_uni = true}, State) ->
    Current = (State#conn_state.streams_state)#conn_streams.local_max_streams_uni,
    Frame = #max_streams{max_streams = Current, is_uni = true},
    {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
    SS1 = (State1#conn_state.streams_state)#conn_streams{last_sent_max_streams_uni = Current},
    {ok, [], State1#conn_state{streams_state = SS1}};
handle_flow_control_frame(#data_blocked{limit = Limit}, State) ->
    nquic_protocol_streams:respond_to_data_blocked(Limit, State);
handle_flow_control_frame(#stream_data_blocked{stream_id = StreamID, limit = Limit}, State) ->
    nquic_protocol_streams:respond_to_stream_data_blocked(StreamID, Limit, State).

-spec handle_frame(nquic_frame:t(), nquic_packet:header(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_frame(#crypto{} = F, H, S) ->
    handle_crypto_frame(F, H, S);
handle_frame(#stream{} = F, _H, S) ->
    handle_stream_data_frame(F, S);
handle_frame(#reset_stream{} = F, _H, S) ->
    handle_reset_stream_frame(F, S);
handle_frame(#stop_sending{} = F, _H, S) ->
    handle_stop_sending_frame(F, S);
handle_frame(#ack{} = F, H, S) ->
    handle_ack_frame(F, H, S);
handle_frame(#max_data{} = F, _H, S) ->
    handle_flow_control_frame(F, S);
handle_frame(#max_stream_data{} = F, _H, S) ->
    handle_flow_control_frame(F, S);
handle_frame(#max_streams{} = F, _H, S) ->
    handle_flow_control_frame(F, S);
handle_frame(#streams_blocked{} = F, _H, S) ->
    handle_flow_control_frame(F, S);
handle_frame(#data_blocked{} = F, _H, S) ->
    handle_flow_control_frame(F, S);
handle_frame(#stream_data_blocked{} = F, _H, S) ->
    handle_flow_control_frame(F, S);
handle_frame(#path_challenge{} = F, H, S) ->
    handle_path_frame(F, H, S);
handle_frame(#path_response{} = F, H, S) ->
    handle_path_frame(F, H, S);
handle_frame(#new_connection_id{} = F, _H, S) ->
    handle_cid_frame(F, S);
handle_frame(#retire_connection_id{} = F, _H, S) ->
    handle_cid_frame(F, S);
handle_frame(F, _H, S) ->
    handle_misc_frame(F, S).

-spec handle_frames([nquic_frame:t()], nquic_packet:header(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_frames(Frames, Header, State) ->
    handle_frames_acc(Frames, Header, State, []).

-spec handle_frames_acc([nquic_frame:t()], nquic_packet:header(), nquic_protocol:state(), [
    nquic_protocol:event()
]) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_frames_acc([], _Header, State, EventsAcc) ->
    {ok, lists:reverse(EventsAcc), State};
handle_frames_acc([Frame | Rest], Header, State, EventsAcc) ->
    case handle_frame(Frame, Header, State) of
        {ok, [], NewState} ->
            handle_frames_acc(Rest, Header, NewState, EventsAcc);
        {ok, Events, NewState} ->
            handle_frames_acc(Rest, Header, NewState, lists:reverse(Events, EventsAcc));
        {error, _, _} = Error ->
            Error
    end.

-spec handle_misc_frame(nquic_frame:t(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_misc_frame(#new_token{}, #conn_state{role = server} = State) ->
    {error, {transport_error, protocol_violation}, State};
handle_misc_frame(#new_token{token = Token}, #conn_state{role = client} = State) ->
    {ok, [{new_token_received, Token}], State};
handle_misc_frame(#handshake_done{}, #conn_state{role = server} = State) ->
    {error, {transport_error, protocol_violation}, State};
handle_misc_frame(#handshake_done{}, State) ->
    {ok, [], nquic_protocol_handshake:discard_handshake_keys(State)};
handle_misc_frame(#connection_close{}, State) ->
    {ok, [connection_closed], State};
handle_misc_frame(#ping{}, State) ->
    {ok, [], State};
handle_misc_frame(#datagram{data = Data}, State) ->
    {ok, [{datagram_received, Data}], State};
handle_misc_frame(_Frame, State) ->
    {ok, [], State}.

-spec handle_path_frame(nquic_frame:t(), nquic_packet:header(), nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_path_frame(#path_challenge{}, #long_header{type = handshake}, State) ->
    {error, {transport_error, protocol_violation}, State};
handle_path_frame(#path_challenge{data = ChallengeData}, _Header, State) ->
    Frame = #path_response{data = ChallengeData},
    {ok, NewState} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
    {ok, [], NewState};
handle_path_frame(#path_response{data = ResponseData}, _Header, State) ->
    Path0 = State#conn_state.path,
    case nquic_path:on_response(Path0#conn_path_mgmt.path_state, ResponseData) of
        {validated, NewPS} ->
            State1 = State#conn_state{path = Path0#conn_path_mgmt{path_state = NewPS}},
            on_path_validated(State1);
        {mismatch, _} ->
            {ok, [], State}
    end.

-spec handle_reset_existing(
    nquic:stream_id(), non_neg_integer(), non_neg_integer(), #stream_state{}, nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_reset_existing(StreamID, FinalSize, AppErrCode, Stream, State) ->
    case
        nquic_protocol_streams:handle_reset_stream(
            StreamID, FinalSize, AppErrCode, Stream, State
        )
    of
        {ok, Events, State1} ->
            State2 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(StreamID, State1),
            {ok, Events, State2};
        Error ->
            Error
    end.

-spec handle_reset_stream_frame(#reset_stream{}, nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_reset_stream_frame(
    #reset_stream{stream_id = StreamID, app_error_code = AppErrCode, final_size = FinalSize},
    State
) ->
    #conn_state{role = Role, streams_state = #conn_streams{streams = Streams}} = State,
    case nquic_frame_handler:validate_stream_for_reset(StreamID, Role) of
        {error, stream_state_error} ->
            {error, {transport_error, stream_state_error}, State};
        ok ->
            case maps:find(StreamID, Streams) of
                {ok, Stream} ->
                    handle_reset_existing(StreamID, FinalSize, AppErrCode, Stream, State);
                error ->
                    case nquic_protocol_streams_lifecycle:is_closed_stream(StreamID, State) of
                        true -> {ok, [], State};
                        false -> nquic_protocol_streams:handle_reset_stream_new(FinalSize, State)
                    end
            end
    end.

-spec handle_stop_sending_frame(#stop_sending{}, nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_stop_sending_frame(
    #stop_sending{stream_id = StreamID, app_error_code = ErrCode}, State
) ->
    #conn_state{role = Role, streams_state = #conn_streams{streams = Streams}} = State,
    case nquic_frame_handler:validate_stream_for_stop_sending(StreamID, Role, Streams) of
        {error, stream_state_error} ->
            case nquic_protocol_streams_lifecycle:is_closed_stream(StreamID, State) of
                true -> {ok, [], State};
                false -> {error, {transport_error, stream_state_error}, State}
            end;
        ok ->
            nquic_protocol_streams:handle_stop_sending(StreamID, ErrCode, State)
    end.

-spec handle_stream_data_dispatch(
    nquic:stream_id(), non_neg_integer(), binary(), nquic_frame:t(), map(), nquic_protocol:state()
) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_stream_data_dispatch(StreamID, Offset, StreamData, Frame, Streams, State) ->
    Existing = maps:find(StreamID, Streams),
    case
        Existing =:= error andalso
            nquic_protocol_streams_lifecycle:is_closed_stream(StreamID, State)
    of
        true ->
            {ok, [], State};
        false ->
            Limits = #{
                max_bidi =>
                    (State#conn_state.streams_state)#conn_streams.local_max_streams_bidi,
                max_uni =>
                    (State#conn_state.streams_state)#conn_streams.local_max_streams_uni
            },
            nquic_protocol_streams:handle_stream_frame(
                StreamID, Offset, StreamData, Frame, Existing, Limits, State
            )
    end.

-spec handle_stream_data_frame(#stream{}, nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}
    | {error, term(), nquic_protocol:state()}.
handle_stream_data_frame(
    #stream{stream_id = StreamID, offset = Offset, data = StreamData} = Frame, State
) ->
    #conn_state{streams_state = #conn_streams{streams = Streams}, role = Role} = State,
    case nquic_frame_handler:validate_stream_for_recv(StreamID, Role, Streams) of
        {error, stream_state_error} ->
            case nquic_protocol_streams_lifecycle:is_closed_stream(StreamID, State) of
                true -> {ok, [], State};
                false -> {error, {transport_error, stream_state_error}, State}
            end;
        ok ->
            handle_stream_data_dispatch(StreamID, Offset, StreamData, Frame, Streams, State)
    end.

-spec on_path_validated(nquic_protocol:state()) ->
    {ok, [nquic_protocol:event()], nquic_protocol:state()}.
on_path_validated(#conn_state{self_migration_pending = true} = State) ->
    State1 = State#conn_state{self_migration_pending = false},
    {ok, [local_migration_validated], State1};
on_path_validated(State) ->
    case nquic_protocol_migration:complete_migration(State) of
        {ok, State1} ->
            {ok, [], State1};
        {error, no_available_cids} ->
            {ok, [], nquic_protocol_migration:revert_migration(State)}
    end.
