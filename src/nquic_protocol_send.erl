-module(nquic_protocol_send).
-moduledoc """
Outbound side of the QUIC protocol state.

Pure functions over `#conn_state{}` covering encrypted packet
construction (Initial / Handshake / 1-RTT / 0-RTT), MTU-aware
splitting and batched send, the per-flush send context,
anti-amplification gating (RFC 9000 §8.1), congestion-control
admission (RFC 9002), header protection sample extraction
(RFC 9001 §5.4), Initial-key derivation, and the loss-detection
retransmission glue.

ACK generation lives in `nquic_protocol_ack`; the per-encryption-level
pending-frame queues and their flush drains live in
`nquic_protocol_send_queues`. Both call down into this module's packet
builders module-qualified; the dependency is one-way.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-export([
    build_app_packet/2,
    build_handshake_packet/2,
    build_initial_packet/2,
    build_initial_packet/3
]).

-export([
    build_app_packet_pre/3,
    build_app_packet_pre_ctx/3,
    build_packets_mtu_pre/5,
    build_packets_mtu_pre_ctx/5,
    build_zero_rtt_packet_pre/3,
    make_app_send_ctx/2,
    packet_payload_budget/1
]).

-export([
    check_anti_amplification/2,
    check_congestion_control/2
]).

-export([
    ensure_initial_keys/2,
    get_packet_len/2,
    maybe_update_dcid/2,
    outgoing_spin/1,
    packet_number_from_header/1,
    packet_space_from_header/1
]).

-export([
    ensure_sample_size/2,
    hp_sample/3
]).

-export([handle_lost_frames/3]).

-export([
    take_frames_for_mtu_pre/2
]).

-export_type([pre_encoded/0]).

-type pre_encoded() :: {non_neg_integer(), iodata(), nquic_frame:t()}.
-define(AEAD_TAG_SIZE, 16).

-record(app_send_ctx, {
    cipher :: aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    role_keys :: map(),
    key :: binary(),
    iv :: binary(),
    hp_source :: {ctx, crypto:crypto_state()} | {key, binary()},
    dcid :: nquic:connection_id(),
    dcid_prefix_size :: pos_integer(),
    gso_size :: undefined | pos_integer(),
    pad_bin :: undefined | binary(),
    key_phase :: boolean(),
    largest_acked :: non_neg_integer(),
    time :: integer(),
    track_anti_amp :: boolean()
}).

%%%-----------------------------------------------------------------------------
%% PACKET BUILDERS (RFC 9000 17, RFC 9001 5)
%%%-----------------------------------------------------------------------------
-spec build_app_packet([nquic_frame:t()], nquic_protocol:state()) ->
    {ok, iodata(), nquic_protocol:state()} | {error, term(), nquic_protocol:state()}.
build_app_packet(Frames, State) ->
    #conn_state{
        crypto = #conn_crypto{cipher = Cipher, app_send_keys = SendKeys},
        app_next_pn = PN,
        dcid = DCID,
        peer = Peer
    } = State,
    case SendKeys of
        undefined ->
            {error, no_app_keys, State};
        RoleKeys ->
            #{key := Key, iv := IV, hp := _} = RoleKeys,
            Payload0 = [nquic_frame:encode(F) || F <- Frames],
            LargestAcked = nquic_loss:get_largest_acked(State#conn_state.loss_state, application),
            {PnLen, TruncPN} = nquic_packet_number:encode(PN, LargestAcked),
            Payload = ensure_sample_size(Payload0, PnLen),
            Header = #short_header{
                dcid = DCID,
                packet_number = TruncPN,
                key_phase = (State#conn_state.crypto)#conn_crypto.key_phase,
                spin = outgoing_spin(State),
                pn_len = PnLen
            },
            HeaderBin = nquic_packet:encode_header(Header),
            PnOffset = byte_size(HeaderBin) - PnLen,
            {Ciphertext, Tag} = nquic_crypto:encrypt(Cipher, Key, IV, PN, HeaderBin, Payload),
            SampleOff = 4 - PnLen,
            Sample = hp_sample(Ciphertext, Tag, SampleOff),
            Mask = nquic_hp:generate_mask_from_keys(RoleKeys, Cipher, Sample),
            {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, false),
            MaskedPacket = [MaskedHeader, Ciphertext, Tag],
            PacketSize = byte_size(HeaderBin) + byte_size(Ciphertext) + byte_size(Tag),
            case check_anti_amplification(State, PacketSize) of
                amplification_limited ->
                    {ok, <<>>, State};
                AntiAmp ->
                    Time = erlang:monotonic_time(microsecond),
                    LossState = nquic_loss:on_packet_sent(
                        State#conn_state.loss_state, application, PN, Frames, Time, PacketSize
                    ),
                    State1 = apply_post_send_app(
                        AntiAmp, State, PN + 1, LossState, PacketSize
                    ),
                    _ = Peer,
                    {ok, MaskedPacket, State1}
            end
    end.

-doc """
Build an encrypted Handshake-space packet from a list of frames.
Same return shape as `build_initial_packet/2`. Returns
`{error, no_handshake_keys, nquic_protocol:state()}` before Handshake keys are
installed.
""".
-spec build_handshake_packet([nquic_frame:t()], nquic_protocol:state()) ->
    {ok, iodata(), nquic_protocol:state()} | {error, term(), nquic_protocol:state()}.
build_handshake_packet(Frames, State) ->
    #conn_state{
        crypto = #conn_crypto{keys = Keys, cipher = Cipher},
        pn_spaces = PnSpaces,
        dcid = DCID,
        scid = SCID,
        role = Role,
        version = Ver
    } = State,
    case maps:get(handshake, Keys, undefined) of
        undefined ->
            {error, no_handshake_keys, State};
        HsKeys ->
            RoleKeys = nquic_keys:local_keys(Role, HsKeys),
            #{key := Key, iv := IV, hp := _} = RoleKeys,
            Payload0 = [nquic_frame:encode(F) || F <- Frames],
            Payload0Size = iolist_size(Payload0),
            HsSpaceMap = maps:get(handshake, PnSpaces, #{next_pn => 0}),
            PN = maps:get(next_pn, HsSpaceMap, 0),
            LargestAcked = nquic_loss:get_largest_acked(
                State#conn_state.loss_state, handshake
            ),
            {PnLen, TruncPN} = nquic_packet_number:encode(PN, LargestAcked),
            {Payload, PayloadSize} = ensure_sample_size_sized(
                Payload0, Payload0Size, PnLen
            ),
            Header = #long_header{
                type = handshake,
                version = Ver,
                dcid = DCID,
                scid = SCID,
                payload_len = PayloadSize + ?AEAD_TAG_SIZE,
                packet_number = TruncPN,
                pn_len = PnLen
            },
            HeaderBin = nquic_packet:encode_header(Header),
            HeaderSize = byte_size(HeaderBin),
            PnOffset = HeaderSize - PnLen,
            {Ciphertext, Tag} = nquic_crypto:encrypt(
                Cipher, Key, IV, PN, HeaderBin, Payload
            ),
            SampleOff = 4 - PnLen,
            Sample = hp_sample(Ciphertext, Tag, SampleOff),
            Mask = nquic_hp:generate_mask_from_keys(RoleKeys, Cipher, Sample),
            {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, true),
            MaskedPacket = [MaskedHeader, Ciphertext, Tag],
            PacketSize = HeaderSize + PayloadSize + ?AEAD_TAG_SIZE,
            case check_anti_amplification(State, PacketSize) of
                amplification_limited ->
                    {ok, <<>>, State};
                AntiAmp ->
                    Time = erlang:monotonic_time(microsecond),
                    LossState = nquic_loss:on_packet_sent(
                        State#conn_state.loss_state,
                        handshake,
                        PN,
                        Frames,
                        Time,
                        PacketSize
                    ),
                    NewPnSpaces = PnSpaces#{
                        handshake => HsSpaceMap#{next_pn => PN + 1}
                    },
                    State1 = apply_post_send(
                        AntiAmp, State, NewPnSpaces, LossState, PacketSize
                    ),
                    State2 = maybe_discard_initial_on_client_handshake_sent(Role, State1),
                    {ok, MaskedPacket, State2}
            end
    end.

-doc """
Build an encrypted Initial-space packet from a list of frames.
Returns `{ok, iodata(), nquic_protocol:state()}` with the masked packet and the state
updated for loss detection, anti-amplification, and packet-number space.
The wire datagram is padded to RFC 9000 §14.1's 1200-byte minimum.
Returns `{ok, <<>>, nquic_protocol:state()}` if the connection is anti-amplification
limited (server has not yet validated the client). The caller should
not send anything in that case.
Returns `{error, no_initial_keys, nquic_protocol:state()}` if Initial keys have not
been derived yet (caller bug).
Used by `flush/1` to drain `pending_initial_frames` and by callers that
need to send a single Initial packet directly (e.g. client first flight
once the handshake API exposes it).
""".
-spec build_initial_packet([nquic_frame:t()], nquic_protocol:state()) ->
    {ok, iodata(), nquic_protocol:state()} | {error, term(), nquic_protocol:state()}.
build_initial_packet(Frames, State) ->
    build_initial_packet(Frames, State, State#conn_state.retry_token).

-doc """
Build an encrypted Initial-space packet with a Retry token.
Same shape as `build_initial_packet/2`. The token is included in the
long-header packet (see RFC 9000 §17.2.5, Retry); pass `<<>>` for
no-token Initials.
""".
-spec build_initial_packet([nquic_frame:t()], nquic_protocol:state(), binary()) ->
    {ok, iodata(), nquic_protocol:state()} | {error, term(), nquic_protocol:state()}.
build_initial_packet(Frames, State, RetryToken) ->
    #conn_state{
        crypto = #conn_crypto{keys = Keys},
        pn_spaces = PnSpaces,
        dcid = DCID,
        scid = SCID,
        role = Role,
        version = Ver
    } = State,
    case maps:get(initial, Keys, undefined) of
        undefined ->
            {error, no_initial_keys, State};
        InitKeys ->
            RoleKeys = nquic_keys:local_keys(Role, InitKeys),
            #{key := Key, iv := IV, hp := _} = RoleKeys,
            Payload0 = [nquic_frame:encode(F) || F <- Frames],
            Payload0Size = iolist_size(Payload0),
            InitSpaceMap = maps:get(initial, PnSpaces, #{next_pn => 0}),
            PN = maps:get(next_pn, InitSpaceMap, 0),
            LargestAcked = nquic_loss:get_largest_acked(State#conn_state.loss_state, initial),
            {PnLen, TruncPN} = nquic_packet_number:encode(PN, LargestAcked),
            TrialHeader = #long_header{
                type = initial,
                version = Ver,
                dcid = DCID,
                scid = SCID,
                token = RetryToken,
                payload_len = Payload0Size + ?AEAD_TAG_SIZE,
                packet_number = TruncPN,
                pn_len = PnLen
            },
            TrialHeaderBin = nquic_packet:encode_header(TrialHeader),
            TrialHeaderSize = byte_size(TrialHeaderBin),
            MinPayloadSize = max(0, 1200 - TrialHeaderSize - ?AEAD_TAG_SIZE),
            PadLen = max(0, MinPayloadSize - Payload0Size),
            Padding = <<0:(PadLen * 8)>>,
            PaddedPayloadSize = Payload0Size + PadLen,
            {Payload, PayloadSize} = ensure_sample_size_sized(
                [Payload0, Padding], PaddedPayloadSize, PnLen
            ),
            Header = TrialHeader#long_header{
                payload_len = PayloadSize + ?AEAD_TAG_SIZE
            },
            HeaderBin = nquic_packet:encode_header(Header),
            HeaderSize = byte_size(HeaderBin),
            PnOffset = HeaderSize - PnLen,
            {Ciphertext, Tag} = nquic_crypto:encrypt(
                aes_128_gcm, Key, IV, PN, HeaderBin, Payload
            ),
            SampleOff = 4 - PnLen,
            Sample = hp_sample(Ciphertext, Tag, SampleOff),
            Mask = nquic_hp:generate_mask_from_keys(RoleKeys, aes_128_gcm, Sample),
            {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, true),
            MaskedPacket = [MaskedHeader, Ciphertext, Tag],
            PacketSize = HeaderSize + PayloadSize + ?AEAD_TAG_SIZE,
            case check_anti_amplification(State, PacketSize) of
                amplification_limited ->
                    {ok, <<>>, State};
                AntiAmp ->
                    Time = erlang:monotonic_time(microsecond),
                    LossState = nquic_loss:on_packet_sent(
                        State#conn_state.loss_state, initial, PN, Frames, Time, PacketSize
                    ),
                    NewPnSpaces = PnSpaces#{
                        initial => InitSpaceMap#{next_pn => PN + 1}
                    },
                    State1 = apply_post_send(
                        AntiAmp, State, NewPnSpaces, LossState, PacketSize
                    ),
                    {ok, MaskedPacket, State1}
            end
    end.

-spec maybe_discard_initial_on_client_handshake_sent(
    client | server, nquic_protocol:state()
) -> nquic_protocol:state().
maybe_discard_initial_on_client_handshake_sent(client, State) ->
    case maps:is_key(initial, (State#conn_state.crypto)#conn_crypto.keys) of
        true -> nquic_protocol_handshake:discard_initial_keys(State);
        false -> State
    end;
maybe_discard_initial_on_client_handshake_sent(server, State) ->
    State.

%%%-----------------------------------------------------------------------------
%% MTU-AWARE PACKET BUILDING (1-RTT BATCHED SEND)
%%%-----------------------------------------------------------------------------
-spec anti_amp_must_track(client | server, #conn_path_mgmt{} | undefined) -> boolean().
anti_amp_must_track(client, _Path) -> false;
anti_amp_must_track(server, #conn_path_mgmt{address_validated = true}) -> false;
anti_amp_must_track(server, _) -> true.

-spec build_app_packet_pre([pre_encoded()], integer(), nquic_protocol:state()) ->
    {ok, iodata(), nquic_protocol:state()} | {error, term(), nquic_protocol:state()}.
build_app_packet_pre(PreEncoded, Time, State) ->
    #conn_state{
        crypto = #conn_crypto{
            cipher = Cipher, key_phase = KeyPhase, app_send_keys = SendKeys
        },
        app_next_pn = PN,
        dcid = DCID,
        gso_size = GsoSize
    } = State,
    case SendKeys of
        undefined ->
            {error, no_app_keys, State};
        RoleKeys ->
            #{key := Key, iv := IV, hp := _} = RoleKeys,
            {Payload0, OrigFrames, Payload0Size} = unzip_pre_encoded(PreEncoded),
            LargestAcked = nquic_loss:get_largest_acked(State#conn_state.loss_state, application),
            {PnLen, TruncPN} = nquic_packet_number:encode(PN, LargestAcked),
            HeaderSize = 1 + byte_size(DCID) + PnLen,
            {Payload1, Payload1Size} = maybe_pad_to_gso(
                Payload0, Payload0Size, OrigFrames, HeaderSize, GsoSize
            ),
            {Payload, PayloadSize} = ensure_sample_size_sized(Payload1, Payload1Size, PnLen),
            Header = #short_header{
                dcid = DCID,
                packet_number = TruncPN,
                key_phase = KeyPhase,
                spin = outgoing_spin(State),
                pn_len = PnLen
            },
            HeaderBin = nquic_packet:encode_header(Header),
            PnOffset = HeaderSize - PnLen,
            {Ciphertext, Tag} = nquic_crypto:encrypt(Cipher, Key, IV, PN, HeaderBin, Payload),
            SampleOff = 4 - PnLen,
            Sample = hp_sample(Ciphertext, Tag, SampleOff),
            Mask = nquic_hp:generate_mask_from_keys(RoleKeys, Cipher, Sample),
            {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, false),
            MaskedPacket = [MaskedHeader, Ciphertext, Tag],
            PacketSize = HeaderSize + PayloadSize + ?AEAD_TAG_SIZE,
            case check_anti_amplification(State, PacketSize) of
                amplification_limited ->
                    {ok, <<>>, State};
                AntiAmp ->
                    LossState = nquic_loss:on_packet_sent(
                        State#conn_state.loss_state,
                        application,
                        PN,
                        OrigFrames,
                        Time,
                        PacketSize
                    ),
                    State1 = apply_post_send_app(
                        AntiAmp, State, PN + 1, LossState, PacketSize
                    ),
                    {ok, MaskedPacket, State1}
            end
    end.

-spec build_app_packet_pre_ctx(
    [pre_encoded()], #app_send_ctx{}, nquic_protocol:state()
) ->
    {ok, iodata(), nquic_protocol:state()} | {error, term(), nquic_protocol:state()}.
build_app_packet_pre_ctx(PreEncoded, Ctx, State) ->
    #app_send_ctx{
        cipher = Cipher,
        key = Key,
        iv = IV,
        hp_source = HpSource,
        dcid = DCID,
        dcid_prefix_size = DCIDPrefixSize,
        gso_size = GsoSize,
        pad_bin = PadBin,
        key_phase = KeyPhase,
        largest_acked = LargestAcked,
        time = Time,
        track_anti_amp = Track
    } = Ctx,
    {Payload0, OrigFrames, Payload0Size} = unzip_pre_encoded(PreEncoded),
    PN = State#conn_state.app_next_pn,
    {PnLen, TruncPN} = nquic_packet_number:encode(PN, LargestAcked),
    HeaderSize = DCIDPrefixSize + PnLen,
    {Payload1, Payload1Size} = maybe_pad_to_gso_ctx(
        Payload0, Payload0Size, OrigFrames, HeaderSize, GsoSize, PadBin
    ),
    {Payload, PayloadSize} = ensure_sample_size_sized(Payload1, Payload1Size, PnLen),
    Header = #short_header{
        dcid = DCID,
        packet_number = TruncPN,
        key_phase = KeyPhase,
        spin = outgoing_spin(State),
        pn_len = PnLen
    },
    HeaderBin = nquic_packet:encode_header(Header),
    PnOffset = HeaderSize - PnLen,
    {Ciphertext, Tag} = nquic_crypto:encrypt(Cipher, Key, IV, PN, HeaderBin, Payload),
    SampleOff = 4 - PnLen,
    Sample = hp_sample(Ciphertext, Tag, SampleOff),
    Mask = generate_mask_for_source(HpSource, Cipher, Sample),
    {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, false),
    MaskedPacket = [MaskedHeader, Ciphertext, Tag],
    PacketSize = HeaderSize + PayloadSize + ?AEAD_TAG_SIZE,
    case Track of
        false ->
            LossState = nquic_loss:on_packet_sent(
                State#conn_state.loss_state,
                application,
                PN,
                OrigFrames,
                Time,
                PacketSize
            ),
            {ok, MaskedPacket, State#conn_state{
                app_next_pn = PN + 1, loss_state = LossState
            }};
        true ->
            case check_anti_amplification(State, PacketSize) of
                amplification_limited ->
                    {ok, <<>>, State};
                AntiAmp ->
                    LossState = nquic_loss:on_packet_sent(
                        State#conn_state.loss_state,
                        application,
                        PN,
                        OrigFrames,
                        Time,
                        PacketSize
                    ),
                    State1 = apply_post_send_app(
                        AntiAmp, State, PN + 1, LossState, PacketSize
                    ),
                    {ok, MaskedPacket, State1}
            end
    end.

-spec build_packets_mtu_pre(
    [pre_encoded()], pos_integer(), integer(), nquic_protocol:state(), [iodata()]
) ->
    {[iodata()], nquic_protocol:state()}.
build_packets_mtu_pre([], _Budget, _Time, State, Acc) ->
    {lists:reverse(Acc), State};
build_packets_mtu_pre(Frames, Budget, Time, State, Acc) ->
    {Batch, Remaining} = take_frames_for_mtu_pre(Frames, Budget),
    case nquic_protocol_send_queues:build_app_or_zero_rtt(Batch, Time, State) of
        {ok, Packet, State1} ->
            build_packets_mtu_pre(Remaining, Budget, Time, State1, [Packet | Acc]);
        {error, _, State1} ->
            build_packets_mtu_pre(Remaining, Budget, Time, State1, Acc)
    end.

-spec build_packets_mtu_pre_ctx(
    [pre_encoded()], pos_integer(), #app_send_ctx{}, nquic_protocol:state(), [iodata()]
) -> {[iodata()], nquic_protocol:state()}.
build_packets_mtu_pre_ctx([], _Budget, _Ctx, State, Acc) ->
    {lists:reverse(Acc), State};
build_packets_mtu_pre_ctx(Frames, Budget, Ctx, State, Acc) ->
    {Batch, Remaining} = take_frames_for_mtu_pre(Frames, Budget),
    {ok, Packet, State1} = build_app_packet_pre_ctx(Batch, Ctx, State),
    build_packets_mtu_pre_ctx(Remaining, Budget, Ctx, State1, [Packet | Acc]).

-spec build_zero_rtt_packet_pre([pre_encoded()], integer(), nquic_protocol:state()) ->
    {ok, iodata(), nquic_protocol:state()} | {error, term(), nquic_protocol:state()}.
build_zero_rtt_packet_pre(PreEncoded, Time, State) ->
    #conn_state{
        crypto = #conn_crypto{keys = Keys, cipher = Cipher},
        app_next_pn = PN,
        dcid = DCID,
        scid = SCID,
        version = Ver,
        role = client
    } = State,
    case maps:get(rtt0, Keys, undefined) of
        undefined ->
            {error, no_zero_rtt_keys, State};
        #{client := RoleKeys} ->
            #{key := Key, iv := IV, hp := _} = RoleKeys,
            {Payload0, OrigFrames, Payload0Size} = unzip_pre_encoded(PreEncoded),
            LargestAcked = nquic_loss:get_largest_acked(
                State#conn_state.loss_state, application
            ),
            {PnLen, TruncPN} = nquic_packet_number:encode(PN, LargestAcked),
            {Payload, PayloadSize} = ensure_sample_size_sized(
                Payload0, Payload0Size, PnLen
            ),
            Header = #long_header{
                type = rtt0,
                version = Ver,
                dcid = DCID,
                scid = SCID,
                payload_len = PayloadSize + ?AEAD_TAG_SIZE,
                packet_number = TruncPN,
                pn_len = PnLen
            },
            HeaderBin = nquic_packet:encode_header(Header),
            HeaderSize = byte_size(HeaderBin),
            PnOffset = HeaderSize - PnLen,
            {Ciphertext, Tag} = nquic_crypto:encrypt(Cipher, Key, IV, PN, HeaderBin, Payload),
            SampleOff = 4 - PnLen,
            Sample = hp_sample(Ciphertext, Tag, SampleOff),
            Mask = nquic_hp:generate_mask_from_keys(RoleKeys, Cipher, Sample),
            {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, true),
            MaskedPacket = [MaskedHeader, Ciphertext, Tag],
            PacketSize = HeaderSize + PayloadSize + ?AEAD_TAG_SIZE,
            case check_anti_amplification(State, PacketSize) of
                amplification_limited ->
                    {ok, <<>>, State};
                AntiAmp ->
                    LossState = nquic_loss:on_packet_sent(
                        State#conn_state.loss_state,
                        application,
                        PN,
                        OrigFrames,
                        Time,
                        PacketSize
                    ),
                    State1 = apply_post_send_app(
                        AntiAmp, State, PN + 1, LossState, PacketSize
                    ),
                    {ok, MaskedPacket, State1}
            end
    end.

-spec generate_mask_for_source(
    {ctx, crypto:crypto_state()} | {key, binary()},
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    binary()
) -> binary().
generate_mask_for_source({ctx, HpCtx}, _Cipher, Sample) ->
    nquic_hp:generate_mask_ctx(HpCtx, Sample);
generate_mask_for_source({key, HP}, Cipher, Sample) ->
    nquic_hp:generate_mask(Cipher, HP, Sample).

-spec make_app_send_ctx(nquic_protocol:state(), integer()) -> #app_send_ctx{}.
make_app_send_ctx(State, Time) ->
    #conn_state{
        crypto = #conn_crypto{
            cipher = Cipher,
            key_phase = KeyPhase,
            app_send_keys = RoleKeys
        },
        dcid = DCID,
        gso_size = GsoSize,
        loss_state = LossState,
        role = Role,
        path = Path
    } = State,
    #{key := Key, iv := IV, hp := HP} = RoleKeys,
    HpSource =
        case RoleKeys of
            #{hp_ctx := HpCtx} -> {ctx, HpCtx};
            _ -> {key, HP}
        end,
    LargestAcked = nquic_loss:get_largest_acked(LossState, application),
    Track = anti_amp_must_track(Role, Path),
    PadBin =
        case GsoSize of
            undefined -> undefined;
            _ -> pad_bin()
        end,
    #app_send_ctx{
        cipher = Cipher,
        role_keys = RoleKeys,
        key = Key,
        iv = IV,
        hp_source = HpSource,
        dcid = DCID,
        dcid_prefix_size = 1 + byte_size(DCID),
        gso_size = GsoSize,
        pad_bin = PadBin,
        key_phase = KeyPhase,
        largest_acked = LargestAcked,
        time = Time,
        track_anti_amp = Track
    }.

-spec packet_payload_budget(nquic_protocol:state()) -> pos_integer().
packet_payload_budget(#conn_state{dcid = DCID, max_payload_size = MaxPayload}) ->
    Overhead = 1 + byte_size(DCID) + 4 + 16,
    MaxPayload - Overhead.

-spec take_frames_for_mtu_pre([pre_encoded()], pos_integer()) ->
    {[pre_encoded()], [pre_encoded()]}.
take_frames_for_mtu_pre(Frames, Budget) ->
    take_frames_for_mtu_pre(Frames, Budget, 0, []).

-spec take_frames_for_mtu_pre(
    [pre_encoded()], pos_integer(), non_neg_integer(), [pre_encoded()]
) -> {[pre_encoded()], [pre_encoded()]}.
take_frames_for_mtu_pre([], _Budget, _Used, Acc) ->
    {lists:reverse(Acc), []};
take_frames_for_mtu_pre([{Size, _, _} = Entry | Rest], Budget, Used, Acc) ->
    case Acc of
        [] ->
            take_frames_for_mtu_pre(Rest, Budget, Size, [Entry]);
        _ when Used + Size =< Budget ->
            take_frames_for_mtu_pre(Rest, Budget, Used + Size, [Entry | Acc]);
        _ ->
            {lists:reverse(Acc), [Entry | Rest]}
    end.

-spec unzip_pre_encoded([pre_encoded(), ...]) ->
    {[iodata()], [nquic_frame:t()], non_neg_integer()}.
unzip_pre_encoded([{Sz, Enc, Frame}]) ->
    {[Enc], [Frame], Sz};
unzip_pre_encoded(PreEncoded) ->
    unzip_pre_encoded(PreEncoded, [], [], 0).

-spec unzip_pre_encoded([pre_encoded()], [iodata()], [nquic_frame:t()], non_neg_integer()) ->
    {[iodata()], [nquic_frame:t()], non_neg_integer()}.
unzip_pre_encoded([], PayloadAcc, FrameAcc, Size) ->
    {lists:reverse(PayloadAcc), lists:reverse(FrameAcc), Size};
unzip_pre_encoded([{Sz, Enc, Frame} | Rest], PayloadAcc, FrameAcc, Size) ->
    unzip_pre_encoded(Rest, [Enc | PayloadAcc], [Frame | FrameAcc], Size + Sz).

%%%-----------------------------------------------------------------------------
%% SEND-SIDE GATES (ANTI-AMPLIFICATION CONGESTION CONTROL)
%%%-----------------------------------------------------------------------------
-spec apply_post_send(
    ok_track | ok_no_track,
    nquic_protocol:state(),
    map(),
    nquic_loss:loss_state(),
    non_neg_integer()
) -> nquic_protocol:state().
apply_post_send(ok_no_track, State, NewPnSpaces, LossState, _PacketSize) ->
    State#conn_state{pn_spaces = NewPnSpaces, loss_state = LossState};
apply_post_send(ok_track, State, NewPnSpaces, LossState, PacketSize) ->
    Path0 = State#conn_state.path,
    NewPath = Path0#conn_path_mgmt{
        anti_amp_bytes_sent = Path0#conn_path_mgmt.anti_amp_bytes_sent + PacketSize
    },
    State#conn_state{
        pn_spaces = NewPnSpaces,
        loss_state = LossState,
        path = NewPath
    }.

-spec apply_post_send_app(
    ok_track | ok_no_track,
    nquic_protocol:state(),
    non_neg_integer(),
    nquic_loss:loss_state(),
    non_neg_integer()
) -> nquic_protocol:state().
apply_post_send_app(ok_no_track, State, NewAppNextPn, LossState, _PacketSize) ->
    State#conn_state{app_next_pn = NewAppNextPn, loss_state = LossState};
apply_post_send_app(ok_track, State, NewAppNextPn, LossState, PacketSize) ->
    Path0 = State#conn_state.path,
    NewPath = Path0#conn_path_mgmt{
        anti_amp_bytes_sent = Path0#conn_path_mgmt.anti_amp_bytes_sent + PacketSize
    },
    State#conn_state{
        app_next_pn = NewAppNextPn,
        loss_state = LossState,
        path = NewPath
    }.

-spec check_anti_amplification(nquic_protocol:state(), non_neg_integer()) ->
    ok_no_track | ok_track | amplification_limited.
check_anti_amplification(#conn_state{path = #conn_path_mgmt{address_validated = true}}, _Size) ->
    ok_no_track;
check_anti_amplification(#conn_state{role = client}, _Size) ->
    ok_no_track;
check_anti_amplification(
    #conn_state{
        path = #conn_path_mgmt{
            anti_amp_bytes_sent = Sent,
            anti_amp_bytes_received = Received
        }
    },
    Size
) ->
    case Sent + Size =< 3 * Received of
        true -> ok_track;
        false -> amplification_limited
    end.

-spec check_congestion_control(nquic_protocol:state(), non_neg_integer()) ->
    ok | {blocked, non_neg_integer()}.
check_congestion_control(#conn_state{loss_state = LossState}, Len) ->
    Cwnd = nquic_loss:get_cwnd(LossState),
    InFlight = nquic_loss:get_bytes_in_flight(LossState),
    case InFlight + Len =< Cwnd of
        true -> ok;
        false -> {blocked, Cwnd}
    end.

%%%-----------------------------------------------------------------------------
%% HEADER / PACKET HELPERS
%%%-----------------------------------------------------------------------------
-spec ensure_initial_keys(nquic_packet:header(), nquic_protocol:state()) ->
    {ok, nquic_protocol:state()} | {error, nquic_error:any_reason()}.
ensure_initial_keys(#long_header{type = initial, dcid = DCID, version = HeaderVer}, State) ->
    Crypto0 = State#conn_state.crypto,
    case maps:get(initial, Crypto0#conn_crypto.keys, undefined) of
        undefined ->
            case State#conn_state.role of
                server ->
                    {CSecret, SSecret} = nquic_keys:initial_secrets(DCID, HeaderVer),
                    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(
                        CSecret, aes_128_gcm, HeaderVer
                    ),
                    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(
                        SSecret, aes_128_gcm, HeaderVer
                    ),
                    Keys = #{
                        initial => #{
                            client => nquic_keys:make_role_keys(aes_128_gcm, CKey, CIV, CHP),
                            server => nquic_keys:make_role_keys(aes_128_gcm, SKey, SIV, SHP)
                        }
                    },
                    {ok, State#conn_state{crypto = Crypto0#conn_crypto{keys = Keys}}};
                client ->
                    {error, no_initial_keys}
            end;
        _ ->
            {ok, State}
    end;
ensure_initial_keys(_, State) ->
    {ok, State}.

-spec get_packet_len(nquic_packet:header(), non_neg_integer()) -> {ok, non_neg_integer()}.
get_packet_len(#long_header{payload_len = Len}, _) -> {ok, Len};
get_packet_len(#short_header{}, RestLen) -> {ok, RestLen}.

-spec maybe_update_dcid(nquic_packet:header(), nquic_protocol:state()) -> nquic_protocol:state().
maybe_update_dcid(
    #long_header{type = initial, scid = PeerSCID}, #conn_state{role = server, dcid = <<>>} = State
) ->
    State#conn_state{dcid = PeerSCID};
maybe_update_dcid(
    #long_header{scid = PeerSCID},
    #conn_state{role = client, server_packet_processed = false} = State
) when PeerSCID =/= <<>> ->
    State#conn_state{dcid = PeerSCID};
maybe_update_dcid(_, State) ->
    State.

-doc """
Outgoing latency spin bit for 1-RTT packets (RFC 9000 §17.4).
Returns 0 when the spin bit is disabled or no peer packet has been
seen yet. When enabled, the server inverts the peer's last spin
sample and the client mirrors it.
""".
-spec outgoing_spin(nquic_protocol:state()) -> 0..1.
outgoing_spin(#conn_state{spin_enabled = false}) -> 0;
outgoing_spin(#conn_state{role = client, peer_spin = PS}) -> PS;
outgoing_spin(#conn_state{role = server, peer_spin = PS}) -> 1 - PS.

-spec packet_number_from_header(nquic_packet:header()) -> nquic_packet_number:t() | undefined.
packet_number_from_header(#long_header{packet_number = PN}) -> PN;
packet_number_from_header(#short_header{packet_number = PN}) -> PN.

-spec packet_space_from_header(nquic_packet:header()) -> nquic_packet:space().
packet_space_from_header(#long_header{type = initial}) -> initial;
packet_space_from_header(#long_header{type = handshake}) -> handshake;
packet_space_from_header(#long_header{type = rtt0}) -> application;
packet_space_from_header(#short_header{}) -> application.

%%%-----------------------------------------------------------------------------
%% HEADER PROTECTION SAMPLE / PAYLOAD PADDING
%%%-----------------------------------------------------------------------------
-spec ensure_sample_size(iodata(), 1..4) -> iodata().
ensure_sample_size(Payload, PnLen) ->
    {Out, _} = ensure_sample_size_sized(Payload, iolist_size(Payload), PnLen),
    Out.

-spec ensure_sample_size_sized(iodata(), non_neg_integer(), 1..4) ->
    {iodata(), non_neg_integer()}.
ensure_sample_size_sized(Payload, PayloadSize, PnLen) ->
    MinPlaintext = max(0, 4 - PnLen),
    case PayloadSize < MinPlaintext of
        true ->
            PadLen = MinPlaintext - PayloadSize,
            {[Payload, <<0:(PadLen * 8)>>], PayloadSize + PadLen};
        false ->
            {Payload, PayloadSize}
    end.

-spec maybe_pad_to_gso(
    [iodata()],
    non_neg_integer(),
    [nquic_frame:t()],
    non_neg_integer(),
    undefined | pos_integer()
) -> {[iodata()], non_neg_integer()}.
maybe_pad_to_gso(Payload, PayloadSize, _Frames, _HeaderSize, undefined) ->
    {Payload, PayloadSize};
maybe_pad_to_gso(Payload, PayloadSize, Frames, HeaderSize, GsoSize) ->
    case has_stream_frame(Frames) of
        false ->
            {Payload, PayloadSize};
        true ->
            CurrentSize = HeaderSize + PayloadSize + ?AEAD_TAG_SIZE,
            case GsoSize - CurrentSize of
                Pad when Pad > 0 ->
                    {[Payload, binary:part(pad_bin(), 0, Pad)], PayloadSize + Pad};
                _ ->
                    {Payload, PayloadSize}
            end
    end.

-spec maybe_pad_to_gso_ctx(
    [iodata()],
    non_neg_integer(),
    [nquic_frame:t()],
    non_neg_integer(),
    undefined | pos_integer(),
    undefined | binary()
) -> {[iodata()], non_neg_integer()}.
maybe_pad_to_gso_ctx(Payload, PayloadSize, _Frames, _HeaderSize, _GsoSize, undefined) ->
    {Payload, PayloadSize};
maybe_pad_to_gso_ctx(Payload, PayloadSize, Frames, HeaderSize, GsoSize, PadBin) ->
    case has_stream_frame(Frames) of
        false ->
            {Payload, PayloadSize};
        true ->
            CurrentSize = HeaderSize + PayloadSize + ?AEAD_TAG_SIZE,
            case GsoSize - CurrentSize of
                Pad when Pad > 0 ->
                    {[Payload, binary:part(PadBin, 0, Pad)], PayloadSize + Pad};
                _ ->
                    {Payload, PayloadSize}
            end
    end.

-define(PAD_BIN_KEY, '$nquic_pad_bin').
-define(PAD_BIN_SIZE, 65000).
-spec has_stream_frame([nquic_frame:t()]) -> boolean().
has_stream_frame([]) -> false;
has_stream_frame([#stream{} | _]) -> true;
has_stream_frame([_ | Rest]) -> has_stream_frame(Rest).

-spec hp_sample(binary(), binary(), non_neg_integer()) -> binary().
hp_sample(Ciphertext, _Tag, SampleOff) when byte_size(Ciphertext) >= SampleOff + 16 ->
    <<_:SampleOff/binary, Sample:16/binary, _/binary>> = Ciphertext,
    Sample;
hp_sample(Ciphertext, Tag, SampleOff) ->
    <<_:SampleOff/binary, Sample:16/binary, _/binary>> = <<Ciphertext/binary, Tag/binary>>,
    Sample.

-spec pad_bin() -> binary().
pad_bin() ->
    case erlang:get(?PAD_BIN_KEY) of
        undefined ->
            B = binary:copy(<<0>>, ?PAD_BIN_SIZE),
            _ = erlang:put(?PAD_BIN_KEY, B),
            B;
        Bin ->
            Bin
    end.

%%%-----------------------------------------------------------------------------
%% LOSS DETECTION / RETRANSMISSION (RFC 9002 6 2)
%%%-----------------------------------------------------------------------------
-spec handle_lost_frames([nquic_frame:t()], nquic_packet:space(), nquic_protocol:state()) ->
    nquic_protocol:state().
handle_lost_frames([], _Space, State) ->
    State;
handle_lost_frames([Frame | Rest], Space, State) ->
    State1 = retransmit_frame(Frame, Space, State),
    handle_lost_frames(Rest, Space, State1).

-spec retransmit_data_blocked(non_neg_integer(), nquic_protocol:state()) -> nquic_protocol:state().
retransmit_data_blocked(Limit, State) ->
    Flow = State#conn_state.flow,
    case
        Flow#conn_flow.remote_max_data =:= Limit andalso
            Flow#conn_flow.data_sent >= Limit
    of
        true ->
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(
                #data_blocked{limit = Limit}, State
            ),
            State1;
        false ->
            State
    end.

-spec retransmit_frame(nquic_frame:t(), nquic_packet:space(), nquic_protocol:state()) ->
    nquic_protocol:state().
retransmit_frame(#stream{} = Frame, _Space, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
    State1;
retransmit_frame(#crypto{} = Frame, application, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
    State1;
retransmit_frame(#crypto{} = Frame, initial, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_initial_frame(Frame, State),
    State1;
retransmit_frame(#crypto{} = Frame, handshake, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_handshake_frame(Frame, State),
    State1;
retransmit_frame(#max_data{max_data = Lost}, _Space, State) ->
    retransmit_max_data(Lost, State);
retransmit_frame(#max_stream_data{stream_id = StreamID, max_stream_data = Lost}, _Space, State) ->
    retransmit_max_stream_data(StreamID, Lost, State);
retransmit_frame(#data_blocked{limit = Limit}, _Space, State) ->
    retransmit_data_blocked(Limit, State);
retransmit_frame(#stream_data_blocked{stream_id = StreamID, limit = Limit}, _Space, State) ->
    retransmit_stream_data_blocked(StreamID, Limit, State);
retransmit_frame(#max_streams{is_uni = IsUni, max_streams = Lost}, _Space, State) ->
    retransmit_max_streams(IsUni, Lost, State);
retransmit_frame(#streams_blocked{is_uni = IsUni, limit = Limit}, _Space, State) ->
    retransmit_streams_blocked(IsUni, Limit, State);
retransmit_frame(_, _Space, State) ->
    State.

-spec retransmit_max_data(non_neg_integer(), nquic_protocol:state()) -> nquic_protocol:state().
retransmit_max_data(Lost, State) ->
    Current = (State#conn_state.flow)#conn_flow.local_max_data,
    case Current >= Lost of
        true ->
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(
                #max_data{max_data = Current}, State
            ),
            State1;
        false ->
            State
    end.

-spec retransmit_max_stream_data(nquic:stream_id(), non_neg_integer(), nquic_protocol:state()) ->
    nquic_protocol:state().
retransmit_max_stream_data(StreamID, Lost, State) ->
    Streams = (State#conn_state.streams_state)#conn_streams.streams,
    case maps:find(StreamID, Streams) of
        {ok, #stream_state{recv_window = Current}} when Current >= Lost ->
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(
                #max_stream_data{stream_id = StreamID, max_stream_data = Current}, State
            ),
            State1;
        _ ->
            State
    end.

-spec retransmit_max_streams(boolean(), non_neg_integer(), nquic_protocol:state()) ->
    nquic_protocol:state().
retransmit_max_streams(false, Lost, State) ->
    SS = State#conn_state.streams_state,
    Current = SS#conn_streams.local_max_streams_bidi,
    case Current >= Lost of
        true ->
            Frame = #max_streams{max_streams = Current, is_uni = false},
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
            SS1 = (State1#conn_state.streams_state)#conn_streams{
                last_sent_max_streams_bidi = Current
            },
            State1#conn_state{streams_state = SS1};
        false ->
            State
    end;
retransmit_max_streams(true, Lost, State) ->
    SS = State#conn_state.streams_state,
    Current = SS#conn_streams.local_max_streams_uni,
    case Current >= Lost of
        true ->
            Frame = #max_streams{max_streams = Current, is_uni = true},
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
            SS1 = (State1#conn_state.streams_state)#conn_streams{
                last_sent_max_streams_uni = Current
            },
            State1#conn_state{streams_state = SS1};
        false ->
            State
    end.

-spec retransmit_stream_data_blocked(nquic:stream_id(), non_neg_integer(), nquic_protocol:state()) ->
    nquic_protocol:state().
retransmit_stream_data_blocked(StreamID, Limit, State) ->
    Streams = (State#conn_state.streams_state)#conn_streams.streams,
    case maps:find(StreamID, Streams) of
        {ok, #stream_state{send_max_data = Max, send_offset = Off}} when
            Max =:= Limit, Off >= Limit
        ->
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(
                #stream_data_blocked{stream_id = StreamID, limit = Limit}, State
            ),
            State1;
        _ ->
            State
    end.

-spec retransmit_streams_blocked(boolean(), non_neg_integer(), nquic_protocol:state()) ->
    nquic_protocol:state().
retransmit_streams_blocked(false, Limit, State) ->
    SS = State#conn_state.streams_state,
    PeerMax = SS#conn_streams.peer_max_streams_bidi,
    NextStream = SS#conn_streams.next_bidi_stream,
    BlockedAtPeerMax = NextStream =/= undefined andalso NextStream div 4 >= PeerMax,
    case PeerMax =:= Limit andalso BlockedAtPeerMax of
        true ->
            Frame = #streams_blocked{limit = Limit, is_uni = false},
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
            State1;
        false ->
            State
    end;
retransmit_streams_blocked(true, Limit, State) ->
    SS = State#conn_state.streams_state,
    PeerMax = SS#conn_streams.peer_max_streams_uni,
    NextStream = SS#conn_streams.next_uni_stream,
    BlockedAtPeerMax = NextStream =/= undefined andalso NextStream div 4 >= PeerMax,
    case PeerMax =:= Limit andalso BlockedAtPeerMax of
        true ->
            Frame = #streams_blocked{limit = Limit, is_uni = true},
            {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
            State1;
        false ->
            State
    end.
