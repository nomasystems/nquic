-module(nquic_packet_io).
-moduledoc """
Packet construction, encryption, and sending for QUIC connections.

This module handles the common logic for building and sending QUIC packets
across all packet types (Initial, Handshake, 1-RTT).
""".

-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-export([send_initial_packet/6, send_initial_packet/7]).
-export([send_handshake_packet/6, send_handshake_packet/7]).
-export([send_app_packet/5]).
-export([send_close_frame/3]).
-export([find_highest_key_level/1, hp_sample/3]).

-doc "Send a 1-RTT packet with the specified frame.".
-spec send_app_packet(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    nquic:connection_id(),
    #{key := binary(), iv := binary(), hp := binary(), atom() => term()},
    {nquic_packet_number:t(), nquic_frame:t()}
) -> {ok, iodata(), non_neg_integer()} | {error, term()}.
send_app_packet(Socket, Peer, DCID, Keys, {PN, Frame}) ->
    Payload = nquic_frame:encode(Frame),

    Header = #short_header{
        dcid = DCID,
        packet_number = PN,
        key_phase = false
    },

    send_short_packet(Socket, Peer, Header, Payload, Keys).

-doc "Send a CONNECTION_CLOSE frame.".
-spec send_close_frame(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    #{
        dcid := nquic:connection_id(),
        scid := nquic:connection_id(),
        keys := map(),
        pn_spaces := map(),
        role := client | server,
        frame := #connection_close{}
    }
) -> ok | {error, term()}.
send_close_frame(Socket, Peer, Params) ->
    #{
        dcid := DCID,
        scid := SCID,
        keys := Keys,
        pn_spaces := PnSpaces,
        role := Role,
        frame := Frame
    } = Params,

    Level = find_highest_key_level(Keys),

    case Level of
        application ->
            #{application := AppKeys} = Keys,
            #{Role := RoleKeys} = AppKeys,
            #{application := #{next_pn := PN}} = PnSpaces,
            case send_app_packet(Socket, Peer, DCID, RoleKeys, {PN, Frame}) of
                {ok, _, _} -> ok;
                Error -> Error
            end;
        handshake ->
            #{handshake := HsKeys} = Keys,
            #{Role := RoleKeys} = HsKeys,
            #{handshake := #{next_pn := PN}} = PnSpaces,
            case send_handshake_packet(Socket, Peer, DCID, SCID, RoleKeys, {PN, [Frame]}) of
                {ok, _, _} -> ok;
                Error -> Error
            end;
        initial ->
            #{initial := InitKeys} = Keys,
            #{Role := RoleKeys} = InitKeys,
            PN =
                case maps:get(initial, PnSpaces, undefined) of
                    undefined -> 0;
                    #{next_pn := P} -> P
                end,
            case send_initial_packet(Socket, Peer, DCID, SCID, RoleKeys, {PN, [Frame]}) of
                {ok, _, _} -> ok;
                Error -> Error
            end
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec find_highest_key_level(map()) -> application | handshake | initial.
find_highest_key_level(Keys) ->
    case maps:is_key(application, Keys) of
        true ->
            application;
        false ->
            case maps:is_key(handshake, Keys) of
                true -> handshake;
                false -> initial
            end
    end.

-spec hp_sample(binary(), binary(), non_neg_integer()) -> binary().
hp_sample(Ciphertext, _Tag, SampleOff) when byte_size(Ciphertext) >= SampleOff + 16 ->
    <<_:SampleOff/binary, Sample:16/binary, _/binary>> = Ciphertext,
    Sample;
hp_sample(Ciphertext, Tag, SampleOff) ->
    <<_:SampleOff/binary, Sample:16/binary, _/binary>> = <<Ciphertext/binary, Tag/binary>>,
    Sample.

-doc "Send a Handshake packet with the specified frames.".
-spec send_handshake_packet(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    nquic:connection_id(),
    nquic:connection_id(),
    #{key := binary(), iv := binary(), hp := binary(), atom() => term()},
    {nquic_packet_number:t(), [nquic_frame:t()]}
) -> {ok, iodata(), non_neg_integer()} | {error, term()}.
send_handshake_packet(Socket, Peer, DCID, SCID, Keys, PNFrames) ->
    send_handshake_packet(Socket, Peer, DCID, SCID, Keys, PNFrames, 1).

-spec send_handshake_packet(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    nquic:connection_id(),
    nquic:connection_id(),
    #{key := binary(), iv := binary(), hp := binary(), atom() => term()},
    {nquic_packet_number:t(), [nquic_frame:t()]},
    non_neg_integer()
) -> {ok, iodata(), non_neg_integer()} | {error, term()}.
send_handshake_packet(Socket, Peer, DCID, SCID, Keys, {PN, Frames}, Version) ->
    Payload = [nquic_frame:encode(F) || F <- Frames],

    Header = #long_header{
        type = handshake,
        version = Version,
        dcid = DCID,
        scid = SCID,
        payload_len = iolist_size(Payload) + 16,
        packet_number = PN
    },

    send_long_packet(Socket, Peer, Header, Payload, Keys).

-doc "Send an Initial packet with the specified frames.".
-spec send_initial_packet(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    nquic:connection_id(),
    nquic:connection_id(),
    #{key := binary(), iv := binary(), hp := binary(), atom() => term()},
    {nquic_packet_number:t(), [nquic_frame:t()]}
) -> {ok, iodata(), non_neg_integer()} | {error, term()}.
send_initial_packet(Socket, Peer, DCID, SCID, Keys, PNFrames) ->
    send_initial_packet(Socket, Peer, DCID, SCID, Keys, PNFrames, 1).

-spec send_initial_packet(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    nquic:connection_id(),
    nquic:connection_id(),
    #{key := binary(), iv := binary(), hp := binary(), atom() => term()},
    {nquic_packet_number:t(), [nquic_frame:t()]},
    non_neg_integer()
) -> {ok, iodata(), non_neg_integer()} | {error, term()}.
send_initial_packet(Socket, Peer, DCID, SCID, Keys, {PN, Frames}, Version) ->
    Payload0 = [nquic_frame:encode(F) || F <- Frames],
    PayloadSize0 = iolist_size(Payload0),
    PadLen = max(0, 1200 - PayloadSize0),
    Payload = [Payload0, <<0:(PadLen * 8)>>],

    Header = #long_header{
        type = initial,
        version = Version,
        dcid = DCID,
        scid = SCID,
        token = <<>>,
        payload_len = PayloadSize0 + PadLen + 16,
        packet_number = PN
    },

    send_long_packet(Socket, Peer, Header, Payload, Keys).

-spec send_long_packet(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    #long_header{},
    iodata(),
    #{key := binary(), iv := binary(), hp := binary()}
) -> {ok, iodata(), non_neg_integer()} | {error, term()}.
send_long_packet(Socket, Peer, Header, Payload, #{key := Key, iv := IV, hp := _} = Keys) ->
    PN = Header#long_header.packet_number,
    HeaderBin = nquic_packet:encode_header(Header),
    PnLen = 4,
    PnOffset = byte_size(HeaderBin) - PnLen,

    {Ciphertext, Tag} = nquic_crypto:encrypt(aes_128_gcm, Key, IV, PN, HeaderBin, Payload),
    Sample = hp_sample(Ciphertext, Tag, 4 - PnLen),
    Mask = nquic_hp:generate_mask_from_keys(Keys, aes_128_gcm, Sample),
    {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, true),
    MaskedPacket = [MaskedHeader, Ciphertext, Tag],
    PacketSize = byte_size(HeaderBin) + byte_size(Ciphertext) + byte_size(Tag),

    case nquic_socket:send(Socket, Peer, MaskedPacket) of
        ok -> {ok, MaskedPacket, PacketSize};
        Error -> Error
    end.

-spec send_short_packet(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    #short_header{},
    iodata(),
    #{key := binary(), iv := binary(), hp := binary()}
) -> {ok, iodata(), non_neg_integer()} | {error, term()}.
send_short_packet(Socket, Peer, Header, Payload, #{key := Key, iv := IV, hp := _} = Keys) ->
    PN = Header#short_header.packet_number,
    HeaderBin = nquic_packet:encode_header(Header),
    PnLen = 4,
    PnOffset = byte_size(HeaderBin) - PnLen,

    {Ciphertext, Tag} = nquic_crypto:encrypt(aes_128_gcm, Key, IV, PN, HeaderBin, Payload),
    Sample = hp_sample(Ciphertext, Tag, 4 - PnLen),
    Mask = nquic_hp:generate_mask_from_keys(Keys, aes_128_gcm, Sample),
    {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, false),
    MaskedPacket = [MaskedHeader, Ciphertext, Tag],
    PacketSize = byte_size(HeaderBin) + byte_size(Ciphertext) + byte_size(Tag),

    case nquic_socket:send(Socket, Peer, MaskedPacket) of
        ok -> {ok, MaskedPacket, PacketSize};
        Error -> Error
    end.
