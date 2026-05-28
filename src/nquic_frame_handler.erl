-module(nquic_frame_handler).
-moduledoc """
QUIC frame handling helpers.

This module provides validation and processing helpers for QUIC frames,
including stream validation per RFC 9000 and TLS message validation per RFC 9001.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-export([stream_initiator/1, stream_is_unidirectional/1]).
-export([i_can_send/2, is_locally_initiated/2, peer_can_send/2]).
-export([validate_stream_for_reset/2, validate_stream_for_stop_sending/3]).
-export([validate_stream_for_max_stream_data/3, validate_stream_for_recv/3]).

-export([check_handshake_crypto/1, check_post_handshake_crypto/1]).

-export([ensure_stream_limits/2]).

-export([decode_ack_ranges/3]).

%%%-----------------------------------------------------------------------------
%% STREAM VALIDATION (RFC 9000 SECTION 2 1)
%%%-----------------------------------------------------------------------------
-doc """
Returns true if we can send data on this stream.

Bidirectional streams allow both sides to send.
Unidirectional streams only allow the initiator to send.
""".
-spec i_can_send(nquic:stream_id(), client | server) -> boolean().
i_can_send(StreamID, MyRole) ->
    case stream_is_unidirectional(StreamID) of
        false ->
            true;
        true ->
            Initiator = stream_initiator(StreamID),
            Initiator =:= MyRole
    end.

-doc "Returns true if this stream was locally initiated.".
-spec is_locally_initiated(nquic:stream_id(), client | server) -> boolean().
is_locally_initiated(StreamID, MyRole) ->
    stream_initiator(StreamID) =:= MyRole.

-doc """
Returns true if the peer can send data on this stream.
Bidirectional streams allow both sides to send.
Unidirectional streams only allow the initiator to send.
""".
-spec peer_can_send(nquic:stream_id(), client | server) -> boolean().
peer_can_send(StreamID, MyRole) ->
    case stream_is_unidirectional(StreamID) of
        false ->
            true;
        true ->
            Initiator = stream_initiator(StreamID),
            Initiator =/= MyRole
    end.

-doc "Returns the initiator (client or server) of a stream based on its ID.".
-spec stream_initiator(nquic:stream_id()) -> client | server.
stream_initiator(StreamID) ->
    case StreamID band 1 of
        0 -> client;
        1 -> server
    end.

-doc "Returns true if the stream is unidirectional.".
-spec stream_is_unidirectional(nquic:stream_id()) -> boolean().
stream_is_unidirectional(StreamID) ->
    (StreamID band 2) =:= 2.

-doc """
Validate MAX_STREAM_DATA frame per RFC 9000 Section 19.10.
Can only receive for streams where we can send.
Stream must exist or be implicitly creatable.
""".
-spec validate_stream_for_max_stream_data(nquic:stream_id(), client | server, map()) ->
    ok | {error, stream_state_error}.
validate_stream_for_max_stream_data(StreamID, MyRole, Streams) ->
    case i_can_send(StreamID, MyRole) of
        false ->
            {error, stream_state_error};
        true ->
            case maps:is_key(StreamID, Streams) of
                true ->
                    ok;
                false ->
                    case is_locally_initiated(StreamID, MyRole) of
                        true -> {error, stream_state_error};
                        false -> ok
                    end
            end
    end.

-doc """
Validate STREAM frame per RFC 9000 Section 19.8.
Can only receive on streams where peer can send.
For locally-initiated streams, we must have created it first.
""".
-spec validate_stream_for_recv(nquic:stream_id(), client | server, map()) ->
    ok | {error, stream_state_error}.
validate_stream_for_recv(StreamID, MyRole, Streams) ->
    case peer_can_send(StreamID, MyRole) of
        false ->
            {error, stream_state_error};
        true ->
            case is_locally_initiated(StreamID, MyRole) of
                true ->
                    case maps:is_key(StreamID, Streams) of
                        true -> ok;
                        false -> {error, stream_state_error}
                    end;
                false ->
                    ok
            end
    end.

-doc """
Validate RESET_STREAM frame per RFC 9000 Section 19.4.
Can only receive RESET_STREAM on streams where peer can send.
""".
-spec validate_stream_for_reset(nquic:stream_id(), client | server) ->
    ok | {error, stream_state_error}.
validate_stream_for_reset(StreamID, MyRole) ->
    case peer_can_send(StreamID, MyRole) of
        true -> ok;
        false -> {error, stream_state_error}
    end.

-doc """
Validate STOP_SENDING frame per RFC 9000 Section 19.5.
Can only receive STOP_SENDING for streams where we can send.
Stream must exist or be implicitly creatable.
""".
-spec validate_stream_for_stop_sending(nquic:stream_id(), client | server, map()) ->
    ok | {error, stream_state_error}.
validate_stream_for_stop_sending(StreamID, MyRole, Streams) ->
    case i_can_send(StreamID, MyRole) of
        false ->
            {error, stream_state_error};
        true ->
            case maps:is_key(StreamID, Streams) of
                true ->
                    ok;
                false ->
                    case is_locally_initiated(StreamID, MyRole) of
                        true -> {error, stream_state_error};
                        false -> ok
                    end
            end
    end.

%%%-----------------------------------------------------------------------------
%% TLS CRYPTO VALIDATION (RFC 9001)
%%%-----------------------------------------------------------------------------
-doc """
Check for invalid TLS message types in Handshake-level CRYPTO frames.
RFC 9001 Section 6: KeyUpdate (24) MUST NOT be sent in CRYPTO frames.
RFC 9001 Section 8.3: EndOfEarlyData (5) is not used in QUIC.
""".
-spec check_handshake_crypto(binary()) -> ok | {error, {tls_alert, unexpected_message}}.
check_handshake_crypto(<<>>) ->
    ok;
check_handshake_crypto(<<Type:8, Len:24, _Body:Len/binary, Rest/binary>>) ->
    case Type of
        5 ->
            {error, {tls_alert, unexpected_message}};
        24 ->
            {error, {tls_alert, unexpected_message}};
        _ ->
            check_handshake_crypto(Rest)
    end;
check_handshake_crypto(_) ->
    ok.

-doc """
Check for invalid TLS message types in post-handshake CRYPTO frames.
RFC 9001 Section 6: KeyUpdate (24) MUST NOT be sent in CRYPTO frames.
RFC 9001 Section 8.3: EndOfEarlyData (5) is not used in QUIC.
NewSessionTicket (4) is allowed.
""".
-spec check_post_handshake_crypto(binary()) -> ok | {error, {tls_alert, unexpected_message}}.
check_post_handshake_crypto(<<>>) ->
    ok;
check_post_handshake_crypto(<<Type:8, Len:24, _Body:Len/binary, Rest/binary>>) ->
    case Type of
        5 ->
            {error, {tls_alert, unexpected_message}};
        24 ->
            {error, {tls_alert, unexpected_message}};
        _ ->
            check_post_handshake_crypto(Rest)
    end;
check_post_handshake_crypto(_) ->
    ok.

%%%-----------------------------------------------------------------------------
%% STREAM LIMIT HELPERS
%%%-----------------------------------------------------------------------------
-doc "Ensure stream flow control limits are initialized.".
-spec ensure_stream_limits(#stream_state{}, #conn_state{}) -> #stream_state{}.
ensure_stream_limits(StreamState, ConnState) ->
    if
        StreamState#stream_state.send_max_data =:= 0 andalso
            StreamState#stream_state.recv_window =:= 0 ->
            StreamType = nquic_stream_manager:type(StreamState#stream_state.stream_id),
            nquic_flow:init_stream_limits(StreamState, ConnState, StreamType);
        true ->
            StreamState
    end.

%%%-----------------------------------------------------------------------------
%% ACK PROCESSING
%%%-----------------------------------------------------------------------------
-doc "Decode ACK ranges into {Low, High} inclusive intervals. O(R) where R is the number of ranges.".
-spec decode_ack_ranges(non_neg_integer(), non_neg_integer(), [#ack_range{}]) ->
    [{non_neg_integer(), non_neg_integer()}].
decode_ack_ranges(Largest, FirstRange, Ranges) ->
    FirstLow = Largest - FirstRange,
    decode_ack_ranges_loop(FirstLow, Ranges, [{FirstLow, Largest}]).

-spec decode_ack_ranges_loop(
    non_neg_integer(), [#ack_range{}], [{non_neg_integer(), non_neg_integer()}]
) ->
    [{non_neg_integer(), non_neg_integer()}].
decode_ack_ranges_loop(_, [], Acc) ->
    Acc;
decode_ack_ranges_loop(PrevSmallest, [#ack_range{gap = Gap, length = Len} | Rest], Acc) ->
    High = PrevSmallest - Gap - 2,
    Low = High - Len,
    decode_ack_ranges_loop(Low, Rest, [{Low, High} | Acc]).
