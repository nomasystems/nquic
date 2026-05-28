-module(nquic_transport).

-moduledoc """
QUIC transport parameter encoding and decoding per RFC 9000 Section 18.

Transport parameters are exchanged during the TLS handshake and configure
connection behavior: flow control limits, stream limits, idle timeout,
connection ID management, and more.
""".

-include("nquic_transport.hrl").
-export([decode/2, encode/1]).

-export_type([params/0, preferred_address/0, version_information/0]).

-type params() :: #transport_params{}.

-type preferred_address() :: #{
    ipv4 := {inet:ip4_address(), inet:port_number()},
    ipv6 := {inet:ip6_address(), inet:port_number()},
    cid := nquic:connection_id(),
    stateless_reset_token := binary()
}.

-type version_information() :: #{
    chosen_version := non_neg_integer(),
    other_versions := [non_neg_integer()]
}.

-define(PARAM_ORIGINAL_DEST_CID, 16#00).
-define(PARAM_MAX_IDLE_TIMEOUT, 16#01).
-define(PARAM_STATELESS_RESET_TOKEN, 16#02).
-define(PARAM_MAX_UDP_PAYLOAD_SIZE, 16#03).
-define(PARAM_INITIAL_MAX_DATA, 16#04).
-define(PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 16#05).
-define(PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 16#06).
-define(PARAM_INITIAL_MAX_STREAM_DATA_UNI, 16#07).
-define(PARAM_INITIAL_MAX_STREAMS_BIDI, 16#08).
-define(PARAM_INITIAL_MAX_STREAMS_UNI, 16#09).
-define(PARAM_ACK_DELAY_EXPONENT, 16#0a).
-define(PARAM_MAX_ACK_DELAY, 16#0b).
-define(PARAM_DISABLE_ACTIVE_MIGRATION, 16#0c).
-define(PARAM_PREFERRED_ADDRESS, 16#0d).
-define(PARAM_ACTIVE_CONNECTION_ID_LIMIT, 16#0e).
-define(PARAM_INITIAL_SOURCE_CID, 16#0f).
-define(PARAM_RETRY_SOURCE_CID, 16#10).
-define(PARAM_VERSION_INFORMATION, 16#11).
-define(PARAM_MAX_DATAGRAM_FRAME_SIZE, 16#20).

-spec apply_param(non_neg_integer(), binary(), params(), client | server) ->
    {ok, params()} | {error, term()}.
apply_param(?PARAM_ORIGINAL_DEST_CID, Val, Acc, SenderRole) ->
    if
        SenderRole =:= client -> {error, transport_parameter_error};
        true -> {ok, Acc#transport_params{original_destination_connection_id = Val}}
    end;
apply_param(?PARAM_MAX_IDLE_TIMEOUT, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    {ok, Acc#transport_params{max_idle_timeout = ValInt}};
apply_param(?PARAM_STATELESS_RESET_TOKEN, Val, Acc, SenderRole) ->
    if
        SenderRole =:= client -> {error, transport_parameter_error};
        byte_size(Val) =/= 16 -> {error, transport_parameter_error};
        true -> {ok, Acc#transport_params{stateless_reset_token = Val}}
    end;
apply_param(?PARAM_MAX_UDP_PAYLOAD_SIZE, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    if
        ValInt < 1200 -> {error, transport_parameter_error};
        true -> {ok, Acc#transport_params{max_udp_payload_size = ValInt}}
    end;
apply_param(?PARAM_INITIAL_MAX_DATA, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    {ok, Acc#transport_params{initial_max_data = ValInt}};
apply_param(?PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    {ok, Acc#transport_params{initial_max_stream_data_bidi_local = ValInt}};
apply_param(?PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    {ok, Acc#transport_params{initial_max_stream_data_bidi_remote = ValInt}};
apply_param(?PARAM_INITIAL_MAX_STREAM_DATA_UNI, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    {ok, Acc#transport_params{initial_max_stream_data_uni = ValInt}};
apply_param(?PARAM_INITIAL_MAX_STREAMS_BIDI, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    {ok, Acc#transport_params{initial_max_streams_bidi = ValInt}};
apply_param(?PARAM_INITIAL_MAX_STREAMS_UNI, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    {ok, Acc#transport_params{initial_max_streams_uni = ValInt}};
apply_param(?PARAM_ACK_DELAY_EXPONENT, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    if
        ValInt > 20 -> {error, transport_parameter_error};
        true -> {ok, Acc#transport_params{ack_delay_exponent = ValInt}}
    end;
apply_param(?PARAM_MAX_ACK_DELAY, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    if
        ValInt >= 16384 -> {error, transport_parameter_error};
        true -> {ok, Acc#transport_params{max_ack_delay = ValInt}}
    end;
apply_param(?PARAM_DISABLE_ACTIVE_MIGRATION, _Val, Acc, _SenderRole) ->
    {ok, Acc#transport_params{disable_active_migration = true}};
apply_param(?PARAM_ACTIVE_CONNECTION_ID_LIMIT, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    if
        ValInt < 2 -> {error, {transport_parameter_error, invalid_active_cid_limit}};
        true -> {ok, Acc#transport_params{active_connection_id_limit = ValInt}}
    end;
apply_param(?PARAM_INITIAL_SOURCE_CID, Val, Acc, _SenderRole) ->
    {ok, Acc#transport_params{initial_source_connection_id = Val}};
apply_param(?PARAM_RETRY_SOURCE_CID, Val, Acc, SenderRole) ->
    if
        SenderRole =:= client -> {error, transport_parameter_error};
        true -> {ok, Acc#transport_params{retry_source_connection_id = Val}}
    end;
apply_param(?PARAM_PREFERRED_ADDRESS, Val, Acc, SenderRole) ->
    if
        SenderRole =:= client ->
            {error, transport_parameter_error};
        true ->
            case parse_preferred_address(Val) of
                {ok, PA} -> {ok, Acc#transport_params{preferred_address = PA}};
                {error, _} = Err -> Err
            end
    end;
apply_param(?PARAM_VERSION_INFORMATION, Val, Acc, _SenderRole) ->
    case parse_version_information(Val) of
        {ok, VI} -> {ok, Acc#transport_params{version_information = VI}};
        {error, _} = Err -> Err
    end;
apply_param(?PARAM_MAX_DATAGRAM_FRAME_SIZE, Val, Acc, _SenderRole) ->
    {ok, ValInt, _} = nquic_varint:decode(Val),
    {ok, Acc#transport_params{max_datagram_frame_size = ValInt}};
apply_param(_ID, _Val, Acc, _SenderRole) ->
    {ok, Acc}.

-doc "Decode transport parameters from binary. SenderRole identifies who sent them.".
-spec decode(binary(), client | server) ->
    {ok, params()} | {error, nquic_error:any_reason()}.
decode(Bin, SenderRole) ->
    case decode_loop(Bin, SenderRole, #transport_params{}, #{}) of
        {ok, Params, Seen} ->
            validate_required(Params, Seen, SenderRole);
        Error ->
            Error
    end.

-spec decode_loop(binary(), client | server, params(), #{non_neg_integer() => true}) ->
    {ok, params(), #{non_neg_integer() => true}} | {error, term()}.
decode_loop(<<>>, _SenderRole, Acc, Seen) ->
    {ok, Acc, Seen};
decode_loop(Bin, SenderRole, Acc, Seen) ->
    case nquic_varint:decode(Bin) of
        {ok, ID, Rest1} ->
            case maps:is_key(ID, Seen) of
                true ->
                    {error, duplicate_parameter};
                false ->
                    case nquic_varint:decode(Rest1) of
                        {ok, Len, Rest2} ->
                            case Rest2 of
                                <<Val:Len/binary, Rest3/binary>> ->
                                    case apply_param(ID, Val, Acc, SenderRole) of
                                        {ok, NewAcc} ->
                                            decode_loop(Rest3, SenderRole, NewAcc, Seen#{ID => true});
                                        Error ->
                                            Error
                                    end;
                                _ ->
                                    {error, truncated_param_value}
                            end;
                        Error ->
                            Error
                    end
            end;
        Error ->
            Error
    end.

-doc "Encode transport parameters to binary for the TLS handshake.".
-spec encode(params()) -> binary().
encode(Params) ->
    iolist_to_binary([
        encode_param(
            ?PARAM_ORIGINAL_DEST_CID, Params#transport_params.original_destination_connection_id
        ),
        encode_param(?PARAM_MAX_IDLE_TIMEOUT, Params#transport_params.max_idle_timeout),
        encode_param(?PARAM_STATELESS_RESET_TOKEN, Params#transport_params.stateless_reset_token),
        encode_param(?PARAM_MAX_UDP_PAYLOAD_SIZE, Params#transport_params.max_udp_payload_size),
        encode_param(?PARAM_INITIAL_MAX_DATA, Params#transport_params.initial_max_data),
        encode_param(
            ?PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            Params#transport_params.initial_max_stream_data_bidi_local
        ),
        encode_param(
            ?PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            Params#transport_params.initial_max_stream_data_bidi_remote
        ),
        encode_param(
            ?PARAM_INITIAL_MAX_STREAM_DATA_UNI, Params#transport_params.initial_max_stream_data_uni
        ),
        encode_param(
            ?PARAM_INITIAL_MAX_STREAMS_BIDI, Params#transport_params.initial_max_streams_bidi
        ),
        encode_param(
            ?PARAM_INITIAL_MAX_STREAMS_UNI, Params#transport_params.initial_max_streams_uni
        ),
        encode_param(?PARAM_ACK_DELAY_EXPONENT, Params#transport_params.ack_delay_exponent),
        encode_param(?PARAM_MAX_ACK_DELAY, Params#transport_params.max_ack_delay),
        encode_param(
            ?PARAM_DISABLE_ACTIVE_MIGRATION, Params#transport_params.disable_active_migration
        ),
        encode_preferred_address(Params#transport_params.preferred_address),
        encode_param(
            ?PARAM_ACTIVE_CONNECTION_ID_LIMIT, Params#transport_params.active_connection_id_limit
        ),
        encode_param(
            ?PARAM_INITIAL_SOURCE_CID, Params#transport_params.initial_source_connection_id
        ),
        encode_param(?PARAM_RETRY_SOURCE_CID, Params#transport_params.retry_source_connection_id),
        encode_version_information(Params#transport_params.version_information),
        encode_param(
            ?PARAM_MAX_DATAGRAM_FRAME_SIZE, Params#transport_params.max_datagram_frame_size
        )
    ]).

-spec encode_param(non_neg_integer(), undefined | boolean() | non_neg_integer() | binary()) ->
    binary().
encode_param(_ID, undefined) ->
    <<>>;
encode_param(?PARAM_DISABLE_ACTIVE_MIGRATION, false) ->
    <<>>;
encode_param(?PARAM_DISABLE_ACTIVE_MIGRATION, true) ->
    encode_tl(?PARAM_DISABLE_ACTIVE_MIGRATION, <<>>);
encode_param(ID, Val) when is_integer(Val) ->
    encode_tl(ID, nquic_varint:encode(Val));
encode_param(ID, Val) when is_binary(Val) ->
    encode_tl(ID, Val).

-spec encode_preferred_address(preferred_address() | undefined) -> binary().
encode_preferred_address(undefined) ->
    <<>>;
encode_preferred_address(#{
    ipv4 := {IPv4, V4Port}, ipv6 := {IPv6, V6Port}, cid := CID, stateless_reset_token := Token
}) ->
    {A, B, C, D} = IPv4,
    {E, F, G, H, I, J, K, L} = IPv6,
    CIDLen = byte_size(CID),
    Val = <<
        A,
        B,
        C,
        D,
        V4Port:16,
        E:16,
        F:16,
        G:16,
        H:16,
        I:16,
        J:16,
        K:16,
        L:16,
        V6Port:16,
        CIDLen,
        CID/binary,
        Token:16/binary
    >>,
    encode_tl(?PARAM_PREFERRED_ADDRESS, Val).

-spec encode_tl(non_neg_integer(), binary()) -> binary().
encode_tl(ID, Val) ->
    <<(nquic_varint:encode(ID))/binary, (nquic_varint:encode(byte_size(Val)))/binary, Val/binary>>.

-spec encode_version_information(version_information() | undefined) -> binary().
encode_version_information(undefined) ->
    <<>>;
encode_version_information(#{chosen_version := Chosen, other_versions := Others}) ->
    OthersBin = <<<<V:32>> || V <- Others>>,
    Val = <<Chosen:32, OthersBin/binary>>,
    encode_tl(?PARAM_VERSION_INFORMATION, Val).

-spec parse_preferred_address(binary()) ->
    {ok, preferred_address()} | {error, nquic_error:any_reason()}.
parse_preferred_address(<<
    A,
    B,
    C,
    D,
    V4Port:16,
    E:16,
    F:16,
    G:16,
    H:16,
    I:16,
    J:16,
    K:16,
    L:16,
    V6Port:16,
    CIDLen,
    Rest/binary
>>) when CIDLen >= 0, CIDLen =< 20 ->
    case Rest of
        <<CID:CIDLen/binary, Token:16/binary>> ->
            {ok, #{
                ipv4 => {{A, B, C, D}, V4Port},
                ipv6 => {{E, F, G, H, I, J, K, L}, V6Port},
                cid => CID,
                stateless_reset_token => Token
            }};
        _ ->
            {error, {transport_parameter_error, malformed_preferred_address}}
    end;
parse_preferred_address(_) ->
    {error, {transport_parameter_error, malformed_preferred_address}}.

-spec parse_version_information(binary()) ->
    {ok, version_information()} | {error, term()}.
parse_version_information(<<Chosen:32, Rest/binary>>) when byte_size(Rest) rem 4 =:= 0 ->
    Others = [V || <<V:32>> <= Rest],
    {ok, #{chosen_version => Chosen, other_versions => Others}};
parse_version_information(_) ->
    {error, {transport_parameter_error, malformed_version_information}}.

-spec validate_required(params(), #{non_neg_integer() => true}, client | server) ->
    {ok, params()} | {error, term()}.
validate_required(Params, Seen, SenderRole) ->
    case maps:is_key(?PARAM_INITIAL_SOURCE_CID, Seen) of
        false ->
            {error, {transport_parameter_error, missing_initial_source_cid}};
        true ->
            case SenderRole of
                server ->
                    case maps:is_key(?PARAM_ORIGINAL_DEST_CID, Seen) of
                        false ->
                            {error, {transport_parameter_error, missing_original_dest_cid}};
                        true ->
                            {ok, Params}
                    end;
                client ->
                    {ok, Params}
            end
    end.
