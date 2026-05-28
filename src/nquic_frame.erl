-module(nquic_frame).

-moduledoc """
QUIC frame encoding and decoding per RFC 9000 Section 12.4.

Handles all 20+ frame types defined by the QUIC protocol. Encoding produces
iodata for zero-copy sending. Decoding uses inline varint macros
(`?DECODE_VARINT`) that preserve the binary match context for performance.
""".

-include("nquic_frame.hrl").
-export([decode/1, encode/1]).

-export_type([t/0]).

-type t() ::
    #padding{}
    | #ping{}
    | #ack{}
    | #reset_stream{}
    | #stop_sending{}
    | #crypto{}
    | #new_token{}
    | #stream{}
    | #max_data{}
    | #max_stream_data{}
    | #max_streams{}
    | #data_blocked{}
    | #stream_data_blocked{}
    | #streams_blocked{}
    | #new_connection_id{}
    | #retire_connection_id{}
    | #path_challenge{}
    | #path_response{}
    | #connection_close{}
    | #handshake_done{}
    | #datagram{}.

-define(DECODE_VARINT(Bin, Val, Rest),
    case Bin of
        <<0:2, Val:6, Rest/binary>> ->
            ok;
        <<1:2, Val:14, Rest/binary>> ->
            ok;
        <<2:2, Val:30, Rest/binary>> ->
            ok;
        <<3:2, Val:62, Rest/binary>> ->
            ok;
        _ ->
            Val = 0,
            Rest = <<>>,
            {error, incomplete_binary}
    end
).

-define(MATCH_BINARY(Bin, Len, Data, Rest),
    case Bin of
        <<Data:Len/binary, Rest/binary>> ->
            ok;
        _ ->
            Data = <<>>,
            Rest = <<>>,
            {error, incomplete_binary}
    end
).

-doc "Decode a single QUIC frame from binary. Returns `{ok, Frame, Rest}` or `{error, Reason}`.".
-spec decode(binary()) -> {ok, t(), binary()} | {error, nquic_error:any_reason()}.
decode(<<8, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, StreamID, Rest1),
        {ok,
            #stream{
                stream_id = StreamID,
                offset = 0,
                fin = false,
                data = Rest1,
                length = byte_size(Rest1)
            },
            <<>>}
    end;
decode(<<9, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, StreamID, Rest1),
        {ok,
            #stream{
                stream_id = StreamID,
                offset = 0,
                fin = true,
                data = Rest1,
                length = byte_size(Rest1)
            },
            <<>>}
    end;
decode(<<10, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, StreamID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Len, Rest2),
        ok ?= ?MATCH_BINARY(Rest2, Len, Data, Rest3),
        {ok,
            #stream{
                stream_id = StreamID,
                offset = 0,
                fin = false,
                data = Data,
                length = Len
            },
            Rest3}
    end;
decode(<<11, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, StreamID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Len, Rest2),
        ok ?= ?MATCH_BINARY(Rest2, Len, Data, Rest3),
        {ok,
            #stream{
                stream_id = StreamID,
                offset = 0,
                fin = true,
                data = Data,
                length = Len
            },
            Rest3}
    end;
decode(<<12, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, StreamID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Offset, Rest2),
        {ok,
            #stream{
                stream_id = StreamID,
                offset = Offset,
                fin = false,
                data = Rest2,
                length = byte_size(Rest2)
            },
            <<>>}
    end;
decode(<<13, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, StreamID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Offset, Rest2),
        {ok,
            #stream{
                stream_id = StreamID,
                offset = Offset,
                fin = true,
                data = Rest2,
                length = byte_size(Rest2)
            },
            <<>>}
    end;
decode(<<14, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, StreamID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Offset, Rest2),
        ok ?= ?DECODE_VARINT(Rest2, Len, Rest3),
        ok ?= ?MATCH_BINARY(Rest3, Len, Data, Rest4),
        {ok,
            #stream{
                stream_id = StreamID,
                offset = Offset,
                fin = false,
                data = Data,
                length = Len
            },
            Rest4}
    end;
decode(<<15, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, StreamID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Offset, Rest2),
        ok ?= ?DECODE_VARINT(Rest2, Len, Rest3),
        ok ?= ?MATCH_BINARY(Rest3, Len, Data, Rest4),
        {ok,
            #stream{
                stream_id = StreamID,
                offset = Offset,
                fin = true,
                data = Data,
                length = Len
            },
            Rest4}
    end;
decode(<<4, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, ID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Err, Rest2),
        ok ?= ?DECODE_VARINT(Rest2, Size, Rest3),
        {ok, #reset_stream{stream_id = ID, app_error_code = Err, final_size = Size}, Rest3}
    end;
decode(<<5, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, ID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Err, Rest2),
        {ok, #stop_sending{stream_id = ID, app_error_code = Err}, Rest2}
    end;
decode(<<7, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Len, Rest1),
        ok ?= ?MATCH_BINARY(Rest1, Len, Token, Rest2),
        {ok, #new_token{token = Token}, Rest2}
    end;
decode(<<16, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Max, Rest1),
        {ok, #max_data{max_data = Max}, Rest1}
    end;
decode(<<17, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, ID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Max, Rest2),
        {ok, #max_stream_data{stream_id = ID, max_stream_data = Max}, Rest2}
    end;
decode(<<18, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Max, Rest1),
        ok ?= validate_max_streams(Max),
        {ok, #max_streams{max_streams = Max, is_uni = false}, Rest1}
    end;
decode(<<19, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Max, Rest1),
        ok ?= validate_max_streams(Max),
        {ok, #max_streams{max_streams = Max, is_uni = true}, Rest1}
    end;
decode(<<20, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Limit, Rest1),
        {ok, #data_blocked{limit = Limit}, Rest1}
    end;
decode(<<21, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, ID, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Limit, Rest2),
        {ok, #stream_data_blocked{stream_id = ID, limit = Limit}, Rest2}
    end;
decode(<<22, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Limit, Rest1),
        ok ?= validate_max_streams(Limit),
        {ok, #streams_blocked{limit = Limit, is_uni = false}, Rest1}
    end;
decode(<<23, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Limit, Rest1),
        ok ?= validate_max_streams(Limit),
        {ok, #streams_blocked{limit = Limit, is_uni = true}, Rest1}
    end;
decode(<<24, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Seq, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Retire, Rest2),
        ok ?=
            case Rest2 of
                <<Len, CID:Len/binary, Token:16/binary, Rest3/binary>> ->
                    ok;
                _ ->
                    Len = 0,
                    CID = <<>>,
                    Token = <<>>,
                    Rest3 = <<>>,
                    {error, incomplete_binary}
            end,
        ok ?= validate_new_connection_id(Seq, Retire, Len),
        {ok,
            #new_connection_id{
                seq_num = Seq,
                retire_prior_to = Retire,
                cid = CID,
                stateless_reset_token = Token
            },
            Rest3}
    end;
decode(<<25, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Seq, Rest1),
        {ok, #retire_connection_id{seq_num = Seq}, Rest1}
    end;
decode(<<26, Data:8/binary, Rest/binary>>) ->
    {ok, #path_challenge{data = Data}, Rest};
decode(<<27, Data:8/binary, Rest/binary>>) ->
    {ok, #path_response{data = Data}, Rest};
decode(<<28, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Err, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Frame, Rest2),
        ok ?= ?DECODE_VARINT(Rest2, Len, Rest3),
        ok ?= ?MATCH_BINARY(Rest3, Len, Reason, Rest4),
        {ok,
            #connection_close{
                error_code = Err,
                frame_type = Frame,
                reason_phrase = Reason,
                is_application = false
            },
            Rest4}
    end;
decode(<<29, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Err, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Len, Rest2),
        ok ?= ?MATCH_BINARY(Rest2, Len, Reason, Rest3),
        {ok,
            #connection_close{
                error_code = Err,
                frame_type = 0,
                reason_phrase = Reason,
                is_application = true
            },
            Rest3}
    end;
decode(<<30, Rest/binary>>) ->
    {ok, #handshake_done{}, Rest};
decode(<<0, Rest/binary>>) ->
    {ok, #padding{}, Rest};
decode(<<1, Rest/binary>>) ->
    {ok, #ping{}, Rest};
decode(<<Type, Rest/binary>>) when Type =:= 2; Type =:= 3 ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Largest, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Delay, Rest2),
        ok ?= ?DECODE_VARINT(Rest2, RangeCount, Rest3),
        ok ?= ?DECODE_VARINT(Rest3, FirstRange, Rest4),
        {ok, Ranges, Rest5} ?= decode_ack_ranges(RangeCount, Rest4),
        {ok, ECN, Rest6} ?= decode_ecn(Type, Rest5),
        {ok,
            #ack{
                largest_acknowledged = Largest,
                delay = Delay,
                first_ack_range = FirstRange,
                ack_ranges = Ranges,
                ecn_counts = ECN
            },
            Rest6}
    end;
decode(<<6, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Offset, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Len, Rest2),
        ok ?= ?MATCH_BINARY(Rest2, Len, Data, Rest3),
        {ok, #crypto{offset = Offset, data = Data}, Rest3}
    end;
decode(<<16#30, Rest/binary>>) ->
    {ok, #datagram{data = Rest}, <<>>};
decode(<<16#31, Rest/binary>>) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Len, Rest1),
        ok ?= ?MATCH_BINARY(Rest1, Len, Data, Rest2),
        {ok, #datagram{data = Data}, Rest2}
    end;
decode(_) ->
    {error, frame_encoding_error}.

-spec decode_ack_ranges(non_neg_integer(), binary()) ->
    {ok, [#ack_range{}], binary()} | {error, term()}.
decode_ack_ranges(Count, Rest) ->
    decode_ack_ranges(Count, Rest, []).

-spec decode_ack_ranges(non_neg_integer(), binary(), [#ack_range{}]) ->
    {ok, [#ack_range{}], binary()} | {error, term()}.
decode_ack_ranges(0, Rest, Acc) ->
    {ok, lists:reverse(Acc), Rest};
decode_ack_ranges(Count, Rest, Acc) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, Gap, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, Len, Rest2),
        Range = #ack_range{gap = Gap, length = Len},
        decode_ack_ranges(Count - 1, Rest2, [Range | Acc])
    end.

-spec decode_ecn(2 | 3, binary()) ->
    {ok, undefined | {non_neg_integer(), non_neg_integer(), non_neg_integer()}, binary()}
    | {error, term()}.
decode_ecn(2, Rest) ->
    {ok, undefined, Rest};
decode_ecn(3, Rest) ->
    maybe
        ok ?= ?DECODE_VARINT(Rest, ECT0, Rest1),
        ok ?= ?DECODE_VARINT(Rest1, ECT1, Rest2),
        ok ?= ?DECODE_VARINT(Rest2, CE, Rest3),
        {ok, {ECT0, ECT1, CE}, Rest3}
    end.

-doc "Encode a QUIC frame record to iodata.".
-spec encode(t()) -> iodata().
encode(#padding{}) ->
    <<0>>;
encode(#ping{}) ->
    <<1>>;
encode(#ack{
    largest_acknowledged = Largest,
    delay = Delay,
    first_ack_range = FirstRange,
    ack_ranges = Ranges,
    ecn_counts = ECN
}) ->
    Type =
        case ECN of
            undefined -> 2;
            _ -> 3
        end,
    Bytes = [
        <<Type>>,
        nquic_varint:encode(Largest),
        nquic_varint:encode(Delay),
        nquic_varint:encode(length(Ranges)),
        nquic_varint:encode(FirstRange),
        [
            [nquic_varint:encode(G), nquic_varint:encode(L)]
         || #ack_range{gap = G, length = L} <- Ranges
        ],
        case ECN of
            undefined ->
                <<>>;
            {ECT0, ECT1, CE} ->
                [nquic_varint:encode(ECT0), nquic_varint:encode(ECT1), nquic_varint:encode(CE)]
        end
    ],
    Bytes;
encode(#reset_stream{stream_id = ID, app_error_code = Err, final_size = Size}) ->
    [<<4>>, nquic_varint:encode(ID), nquic_varint:encode(Err), nquic_varint:encode(Size)];
encode(#stop_sending{stream_id = ID, app_error_code = Err}) ->
    [<<5>>, nquic_varint:encode(ID), nquic_varint:encode(Err)];
encode(#crypto{offset = Offset, data = Data}) ->
    [<<6>>, nquic_varint:encode(Offset), nquic_varint:encode(byte_size(Data)), Data];
encode(#new_token{token = Token}) ->
    [<<7>>, nquic_varint:encode(byte_size(Token)), Token];
encode(#stream{stream_id = ID, offset = Offset, length = Len, data = Data, fin = Fin}) ->
    HasOffset = Offset > 0,
    Type = 8 bor stream_fin_bit(Fin) bor 2 bor stream_offset_bit(HasOffset),
    [
        <<Type>>,
        nquic_varint:encode(ID),
        encode_stream_offset(HasOffset, Offset),
        nquic_varint:encode(Len),
        Data
    ];
encode(#max_data{max_data = Max}) ->
    [<<16>>, nquic_varint:encode(Max)];
encode(#max_stream_data{stream_id = ID, max_stream_data = Max}) ->
    [<<17>>, nquic_varint:encode(ID), nquic_varint:encode(Max)];
encode(#max_streams{max_streams = Max, is_uni = false}) ->
    [<<18>>, nquic_varint:encode(Max)];
encode(#max_streams{max_streams = Max, is_uni = true}) ->
    [<<19>>, nquic_varint:encode(Max)];
encode(#data_blocked{limit = Limit}) ->
    [<<20>>, nquic_varint:encode(Limit)];
encode(#stream_data_blocked{stream_id = ID, limit = Limit}) ->
    [<<21>>, nquic_varint:encode(ID), nquic_varint:encode(Limit)];
encode(#streams_blocked{limit = Limit, is_uni = false}) ->
    [<<22>>, nquic_varint:encode(Limit)];
encode(#streams_blocked{limit = Limit, is_uni = true}) ->
    [<<23>>, nquic_varint:encode(Limit)];
encode(#new_connection_id{
    seq_num = Seq, retire_prior_to = Retire, cid = CID, stateless_reset_token = Token
}) ->
    [
        <<24>>,
        nquic_varint:encode(Seq),
        nquic_varint:encode(Retire),
        <<(byte_size(CID))>>,
        CID,
        Token
    ];
encode(#retire_connection_id{seq_num = Seq}) ->
    [<<25>>, nquic_varint:encode(Seq)];
encode(#path_challenge{data = Data}) ->
    <<26, Data/binary>>;
encode(#path_response{data = Data}) ->
    <<27, Data/binary>>;
encode(#connection_close{
    error_code = Err, frame_type = Frame, reason_phrase = Reason, is_application = false
}) ->
    [
        <<28>>,
        nquic_varint:encode(Err),
        nquic_varint:encode(Frame),
        nquic_varint:encode(byte_size(Reason)),
        Reason
    ];
encode(#connection_close{error_code = Err, reason_phrase = Reason, is_application = true}) ->
    [
        <<29>>,
        nquic_varint:encode(Err),
        nquic_varint:encode(byte_size(Reason)),
        Reason
    ];
encode(#handshake_done{}) ->
    <<30>>;
encode(#datagram{data = Data}) ->
    [<<16#31>>, nquic_varint:encode(byte_size(Data)), Data].

-spec encode_stream_offset(boolean(), non_neg_integer()) -> binary().
encode_stream_offset(true, Offset) -> nquic_varint:encode(Offset);
encode_stream_offset(false, _Offset) -> <<>>.

-spec stream_fin_bit(boolean()) -> 0 | 1.
stream_fin_bit(true) -> 1;
stream_fin_bit(false) -> 0.

-spec stream_offset_bit(boolean()) -> 0 | 4.
stream_offset_bit(true) -> 4;
stream_offset_bit(false) -> 0.

-spec validate_max_streams(non_neg_integer()) -> ok | {error, frame_encoding_error}.
validate_max_streams(Max) when Max < 16#1000000000000000 -> ok;
validate_max_streams(_) -> {error, frame_encoding_error}.

-spec validate_new_connection_id(non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, frame_encoding_error}.
validate_new_connection_id(Seq, Retire, Len) when Retire =< Seq, Len >= 1, Len =< 20 -> ok;
validate_new_connection_id(_, _, _) -> {error, frame_encoding_error}.
