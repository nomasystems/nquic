-module(nquic_stream_manager).
-moduledoc """
Stream ID allocation and validation per RFC 9000 Section 2.

Manages stream creation with limit checking. Stream IDs encode the
initiator (client/server) and type (bidi/uni) in the low 2 bits, and
increment by 4 for each new stream of the same type.
""".

-include("nquic_conn.hrl").
-export([
    first_peer_stream_id/2,
    get_or_create/3,
    get_or_create/4,
    type/1
]).

-spec check_stream_limit(nquic:stream_id(), bidi | uni, client | server, client | server, map()) ->
    ok | {error, stream_limit_error}.
check_stream_limit(StreamID, Type, Init, MyRole, Limits) ->
    case Init =:= MyRole of
        true ->
            ok;
        false ->
            StreamNum = StreamID div 4,
            MaxCount =
                case Type of
                    bidi -> maps:get(max_bidi, Limits, infinity);
                    uni -> maps:get(max_uni, Limits, infinity)
                end,
            case MaxCount of
                infinity -> ok;
                N when StreamNum < N -> ok;
                _ -> {error, stream_limit_error}
            end
    end.

-doc "Return the first stream ID initiated by the peer for the given type.".
-spec first_peer_stream_id(client | server, bidi | uni) -> nquic:stream_id().
first_peer_stream_id(server, bidi) -> 0;
first_peer_stream_id(server, uni) -> 2;
first_peer_stream_id(client, bidi) -> 1;
first_peer_stream_id(client, uni) -> 3.

-doc "Retrieve an existing stream or create a new one with no limit checking.".
-spec get_or_create(nquic:stream_id(), map(), client | server) ->
    {ok, #stream_state{}, map()} | {error, term()}.
get_or_create(StreamID, Streams, Role) ->
    get_or_create(StreamID, Streams, Role, #{max_bidi => infinity, max_uni => infinity}).

-doc "Retrieve an existing stream or create a new one, validating against concurrency limits.".
-spec get_or_create(nquic:stream_id(), map(), client | server, map()) ->
    {ok, #stream_state{}, map()} | {error, term()}.
get_or_create(StreamID, Streams, Role, Limits) ->
    case maps:find(StreamID, Streams) of
        {ok, State} ->
            {ok, State, Streams};
        error ->
            Type = type(StreamID),
            Init = nquic_frame_handler:stream_initiator(StreamID),

            case check_stream_limit(StreamID, Type, Init, Role, Limits) of
                {error, _} = Err ->
                    Err;
                ok ->
                    if
                        StreamID > 16#3FFFFFFFFFFFFFFF ->
                            {error, invalid_stream_id};
                        true ->
                            State = nquic_stream_statem:new(StreamID, Type),
                            {ok, State, Streams#{StreamID => State}}
                    end
            end
    end.

-doc "Return the stream type (bidi or uni) based on the low 2 bits of the stream ID.".
-spec type(nquic:stream_id()) -> bidi | uni.
type(StreamID) ->
    case StreamID rem 4 of
        0 -> bidi;
        1 -> bidi;
        2 -> uni;
        3 -> uni
    end.
