%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_varint}.
%%%-------------------------------------------------------------------
-module(nquic_varint_tests).

-include_lib("eunit/include/eunit.hrl").

encode_decode_test_() ->
    [
        {"1 byte low", ?_assertMatch(<<0:2, 0:6>>, nquic_varint:encode(0))},
        {"1 byte high", ?_assertMatch(<<0:2, 63:6>>, nquic_varint:encode(63))},
        {"2 byte low", ?_assertMatch(<<1:2, 64:14>>, nquic_varint:encode(64))},
        {"2 byte high", ?_assertMatch(<<1:2, 16383:14>>, nquic_varint:encode(16383))},
        {"4 byte low", ?_assertMatch(<<2:2, 16384:30>>, nquic_varint:encode(16384))},
        {"4 byte high", ?_assertMatch(<<2:2, 1073741823:30>>, nquic_varint:encode(1073741823))},
        {"8 byte low", ?_assertMatch(<<3:2, 1073741824:62>>, nquic_varint:encode(1073741824))},
        {"8 byte high",
            ?_assertMatch(
                <<3:2, 4611686018427387903:62>>, nquic_varint:encode(4611686018427387903)
            )}
    ].

roundtrip_test() ->
    Values = [0, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903],
    [
        ?_assertEqual({ok, V, <<>>}, nquic_varint:decode(nquic_varint:encode(V)))
     || V <- Values
    ].

decode_incomplete_test() ->
    ?assertMatch({error, incomplete_binary}, nquic_varint:decode(<<1:2, 1:6>>)).

safe_encode_test() ->
    ?assertEqual({ok, <<0:2, 42:6>>}, nquic_varint:safe_encode(42)),
    ?assertEqual({error, overflow}, nquic_varint:safe_encode(4611686018427387904)),
    ?assertEqual({error, overflow}, nquic_varint:safe_encode(-1)).
