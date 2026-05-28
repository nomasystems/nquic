%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_packet_number}.
%%%-------------------------------------------------------------------
-module(nquic_packet_number_tests).

-include_lib("eunit/include/eunit.hrl").

roundtrip_test() ->
    Largest = 1000,
    PN = 1010,
    {Len, Trunc} = nquic_packet_number:encode(PN, Largest),
    ?assertEqual(PN, nquic_packet_number:decode(Largest, Trunc, Len)).

wrap_around_test() ->
    Largest = 16#FFFF,
    PN = 16#10001,
    {Len, Trunc} = nquic_packet_number:encode(PN, Largest),
    ?assertEqual(PN, nquic_packet_number:decode(Largest, Trunc, Len)).
