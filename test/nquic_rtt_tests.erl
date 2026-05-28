-module(nquic_rtt_tests).
-include_lib("eunit/include/eunit.hrl").

-define(INITIAL_RTT_US, 333_000).

init_test() ->
    State = nquic_rtt:new(),
    Stats = nquic_rtt:get(State),
    ?assertEqual(0, maps:get(latest_rtt, Stats)),
    ?assertEqual(0, maps:get(min_rtt, Stats)),
    ?assertEqual(?INITIAL_RTT_US, maps:get(smoothed_rtt, Stats)),
    ?assertEqual(?INITIAL_RTT_US div 2, maps:get(rttvar, Stats)).

first_sample_test() ->
    State0 = nquic_rtt:new(),
    State1 = nquic_rtt:update(State0, 100, 0),
    Stats = nquic_rtt:get(State1),

    ?assertEqual(100, maps:get(latest_rtt, Stats)),
    ?assertEqual(100, maps:get(min_rtt, Stats)),
    ?assertEqual(100, maps:get(smoothed_rtt, Stats)),
    ?assertEqual(50, maps:get(rttvar, Stats)).

subsequent_update_test() ->
    State0 = nquic_rtt:new(),
    State1 = nquic_rtt:update(State0, 100, 0),

    State2 = nquic_rtt:update(State1, 200, 0),
    Stats = nquic_rtt:get(State2),

    ?assertEqual(200, maps:get(latest_rtt, Stats)),
    ?assertEqual(100, maps:get(min_rtt, Stats)),

    ?assertEqual(112, maps:get(smoothed_rtt, Stats)).

ack_delay_test() ->
    State0 = nquic_rtt:new(),
    State1 = nquic_rtt:update(State0, 100, 0),

    State2 = nquic_rtt:update(State1, 200, 50),
    Stats = nquic_rtt:get(State2),

    ?assertEqual(106, maps:get(smoothed_rtt, Stats)).
