%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_pmtud}.
%%%
%%% Macros and the `pmtud' record mirror the source-of-truth in
%%% `src/nquic_pmtud.erl'; if the production constants/layout change,
%%% update the values here so the tests stay in sync.
%%%-------------------------------------------------------------------
-module(nquic_pmtud_tests).

-include_lib("eunit/include/eunit.hrl").

-define(BASE_PLPMTU, 1200).
-define(MAX_PLPMTU, 1452).
-define(REPROBE_INTERVAL_MS, 600000).

-record(pmtud, {
    state = disabled :: disabled | base | searching | search_complete | error,
    current_mtu = ?BASE_PLPMTU :: pos_integer(),
    probe_size = 0 :: non_neg_integer(),
    probe_count = 0 :: non_neg_integer(),
    search_low = ?BASE_PLPMTU :: pos_integer(),
    search_high = ?MAX_PLPMTU :: pos_integer(),
    probe_pending = false :: boolean(),
    last_probe_time = 0 :: non_neg_integer()
}).

new_default_test() ->
    S = nquic_pmtud:new(),
    ?assertEqual(disabled, nquic_pmtud:get_state(S)),
    ?assertEqual(?BASE_PLPMTU, nquic_pmtud:get_current_mtu(S)),
    ?assertNot(nquic_pmtud:needs_probe(S)).

new_custom_max_test() ->
    S = nquic_pmtud:new(9000),
    ?assertEqual(disabled, nquic_pmtud:get_state(S)),
    ?assertEqual(9000, S#pmtud.search_high).

enable_test() ->
    S0 = nquic_pmtud:new(),
    S1 = nquic_pmtud:enable(S0),
    ?assertEqual(searching, nquic_pmtud:get_state(S1)),
    ?assert(nquic_pmtud:needs_probe(S1)),
    ProbeSize = nquic_pmtud:get_probe_size(S1),
    ?assert(ProbeSize > ?BASE_PLPMTU),
    ?assert(ProbeSize =< ?MAX_PLPMTU).

disable_test() ->
    S0 = nquic_pmtud:enable(nquic_pmtud:new()),
    S1 = nquic_pmtud:disable(S0),
    ?assertEqual(disabled, nquic_pmtud:get_state(S1)),
    ?assertEqual(?BASE_PLPMTU, nquic_pmtud:get_current_mtu(S1)),
    ?assertNot(nquic_pmtud:needs_probe(S1)).

generate_probe_test() ->
    S0 = nquic_pmtud:enable(nquic_pmtud:new()),
    {ok, Frames, Size, S1} = nquic_pmtud:generate_probe(S0),
    ?assert(length(Frames) > 0),
    ?assert(Size > ?BASE_PLPMTU),
    ?assertNot(nquic_pmtud:needs_probe(S1)).

generate_probe_not_needed_test() ->
    S = nquic_pmtud:new(),
    ?assertEqual({error, no_probe_needed}, nquic_pmtud:generate_probe(S)).

probe_acked_continues_search_test() ->
    S0 = nquic_pmtud:enable(nquic_pmtud:new()),
    {ok, _, _, S1} = nquic_pmtud:generate_probe(S0),
    S2 = nquic_pmtud:on_probe_acked(S1),
    ?assert(nquic_pmtud:get_current_mtu(S2) > ?BASE_PLPMTU),
    ?assert(
        nquic_pmtud:get_state(S2) =:= searching orelse
            nquic_pmtud:get_state(S2) =:= search_complete
    ).

probe_lost_retries_test() ->
    S0 = nquic_pmtud:enable(nquic_pmtud:new()),
    {ok, _, _, S1} = nquic_pmtud:generate_probe(S0),
    S2 = nquic_pmtud:on_probe_lost(S1),
    ?assertEqual(searching, nquic_pmtud:get_state(S2)),
    ?assert(nquic_pmtud:needs_probe(S2)),
    ?assertEqual(nquic_pmtud:get_probe_size(S0), nquic_pmtud:get_probe_size(S2)).

probe_lost_three_times_steps_down_test() ->
    S0 = nquic_pmtud:enable(nquic_pmtud:new()),
    {ok, _, _, S1} = nquic_pmtud:generate_probe(S0),
    S2 = nquic_pmtud:on_probe_lost(S1),
    {ok, _, _, S3} = nquic_pmtud:generate_probe(S2),
    S4 = nquic_pmtud:on_probe_lost(S3),
    {ok, _, _, S5} = nquic_pmtud:generate_probe(S4),
    S6 = nquic_pmtud:on_probe_lost(S5),
    case nquic_pmtud:get_state(S6) of
        searching ->
            ?assert(nquic_pmtud:get_probe_size(S6) < nquic_pmtud:get_probe_size(S0));
        search_complete ->
            ok
    end.

search_complete_reprobe_test() ->
    S0 = nquic_pmtud:new(1220),
    S1 = nquic_pmtud:enable(S0),
    {ok, _, _, S2} = nquic_pmtud:generate_probe(S1),
    S3 = nquic_pmtud:on_probe_acked(S2),
    ?assertEqual(search_complete, nquic_pmtud:get_state(S3)),
    ?assertEqual(?REPROBE_INTERVAL_MS, nquic_pmtud:get_timer_ms(S3)).

on_timeout_reprobes_test() ->
    S0 = nquic_pmtud:new(1452),
    S1 = nquic_pmtud:enable(S0),
    {ok, _, _, S2} = nquic_pmtud:generate_probe(S1),
    S3 = nquic_pmtud:on_probe_acked(S2),
    S4 = search_until_complete(S3),
    ?assertEqual(search_complete, nquic_pmtud:get_state(S4)),
    S5 = nquic_pmtud:on_timeout(S4),
    case nquic_pmtud:get_current_mtu(S4) < S4#pmtud.search_high of
        true ->
            ?assertEqual(searching, nquic_pmtud:get_state(S5)),
            ?assert(nquic_pmtud:needs_probe(S5));
        false ->
            ?assertEqual(search_complete, nquic_pmtud:get_state(S5))
    end.

black_hole_test() ->
    S0 = nquic_pmtud:enable(nquic_pmtud:new()),
    {ok, _, _, S1} = nquic_pmtud:generate_probe(S0),
    S2 = nquic_pmtud:on_probe_acked(S1),
    S3 = nquic_pmtud:on_black_hole(S2),
    ?assertEqual(error, nquic_pmtud:get_state(S3)),
    ?assertEqual(?BASE_PLPMTU, nquic_pmtud:get_current_mtu(S3)).

timer_disabled_test() ->
    ?assertEqual(infinity, nquic_pmtud:get_timer_ms(nquic_pmtud:new())).

timer_searching_test() ->
    S = nquic_pmtud:enable(nquic_pmtud:new()),
    ?assertEqual(infinity, nquic_pmtud:get_timer_ms(S)).

search_until_complete(#pmtud{state = search_complete} = S) ->
    S;
search_until_complete(#pmtud{state = searching} = S) ->
    case nquic_pmtud:needs_probe(S) of
        true ->
            {ok, _, _, S1} = nquic_pmtud:generate_probe(S),
            S2 = nquic_pmtud:on_probe_acked(S1),
            search_until_complete(S2);
        false ->
            S
    end.

%% Drive the full DPLPMTUD search to completion: enable (and the
%% already-enabled idempotent arm) -> repeated probe acks until the
%% binary search collapses to search_complete -> on_timeout from
%% search_complete -> probe-loss give-up, exercising every arm.
search_lifecycle_test() ->
    S0 = nquic_pmtud:enable(nquic_pmtud:new(9000)),
    ?assertEqual(searching, nquic_pmtud:get_state(S0)),
    %% enable/1 on an already-enabled state is the identity arm.
    ?assertEqual(S0, nquic_pmtud:enable(S0)),
    %% Ack probes until the search range collapses (search_complete),
    %% bounded so a non-converging change can't hang the suite.
    Done = ack_until_complete(S0, 64),
    ?assertEqual(search_complete, nquic_pmtud:get_state(Done)),
    ?assert(nquic_pmtud:get_current_mtu(Done) >= ?BASE_PLPMTU),
    %% on_timeout from search_complete reprobes (or stays put).
    T1 = nquic_pmtud:on_timeout(Done),
    ?assert(nquic_pmtud:get_current_mtu(T1) >= ?BASE_PLPMTU),
    %% Probe-loss give-up path from a fresh search.
    L0 = nquic_pmtud:enable(nquic_pmtud:new(9000)),
    Lost = lists:foldl(fun(_, S) -> nquic_pmtud:on_probe_lost(S) end, L0, lists:seq(1, 12)),
    ?assert(nquic_pmtud:get_current_mtu(Lost) >= ?BASE_PLPMTU),
    %% on_timeout from a non-search_complete state hits the fallthrough.
    T2 = nquic_pmtud:on_timeout(Lost),
    ?assert(nquic_pmtud:get_current_mtu(T2) >= ?BASE_PLPMTU).

ack_until_complete(S, 0) ->
    S;
ack_until_complete(S, N) ->
    case nquic_pmtud:get_state(S) of
        searching -> ack_until_complete(nquic_pmtud:on_probe_acked(S), N - 1);
        _ -> S
    end.
