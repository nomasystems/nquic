%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_token_cache}.
%%%-------------------------------------------------------------------
-module(nquic_token_cache_tests).

-include_lib("eunit/include/eunit.hrl").

child_spec_default_test() ->
    Spec = nquic_token_cache:child_spec(test_token_cache_a),
    ?assertEqual({nquic_token_cache, test_token_cache_a}, maps:get(id, Spec)),
    ?assertMatch({nquic_token_cache, start_link, [_, _]}, maps:get(start, Spec)),
    ?assertEqual(permanent, maps:get(restart, Spec)),
    ?assertEqual(worker, maps:get(type, Spec)).

child_spec_custom_opts_test() ->
    Spec = nquic_token_cache:child_spec(test_token_cache_b, #{sweep_ms => 5000}),
    {nquic_token_cache, start_link, [_, Opts]} = maps:get(start, Spec),
    ?assertEqual(5000, maps:get(sweep_ms, Opts)).

start_stop_cache_test() ->
    {ok, _Pid} = nquic_token_cache:start_link(test_token_cache_c),
    ?assertEqual(0, nquic_token_cache:size(test_token_cache_c)),
    ?assertEqual(ok, nquic_token_cache:stop(test_token_cache_c)).

stop_unstarted_cache_is_ok_test() ->
    ?assertEqual(ok, nquic_token_cache:stop(never_started_token_cache)).

store_lookup_roundtrip_test() ->
    Name = test_token_cache_d,
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        Host = "example.com",
        Port = 4433,
        Token = <<"token-bytes">>,
        ok = nquic_token_cache:store(Name, Host, Port, Token),
        ?assertEqual(1, nquic_token_cache:size(Name)),
        ?assertEqual({ok, Token}, nquic_token_cache:lookup(Name, Host, Port))
    after
        nquic_token_cache:stop(Name)
    end.

lookup_miss_returns_not_found_test() ->
    Name = test_token_cache_e,
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        ?assertEqual({error, not_found}, nquic_token_cache:lookup(Name, "missing.test", 1))
    after
        nquic_token_cache:stop(Name)
    end.

lookup_expired_evicts_entry_test() ->
    Name = test_token_cache_f,
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        Host = "expired.test",
        Port = 4433,
        Token = <<"x">>,
        Key = {Host, Port},
        Past = erlang:system_time(second) - 10,
        true = ets:insert(Name, {Key, Token, Past}),
        ?assertEqual({error, not_found}, nquic_token_cache:lookup(Name, Host, Port)),
        ?assertEqual(0, nquic_token_cache:size(Name))
    after
        nquic_token_cache:stop(Name)
    end.

delete_entry_test() ->
    Name = test_token_cache_g,
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        ok = nquic_token_cache:store(Name, "x.test", 1, <<"t">>),
        ok = nquic_token_cache:delete(Name, "x.test", 1),
        ?assertEqual({error, not_found}, nquic_token_cache:lookup(Name, "x.test", 1))
    after
        nquic_token_cache:stop(Name)
    end.

clear_all_entries_test() ->
    Name = test_token_cache_h,
    {ok, _Pid} = nquic_token_cache:start_link(Name),
    try
        ok = nquic_token_cache:store(Name, "a.test", 1, <<"a">>),
        ok = nquic_token_cache:store(Name, "b.test", 2, <<"b">>),
        ?assertEqual(2, nquic_token_cache:size(Name)),
        ok = nquic_token_cache:clear(Name),
        ?assertEqual(0, nquic_token_cache:size(Name))
    after
        nquic_token_cache:stop(Name)
    end.

handle_call_unknown_test() ->
    Name = test_token_cache_i,
    {ok, Pid} = nquic_token_cache:start_link(Name),
    try
        ?assertEqual({error, unknown_request}, gen_server:call(Pid, surprise))
    after
        nquic_token_cache:stop(Name)
    end.

handle_cast_unknown_test() ->
    Name = test_token_cache_j,
    {ok, Pid} = nquic_token_cache:start_link(Name),
    try
        gen_server:cast(Pid, anything),
        ?assert(is_process_alive(Pid))
    after
        nquic_token_cache:stop(Name)
    end.

handle_info_unknown_test() ->
    Name = test_token_cache_k,
    {ok, Pid} = nquic_token_cache:start_link(Name),
    try
        Pid ! random_info,
        timer:sleep(10),
        ?assert(is_process_alive(Pid))
    after
        nquic_token_cache:stop(Name)
    end.

handle_info_sweep_runs_eviction_test() ->
    Name = test_token_cache_l,
    {ok, Pid} = nquic_token_cache:start_link(Name, #{sweep_ms => 1_000_000}),
    try
        Past = erlang:system_time(second) - 10,
        true = ets:insert(Name, {{"old.test", 1}, <<"old">>, Past}),
        Pid ! sweep,
        timer:sleep(20),
        ?assert(is_process_alive(Pid)),
        ?assertEqual(0, nquic_token_cache:size(Name))
    after
        nquic_token_cache:stop(Name)
    end.
