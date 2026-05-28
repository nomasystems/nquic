%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_session_cache}.
%%%-------------------------------------------------------------------
-module(nquic_session_cache_tests).

-include_lib("eunit/include/eunit.hrl").

-define(NAME, nquic_session_cache_test).

setup_() ->
    nquic_session_cache:stop(?NAME),
    {ok, _} = nquic_session_cache:start_link(?NAME, #{sweep_ms => 60_000}),
    ok.

teardown_() ->
    nquic_session_cache:stop(?NAME).

store_lookup_test() ->
    setup_(),
    try
        Ticket = #{psk => <<1:256>>, cipher => aes_128_gcm, lifetime => 3600},
        ok = nquic_session_cache:store(?NAME, "localhost", 4433, Ticket),
        {ok, Retrieved} = nquic_session_cache:lookup(?NAME, "localhost", 4433),
        ?assertEqual(Ticket, Retrieved)
    after
        teardown_()
    end.

lookup_missing_test() ->
    setup_(),
    try
        ?assertEqual({error, not_found}, nquic_session_cache:lookup(?NAME, "unknown", 9999))
    after
        teardown_()
    end.

lookup_expired_test() ->
    setup_(),
    try
        Ticket = #{psk => <<1:256>>, cipher => aes_128_gcm, lifetime => 0},
        ok = nquic_session_cache:store(?NAME, "localhost", 4433, Ticket),
        timer:sleep(1100),
        ?assertEqual({error, not_found}, nquic_session_cache:lookup(?NAME, "localhost", 4433))
    after
        teardown_()
    end.

delete_test() ->
    setup_(),
    try
        Ticket = #{psk => <<1:256>>, cipher => aes_128_gcm, lifetime => 3600},
        ok = nquic_session_cache:store(?NAME, "localhost", 4433, Ticket),
        ok = nquic_session_cache:delete(?NAME, "localhost", 4433),
        ?assertEqual({error, not_found}, nquic_session_cache:lookup(?NAME, "localhost", 4433))
    after
        teardown_()
    end.

clear_test() ->
    setup_(),
    try
        ok = nquic_session_cache:store(?NAME, "a", 1, #{lifetime => 3600}),
        ok = nquic_session_cache:store(?NAME, "b", 2, #{lifetime => 3600}),
        ?assert(nquic_session_cache:size(?NAME) >= 2),
        nquic_session_cache:clear(?NAME),
        ?assertEqual(0, nquic_session_cache:size(?NAME))
    after
        teardown_()
    end.

overwrite_test() ->
    setup_(),
    try
        T1 = #{psk => <<1:256>>, cipher => aes_128_gcm, lifetime => 3600},
        T2 = #{psk => <<2:256>>, cipher => aes_256_gcm, lifetime => 3600},
        ok = nquic_session_cache:store(?NAME, "localhost", 4433, T1),
        ok = nquic_session_cache:store(?NAME, "localhost", 4433, T2),
        {ok, Retrieved} = nquic_session_cache:lookup(?NAME, "localhost", 4433),
        ?assertEqual(T2, Retrieved),
        ?assertEqual(1, nquic_session_cache:size(?NAME))
    after
        teardown_()
    end.

fails_loud_when_not_started_test() ->
    nquic_session_cache:stop(?NAME),
    ?assertError(badarg, nquic_session_cache:lookup(?NAME, "localhost", 4433)).

sweep_test() ->
    nquic_session_cache:stop(?NAME),
    {ok, _} = nquic_session_cache:start_link(?NAME, #{sweep_ms => 50}),
    try
        ok = nquic_session_cache:store(?NAME, "a", 1, #{lifetime => 0}),
        ?assertEqual(1, nquic_session_cache:size(?NAME)),
        timer:sleep(150),
        ?assertEqual(0, nquic_session_cache:size(?NAME))
    after
        teardown_()
    end.

multiple_instances_test() ->
    A = nquic_session_cache_a,
    B = nquic_session_cache_b,
    nquic_session_cache:stop(A),
    nquic_session_cache:stop(B),
    {ok, _} = nquic_session_cache:start_link(A),
    {ok, _} = nquic_session_cache:start_link(B),
    try
        ok = nquic_session_cache:store(A, "h", 1, #{lifetime => 3600}),
        ?assertEqual(1, nquic_session_cache:size(A)),
        ?assertEqual(0, nquic_session_cache:size(B)),
        ok = nquic_session_cache:store(B, "h", 1, #{lifetime => 3600}),
        ?assertEqual(1, nquic_session_cache:size(A)),
        ?assertEqual(1, nquic_session_cache:size(B))
    after
        nquic_session_cache:stop(A),
        nquic_session_cache:stop(B)
    end.
