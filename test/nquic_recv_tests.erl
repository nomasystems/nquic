%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_recv}.
%%%
%%% Macro values mirror the production defaults defined in
%%% `src/nquic_recv.erl'; if those defaults change, update the values
%%% here so the regression tests stay in sync.
%%%-------------------------------------------------------------------
-module(nquic_recv_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DEFAULT_RECBUF, 2 * 1024 * 1024).
-define(DEFAULT_SNDBUF, 2 * 1024 * 1024).

socket_options_default_test() ->
    Opts = nquic_recv:socket_options(),
    ?assertEqual(?DEFAULT_RECBUF, maps:get(recbuf, Opts)),
    ?assertEqual(?DEFAULT_SNDBUF, maps:get(sndbuf, Opts)),
    ?assertEqual(true, maps:get(reuseaddr, Opts)).

socket_options_custom_test() ->
    Opts = nquic_recv:socket_options(#{recbuf => 1024, sndbuf => 2048}),
    ?assertEqual(1024, maps:get(recbuf, Opts)),
    ?assertEqual(2048, maps:get(sndbuf, Opts)),
    ?assertEqual(true, maps:get(reuseaddr, Opts)).

socket_options_reuseaddr_override_test() ->
    Opts = nquic_recv:socket_options(#{reuseaddr => false}),
    ?assertEqual(false, maps:get(reuseaddr, Opts)).

socket_options_reuseport_test() ->
    Opts = nquic_recv:socket_options(#{reuseport => true}),
    ?assertEqual(true, maps:get(reuseport, Opts)).

socket_options_no_reuseport_test() ->
    Opts = nquic_recv:socket_options(#{}),
    ?assertEqual(false, maps:is_key(reuseport, Opts)).
