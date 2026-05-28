%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_conn}.
%%%-------------------------------------------------------------------
-module(nquic_conn_tests).

-include_lib("eunit/include/eunit.hrl").

info_closed_test() ->
    FakePid = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertEqual({error, closed}, nquic_conn:info(FakePid)).

peercert_closed_test() ->
    FakePid = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertEqual({error, closed}, nquic_conn:peercert(FakePid)).

peername_closed_test() ->
    FakePid = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertEqual({error, closed}, nquic_conn:peername(FakePid)).

sockname_closed_test() ->
    FakePid = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertEqual({error, closed}, nquic_conn:sockname(FakePid)).

streams_closed_test() ->
    FakePid = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertEqual({error, closed}, nquic_conn:streams(FakePid)).

close_idempotent_test() ->
    FakePid = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertEqual(ok, nquic_conn:close(FakePid)).

migrate_closed_test() ->
    FakePid = spawn(fun() -> ok end),
    timer:sleep(10),
    Addr = nquic_socket:make_sockaddr({127, 0, 0, 1}, 0),
    ?assertEqual({error, closed}, nquic_conn:migrate(FakePid, Addr)).
