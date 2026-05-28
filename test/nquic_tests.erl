%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic}.
%%%
%%% Option validation (connect/listen) is exercised through the public
%%% `nquic:connect/3' and `nquic:listen/2' surface, not by poking the
%%% private validators directly.
%%%-------------------------------------------------------------------
-module(nquic_tests).

-include_lib("eunit/include/eunit.hrl").

conf_dir() ->
    SrcFile = code:which(?MODULE),
    ProjectRoot = find_project_root(filename:dirname(SrcFile)),
    filename:join([ProjectRoot, "test", "conf"]).

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> find_project_root(filename:dirname(Dir))
    end.

dead_pid() ->
    P = spawn(fun() -> ok end),
    MRef = monitor(process, P),
    receive
        {'DOWN', MRef, process, P, _} -> ok
    after 100 -> ok
    end,
    P.

listen_happy_path_test() ->
    Cert = filename:join(conf_dir(), "server.pem"),
    Key = filename:join(conf_dir(), "server.key"),
    {ok, Listener} = nquic:listen(0, #{
        tls => #{certfile => Cert, keyfile => Key},
        transport => #{pacing => true, send_timeout => 1000},
        cc => #{algo => newreno}
    }),
    ?assert(is_pid(Listener)),
    ?assertEqual(ok, nquic:stop_listener(Listener)).

listen_missing_tls_test() ->
    Opts = {opts, {missing_option, tls}},
    ?assertEqual({error, Opts}, nquic:listen(0, #{})),
    ?assertEqual({error, Opts}, nquic:listen(0, #{tls => #{certfile => "c.pem"}})),
    ?assertEqual({error, Opts}, nquic:listen(0, #{tls => #{keyfile => "k.pem"}})).

listen_misplaced_key_test() ->
    ?assertEqual(
        {error, {opts, {misplaced_option, certfile}}},
        nquic:listen(0, #{
            tls => #{certfile => "c.pem", keyfile => "k.pem"}, certfile => "stray.pem"
        })
    ).

connect_misplaced_key_test() ->
    ?assertEqual(
        {error, {opts, {misplaced_option, verify}}},
        nquic:connect("127.0.0.1", 4433, #{verify => verify_none})
    ).

connect_flatten_test() ->
    %% Valid (verify lives under tls); flatten + cc_flat run, then the
    %% handshake times out against a dead UDP port. The result is a
    %% transport-level error, never an {opts, _} validation error.
    R = nquic:connect("127.0.0.1", 1, #{
        tls => #{verify => verify_none, cacerts => [<<"ca">>]},
        transport => #{gso => 8, gro => true},
        cc => #{algo => newreno, slow_start => hystart_plus_plus},
        timeout => 300
    }),
    ?assertMatch({error, _}, R),
    ?assertNotMatch({error, {opts, _}}, R).

connect_bad_host_test() ->
    ?assertMatch(
        {error, _},
        nquic:connect("nonexistent-host.invalid", 4433, #{
            tls => #{verify => verify_none}, timeout => 100
        })
    ).

connect_nowait_rejected_test() ->
    ?assertEqual(
        {error, {opts, ctx_requires_wait}},
        nquic:connect("nonexistent-host.invalid", 4433, #{nowait => true})
    ),
    ?assertMatch(
        {error, _},
        nquic:connect("nonexistent-host.invalid", 4433, #{
            nowait => false, tls => #{verify => verify_none}, timeout => 100
        })
    ).

conn_call_callee_exit_test() ->
    Pid = spawn(fun() ->
        receive
            {'$gen_call', _From, _Req} -> exit(custom_reason)
        end
    end),
    ?assertEqual({error, closed}, nquic_conn:info(Pid)).

accept_dead_test() ->
    ?assertMatch({error, _}, nquic:accept(dead_pid())),
    ?assertMatch({error, _}, nquic:accept(dead_pid(), #{timeout => 10})).

get_port_dead_test() ->
    ?assertMatch({error, _}, nquic:get_port(dead_pid())).

metrics_dead_test() ->
    ?assertMatch({error, _}, nquic:metrics(dead_pid())).
