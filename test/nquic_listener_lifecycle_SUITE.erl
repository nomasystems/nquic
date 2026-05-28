%%%-------------------------------------------------------------------
%%% @doc Public listener lifecycle: `nquic:stop_listener/1,2'.
%%%
%%% Covers the cascade (default) and detach modes, port release,
%%% idempotency, stopping from a non-owner process without killing the
%%% owner, and a blocked `accept/1' returning `{error, closed}' once
%%% the listener is stopped.
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_listener_lifecycle_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-compile([export_all, nowarn_export_all]).

all() ->
    [
        stop_returns_ok_and_kills_tree_test,
        idempotent_stop_test,
        port_released_after_cascade_test,
        cascade_closes_connections_test,
        cascade_drains_owner_held_connection_test,
        accept_after_cascade_returns_closed_test,
        cascade_completes_within_bound_with_conn_test,
        detach_frees_port_but_keeps_connections_test,
        detach_sends_no_drain_signal_test,
        stop_from_non_owner_does_not_kill_owner_test,
        blocked_accept_returns_closed_on_stop_test,
        stop_listener_accepts_timeout_opt_test
    ].

init_per_suite(Config) ->
    ssl:start(),
    application:ensure_all_started(crypto),
    ok = nquic_test_util:ensure_test_certs(conf_dir()),
    Config.

end_per_suite(_Config) ->
    ssl:stop(),
    ok.

%%%-----------------------------------------------------------------------------
%% TESTS
%%%-----------------------------------------------------------------------------

stop_returns_ok_and_kills_tree_test(_Config) ->
    {ok, Listener} = start_listener(),
    ?assert(is_process_alive(Listener)),
    ?assertEqual(ok, nquic:stop_listener(Listener)),
    wait_until(fun() -> not is_process_alive(Listener) end),
    ?assertNot(is_process_alive(Listener)).

idempotent_stop_test(_Config) ->
    {ok, Listener} = start_listener(),
    ?assertEqual(ok, nquic:stop_listener(Listener)),
    ?assertEqual(ok, nquic:stop_listener(Listener)),
    ?assertEqual(ok, nquic:stop_listener(Listener, #{mode => cascade})),
    ?assertNot(is_process_alive(Listener)).

port_released_after_cascade_test(_Config) ->
    {ok, Listener} = start_listener(),
    {ok, Port} = nquic:get_port(Listener),
    ?assertEqual(ok, nquic:stop_listener(Listener)),
    %% A fresh listener can bind the exact same port: it was released.
    {ok, Listener2} = rebind(Port),
    try
        ?assertEqual({ok, Port}, nquic:get_port(Listener2))
    after
        nquic:stop_listener(Listener2)
    end.

cascade_closes_connections_test(_Config) ->
    {ok, Listener} = start_listener(),
    {ok, Port} = nquic:get_port(Listener),
    {ok, Server, _Client, Connector} = establish(Listener),
    ?assert(is_process_alive(Server)),
    %% Cascade tears down the whole listener tree and frees the port
    %% even with an established connection in flight.
    ?assertEqual(ok, nquic:stop_listener(Listener, #{mode => cascade})),
    wait_until(fun() -> not is_process_alive(Listener) end),
    ?assertNot(is_process_alive(Listener)),
    {ok, Listener2} = rebind(Port),
    nquic:stop_listener(Listener2),
    stop_connector(Connector).

cascade_drains_owner_held_connection_test(_Config) ->
    %% The owner-held established connection has no nquic process and
    %% is not linked to the listener tree: the only way it dies on a
    %% cascade is by observing the `{quic_drain, _}' signal and closing
    %% itself. Asserts no established connection leaks past a drain.
    {ok, Listener} = start_listener(),
    {ok, Server, _Client, Connector} = establish(Listener),
    ?assert(is_process_alive(Server)),
    Mon = monitor(process, Server),
    ?assertEqual(ok, nquic:stop_listener(Listener, #{mode => cascade})),
    receive
        {'DOWN', Mon, process, Server, Reason} ->
            ?assertEqual(normal, Reason)
    after 5000 ->
        error(owner_not_drained)
    end,
    ?assertNot(is_process_alive(Server)),
    stop_connector(Connector).

cascade_completes_within_bound_with_conn_test(_Config) ->
    %% With a live connection in flight, a cascade must drain it via
    %% the signal and tear the tree down promptly, far below the
    %% idle timeout, bounded by the cascade timeout, not by the peer.
    {ok, Listener} = start_listener(),
    {ok, Server, _Client, Connector} = establish(Listener),
    ?assert(is_process_alive(Server)),
    T0 = erlang:monotonic_time(millisecond),
    ?assertEqual(ok, nquic:stop_listener(Listener, #{mode => cascade, timeout => 5000})),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assert(Elapsed < 5000),
    wait_until(fun() -> not is_process_alive(Listener) end),
    wait_until(fun() -> not is_process_alive(Server) end),
    ?assertNot(is_process_alive(Listener)),
    ?assertNot(is_process_alive(Server)),
    stop_connector(Connector).

accept_after_cascade_returns_closed_test(_Config) ->
    {ok, Listener} = start_listener(),
    ?assertEqual(ok, nquic:stop_listener(Listener, #{mode => cascade})),
    wait_until(fun() -> not is_process_alive(Listener) end),
    ?assertEqual({error, closed}, nquic:accept(Listener, #{timeout => 200})).

detach_sends_no_drain_signal_test(_Config) ->
    %% `detach' is the explicit non-draining mode: an owner-held
    %% connection must NOT receive `{quic_drain, _}' and must keep
    %% running until its own idle timeout.
    {ok, Listener} = start_listener(),
    {ok, Server, _Client, Connector} = establish(Listener),
    try
        ?assertEqual(ok, nquic:stop_listener(Listener, #{mode => detach})),
        timer:sleep(300),
        ?assert(is_process_alive(Server))
    after
        stop_connector(Connector),
        nquic:stop_listener(Listener)
    end.

detach_frees_port_but_keeps_connections_test(_Config) ->
    {ok, Listener} = start_listener(),
    {ok, Port} = nquic:get_port(Listener),
    {ok, Server, _Client, Connector} = establish(Listener),
    try
        ?assertEqual(ok, nquic:stop_listener(Listener, #{mode => detach})),
        %% Owner-driven connection is independent of the listener tree.
        ?assert(is_process_alive(Server)),
        %% Port was freed (receiver sub-tree gone): rebind succeeds.
        {ok, Listener2} = rebind(Port),
        nquic:stop_listener(Listener2)
    after
        stop_connector(Connector),
        nquic:stop_listener(Listener)
    end.

stop_from_non_owner_does_not_kill_owner_test(_Config) ->
    Parent = self(),
    Owner = spawn(fun() ->
        {ok, L} = start_listener(),
        Parent ! {listener, self(), L},
        receive
            release -> ok
        end
    end),
    Listener =
        receive
            {listener, Owner, L} -> L
        after 5000 -> error(owner_listen_timeout)
        end,
    ?assert(is_process_alive(Listener)),
    %% Caller here is NOT the process that opened the listener.
    ?assertEqual(ok, nquic:stop_listener(Listener)),
    wait_until(fun() -> not is_process_alive(Listener) end),
    ?assertNot(is_process_alive(Listener)),
    %% Owner is linked to the listener supervisor but is not killed,
    %% because the supervisor exits with reason `normal'.
    ?assert(is_process_alive(Owner)),
    Owner ! release.

blocked_accept_returns_closed_on_stop_test(_Config) ->
    {ok, Listener} = start_listener(),
    Parent = self(),
    Acceptor = spawn(fun() ->
        Parent ! {accepting, self()},
        R = nquic:accept(Listener),
        Parent ! {accept_result, self(), R}
    end),
    receive
        {accepting, Acceptor} -> ok
    after 5000 -> error(acceptor_start_timeout)
    end,
    %% Give the acceptor time to park inside the gen_server call.
    timer:sleep(100),
    ?assertEqual(ok, nquic:stop_listener(Listener)),
    receive
        {accept_result, Acceptor, Res} ->
            ?assertEqual({error, closed}, Res)
    after 5000 ->
        error(accept_did_not_unblock)
    end.

stop_listener_accepts_timeout_opt_test(_Config) ->
    {ok, Listener} = start_listener(),
    ?assertEqual(ok, nquic:stop_listener(Listener, #{mode => cascade, timeout => 10000})),
    ?assertNot(is_process_alive(Listener)).

%%%-----------------------------------------------------------------------------
%% Helpers
%%%-----------------------------------------------------------------------------

conf_dir() ->
    SrcFile = code:which(?MODULE),
    ProjectRoot = find_project_root(filename:dirname(SrcFile)),
    filename:join([ProjectRoot, "test", "conf"]).

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> find_project_root(filename:dirname(Dir))
    end.

listen_opts() ->
    #{
        tls => #{
            certfile => filename:join(conf_dir(), "server.pem"),
            keyfile => filename:join(conf_dir(), "server.key"),
            alpn => [<<"h3">>]
        },
        receivers => 1
    }.

start_listener() ->
    nquic:listen(0, listen_opts()).

rebind(Port) ->
    rebind(Port, 20).

rebind(Port, 0) ->
    nquic:listen(Port, listen_opts());
rebind(Port, N) ->
    case nquic:listen(Port, listen_opts()) of
        {ok, _} = Ok ->
            Ok;
        {error, _} ->
            timer:sleep(50),
            rebind(Port, N - 1)
    end.

establish(Listener) ->
    {ok, Port} = nquic:get_port(Listener),
    Parent = self(),
    Connector = spawn(fun() ->
        case
            nquic_ctx_driver:connect(
                "127.0.0.1",
                Port,
                #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000}
            )
        of
            {ok, Client} ->
                Parent ! {client, self(), Client},
                receive
                    stop -> nquic_ctx_driver:close(Client)
                end;
            {error, Reason} ->
                Parent ! {client_error, self(), Reason}
        end
    end),
    {ok, Server} = nquic_ctx_driver:accept(Listener, #{timeout => 5000}),
    receive
        {client, Connector, Client} ->
            {ok, Server, Client, Connector};
        {client_error, Connector, Reason} ->
            error({connect_failed, Reason})
    after 5000 ->
        error(connect_timeout)
    end.

stop_connector(Connector) ->
    case is_process_alive(Connector) of
        true -> Connector ! stop;
        false -> ok
    end.

wait_until(Fun) ->
    wait_until(Fun, 50, 100).

wait_until(_Fun, _Sleep, 0) ->
    error(wait_until_timeout);
wait_until(Fun, Sleep, N) ->
    case
        try
            Fun()
        catch
            _:_ -> false
        end
    of
        true ->
            ok;
        false ->
            timer:sleep(Sleep),
            wait_until(Fun, Sleep, N - 1)
    end.
