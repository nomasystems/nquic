%%%-------------------------------------------------------------------
%%% @doc End-to-end coverage for the listener-wide `nquic:metrics/1'
%%% snapshot on a real listener driven through `m:nquic_ctx_driver'.
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_observability_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-compile([export_all, nowarn_export_all]).

all() ->
    [
        metrics_initial_snapshot_test,
        metrics_counts_traffic_test,
        metrics_survives_connection_close_test,
        metrics_unknown_listener_returns_error_test
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

metrics_initial_snapshot_test(_Config) ->
    {ok, Listener} = start_listener(),
    {ok, M0} = nquic:metrics(Listener),
    ?assertEqual(0, maps:get(packets_in, M0)),
    ?assertEqual(0, maps:get(conns_established, M0)),
    ?assertEqual(0, maps:get(handshakes_inflight, M0)),
    ?assertEqual(0, maps:get(accept_queue_depth, M0)),
    ?assert(is_integer(maps:get(uptime_ms, M0))),
    ?assert(maps:get(uptime_ms, M0) >= 0),
    stop_listener(Listener),
    ok.

metrics_counts_traffic_test(_Config) ->
    {ok, Listener} = start_listener(),
    {ok, Port} = nquic:get_port(Listener),
    {ok, ClientDrv} = connect_drv(Port),
    {ok, ServerDrv} = accept_drv(Listener),
    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send(ClientDrv, StreamId, <<"ping">>),
    {ok, SrvStreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, <<"ping">>, _} = nquic_ctx_driver:recv(ServerDrv, SrvStreamId, 5000),
    ok = nquic_ctx_driver:send_fin(ServerDrv, SrvStreamId, <<"pong">>),
    {ok, <<"pong">>, fin} = nquic_ctx_driver:recv(ClientDrv, StreamId, 5000),
    wait_for(
        fun() ->
            {ok, M} = nquic:metrics(Listener),
            maps:get(packets_in, M) > 0 andalso
                maps:get(conns_established, M) >= 1
        end,
        2000
    ),
    {ok, M} = nquic:metrics(Listener),
    ?assert(maps:get(packets_in, M) > 0),
    ?assert(maps:get(conns_established, M) >= 1),
    ?assertEqual(0, maps:get(packets_dropped_mailbox, M)),
    catch nquic_ctx_driver:close(ClientDrv),
    catch nquic_ctx_driver:close(ServerDrv),
    stop_listener(Listener),
    ok.

metrics_survives_connection_close_test(_Config) ->
    {ok, Listener} = start_listener(),
    {ok, Port} = nquic:get_port(Listener),
    {ok, ClientDrv} = connect_drv(Port),
    {ok, ServerDrv} = accept_drv(Listener),
    wait_for(
        fun() ->
            {ok, M} = nquic:metrics(Listener),
            maps:get(conns_established, M) >= 1
        end,
        2000
    ),
    ok = nquic_ctx_driver:close(ClientDrv),
    ok = nquic_ctx_driver:close(ServerDrv),
    {ok, M} = nquic:metrics(Listener),
    ?assert(maps:get(conns_established, M) >= 1),
    ?assert(is_integer(maps:get(uptime_ms, M))),
    stop_listener(Listener),
    ok.

metrics_unknown_listener_returns_error_test(_Config) ->
    Dead = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertMatch({error, _}, nquic:metrics(Dead)),
    ok.

%%%-----------------------------------------------------------------------------
%% HELPERS
%%%-----------------------------------------------------------------------------

start_listener() ->
    ConfDir = conf_dir(),
    CertFile = filename:join(ConfDir, "server.pem"),
    KeyFile = filename:join(ConfDir, "server.key"),
    ListenOpts = #{
        tls => #{
            certfile => CertFile,
            keyfile => KeyFile,
            alpn => [<<"h3">>]
        }
    },
    nquic:listen(0, ListenOpts).

stop_listener(Listener) ->
    catch nquic:stop_listener(Listener),
    ok.

connect_drv(Port) ->
    nquic_ctx_driver:connect(
        "127.0.0.1", Port, #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000}
    ).

accept_drv(Listener) ->
    nquic_ctx_driver:accept(Listener, #{timeout => 5000}).

wait_for(_Pred, RemainingMs) when RemainingMs =< 0 ->
    timeout;
wait_for(Pred, RemainingMs) ->
    case catch Pred() of
        true ->
            ok;
        _ ->
            timer:sleep(50),
            wait_for(Pred, RemainingMs - 50)
    end.

conf_dir() ->
    SrcFile = code:which(?MODULE),
    ProjectRoot = find_project_root(filename:dirname(SrcFile)),
    filename:join([ProjectRoot, "test", "conf"]).

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> find_project_root(filename:dirname(Dir))
    end.
