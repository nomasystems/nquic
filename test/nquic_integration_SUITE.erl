%%%-------------------------------------------------------------------
%%% @doc Integration tests for the full QUIC lifecycle.
%%%
%%% Post-handshake traffic runs the production library path
%%% (`#quic_ctx{}' + `m:nquic_lib') driven through the test owner-loop
%%% `m:nquic_ctx_driver'. The `library_mode_*' cases additionally
%%% exercise `m:nquic_lib' directly (recv_batch / flush_notimers /
%%% takeover / recv_pending) at a finer grain than the driver wraps.
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_integration_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
-include("nquic_transport.hrl").
-compile([export_all, nowarn_export_all]).

all() ->
    [
        passive_echo_test,
        library_mode_test,
        library_mode_takeover_test,
        concurrent_connections_test,
        stream_fin_test,
        peercert_test,
        connection_info_test,
        retry_echo_test,
        multi_instance_isolation_test,
        server_per_conn_fd_echo_test,
        server_per_conn_fd_lib_mode_test,
        library_mode_recv_batch_test,
        library_mode_flush_notimers_test,
        library_mode_upgrade_recv_batch_test,
        datagram_roundtrip_test,
        server_short_stream_reclamation_test,
        compat_version_negotiation_v2_test,
        compat_version_negotiation_default_v1_test
    ].

init_per_suite(Config) ->
    ssl:start(),
    application:ensure_all_started(crypto),
    ok = nquic_test_util:ensure_test_certs(conf_dir()),
    Config.

end_per_suite(_Config) ->
    ssl:stop(),
    ok.

init_per_testcase(_TestCase, Config) ->
    process_flag(trap_exit, true),
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

passive_echo_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(ClientDrv, StreamId, <<"hello">>),

    {ok, SStreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Data, fin} = recv_all(ServerDrv, SStreamId, 5000),
    ?assertEqual(<<"hello">>, Data),

    ok = nquic_ctx_driver:send_fin(ServerDrv, SStreamId, <<"world">>),

    {ok, RespData, fin} = recv_all(ClientDrv, StreamId, 5000),
    ?assertEqual(<<"world">>, RespData),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

library_mode_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),

    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}},
    {ok, ClientCtx0} = nquic:connect("localhost", Port, ConnOpts),

    {ok, ServerCtxA} = nquic:accept(Listener, #{timeout => 5000}),
    {ok, ServerCtx0} = nquic_lib:takeover(ServerCtxA),

    {ok, StreamId, ClientCtx1} = nquic_lib:open_stream(ClientCtx0, #{type => bidi}),
    {ok, ClientCtx2} = nquic_lib:send_fin(ClientCtx1, StreamId, <<"lib_hello">>),

    {ok, ServerCtx1} = lib_recv_until_stream(ServerCtx0, 5000),

    {ok, Data, true, ServerCtx2} = nquic_lib:recv(ServerCtx1, StreamId),
    ?assertEqual(<<"lib_hello">>, Data),

    {ok, ServerCtx3} = nquic_lib:send_fin(ServerCtx2, StreamId, <<"lib_world">>),

    {ok, ClientCtx3} = lib_recv_direct_until_data(ClientCtx2, StreamId, 5000),

    {ok, RespData, true, _ClientCtx4} = nquic_lib:recv(ClientCtx3, StreamId),
    ?assertEqual(<<"lib_world">>, RespData),

    {ok, _} = nquic_lib:close(ServerCtx3),
    {ok, _} = nquic_lib:close(ClientCtx3),
    catch gen_server:stop(Listener),
    ok.

library_mode_takeover_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),

    lists:foreach(
        fun(I) ->
            ct:pal("takeover iteration ~p", [I]),
            takeover_iteration(Listener, Port)
        end,
        lists:seq(1, 3)
    ),

    catch gen_server:stop(Listener),
    ok.

takeover_iteration(Listener, Port) ->
    Parent = self(),

    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000},
    {ok, ClientDrv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),

    {ok, ServerCtx0} = nquic:accept(Listener, #{timeout => 5000}),

    Handler = spawn_link(fun() ->
        takeover_handler(Parent, ServerCtx0)
    end),

    receive
        {handler_ready, Handler} -> ok
    after 5000 ->
        ct:fail(handler_ready_timeout)
    end,

    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(ClientDrv, StreamId, <<"takeover_data">>),

    receive
        {handler_received, Handler, RecvData} ->
            ?assertEqual(<<"takeover_data">>, RecvData)
    after 5000 ->
        ct:fail(handler_receive_timeout)
    end,

    Handler ! shutdown,
    receive
        {handler_done, Handler} -> ok
    after 5000 ->
        ct:fail(handler_shutdown_timeout)
    end,
    catch nquic_ctx_driver:close(ClientDrv),
    timer:sleep(50),
    ok.

takeover_handler(Parent, ServerCtx0) ->
    {ok, ServerCtx1} = nquic_lib:takeover(ServerCtx0),

    {ok, ServerCtx2} = nquic_lib:upgrade_to_connected(ServerCtx1),

    {ok, _Events, ServerCtx3} = nquic_lib:recv_pending(ServerCtx2),

    Parent ! {handler_ready, self()},

    ServerCtx4 = takeover_recv_loop(ServerCtx3, 50),

    case nquic_lib:recv(ServerCtx4, 0) of
        {ok, Data, _Fin, _ServerCtx5} ->
            Parent ! {handler_received, self(), Data};
        {error, _} ->
            Parent ! {handler_received, self(), <<>>}
    end,

    receive
        shutdown ->
            nquic_lib:shutdown(ServerCtx4),
            Parent ! {handler_done, self()}
    end.

takeover_recv_loop(Ctx, 0) ->
    Ctx;
takeover_recv_loop(Ctx, Attempts) ->
    case nquic_lib:recv_direct(Ctx, 200) of
        {ok, Events, Ctx1} ->
            case has_stream_event(Events) of
                true -> Ctx1;
                false -> takeover_recv_loop(Ctx1, Attempts - 1)
            end;
        {error, _Reason, Ctx1} ->
            takeover_recv_loop(Ctx1, Attempts - 1)
    end.

concurrent_connections_test(_Config) ->
    {ok, Listener} = start_listener(0, 2),
    {ok, Port} = nquic:get_port(Listener),

    N = 5,
    Parent = self(),

    ClientPids = lists:map(
        fun(I) ->
            spawn_link(fun() -> concurrent_client(Parent, Port, I) end)
        end,
        lists:seq(1, N)
    ),

    ServerDrvs = accept_n_connections(Listener, N, 10000),
    ?assertEqual(N, length(ServerDrvs)),

    lists:foreach(
        fun(ServerDrv) -> verify_server_recv(ServerDrv) end,
        ServerDrvs
    ),

    lists:foreach(fun(Pid) -> Pid ! stop end, ClientPids),
    lists:foreach(
        fun(Pid) ->
            receive
                {client_done, Pid} -> ok
            after 10000 ->
                ct:fail({client_timeout, Pid})
            end
        end,
        ClientPids
    ),

    lists:foreach(fun(SD) -> catch nquic_ctx_driver:close(SD) end, ServerDrvs),
    catch gen_server:stop(Listener),
    ok.

stream_fin_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send(ClientDrv, StreamId, <<"part1">>),

    {ok, SStreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Data1, nofin} = nquic_ctx_driver:recv(ServerDrv, SStreamId, 5000),
    ?assertEqual(<<"part1">>, Data1),

    ok = nquic_ctx_driver:send_fin(ClientDrv, StreamId, <<"part2">>),

    {ok, Data2, fin} = recv_all(ServerDrv, SStreamId, 5000),
    ?assertEqual(<<"part2">>, Data2),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

peercert_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {error, {tls, no_peercert}} = nquic_ctx_driver:peercert(ServerDrv),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

connection_info_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, Info} = nquic_ctx_driver:info(ServerDrv),
    ?assert(is_map(Info)),
    ?assertEqual(established, maps:get(state, Info)),
    ?assertEqual(server, maps:get(role, Info)),
    ?assert(is_binary(maps:get(scid, Info))),
    ?assert(is_binary(maps:get(dcid, Info))),
    ?assert(is_map(maps:get(rtt, Info))),
    ?assertEqual(0, maps:get(streams_open, Info)),

    {ok, {PeerIP, PeerPort}} = nquic_ctx_driver:peername(ServerDrv),
    ?assert(is_tuple(PeerIP)),
    ?assert(is_integer(PeerPort)),

    {ok, {LocalIP, LocalPort}} = nquic_ctx_driver:sockname(ServerDrv),
    ?assert(is_tuple(LocalIP)),
    ?assert(is_integer(LocalPort)),

    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send(ClientDrv, StreamId, <<"probe">>),

    {ok, _SStreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),

    {ok, Info1} = nquic_ctx_driver:info(ServerDrv),
    ?assert(maps:get(streams_open, Info1) >= 1),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

retry_echo_test(_Config) ->
    {ok, Listener} = start_listener_retry(0),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(ClientDrv, StreamId, <<"retry_hello">>),

    {ok, SStreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Data, fin} = recv_all(ServerDrv, SStreamId, 5000),
    ?assertEqual(<<"retry_hello">>, Data),

    ok = nquic_ctx_driver:send_fin(ServerDrv, SStreamId, <<"retry_world">>),

    {ok, RespData, fin} = recv_all(ClientDrv, StreamId, 5000),
    ?assertEqual(<<"retry_world">>, RespData),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

multi_instance_isolation_test(_Config) ->
    N = 3,
    CertFile = filename:join(conf_dir(), "server.pem"),
    KeyFile = filename:join(conf_dir(), "server.key"),

    Instances = lists:map(
        fun(I) ->
            CacheName = list_to_atom("nquic_multi_cache_" ++ integer_to_list(I)),
            _ = nquic_session_cache:stop(CacheName),
            {ok, CachePid} = nquic_session_cache:start_link(CacheName),
            ALPN = list_to_binary(["nquic-multi-", integer_to_list(I)]),
            {ok, Listener} = nquic:listen(0, #{
                tls => #{
                    certfile => CertFile,
                    keyfile => KeyFile,
                    alpn => [ALPN]
                }
            }),
            {ok, Port} = nquic:get_port(Listener),
            #{
                id => I,
                listener => Listener,
                port => Port,
                cache => CacheName,
                cache_pid => CachePid,
                alpn => ALPN
            }
        end,
        lists:seq(1, N)
    ),

    Listeners = [maps:get(listener, M) || M <- Instances],
    Ports = [maps:get(port, M) || M <- Instances],
    CachePids = [maps:get(cache_pid, M) || M <- Instances],
    ?assertEqual(N, length(lists:uniq(Listeners))),
    ?assertEqual(N, length(lists:uniq(Ports))),
    ?assertEqual(N, length(lists:uniq(CachePids))),

    Dispatches = [
        begin
            {ok, D} = nquic_listener:get_dispatch(L),
            D
        end
     || L <- Listeners
    ],
    ?assertEqual(N, length(lists:uniq(Dispatches))),

    lists:foreach(
        fun(#{listener := Listener, port := Port, alpn := ALPN}) ->
            ConnOpts = #{tls => #{alpn => [ALPN], verify => verify_none}, timeout => 5000},
            {ClientDrv, ServerDrv, Helper} = establish(Port, Listener, ConnOpts),

            {ok, Sid} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
            ok = nquic_ctx_driver:send_fin(ClientDrv, Sid, <<"ping:", ALPN/binary>>),
            {ok, SSid} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
            {ok, Received, fin} = recv_all(ServerDrv, SSid, 5000),
            ?assertEqual(<<"ping:", ALPN/binary>>, Received),
            ok = nquic_ctx_driver:send_fin(ServerDrv, SSid, <<"pong:", ALPN/binary>>),
            {ok, Reply, fin} = recv_all(ClientDrv, Sid, 5000),
            ?assertEqual(<<"pong:", ALPN/binary>>, Reply),

            teardown(ClientDrv, ServerDrv, Helper)
        end,
        Instances
    ),

    lists:foreach(
        fun(#{id := I, cache := Cache}) ->
            Ticket = #{
                psk => crypto:strong_rand_bytes(32),
                cipher => aes_128_gcm,
                lifetime => 3600,
                instance => I
            },
            ok = nquic_session_cache:store(Cache, "host", 1000 + I, Ticket)
        end,
        Instances
    ),
    lists:foreach(
        fun(#{id := I, cache := Cache}) ->
            ?assertMatch(
                {ok, #{instance := I}},
                nquic_session_cache:lookup(Cache, "host", 1000 + I)
            ),
            lists:foreach(
                fun
                    (J) when J =/= I ->
                        ?assertEqual(
                            {error, not_found},
                            nquic_session_cache:lookup(Cache, "host", 1000 + J)
                        );
                    (_) ->
                        ok
                end,
                lists:seq(1, N)
            )
        end,
        Instances
    ),

    #{listener := L1} = hd(Instances),
    MRef = monitor(process, L1),
    exit(L1, kill),
    receive
        {'DOWN', MRef, process, L1, _} -> ok
    after 2000 -> ct:fail(listener_did_not_die)
    end,

    lists:foreach(
        fun
            (#{id := I, port := Port, alpn := ALPN}) when I > 1 ->
                {ok, ClientDrv} = nquic_ctx_driver:connect(
                    "127.0.0.1",
                    Port,
                    #{
                        tls => #{alpn => [ALPN], verify => verify_none},
                        timeout => 5000
                    }
                ),
                ?assert(is_process_alive(ClientDrv)),
                catch nquic_ctx_driver:close(ClientDrv);
            (_) ->
                ok
        end,
        Instances
    ),

    lists:foreach(
        fun
            (#{id := I, listener := Listener, cache := Cache}) when I > 1 ->
                catch gen_server:stop(Listener),
                nquic_session_cache:stop(Cache);
            (#{cache := Cache}) ->
                nquic_session_cache:stop(Cache)
        end,
        Instances
    ),
    ok.

server_per_conn_fd_echo_test(_Config) ->
    {ok, Listener} = start_listener_per_conn_fd(0),
    {ok, ListenPort} = nquic:get_port(Listener),

    ConnOpts = #{
        tls => #{
            alpn => [<<"h3">>],
            verify => verify_none
        },
        proactive_cids => true,
        timeout => 5000
    },
    {ClientDrv, ServerDrv, Helper} = establish(ListenPort, Listener, ConnOpts),

    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(ClientDrv, StreamId, <<"per-conn-fd">>),

    {ok, SStreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Data, fin} = recv_all(ServerDrv, SStreamId, 5000),
    ?assertEqual(<<"per-conn-fd">>, Data),
    ok = nquic_ctx_driver:send_fin(ServerDrv, SStreamId, <<"world">>),
    {ok, RespData, fin} = recv_all(ClientDrv, StreamId, 5000),
    ?assertEqual(<<"world">>, RespData),

    ok = wait_for_sockname_change(ServerDrv, ListenPort, 50, 100),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

server_per_conn_fd_lib_mode_test(_Config) ->
    {ok, Listener} = start_listener_per_conn_fd(0),
    {ok, ListenPort} = nquic:get_port(Listener),

    ConnOpts = #{
        tls => #{
            alpn => [<<"h3">>],
            verify => verify_none
        },
        proactive_cids => true
    },
    {ok, ClientCtx0} = nquic:connect("localhost", ListenPort, ConnOpts),
    {ok, ServerCtxA} = nquic:accept(Listener, #{timeout => 5000}),
    {ok, ServerCtx0} = nquic_lib:takeover(ServerCtxA),

    {ok, StreamId, ClientCtx1} = nquic_lib:open_stream(ClientCtx0, #{type => bidi}),
    {ok, ClientCtx2} = nquic_lib:send_fin(ClientCtx1, StreamId, <<"per-conn-fd-lib">>),

    {ok, ServerCtx1} = lib_recv_until_stream(ServerCtx0, 5000),
    {ok, Data, true, ServerCtx2} = nquic_lib:recv(ServerCtx1, StreamId),
    ?assertEqual(<<"per-conn-fd-lib">>, Data),
    {ok, ServerCtx3} = nquic_lib:send_fin(ServerCtx2, StreamId, <<"hello-back">>),

    {ok, ClientCtx3} = lib_recv_direct_until_data(ClientCtx2, StreamId, 5000),
    {ok, RespData, true, _ClientCtx4} = nquic_lib:recv(ClientCtx3, StreamId),
    ?assertEqual(<<"hello-back">>, RespData),

    ok = lib_wait_for_sockname_change(ServerCtx3, ListenPort, 50, 100),

    {ok, _} = nquic_lib:close(ServerCtx3),
    {ok, _} = nquic_lib:close(ClientCtx3),
    catch gen_server:stop(Listener),
    ok.

library_mode_recv_batch_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),

    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}},
    {ok, ClientCtx0} = nquic:connect("localhost", Port, ConnOpts),
    {ok, ServerCtxA} = nquic:accept(Listener, #{timeout => 5000}),
    {ok, ServerCtx0} = nquic_lib:takeover(ServerCtxA),

    {ok, StreamId, ClientCtx1} = nquic_lib:open_stream(ClientCtx0, #{type => bidi}),
    {ok, ClientCtx2} = nquic_lib:send_fin(ClientCtx1, StreamId, <<"batch_hello">>),

    {ok, ServerCtx1} = lib_recv_batch_until_stream(ServerCtx0, 5000),
    {ok, Data, true, ServerCtx2} = nquic_lib:recv(ServerCtx1, StreamId),
    ?assertEqual(<<"batch_hello">>, Data),

    {ok, ServerCtx3} = nquic_lib:send_fin(ServerCtx2, StreamId, <<"batch_world">>),

    {ok, ClientCtx3} = lib_recv_batch_until_data(ClientCtx2, StreamId, 5000),
    {ok, RespData, true, _ClientCtx4} = nquic_lib:recv(ClientCtx3, StreamId),
    ?assertEqual(<<"batch_world">>, RespData),

    {ok, _} = nquic_lib:close(ServerCtx3),
    {ok, _} = nquic_lib:close(ClientCtx3),
    catch gen_server:stop(Listener),
    ok.

library_mode_flush_notimers_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),

    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}},
    {ok, ClientCtx0} = nquic:connect("localhost", Port, ConnOpts),
    {ok, ServerCtxA} = nquic:accept(Listener, #{timeout => 5000}),
    {ok, ServerCtx0} = nquic_lib:takeover(ServerCtxA),

    {ok, StreamId, ClientCtx1} = nquic_lib:open_stream(ClientCtx0, #{type => bidi}),
    {ok, ClientCtx2} = nquic_lib:send_fin_noflush(ClientCtx1, StreamId, <<"noflush_hi">>),

    {ok, ClientCtx3} = nquic_lib:flush_notimers(ClientCtx2),

    {ok, ServerCtx1} = lib_recv_until_stream(ServerCtx0, 5000),
    {ok, Data, true, _ServerCtx2} = nquic_lib:recv(ServerCtx1, StreamId),
    ?assertEqual(<<"noflush_hi">>, Data),

    {ok, _} = nquic_lib:close(ClientCtx3),
    catch gen_server:stop(Listener),
    ok.

library_mode_upgrade_recv_batch_test(_Config) ->
    {ok, Listener} = start_listener_per_conn_fd(0),
    {ok, ListenPort} = nquic:get_port(Listener),

    ConnOpts = #{
        tls => #{
            alpn => [<<"h3">>],
            verify => verify_none
        },
        proactive_cids => true
    },
    {ok, ClientCtx0} = nquic:connect("localhost", ListenPort, ConnOpts),
    {ok, ServerCtxA} = nquic:accept(Listener, #{timeout => 5000}),
    {ok, ServerCtx0} = nquic_lib:takeover(ServerCtxA),

    {ok, StreamId, ClientCtx1} = nquic_lib:open_stream(ClientCtx0, #{type => bidi}),
    {ok, ClientCtx2} = nquic_lib:send_fin(ClientCtx1, StreamId, <<"upgrade_batch">>),

    {ok, ServerCtx1} = lib_recv_batch_until_stream(ServerCtx0, 5000),
    {ok, Data, true, ServerCtx2} = nquic_lib:recv(ServerCtx1, StreamId),
    ?assertEqual(<<"upgrade_batch">>, Data),

    {ok, ServerCtx3} = nquic_lib:send_fin(ServerCtx2, StreamId, <<"back_batch">>),

    {ok, ClientCtx3} = lib_recv_batch_until_data(ClientCtx2, StreamId, 5000),
    {ok, RespData, true, _ClientCtx4} = nquic_lib:recv(ClientCtx3, StreamId),
    ?assertEqual(<<"back_batch">>, RespData),

    ok = lib_wait_for_sockname_change(ServerCtx3, ListenPort, 50, 100),

    {ok, _} = nquic_lib:close(ServerCtx3),
    {ok, _} = nquic_lib:close(ClientCtx3),
    catch gen_server:stop(Listener),
    ok.

%%%-------------------------------------------------------------------
%%% RFC 9221 unreliable DATAGRAM round-trip over the production ctx.
%%%-------------------------------------------------------------------

datagram_roundtrip_test(_Config) ->
    ConfDir = conf_dir(),
    TP = #transport_params{max_datagram_frame_size = 65535},
    {ok, Listener} = nquic:listen(0, #{
        tls => #{
            certfile => filename:join(ConfDir, "server.pem"),
            keyfile => filename:join(ConfDir, "server.key"),
            alpn => [<<"h3">>]
        },
        transport_params => TP
    }),
    {ok, Port} = nquic:get_port(Listener),
    ConnOpts = #{
        tls => #{alpn => [<<"h3">>], verify => verify_none},
        transport_params => TP,
        timeout => 5000
    },
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener, ConnOpts),

    ok = nquic_ctx_driver:send_datagram(ClientDrv, <<"ping-dgram">>),
    ?assertEqual({ok, <<"ping-dgram">>}, poll_datagram(ServerDrv, 50)),

    ok = nquic_ctx_driver:send_datagram(ServerDrv, <<"pong-dgram">>),
    ?assertEqual({ok, <<"pong-dgram">>}, poll_datagram(ClientDrv, 50)),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

poll_datagram(_Drv, 0) ->
    ct:fail(no_datagram);
poll_datagram(Drv, N) ->
    case nquic_ctx_driver:recv_datagram(Drv) of
        {ok, _} = Ok ->
            Ok;
        {error, empty} ->
            timer:sleep(50),
            poll_datagram(Drv, N - 1)
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

start_listener(Port) ->
    start_listener(Port, 1).

start_listener(Port, Receivers) ->
    ConfDir = conf_dir(),
    CertFile = filename:join(ConfDir, "server.pem"),
    KeyFile = filename:join(ConfDir, "server.key"),
    ListenOpts = #{
        tls => #{
            certfile => CertFile,
            keyfile => KeyFile,
            alpn => [<<"h3">>]
        },
        receivers => Receivers
    },
    nquic:listen(Port, ListenOpts).

start_listener_per_conn_fd(Port) ->
    ConfDir = conf_dir(),
    CertFile = filename:join(ConfDir, "server.pem"),
    KeyFile = filename:join(ConfDir, "server.key"),
    ListenOpts = #{
        tls => #{
            certfile => CertFile,
            keyfile => KeyFile,
            alpn => [<<"h3">>]
        },
        server_per_conn_fd => true
    },
    nquic:listen(Port, ListenOpts).

wait_for_sockname_change(_Drv, _ListenPort, 0, _SleepMs) ->
    ct:fail(server_sockname_did_not_change);
wait_for_sockname_change(Drv, ListenPort, N, SleepMs) ->
    case nquic_ctx_driver:sockname(Drv) of
        {ok, {_, Port}} when Port =/= ListenPort ->
            ok;
        _ ->
            timer:sleep(SleepMs),
            wait_for_sockname_change(Drv, ListenPort, N - 1, SleepMs)
    end.

lib_wait_for_sockname_change(_Ctx, _ListenPort, 0, _SleepMs) ->
    ct:fail(lib_server_sockname_did_not_change);
lib_wait_for_sockname_change(Ctx, ListenPort, N, SleepMs) ->
    case nquic_socket:sockname(nquic_lib:ctx_socket(Ctx)) of
        {ok, #{port := Port}} when Port =/= ListenPort ->
            ok;
        _ ->
            timer:sleep(SleepMs),
            lib_wait_for_sockname_change(Ctx, ListenPort, N - 1, SleepMs)
    end.

start_listener_retry(Port) ->
    ConfDir = conf_dir(),
    CertFile = filename:join(ConfDir, "server.pem"),
    KeyFile = filename:join(ConfDir, "server.key"),
    ListenOpts = #{
        tls => #{
            certfile => CertFile,
            keyfile => KeyFile,
            alpn => [<<"h3">>]
        },
        retry => true,
        retry_token_lifetime => 30
    },
    nquic:listen(Port, ListenOpts).

start_listener_version_preference(Port, Preference) ->
    ConfDir = conf_dir(),
    CertFile = filename:join(ConfDir, "server.pem"),
    KeyFile = filename:join(ConfDir, "server.key"),
    ListenOpts = #{
        tls => #{
            certfile => CertFile,
            keyfile => KeyFile,
            alpn => [<<"h3">>]
        },
        version_preference => Preference
    },
    nquic:listen(Port, ListenOpts).

%% Establish a client + server connection, both driven through the
%% production ctx owner loop (`m:nquic_ctx_driver'). accept/2 blocks
%% until a peer connects, so the accept runs in a parked helper while
%% the test process connects.
establish(Port, Listener) ->
    establish(Port, Listener, #{
        tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000
    }).

establish(Port, Listener, ConnOpts) ->
    Self = self(),
    Helper = spawn_link(fun() ->
        Result = nquic_ctx_driver:accept(Listener, #{timeout => 5000}),
        Self ! {server_drv, self(), Result},
        receive
            stop -> ok
        end
    end),
    {ok, ClientDrv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),
    ServerDrv =
        receive
            {server_drv, Helper, {ok, SD}} -> SD;
            {server_drv, Helper, {error, E}} -> ct:fail({accept_failed, E})
        after 10000 ->
            ct:fail(accept_timeout)
        end,
    {ClientDrv, ServerDrv, Helper}.

teardown(ClientDrv, ServerDrv, Helper) ->
    catch nquic_ctx_driver:close(ClientDrv),
    catch nquic_ctx_driver:close(ServerDrv),
    Helper ! stop,
    ok.

recv_all(Drv, StreamId, Timeout) ->
    recv_all_acc(Drv, StreamId, Timeout, <<>>).

recv_all_acc(Drv, StreamId, Timeout, Acc) ->
    case nquic_ctx_driver:recv(Drv, StreamId, Timeout) of
        {ok, Data, fin} ->
            {ok, <<Acc/binary, Data/binary>>, fin};
        {ok, Data, nofin} ->
            recv_all_acc(Drv, StreamId, Timeout, <<Acc/binary, Data/binary>>);
        {error, _} = Err ->
            Err
    end.

accept_n_connections(Listener, N, Timeout) ->
    accept_n_connections(Listener, N, Timeout, []).

accept_n_connections(_Listener, 0, _Timeout, Acc) ->
    lists:reverse(Acc);
accept_n_connections(Listener, N, Timeout, Acc) ->
    case nquic_ctx_driver:accept(Listener, #{timeout => Timeout}) of
        {ok, Drv} ->
            accept_n_connections(Listener, N - 1, Timeout, [Drv | Acc]);
        {error, Reason} ->
            ct:fail({accept_failed, Reason, N})
    end.

concurrent_client(Parent, Port, Index) ->
    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000},
    {ok, Drv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),
    {ok, StreamId} = nquic_ctx_driver:open_stream(Drv, #{type => bidi}),
    Payload = <<"client_", (integer_to_binary(Index))/binary>>,
    ok = nquic_ctx_driver:send_fin(Drv, StreamId, Payload),
    receive
        stop -> ok
    after 15000 -> ok
    end,
    catch nquic_ctx_driver:close(Drv),
    Parent ! {client_done, self()}.

verify_server_recv(ServerDrv) ->
    {ok, StreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Data, fin} = recv_all(ServerDrv, StreamId, 5000),
    <<"client_", _/binary>> = Data,
    ok.

lib_recv_until_stream(Ctx, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    lib_recv_until_stream_loop(Ctx, Deadline).

lib_recv_until_stream_loop(Ctx, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            ct:fail(lib_stream_timeout);
        false ->
            WaitMs = min(Remaining, 100),
            case nquic_lib:recv_and_process(Ctx, WaitMs) of
                {ok, Events, Ctx1} ->
                    case has_stream_event(Events) of
                        true -> {ok, Ctx1};
                        false -> lib_recv_until_stream_loop(Ctx1, Deadline)
                    end;
                {error, _Reason, Ctx1} ->
                    lib_recv_until_stream_loop(Ctx1, Deadline)
            end
    end.

lib_recv_direct_until_data(Ctx, StreamId, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    lib_recv_direct_until_data_loop(Ctx, StreamId, Deadline).

lib_recv_direct_until_data_loop(Ctx, StreamId, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            ct:fail(lib_data_timeout);
        false ->
            WaitMs = min(Remaining, 100),
            case nquic_lib:recv_direct(Ctx, WaitMs) of
                {ok, _Events, Ctx1} ->
                    case nquic_lib:recv(Ctx1, StreamId) of
                        {ok, <<>>, false, _} ->
                            lib_recv_direct_until_data_loop(Ctx1, StreamId, Deadline);
                        {ok, _Data, _IsFin, _Ctx2} ->
                            {ok, Ctx1};
                        {error, _} ->
                            lib_recv_direct_until_data_loop(Ctx1, StreamId, Deadline)
                    end;
                {error, _Reason, Ctx1} ->
                    lib_recv_direct_until_data_loop(Ctx1, StreamId, Deadline)
            end
    end.

lib_recv_batch_until_stream(Ctx, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    lib_recv_batch_until_stream_loop(Ctx, Deadline).

lib_recv_batch_until_stream_loop(Ctx, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            ct:fail(lib_stream_timeout);
        false ->
            WaitMs = min(Remaining, 100),
            case nquic_lib:recv_batch(Ctx, WaitMs) of
                {ok, Events, Ctx1} ->
                    case has_stream_event(Events) of
                        true -> {ok, Ctx1};
                        false -> lib_recv_batch_until_stream_loop(Ctx1, Deadline)
                    end;
                {error, _Reason, Ctx1} ->
                    lib_recv_batch_until_stream_loop(Ctx1, Deadline)
            end
    end.

lib_recv_batch_until_data(Ctx, StreamId, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    lib_recv_batch_until_data_loop(Ctx, StreamId, Deadline).

lib_recv_batch_until_data_loop(Ctx, StreamId, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            ct:fail(lib_data_timeout);
        false ->
            WaitMs = min(Remaining, 100),
            case nquic_lib:recv_batch(Ctx, WaitMs) of
                {ok, _Events, Ctx1} ->
                    case nquic_lib:recv(Ctx1, StreamId) of
                        {ok, <<>>, false, _} ->
                            lib_recv_batch_until_data_loop(Ctx1, StreamId, Deadline);
                        {ok, _Data, _IsFin, _Ctx2} ->
                            {ok, Ctx1};
                        {error, _} ->
                            lib_recv_batch_until_data_loop(Ctx1, StreamId, Deadline)
                    end;
                {error, _Reason, Ctx1} ->
                    lib_recv_batch_until_data_loop(Ctx1, StreamId, Deadline)
            end
    end.

has_stream_event([]) ->
    false;
has_stream_event([{stream_data, _} | _]) ->
    true;
has_stream_event([{stream_opened, _} | _]) ->
    true;
has_stream_event([_ | Rest]) ->
    has_stream_event(Rest).

%%%-------------------------------------------------------------------
%%% Server-accepted short-stream reclamation regression
%%%
%%% Drives N peer-initiated bidi request/echo streams over ONE
%%% connection using the legitimate handler sequence (recv, echo
%%% without FIN, recv -> {error, fin}, close_stream). Asserts the
%%% server connection's #conn_streams{} stays bounded (streams and
%%% closed_peer_streams do not grow O(N), the peer watermark advances)
%%% and that per-stream latency does not grow O(N).
%%%-------------------------------------------------------------------

compat_version_negotiation_v2_test(_Config) ->
    {ok, Listener} = start_listener_version_preference(0, [16#6b3343cf, 1]),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(ClientDrv, StreamId, <<"compat-v2">>),
    {ok, SStreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Data, fin} = recv_all(ServerDrv, SStreamId, 5000),
    ?assertEqual(<<"compat-v2">>, Data),

    {ok, #conn_state{version = ServerVersion}} = nquic_ctx_driver:conn_state(ServerDrv),
    {ok, #conn_state{version = ClientVersion}} = nquic_ctx_driver:conn_state(ClientDrv),
    ?assertEqual(16#6b3343cf, ServerVersion),
    ?assertEqual(16#6b3343cf, ClientVersion),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

compat_version_negotiation_default_v1_test(_Config) ->
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, #conn_state{version = ServerVersion}} = nquic_ctx_driver:conn_state(ServerDrv),
    {ok, #conn_state{version = ClientVersion}} = nquic_ctx_driver:conn_state(ClientDrv),
    ?assertEqual(1, ServerVersion),
    ?assertEqual(1, ClientVersion),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

server_short_stream_reclamation_test(_Config) ->
    N = 2000,
    Payload = <<"reclaim-me">>,
    {ok, Listener} = start_listener(0),
    {ok, Port} = nquic:get_port(Listener),
    {ClientConn, ServerConn, Helper} = establish(Port, Listener),

    Acceptor = spawn_link(fun() -> recl_server_accept_loop(ServerConn) end),

    Times = [recl_client_request(ClientConn, Payload) || _ <- lists:seq(1, N)],

    timer:sleep(2000),

    #conn_streams{
        streams = Streams,
        closed_peer_streams = ClosedPeer,
        closed_peer_bidi_wm = BidiWm
    } = recl_server_conn_streams(ServerConn),

    StreamCount = map_size(Streams),
    ClosedPeerCount = map_size(ClosedPeer),
    ct:pal(
        "reclamation: streams=~p closed_peer=~p bidi_wm=~p (N=~p)",
        [StreamCount, ClosedPeerCount, BidiWm, N]
    ),

    %% Bounded: a handful of in-flight streams at most, never O(N).
    ?assert(StreamCount =< 32),
    ?assert(ClosedPeerCount =< 64),
    %% Watermark advanced in-order over (almost) all peer bidi streams.
    %% Client bidi stream IDs are 0,4,8,...; the last is 4*(N-1).
    ?assert(BidiWm >= 4 * (N - 64)),

    %% Latency is flat (no O(N) growth): the last batch must not be
    %% dramatically slower than the first.
    First = recl_median(lists:sublist(Times, 200)),
    Last = recl_median(lists:sublist(lists:reverse(Times), 200)),
    ct:pal("reclamation latency: first200 median=~pus last200 median=~pus", [First, Last]),
    ?assert(Last =< 8 * max(First, 1)),

    unlink(Acceptor),
    exit(Acceptor, shutdown),
    teardown(ClientConn, ServerConn, Helper),
    catch gen_server:stop(Listener),
    ok.

recl_client_request(ClientConn, Payload) ->
    T0 = erlang:monotonic_time(microsecond),
    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientConn, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(ClientConn, StreamId, Payload),
    ok = recl_client_drain(ClientConn, StreamId),
    erlang:monotonic_time(microsecond) - T0.

recl_client_drain(ClientConn, StreamId) ->
    case nquic_ctx_driver:recv(ClientConn, StreamId, 5000) of
        {ok, Data, _} when byte_size(Data) > 0 -> ok;
        {ok, <<>>, _} -> recl_client_drain(ClientConn, StreamId);
        {error, _} -> ok
    end.

recl_server_accept_loop(ServerConn) ->
    case catch nquic_ctx_driver:accept_stream(ServerConn, 10000) of
        {ok, StreamId} ->
            spawn(fun() -> recl_server_echo_loop(ServerConn, StreamId) end),
            recl_server_accept_loop(ServerConn);
        _ ->
            ok
    end.

recl_server_echo_loop(ServerConn, StreamId) ->
    case nquic_ctx_driver:recv(ServerConn, StreamId, 5000) of
        {ok, Data, nofin} when byte_size(Data) > 0 ->
            case nquic_ctx_driver:send(ServerConn, StreamId, Data) of
                ok -> recl_server_echo_loop(ServerConn, StreamId);
                {error, _} -> ok
            end;
        {ok, Data, fin} ->
            _ =
                case byte_size(Data) > 0 of
                    true -> nquic_ctx_driver:send(ServerConn, StreamId, Data);
                    false -> ok
                end,
            nquic_ctx_driver:close_stream(ServerConn, StreamId);
        {ok, <<>>, nofin} ->
            recl_server_echo_loop(ServerConn, StreamId);
        {error, _} ->
            ok
    end.

recl_server_conn_streams(ServerConn) ->
    {ok, ConnState} = nquic_ctx_driver:conn_state(ServerConn),
    ConnState#conn_state.streams_state.

recl_median([]) ->
    0;
recl_median(L) ->
    Sorted = lists:sort(L),
    lists:nth((length(Sorted) div 2) + 1, Sorted).
