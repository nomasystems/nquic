%%%-------------------------------------------------------------------
%%% @doc Public API integration tests.
%%%
%%% Post-handshake connections are driven through the production
%%% library path (`nquic:connect/accept', then
%%% `m:nquic_lib' / `m:nquic_protocol') via the ergonomic owner-loop
%%% wrapper `m:nquic_ctx_driver'. There is no pid post-handshake API
%%% in this suite. `export_protocol_test' drives the handshake
%%% gen_statem directly and asserts the proactive export handoff:
%%% on handshake completion the FSM hands its `#quic_ctx{}' bundle to
%%% the owning process and terminates with `{shutdown, exported}'.
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-compile([export_all, nowarn_export_all]).

all() ->
    [
        api_connect_listen_test,
        export_protocol_test,
        v2_connect_test,
        session_resumption_test,
        session_ticket_notification_test,
        lib_reconnect_after_data_test,
        lib_reconnect_rapid_test,
        client_terminate_closes_socket_test
    ].

init_per_suite(Config) ->
    ssl:start(),
    application:ensure_all_started(crypto),
    ok = nquic_test_util:ensure_test_certs(conf_dir()),
    Config.

end_per_suite(_Config) ->
    ssl:stop(),
    ok.

api_connect_listen_test(_Config) ->
    {Listener, Port} = start_listener(),
    ConnectOpts = #{
        tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000
    },
    {ok, Drv} = nquic_ctx_driver:connect("localhost", Port, ConnectOpts),
    true = is_process_alive(Drv),
    ok = nquic_ctx_driver:close(Drv),
    ok = nquic:stop_listener(Listener),
    ok.

export_protocol_test(_Config) ->
    {ok, ServerSock} = nquic_socket:open(#{}),
    {ok, SPort} = nquic_socket:port(ServerSock),
    {ok, ClientSock} = nquic_socket:open(#{}),
    ServerPeer = nquic_socket:make_sockaddr({127, 0, 0, 1}, SPort),

    process_flag(trap_exit, true),

    {ok, SPid} = nquic_conn_statem:start_link(#{
        role => server,
        socket => ServerSock,
        owner => self(),
        certfile => "../../../../test/conf/server.pem",
        keyfile => "../../../../test/conf/server.key"
    }),
    ok = nquic_socket:controlling_process(ServerSock, SPid),

    {ok, CPid} = nquic_conn_statem:start_link(#{
        role => client,
        socket => ClientSock,
        peer => ServerPeer,
        owner => self()
    }),
    ok = nquic_socket:controlling_process(ClientSock, CPid),

    {ProtoState, Socket} =
        receive
            {nquic_conn_export, SPid, {ok, PS, Sk, undefined}} -> {PS, Sk}
        after 5000 -> ct:fail(server_export_timeout)
        end,
    receive
        {nquic_conn_export, CPid, {ok, _, _, undefined}} -> ok
    after 5000 -> ct:fail(client_export_timeout)
    end,

    false = is_process_alive(SPid),

    Info = nquic_protocol:info(established, ProtoState),
    true = is_map(Info),
    server = maps:get(role, Info),

    {ok, _Port} = nquic_socket:port(Socket),

    _ = nquic_socket:close(Socket),
    _ = nquic_socket:close(ClientSock),
    ok.

v2_connect_test(_Config) ->
    {Listener, Port} = start_listener(),
    ConnectOpts = #{
        tls => #{alpn => [<<"h3">>], verify => verify_none},
        timeout => 5000,
        version => 16#6b3343cf
    },
    {ok, Drv} = nquic_ctx_driver:connect("localhost", Port, ConnectOpts),
    true = is_process_alive(Drv),
    ok = nquic_ctx_driver:close(Drv),
    ok = nquic:stop_listener(Listener),
    ok.

session_resumption_test(_Config) ->
    Cache = nquic_session_cache_suite,
    _ = nquic_session_cache:stop(Cache),
    {ok, _} = nquic_session_cache:start_link(Cache),

    {Listener, Port} = start_listener(),

    ConnOpts = #{
        tls => #{alpn => [<<"h3">>], verify => verify_none},
        session_cache => Cache,
        timeout => 5000
    },
    {ok, Drv1} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),

    ok = wait_cached(Cache, "127.0.0.1", Port, 50),
    {ok, Ticket} = nquic_session_cache:lookup(Cache, "127.0.0.1", Port),
    ct:pal("Session ticket cached: keys=~p", [maps:keys(Ticket)]),
    true = maps:is_key(psk, Ticket),
    true = maps:is_key(cipher, Ticket),

    ok = nquic_ctx_driver:close(Drv1),

    {ok, Drv2} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),
    {ok, Info2} = nquic_ctx_driver:info(Drv2),
    established = maps:get(state, Info2),

    ok = nquic_ctx_driver:close(Drv2),
    ok = nquic:stop_listener(Listener),
    nquic_session_cache:stop(Cache),
    ok.

session_ticket_notification_test(_Config) ->
    {Listener, Port} = start_listener(),

    ConnOpts = #{
        tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000
    },
    {ok, Drv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),

    receive
        {quic_session_ticket, Drv, Ticket} when is_map(Ticket) ->
            ?assert(maps:is_key(psk, Ticket)),
            ?assert(maps:is_key(cipher, Ticket))
    after 5000 ->
        ct:fail(no_session_ticket_message)
    end,

    ok = nquic_ctx_driver:close(Drv),
    ok = nquic:stop_listener(Listener),
    ok.

lib_reconnect_after_data_test(_Config) ->
    {Listener, Port} = start_listener(),
    lib_connect_exchange_shutdown(Port, Listener, <<"hello1">>),
    lib_connect_exchange_shutdown(Port, Listener, <<"hello2">>),
    ok = nquic:stop_listener(Listener),
    ok.

lib_reconnect_rapid_test(_Config) ->
    {Listener, Port} = start_listener(),
    lists:foreach(
        fun(I) ->
            Data = iolist_to_binary([<<"cycle">>, integer_to_binary(I)]),
            lib_connect_exchange_shutdown(Port, Listener, Data)
        end,
        lists:seq(1, 5)
    ),
    ok = nquic:stop_listener(Listener),
    ok.

client_terminate_closes_socket_test(_Config) ->
    case fd_count() of
        unsupported ->
            {skip, "FD enumeration only supported on Linux /proc/self/fd"};
        Baseline when is_integer(Baseline) ->
            run_client_terminate_closes_socket(Baseline)
    end.

run_client_terminate_closes_socket(Baseline) ->
    {Listener, Port} = start_listener(),
    ConnectOpts = #{
        tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000
    },
    N = 25,
    lists:foreach(
        fun(_) ->
            {ok, Drv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnectOpts),
            MRef = monitor(process, Drv),
            ok = nquic_ctx_driver:close(Drv),
            receive
                {'DOWN', MRef, process, Drv, _} -> ok
            after 5000 ->
                ct:fail({connection_did_not_terminate, Drv})
            end
        end,
        lists:seq(1, N)
    ),

    timer:sleep(200),
    After = fd_count(),
    ok = nquic:stop_listener(Listener),

    Slack = 5,
    ct:pal("fd baseline=~p after=~p N=~p", [Baseline, After, N]),
    case After =< Baseline + Slack of
        true -> ok;
        false -> ct:fail({fd_leak, Baseline, After, N})
    end.

%%%-----------------------------------------------------------------------------
%% HELPERS
%%%-----------------------------------------------------------------------------

start_listener() ->
    ConfDir = conf_dir(),
    ListenOpts = #{
        tls => #{
            certfile => filename:join(ConfDir, "server.pem"),
            keyfile => filename:join(ConfDir, "server.key"),
            alpn => [<<"h3">>]
        }
    },
    {ok, Listener} = nquic:listen(0, ListenOpts),
    {ok, Port} = nquic:get_port(Listener),
    {Listener, Port}.

%% Establish a client + server connection, both driven through the
%% production ctx owner loop. accept/2 blocks until a peer connects, so
%% the accept runs in a parked helper while the test process connects.
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

lib_connect_exchange_shutdown(Port, Listener, Data) ->
    ConnOpts = #{
        tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000
    },
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener, ConnOpts),

    {ok, StreamId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ok = nquic_ctx_driver:send(ClientDrv, StreamId, Data),

    {ok, ServerStreamId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Got, _Fin} = recv_all(ServerDrv, ServerStreamId, byte_size(Data), <<>>, 5000),
    ?assertEqual(Data, Got),

    ok = nquic_ctx_driver:close(ServerDrv),
    ok = nquic_ctx_driver:close(ClientDrv),
    Helper ! stop,
    ok.

recv_all(_Drv, _StreamId, Need, Acc, _Timeout) when byte_size(Acc) >= Need ->
    {ok, Acc, nofin};
recv_all(Drv, StreamId, Need, Acc, Timeout) ->
    case nquic_ctx_driver:recv(Drv, StreamId, Timeout) of
        {ok, Bin, fin} ->
            {ok, <<Acc/binary, Bin/binary>>, fin};
        {ok, Bin, nofin} ->
            recv_all(Drv, StreamId, Need, <<Acc/binary, Bin/binary>>, Timeout);
        {error, Reason} ->
            ct:fail({recv_failed, Reason})
    end.

wait_cached(_Cache, _Host, _Port, 0) ->
    ct:fail(no_cached_ticket);
wait_cached(Cache, Host, Port, Attempts) ->
    case nquic_session_cache:lookup(Cache, Host, Port) of
        {ok, _Ticket} ->
            ok;
        {error, _} ->
            timer:sleep(100),
            wait_cached(Cache, Host, Port, Attempts - 1)
    end.

fd_count() ->
    case filelib:is_dir("/proc/self/fd") of
        true ->
            length(filelib:wildcard("/proc/self/fd/*"));
        false ->
            unsupported
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
