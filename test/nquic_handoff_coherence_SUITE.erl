%%%-------------------------------------------------------------------
%%% @doc CID-routing coherence under warm-wave load.
%%%
%%% The committed regression (`warm_waves_conn_handler_test') drives
%%% repeated warm waves of many concurrent connections, each doing
%%% several small request/response round-trips, against a `conn_handler'
%%% listener (owner-from-first-packet). Because the connection owner is
%%% the dispatch registrant from the first packet, the CID never
%%% resolves to a non-owner; the test asserts every request gets its
%%% correct echo (0 errored).
%%%
%%% The bug this guards against lives in the accept-queue path, where
%%% the acceptor that calls `nquic:accept/2' and the process that owns
%%% the connection are different, with a window between `accept'
%%% returning and the owner's `nquic_lib:takeover/1' during which the
%%% CID resolves to the acceptor (a non-owner). 1-RTT datagrams sent in
%%% that window are stranded in the acceptor's mailbox. The
%%% deterministic, retransmission-proof signal is the count of orphaned
%%% `{packet,_}'-family messages there.
%%%
%%% `reproduce_accept_handoff_on_head/0' exercises that accept-path
%%% topology and returns the orphan count. It is NOT in `all/0': the
%%% accept-queue path is intentionally unchanged by the owner-from-first-
%%% packet fix, so it strands packets both before and after the fix.
%%% Run it by hand to reproduce the bug on HEAD (returns > 0; observed
%%% 176 orphans over the parameters below).
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_handoff_coherence_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-compile([export_all, nowarn_export_all]).

-define(OWNER_TAKEOVER_DELAY_MS, 40).
-define(WAVES, 3).
-define(CONCURRENCY, 6).
-define(REQS_PER_CONN, 2).
-define(CONNECT_TIMEOUT_MS, 15000).
-define(REQUEST_DEADLINE_MS, 12000).
-define(WAVE_DEADLINE_MS, 60000).

all() ->
    [warm_waves_conn_handler_test].

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

warm_waves_conn_handler_test(_Config) ->
    {ok, Listener} = start_listener_handler(0),
    {ok, Port} = nquic:get_port(Listener),

    OkTotal = lists:sum([run_wave(Port, W) || W <- lists:seq(1, ?WAVES)]),
    Expected = ?WAVES * ?CONCURRENCY * ?REQS_PER_CONN,
    ct:pal("conn_handler warm waves: requests_ok=~p expected=~p", [OkTotal, Expected]),

    catch gen_server:stop(Listener),
    ?assertEqual(Expected, OkTotal).

reproduce_accept_handoff_on_head() ->
    ssl:start(),
    application:ensure_all_started(crypto),
    ok = nquic_test_util:ensure_test_certs(conf_dir()),
    {ok, Listener} = start_listener_accept(0),
    {ok, Port} = nquic:get_port(Listener),

    Acceptor = spawn_link(fun() -> acceptor_loop(Listener, []) end),
    OkTotal = lists:sum([run_wave(Port, W) || W <- lists:seq(1, ?WAVES)]),

    Acceptor ! {report, self()},
    {Orphans, Owners} =
        receive
            {orphans, N, OwnerPids} -> {N, OwnerPids}
        after 5000 ->
            error(acceptor_report_timeout)
        end,

    lists:foreach(fun(P) -> catch P ! stop end, Owners),
    unlink(Acceptor),
    exit(Acceptor, shutdown),
    catch gen_server:stop(Listener),
    #{orphaned_packets => Orphans, requests_ok => OkTotal, connections => length(Owners)}.

run_wave(Port, Wave) ->
    Parent = self(),
    Pids = [
        spawn_link(fun() -> client_proc(Parent, Port, Wave, I) end)
     || I <- lists:seq(1, ?CONCURRENCY)
    ],
    lists:sum([
        receive
            {client_ok, Pid, Ok} -> Ok
        after ?WAVE_DEADLINE_MS ->
            ct:fail({client_timeout, Pid})
        end
     || Pid <- Pids
    ]).

client_proc(Parent, Port, Wave, Index) ->
    ConnOpts = #{
        tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => ?CONNECT_TIMEOUT_MS
    },
    case nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts) of
        {ok, Drv} ->
            Ok = do_requests(Drv, Wave, Index, ?REQS_PER_CONN, 0),
            catch nquic_ctx_driver:close(Drv),
            Parent ! {client_ok, self(), Ok};
        {error, _Reason} ->
            Parent ! {client_ok, self(), 0}
    end.

do_requests(_Drv, _Wave, _Index, 0, Ok) ->
    Ok;
do_requests(Drv, Wave, Index, N, Ok) ->
    Payload = iolist_to_binary(io_lib:format("w~p-c~p-r~p", [Wave, Index, N])),
    case nquic_ctx_driver:open_stream(Drv, #{type => bidi}) of
        {ok, Sid} ->
            case nquic_ctx_driver:send_fin(Drv, Sid, Payload) of
                ok ->
                    case recv_all(Drv, Sid, ?REQUEST_DEADLINE_MS) of
                        {ok, Payload, fin} -> do_requests(Drv, Wave, Index, N - 1, Ok + 1);
                        _ -> do_requests(Drv, Wave, Index, N - 1, Ok)
                    end;
                {error, _} ->
                    Ok
            end;
        {error, _} ->
            Ok
    end.

recv_all(Drv, StreamId, Timeout) ->
    recv_all_acc(Drv, StreamId, Timeout, <<>>).

recv_all_acc(Drv, StreamId, Timeout, Acc) ->
    case nquic_ctx_driver:recv(Drv, StreamId, Timeout) of
        {ok, Data, fin} -> {ok, <<Acc/binary, Data/binary>>, fin};
        {ok, Data, nofin} -> recv_all_acc(Drv, StreamId, Timeout, <<Acc/binary, Data/binary>>);
        {error, _} = Err -> Err
    end.

acceptor_loop(Listener, Owners) ->
    case nquic:accept(Listener, #{timeout => 200}) of
        {ok, RawCtx} ->
            Owner = spawn_link(fun() -> owner_init(RawCtx) end),
            acceptor_loop(Listener, [Owner | Owners]);
        {error, {timeout, _}} ->
            receive
                {report, From} ->
                    From ! {orphans, count_orphans(0), Owners}
            after 0 ->
                acceptor_loop(Listener, Owners)
            end;
        {error, _Other} ->
            acceptor_loop(Listener, Owners)
    end.

count_orphans(N) ->
    receive
        {packet, _, _} -> count_orphans(N + 1);
        {packet, _, _, _} -> count_orphans(N + 1);
        {immediate_packet, _, _} -> count_orphans(N + 1);
        {packet_batch, _, _, _, _} -> count_orphans(N + 1)
    after 0 ->
        N
    end.

owner_init(RawCtx) ->
    process_flag(trap_exit, true),
    timer:sleep(?OWNER_TAKEOVER_DELAY_MS),
    {ok, Ctx1} = nquic_lib:takeover(RawCtx),
    case nquic_lib:recv_pending(Ctx1) of
        {ok, Events, Ctx2} ->
            {ok, Ctx3} = nquic_lib:flush(Ctx2),
            owner_serve(echo_events(Events, Ctx3));
        {error, _Reason, Ctx2} ->
            catch nquic_lib:close(Ctx2)
    end.

owner_serve(Ctx) ->
    receive
        {packet, Source, Bin} ->
            owner_after_io(nquic_lib:handle_packet(Ctx, Source, Bin));
        {packet, Source, Bin, ECN} ->
            owner_after_io(nquic_lib:handle_packet(Ctx, Source, Bin, ECN));
        {immediate_packet, Source, Bin} ->
            owner_after_io(nquic_lib:handle_packet(Ctx, Source, Bin));
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            owner_after_io(nquic_lib:handle_packet_batch(Ctx, Source, Buf, GsoSize, ECN));
        {quic_timeout, Type} ->
            owner_after_io(nquic_lib:timeout(Ctx, Type));
        {quic_drain, _Listener} ->
            catch nquic_lib:close(Ctx);
        stop ->
            catch nquic_lib:close(Ctx);
        _Other ->
            owner_serve(Ctx)
    end.

owner_after_io({ok, Events, Ctx1}) ->
    {ok, Ctx2} = nquic_lib:flush(Ctx1),
    owner_serve(echo_events(Events, Ctx2));
owner_after_io({error, _Reason, Ctx1}) ->
    catch nquic_lib:close(Ctx1).

echo_events([], Ctx) ->
    Ctx;
echo_events([{stream_data, Sid} | Rest], Ctx) ->
    echo_events(Rest, maybe_echo(Sid, Ctx));
echo_events([{stream_opened, Sid} | Rest], Ctx) ->
    echo_events(Rest, maybe_echo(Sid, Ctx));
echo_events([_ | Rest], Ctx) ->
    echo_events(Rest, Ctx).

maybe_echo(Sid, Ctx) ->
    case nquic_lib:recv(Ctx, Sid) of
        {ok, Data, true, Ctx1} when byte_size(Data) > 0 ->
            {ok, Ctx2} = nquic_lib:send_fin(Ctx1, Sid, Data),
            {ok, Ctx3} = nquic_lib:flush(Ctx2),
            Ctx3;
        {ok, _Data, _Fin, Ctx1} ->
            Ctx1;
        {error, _} ->
            Ctx
    end.

%%%-------------------------------------------------------------------
%%% Listener setup
%%%-------------------------------------------------------------------
start_listener_handler(Port) ->
    Opts = base_listen_opts(),
    nquic:listen(Port, Opts#{conn_handler => nquic_echo_handler}).

start_listener_accept(Port) ->
    nquic:listen(Port, base_listen_opts()).

base_listen_opts() ->
    ConfDir = conf_dir(),
    #{
        tls => #{
            certfile => filename:join(ConfDir, "server.pem"),
            keyfile => filename:join(ConfDir, "server.key"),
            alpn => [<<"h3">>]
        },
        receivers => 1
    }.

conf_dir() ->
    SrcFile = code:which(?MODULE),
    ProjectRoot = find_project_root(filename:dirname(SrcFile)),
    filename:join([ProjectRoot, "test", "conf"]).

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> find_project_root(filename:dirname(Dir))
    end.
