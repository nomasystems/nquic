-module(nquic_handshake_loss_SUITE).
-moduledoc """
Handshake recovery after the loss of one datagram.

Each drop case drops one of the first eight datagrams in one direction
through `nquic_drop_proxy`, then requires the client connect to finish
within three initial PTOs. Cases run with `echo` then send one
bidirectional stream and require the server to echo it back. The
`accept_server` group runs the `nquic:accept` server path, and the
`handler_server` group runs the `conn_handler` server path.

After each case, both ends must become idle: no packet in flight,
`bytes_in_flight` and `ack_eliciting_in_flight` at 0, and no PTO
deadline. The
client must also discard its Handshake keys. `confirmed_idle_no_pto`
checks this without a drop and without data. The server end is
checked on the `accept_server` path only.
""".
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
-include("nquic_loss.hrl").
-export([all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([no_drop/1, confirmed_idle_no_pto/1]).
-export([
    drop_client_1/1,
    drop_client_2/1,
    drop_client_3/1,
    drop_client_4/1,
    drop_client_5/1,
    drop_client_6/1,
    drop_client_7/1,
    drop_client_8/1
]).
-export([
    drop_server_1/1,
    drop_server_2/1,
    drop_server_3/1,
    drop_server_4/1,
    drop_server_5/1,
    drop_server_6/1,
    drop_server_7/1,
    drop_server_8/1
]).

-define(CONNECT_BUDGET_MS, 3000).
-define(CONNECT_TIMEOUT_MS, 10000).
-define(MAX_INDEX, 8).
-define(ECHO_TIMEOUT_MS, 5000).
-define(ECHO_PAYLOAD, <<"handshake-loss-echo">>).
-define(CONFIRM_TIMEOUT_MS, 5000).

all() ->
    [{group, accept_server}, {group, handler_server}].

groups() ->
    Cases = [
        no_drop,
        confirmed_idle_no_pto
        | [case_name(Dir, I) || Dir <- [client, server], I <- lists:seq(1, ?MAX_INDEX)]
    ],
    [{accept_server, [], Cases}, {handler_server, [], Cases}].

init_per_suite(Config) ->
    ok = nquic_test_util:ensure_test_certs(conf_dir()),
    {ok, _} = application:ensure_all_started(crypto),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(Group, Config) ->
    [{server_path, Group} | Config].

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_Case, Config) ->
    process_flag(trap_exit, true),
    Config.

end_per_testcase(_Case, _Config) ->
    ok.

no_drop(Config) -> run([], echo, Config).

confirmed_idle_no_pto(Config) -> run([], connect_only, Config).

drop_client_1(Config) -> run([{client, 1}], echo, Config).
drop_client_2(Config) -> run([{client, 2}], echo, Config).
drop_client_3(Config) -> run([{client, 3}], echo, Config).
drop_client_4(Config) -> run([{client, 4}], echo, Config).
drop_client_5(Config) -> run([{client, 5}], echo, Config).
drop_client_6(Config) -> run([{client, 6}], echo, Config).
drop_client_7(Config) -> run([{client, 7}], echo, Config).
drop_client_8(Config) -> run([{client, 8}], echo, Config).

drop_server_1(Config) -> run([{server, 1}], connect_only, Config).
drop_server_2(Config) -> run([{server, 2}], connect_only, Config).
drop_server_3(Config) -> run([{server, 3}], connect_only, Config).
drop_server_4(Config) -> run([{server, 4}], connect_only, Config).
drop_server_5(Config) -> run([{server, 5}], connect_only, Config).
drop_server_6(Config) -> run([{server, 6}], connect_only, Config).
drop_server_7(Config) -> run([{server, 7}], connect_only, Config).
drop_server_8(Config) -> run([{server, 8}], connect_only, Config).

%%%-------------------------------------------------------------------

case_name(Dir, I) ->
    list_to_atom(lists:flatten(io_lib:format("drop_~s_~b", [Dir, I]))).

run(Drops, Echo, Config) ->
    Path = ?config(server_path, Config),
    {ok, Listener} = listen(Path),
    {ok, ServerPort} = nquic:get_port(Listener),
    Acceptor = start_acceptor(Path, Listener),
    {ok, Proxy, FrontPort} = nquic_drop_proxy:start_link(ServerPort, Drops),
    T0 = erlang:monotonic_time(millisecond),
    Result = nquic_ctx_driver:connect("127.0.0.1", FrontPort, client_opts()),
    ElapsedMs = erlang:monotonic_time(millisecond) - T0,
    ct:pal("~p ~p: ~p after ~b ms, dropped ~p", [
        Path, Drops, connect_outcome(Result), ElapsedMs, nquic_drop_proxy:dropped(Proxy)
    ]),
    {ok, Drv} = Result,
    ?assert(ElapsedMs =< ?CONNECT_BUDGET_MS),
    ok = echo(Echo, Drv),
    ok = assert_idle(client, Drv),
    ok = assert_idle(server, server_drv(Acceptor)),
    ok = nquic_ctx_driver:close(Drv),
    ok = stop_acceptor(Acceptor),
    ok = nquic_drop_proxy:stop(Proxy),
    ok = gen_server:stop(Listener).

echo(connect_only, _Drv) ->
    ok;
echo(echo, Drv) ->
    {ok, Sid} = nquic_ctx_driver:open_stream(Drv, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(Drv, Sid, ?ECHO_PAYLOAD),
    ?assertEqual(
        {ok, ?ECHO_PAYLOAD, fin}, nquic_test_util:recv_all(Drv, Sid, ?ECHO_TIMEOUT_MS)
    ).

connect_outcome({ok, _}) -> connected;
connect_outcome({error, _} = Error) -> Error.

listen(accept_server) ->
    nquic:listen(0, listen_opts());
listen(handler_server) ->
    nquic:listen(0, (listen_opts())#{conn_handler => nquic_echo_handler}).

listen_opts() ->
    ConfDir = conf_dir(),
    #{
        tls => #{
            certfile => filename:join(ConfDir, "server.pem"),
            keyfile => filename:join(ConfDir, "server.key"),
            alpn => [<<"h3">>]
        },
        receivers => 1
    }.

client_opts() ->
    #{
        tls => #{alpn => [<<"h3">>], verify => verify_none},
        timeout => ?CONNECT_TIMEOUT_MS
    }.

start_acceptor(handler_server, _Listener) ->
    none;
start_acceptor(accept_server, Listener) ->
    Parent = self(),
    spawn_link(fun() -> acceptor(Parent, Listener) end).

stop_acceptor(none) ->
    ok;
stop_acceptor(Pid) ->
    Ref = monitor(process, Pid),
    true = unlink(Pid),
    true = exit(Pid, shutdown),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    end.

acceptor(Parent, Listener) ->
    {ok, Drv} = nquic_ctx_driver:accept(Listener, #{timeout => ?CONNECT_TIMEOUT_MS}),
    Parent ! {server_drv, self(), Drv},
    echo_streams(Drv).

echo_streams(Drv) ->
    case nquic_ctx_driver:accept_stream(Drv) of
        {ok, Sid} ->
            {ok, Data, fin} = nquic_test_util:recv_all(Drv, Sid, ?ECHO_TIMEOUT_MS),
            ok = nquic_ctx_driver:send_fin(Drv, Sid, Data),
            echo_streams(Drv);
        {error, _} ->
            receive
                stop -> ok
            end
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

server_drv(none) ->
    none;
server_drv(Acceptor) ->
    receive
        {server_drv, Acceptor, Drv} -> Drv
    after ?CONFIRM_TIMEOUT_MS -> ct:fail(no_server_driver)
    end.

assert_idle(_Role, none) ->
    ok;
assert_idle(Role, Drv) ->
    Deadline = erlang:monotonic_time(millisecond) + ?CONFIRM_TIMEOUT_MS,
    State = await_idle(Role, Drv, Deadline),
    ?assertEqual(0, nquic_loss:get_bytes_in_flight(State#conn_state.loss_state)),
    ?assertEqual(0, nquic_loss:get_ack_eliciting_in_flight(State#conn_state.loss_state)),
    ?assertEqual(cancel, nquic_protocol_timer:pto_deadline_ms(State)).

await_idle(Role, Drv, Deadline) ->
    {ok, State} = nquic_ctx_driver:conn_state(Drv),
    case is_idle(Role, State) of
        true ->
            State;
        false ->
            ?assert(erlang:monotonic_time(millisecond) < Deadline),
            await_idle(Role, Drv, Deadline)
    end.

is_idle(client, #conn_state{crypto = #conn_crypto{keys = Keys}} = State) ->
    not maps:is_key(handshake, Keys) andalso is_idle(server, State);
is_idle(server, #conn_state{loss_state = LossState}) ->
    [] =:=
        [
            P
         || #sent_packet{in_flight = true} = P <-
                nquic_loss:get_sent_packets(LossState)
        ].
