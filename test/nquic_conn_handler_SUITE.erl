%%%-------------------------------------------------------------------
%%% @doc `conn_handler' (owner-from-first-packet) server path.
%%%
%%% A listener opened with `conn_handler => Module' starts `Module' as
%%% the connection owner from the first packet; the owner drives the
%%% handshake itself via `nquic_lib:server_accept_init/1' +
%%% `handle_packet/flush/handshake_timeout', with no export, accept
%%% queue, or takeover. These cases validate that path end-to-end
%%% against a real client.
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_conn_handler_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-compile([export_all, nowarn_export_all]).

all() ->
    [
        single_conn_handler_echo_test,
        multi_request_handler_echo_test,
        verify_peer_handshake_test
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

single_conn_handler_echo_test(_Config) ->
    {ok, Listener} = start_listener_handler(0),
    {ok, Port} = nquic:get_port(Listener),

    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000},
    {ok, Drv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),

    {ok, Sid} = nquic_ctx_driver:open_stream(Drv, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(Drv, Sid, <<"hello-handler">>),
    {ok, Data, fin} = recv_all(Drv, Sid, 5000),
    ?assertEqual(<<"hello-handler">>, Data),

    catch nquic_ctx_driver:close(Drv),
    catch gen_server:stop(Listener),
    ok.

multi_request_handler_echo_test(_Config) ->
    {ok, Listener} = start_listener_handler(0),
    {ok, Port} = nquic:get_port(Listener),

    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000},
    {ok, Drv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),

    lists:foreach(
        fun(I) ->
            Payload = iolist_to_binary(io_lib:format("req-~p", [I])),
            {ok, Sid} = nquic_ctx_driver:open_stream(Drv, #{type => bidi}),
            ok = nquic_ctx_driver:send_fin(Drv, Sid, Payload),
            ?assertEqual({ok, Payload, fin}, recv_all(Drv, Sid, 5000))
        end,
        lists:seq(1, 20)
    ),

    catch nquic_ctx_driver:close(Drv),
    catch gen_server:stop(Listener),
    ok.

verify_peer_handshake_test(_Config) ->
    {ok, Listener} = start_listener_handler(0),
    {ok, Port} = nquic:get_port(Listener),

    CADer = server_cert_der(),
    ConnOpts = #{
        tls => #{
            alpn => [<<"h3">>],
            verify => verify_peer,
            cacerts => [CADer]
        },
        timeout => 5000
    },
    {ok, Drv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),

    {ok, Sid} = nquic_ctx_driver:open_stream(Drv, #{type => bidi}),
    ok = nquic_ctx_driver:send_fin(Drv, Sid, <<"verify-peer">>),
    {ok, Data, fin} = recv_all(Drv, Sid, 5000),
    ?assertEqual(<<"verify-peer">>, Data),

    catch nquic_ctx_driver:close(Drv),
    catch gen_server:stop(Listener),
    ok.

server_cert_der() ->
    PemPath = filename:join(conf_dir(), "server.pem"),
    {ok, Pem} = file:read_file(PemPath),
    [{'Certificate', Der, not_encrypted} | _] = public_key:pem_decode(Pem),
    Der.

%%%-------------------------------------------------------------------

recv_all(Drv, StreamId, Timeout) ->
    recv_all_acc(Drv, StreamId, Timeout, <<>>).

recv_all_acc(Drv, StreamId, Timeout, Acc) ->
    case nquic_ctx_driver:recv(Drv, StreamId, Timeout) of
        {ok, Data, fin} -> {ok, <<Acc/binary, Data/binary>>, fin};
        {ok, Data, nofin} -> recv_all_acc(Drv, StreamId, Timeout, <<Acc/binary, Data/binary>>);
        {error, _} = Err -> Err
    end.

start_listener_handler(Port) ->
    ConfDir = conf_dir(),
    ListenOpts = #{
        tls => #{
            certfile => filename:join(ConfDir, "server.pem"),
            keyfile => filename:join(ConfDir, "server.key"),
            alpn => [<<"h3">>]
        },
        receivers => 1,
        conn_handler => nquic_echo_handler
    },
    nquic:listen(Port, ListenOpts).

conf_dir() ->
    SrcFile = code:which(?MODULE),
    ProjectRoot = find_project_root(filename:dirname(SrcFile)),
    filename:join([ProjectRoot, "test", "conf"]).

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> find_project_root(filename:dirname(Dir))
    end.
