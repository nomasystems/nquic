%%%-------------------------------------------------------------------
%%% @doc Writable-edge / send-backpressure integration tests.
%%%
%%% Drives the production library path through the test owner-loop
%%% `m:nquic_ctx_driver'. The driver's `send/4' / `send_fin/4' are the
%%% owner-loop equivalent of the old pid `send_sync': they retry
%%% `nquic_lib:send' across the peer's flow-control window, splitting
%%% the payload and pumping recv for credit, and surface
%%% `{error, {timeout, send}}' when the window never reopens within the
%%% deadline. The constrained windows come from the listener's
%%% `transport_params' (a real ctx-model concept); the pid-only
%%% `send_buffer' / `send_timeout' transport opts are gone; the
%%% per-call deadline is now the driver send argument.
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_writable_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("nquic_transport.hrl").
-compile([export_all, nowarn_export_all]).

all() ->
    [
        is_writable_api_test,
        send_sync_blocks_until_buffer_drains_test,
        send_sync_times_out_when_buffer_stays_full_test,
        send4_one_mib_over_constrained_window_completes_test,
        send4_per_call_timeout_overrides_send_timeout_test,
        send4_completes_when_slow_reader_resumes_test
    ].

init_per_suite(Config) ->
    ssl:start(),
    application:ensure_all_started(crypto),
    ok = nquic_test_util:ensure_test_certs(conf_dir()),
    Config.

end_per_suite(_Config) ->
    ssl:stop(),
    ok.

is_writable_api_test(_Config) ->
    {ok, Listener} = listen(#{}),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, SId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    ?assert(nquic_ctx_driver:is_writable(ClientDrv, SId)),

    ?assertNot(nquic_ctx_driver:is_writable(ClientDrv, 999)),

    ok = nquic_ctx_driver:close_stream(ClientDrv, SId),
    timer:sleep(50),
    ?assertNot(nquic_ctx_driver:is_writable(ClientDrv, SId)),

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

%%%-------------------------------------------------------------------
%%% Blocking send / send_fin (backpressure semantics)
%%%-------------------------------------------------------------------

send_sync_blocks_until_buffer_drains_test(_Config) ->
    {ok, Listener} = listen(#{}),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, SId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    Payload = binary:copy(<<"q">>, 256 * 1024),

    TestPid = self(),
    SenderRef = make_ref(),
    spawn(fun() ->
        Result = nquic_ctx_driver:send_fin(ClientDrv, SId, Payload),
        TestPid ! {sender_done, SenderRef, Result}
    end),

    {ok, SId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Received} = recv_all(ServerDrv, SId, byte_size(Payload), 10000),
    ?assertEqual(Payload, Received),

    receive
        {sender_done, SenderRef, ok} -> ok;
        {sender_done, SenderRef, Other} -> ct:fail({unexpected_send_result, Other})
    after 5000 -> ct:fail(send_did_not_complete)
    end,

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

send_sync_times_out_when_buffer_stays_full_test(_Config) ->
    TP = #transport_params{
        initial_max_data = 256,
        initial_max_stream_data_bidi_local = 256,
        initial_max_stream_data_bidi_remote = 64,
        initial_max_stream_data_uni = 256,
        initial_max_streams_bidi = 16,
        initial_max_streams_uni = 16
    },
    {ok, Listener} = listen(#{transport_params => TP}),
    {ok, Port} = nquic:get_port(Listener),
    ClientDrv = establish_unresponsive_peer(Port, Listener),

    {ok, SId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    Payload = binary:copy(<<"x">>, 8 * 1024),

    %% Peer is unresponsive: no MAX_STREAM_DATA / MAX_DATA credit is
    %% ever granted, so the send cannot complete and the deadline fires.
    Result = nquic_ctx_driver:send(ClientDrv, SId, Payload, 200),
    ?assertEqual({error, {timeout, send}}, Result),

    catch nquic_ctx_driver:close(ClientDrv),
    catch gen_server:stop(Listener),
    ok.

send4_one_mib_over_constrained_window_completes_test(_Config) ->
    TP = #transport_params{
        initial_max_data = 65536,
        initial_max_stream_data_bidi_local = 65536,
        initial_max_stream_data_bidi_remote = 32768,
        initial_max_stream_data_uni = 65536,
        initial_max_streams_bidi = 16,
        initial_max_streams_uni = 16
    },
    {ok, Listener} = listen(#{transport_params => TP}),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, SId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    Payload = binary:copy(<<"z">>, 1024 * 1024),

    TestPid = self(),
    SenderRef = make_ref(),
    spawn(fun() ->
        Result = nquic_ctx_driver:send_fin(ClientDrv, SId, Payload, 30000),
        TestPid ! {sender_done, SenderRef, Result}
    end),

    {ok, SId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    {ok, Received} = recv_all(ServerDrv, SId, byte_size(Payload), 30000),
    ?assertEqual(Payload, Received),

    receive
        {sender_done, SenderRef, ok} -> ok;
        {sender_done, SenderRef, Other} -> ct:fail({unexpected_send_result, Other})
    after 30000 -> ct:fail(send_did_not_complete)
    end,

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

send4_per_call_timeout_overrides_send_timeout_test(_Config) ->
    TP = #transport_params{
        initial_max_data = 256,
        initial_max_stream_data_bidi_local = 256,
        initial_max_stream_data_bidi_remote = 64,
        initial_max_stream_data_uni = 256,
        initial_max_streams_bidi = 16,
        initial_max_streams_uni = 16
    },
    {ok, Listener} = listen(#{transport_params => TP}),
    {ok, Port} = nquic:get_port(Listener),
    ClientDrv = establish_unresponsive_peer(Port, Listener),

    {ok, SId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    Payload = binary:copy(<<"x">>, 8 * 1024),

    Start = erlang:monotonic_time(millisecond),
    Result = nquic_ctx_driver:send(ClientDrv, SId, Payload, 200),
    Elapsed = erlang:monotonic_time(millisecond) - Start,

    ?assertEqual({error, {timeout, send}}, Result),
    ?assert(Elapsed >= 200),
    ?assert(Elapsed < 5000),

    catch nquic_ctx_driver:close(ClientDrv),
    catch gen_server:stop(Listener),
    ok.

send4_completes_when_slow_reader_resumes_test(_Config) ->
    TP = #transport_params{
        initial_max_data = 65536,
        initial_max_stream_data_bidi_local = 65536,
        initial_max_stream_data_bidi_remote = 32768,
        initial_max_stream_data_uni = 65536,
        initial_max_streams_bidi = 16,
        initial_max_streams_uni = 16
    },
    {ok, Listener} = listen(#{transport_params => TP}),
    {ok, Port} = nquic:get_port(Listener),
    {ClientDrv, ServerDrv, Helper} = establish(Port, Listener),

    {ok, SId} = nquic_ctx_driver:open_stream(ClientDrv, #{type => bidi}),
    Payload = binary:copy(<<"s">>, 256 * 1024),

    TestPid = self(),
    SenderRef = make_ref(),
    spawn(fun() ->
        Result = nquic_ctx_driver:send_fin(ClientDrv, SId, Payload, 30000),
        TestPid ! {sender_done, SenderRef, Result}
    end),

    {ok, SId} = nquic_ctx_driver:accept_stream(ServerDrv, 5000),
    timer:sleep(750),
    {ok, Received} = recv_all(ServerDrv, SId, byte_size(Payload), 30000),
    ?assertEqual(Payload, Received),

    receive
        {sender_done, SenderRef, ok} -> ok;
        {sender_done, SenderRef, Other} -> ct:fail({unexpected_send_result, Other})
    after 30000 -> ct:fail(send_did_not_complete)
    end,

    teardown(ClientDrv, ServerDrv, Helper),
    catch gen_server:stop(Listener),
    ok.

%%%-----------------------------------------------------------------------------
%% HELPERS
%%%-----------------------------------------------------------------------------

listen(Extra) ->
    ConfDir = conf_dir(),
    Base = #{
        tls => #{
            certfile => filename:join(ConfDir, "server.pem"),
            keyfile => filename:join(ConfDir, "server.key"),
            alpn => [<<"h3">>]
        }
    },
    nquic:listen(0, maps:merge(Base, Extra)).

establish(Port, Listener) ->
    Self = self(),
    Helper = spawn_link(fun() ->
        Result = nquic_ctx_driver:accept(Listener, #{timeout => 5000}),
        Self ! {server_drv, self(), Result},
        receive
            stop -> ok
        end
    end),
    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000},
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

%% Hand back a client whose peer completed the handshake and then went
%% unresponsive (owner killed post-accept, conn_state already exported
%% so nothing services the connection server-side). No flow-control
%% credit is ever granted: the ctx-model equivalent of the old pid
%% send-buffer / send_timeout backpressure that timed a send out.
establish_unresponsive_peer(Port, Listener) ->
    Self = self(),
    _ = spawn(fun() ->
        case nquic_ctx_driver:accept(Listener, #{timeout => 5000}) of
            {ok, SD} ->
                Self ! {peer_ready, ok},
                exit(SD, kill);
            {error, E} ->
                Self ! {peer_ready, {error, E}}
        end
    end),
    ConnOpts = #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000},
    {ok, ClientDrv} = nquic_ctx_driver:connect("127.0.0.1", Port, ConnOpts),
    receive
        {peer_ready, ok} -> ok;
        {peer_ready, {error, E2}} -> ct:fail({accept_failed, E2})
    after 10000 ->
        ct:fail(accept_timeout)
    end,
    ClientDrv.

-spec recv_all(nquic_ctx_driver:driver(), nquic:stream_id(), non_neg_integer(), timeout()) ->
    {ok, binary()} | {error, term()}.
recv_all(Drv, SId, Total, Timeout) ->
    recv_all(Drv, SId, Total, Timeout, <<>>).

-spec recv_all(
    nquic_ctx_driver:driver(), nquic:stream_id(), non_neg_integer(), timeout(), binary()
) ->
    {ok, binary()} | {error, term()}.
recv_all(_Drv, _SId, Total, _Timeout, Acc) when byte_size(Acc) >= Total ->
    {ok, Acc};
recv_all(Drv, SId, Total, Timeout, Acc) ->
    case nquic_ctx_driver:recv(Drv, SId, Timeout) of
        {ok, Bin, _Fin} -> recv_all(Drv, SId, Total, Timeout, <<Acc/binary, Bin/binary>>);
        {error, _} = Err -> Err
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
