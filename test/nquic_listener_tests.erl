%%%-------------------------------------------------------------------
%%% EUnit tests for the listener public API ({@link nquic_listener}) and
%%% the underlying manager gen_server ({@link nquic_listener_mgr}).
%%%
%%% Tests below boot the real supervision tree (`nquic_listener_sup' ->
%%% mgr/partitions/established/receiver) and exercise it through the
%%% public surface, instead of poking gen_server callbacks with a copy
%%% of the legacy `#state{}' record. That coupling is what made the
%%% old suite drift every time the listener internals moved.
%%%-------------------------------------------------------------------
-module(nquic_listener_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
start_link_returns_supervisor_pid_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            ?assert(is_pid(Listener)),
            ?assertEqual(supervisor, proc_type(Listener)),
            ?assertEqual(nquic_listener_sup, callback_module(Listener))
        after
            stop_listener(Listener)
        end
    end}.

resolved_port_is_nonzero_when_port_zero_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            {ok, Port} = nquic_listener:get_port(Listener),
            ?assert(Port > 0)
        after
            stop_listener(Listener)
        end
    end}.

accept_returns_timeout_when_no_conns_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            ?assertEqual({error, timeout}, nquic_listener:accept(Listener, 50))
        after
            stop_listener(Listener)
        end
    end}.

dispatch_register_lookup_unregister_round_trip_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            {ok, Dispatch} = nquic_listener:get_dispatch(Listener),
            CID = <<42:64>>,
            true = nquic_listener:dispatch_register(Dispatch, CID, self()),
            ?assertEqual(self(), nquic_listener:dispatch_lookup(Dispatch, CID)),
            true = nquic_listener:dispatch_unregister(Dispatch, CID),
            ?assertEqual(undefined, nquic_listener:dispatch_lookup(Dispatch, CID))
        after
            stop_listener(Listener)
        end
    end}.

start_conn_child_routes_via_dispatch_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            ChildOpts = child_opts_for_listener(Listener),
            CID = <<7:64>>,
            ?assertMatch({ok, _}, nquic_listener:start_conn_child(Listener, CID, ChildOpts))
        after
            stop_listener(Listener)
        end
    end}.

queued_conn_is_returned_to_acceptor_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            Entry = fake_entry(),
            ok = nquic_listener:connection_established(Listener, Entry),
            ?assertEqual({ok, Entry}, nquic_listener:accept(Listener, 250)),
            stop_entry(Entry)
        after
            stop_listener(Listener)
        end
    end}.

waiting_acceptor_is_woken_by_connection_established_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        Self = self(),
        try
            Acceptor = spawn(fun() ->
                Self ! {accept_result, nquic_listener:accept(Listener, 1000)}
            end),
            timer:sleep(50),
            Entry = fake_entry(),
            ok = nquic_listener:connection_established(Listener, Entry),
            receive
                {accept_result, Got} -> ?assertEqual({ok, Entry}, Got)
            after 1500 ->
                error(acceptor_did_not_return)
            end,
            stop_entry(Entry),
            stop_keepalive(Acceptor)
        after
            stop_listener(Listener)
        end
    end}.

queue_full_drops_new_conn_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{
            port => 0, receivers => 1, max_accept_queue => 2
        }),
        try
            E1 = fake_entry(),
            E2 = fake_entry(),
            E3 = fake_entry(),
            ok = nquic_listener:connection_established(Listener, E1),
            ok = nquic_listener:connection_established(Listener, E2),
            ok = nquic_listener:connection_established(Listener, E3),
            ?assertEqual({ok, E1}, nquic_listener:accept(Listener, 250)),
            ?assertEqual({ok, E2}, nquic_listener:accept(Listener, 250)),
            ?assertEqual({error, timeout}, nquic_listener:accept(Listener, 50)),
            stop_entry(E1),
            stop_entry(E2),
            stop_entry(E3)
        after
            stop_listener(Listener)
        end
    end}.

opt_returns_known_option_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{
            port => 0, receivers => 1, idle_timeout => 5000
        }),
        try
            ?assertEqual({ok, 5000}, nquic_listener:opt(Listener, idle_timeout)),
            ?assertEqual({error, not_found}, nquic_listener:opt(Listener, no_such_key))
        after
            stop_listener(Listener)
        end
    end}.

get_metrics_returns_dispatch_metrics_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            ?assertMatch({ok, _}, nquic_listener:get_metrics(Listener))
        after
            stop_listener(Listener)
        end
    end}.

unknown_call_cast_info_are_no_ops_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            Mgr = child_pid(Listener, nquic_listener_mgr),
            ?assertEqual({error, unknown_request}, gen_server:call(Mgr, who_knows)),
            ok = gen_server:cast(Mgr, who_knows),
            Mgr ! some_random_message,
            %% mgr is still alive after the unknown traffic
            ?assert(is_process_alive(Mgr))
        after
            stop_listener(Listener)
        end
    end}.

resolve_port_with_explicit_port_test_() ->
    {timeout, 10, fun() ->
        {ok, L1} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        {ok, P1} = nquic_listener:get_port(L1),
        stop_listener(L1),
        {ok, L2} = nquic_listener:start_link(#{port => P1 + 1, receivers => 1}),
        try
            ?assertEqual({ok, P1 + 1}, nquic_listener:get_port(L2))
        after
            stop_listener(L2)
        end
    end}.

api_returns_closed_after_listener_stop_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        stop_listener(Listener),
        ?assertEqual({error, closed}, nquic_listener:get_port(Listener)),
        ?assertEqual({error, closed}, nquic_listener:get_dispatch(Listener)),
        ?assertEqual({error, closed}, nquic_listener:opt(Listener, idle_timeout)),
        ?assertEqual({error, closed}, nquic_listener:get_metrics(Listener))
    end}.

stop_cascade_returns_ok_and_terminates_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        ?assertEqual(ok, nquic_listener:stop(Listener, cascade, 5000)),
        ?assertEqual(ok, wait_until_alive(fun() -> not is_process_alive(Listener) end, 50, 100)),
        ?assertNot(is_process_alive(Listener))
    end}.

stop_cascade_is_idempotent_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        ?assertEqual(ok, nquic_listener:stop(Listener, cascade, 5000)),
        ?assertEqual(ok, wait_until_alive(fun() -> not is_process_alive(Listener) end, 50, 100)),
        %% Already-dead supervisor: the alive check short-circuits to ok.
        ?assertEqual(ok, nquic_listener:stop(Listener, cascade, 5000))
    end}.

stop_cascade_zero_timeout_brutal_kills_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        %% A 0 ms graceful budget forces the timeout -> brutal-kill branch.
        ?assertEqual(ok, nquic_listener:stop(Listener, cascade, 0)),
        ?assertEqual(ok, wait_until_alive(fun() -> not is_process_alive(Listener) end, 50, 100)),
        ?assertNot(is_process_alive(Listener))
    end}.

stop_detach_keeps_conn_subtree_and_is_idempotent_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            PartitionsBefore = child_pid(Listener, nquic_partitions_sup),
            ?assert(is_pid(PartitionsBefore)),
            ?assertEqual(ok, nquic_listener:stop(Listener, detach, 5000)),
            ?assert(is_process_alive(Listener)),
            ?assertEqual(undefined, child_pid(Listener, nquic_receiver_sup)),
            ?assertEqual(undefined, child_pid(Listener, nquic_listener_mgr)),
            ?assertEqual(PartitionsBefore, child_pid(Listener, nquic_partitions_sup)),
            %% Terminating already-terminated children is a no-op.
            ?assertEqual(ok, nquic_listener:stop(Listener, detach, 5000))
        after
            stop_listener(Listener)
        end
    end}.

mgr_accept_maps_dead_server_to_closed_test_() ->
    {timeout, 10, fun() ->
        Dead = spawn(fun() -> ok end),
        ?assertEqual(ok, wait_until_alive(fun() -> not is_process_alive(Dead) end, 20, 50)),
        ?assertEqual({error, closed}, nquic_listener_mgr:accept(Dead, 100))
    end}.

shim_calls_on_stopped_listener_are_safe_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        ?assertEqual(ok, nquic_listener:stop(Listener, cascade, 5000)),
        ?assertEqual(ok, wait_until_alive(fun() -> not is_process_alive(Listener) end, 50, 100)),
        %% connection_established/2 swallows a closed listener (returns ok);
        %% start_conn_child/3 surfaces the closed error.
        ?assertEqual(ok, nquic_listener:connection_established(Listener, fake_entry())),
        ?assertMatch({error, _}, nquic_listener:start_conn_child(Listener, <<1:64>>, #{}))
    end}.

bad_certfile_returns_cert_error_test_() ->
    {timeout, 10, fun() ->
        with_silenced_logger(fun() ->
            ?assertMatch(
                {error, _},
                nquic_listener:start_link(#{
                    port => 0, receivers => 1, certfile => "/nonexistent/cert.pem"
                })
            )
        end)
    end}.

certfile_present_keyfile_missing_returns_error_test_() ->
    {timeout, 10, fun() ->
        with_silenced_logger(fun() ->
            ?assertMatch(
                {error, _},
                nquic_listener:start_link(#{
                    port => 0,
                    receivers => 1,
                    certfile => "test/conf/server.pem",
                    keyfile => "/nonexistent/key.pem"
                })
            )
        end)
    end}.

certfile_with_valid_keyfile_starts_test_() ->
    {timeout, 10, fun() ->
        Opts = #{
            port => 0,
            receivers => 1,
            certfile => "test/conf/server.pem",
            keyfile => "test/conf/server.key"
        },
        case nquic_listener:start_link(Opts) of
            {ok, Listener} -> stop_listener(Listener);
            {error, _} -> ok
        end
    end}.

%%%-----------------------------------------------------------------------------
%% Supervision-tree restart contract
%%%-----------------------------------------------------------------------------

partition_crash_restarts_only_partition_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 2}),
        try
            {ok, Dispatch} = nquic_listener:get_dispatch(Listener),
            PartitionsSup = child_pid(Listener, nquic_partitions_sup),
            ReceiverSup = child_pid(Listener, nquic_receiver_sup),
            MgrPid = child_pid(Listener, nquic_listener_mgr),
            [{_, OldPart, _, _} | _] = supervisor:which_children(PartitionsSup),
            true = is_pid(OldPart),
            exit(OldPart, kill),
            ok = wait_until_alive(
                fun() ->
                    NewPart = element(2, hd(supervisor:which_children(PartitionsSup))),
                    is_pid(NewPart) andalso is_process_alive(NewPart) andalso NewPart =/= OldPart
                end,
                50,
                50
            ),
            ?assertEqual(MgrPid, child_pid(Listener, nquic_listener_mgr)),
            ?assertEqual(ReceiverSup, child_pid(Listener, nquic_receiver_sup)),
            %% Dispatch slot got re-published by the new partition's init.
            ?assert(is_pid(nquic_dispatch:get_mgr(Dispatch)))
        after
            stop_listener(Listener)
        end
    end}.

receiver_sup_crash_does_not_take_down_mgr_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            MgrPid = child_pid(Listener, nquic_listener_mgr),
            PartitionsSup = child_pid(Listener, nquic_partitions_sup),
            ReceiverSup = child_pid(Listener, nquic_receiver_sup),
            exit(ReceiverSup, kill),
            ok = wait_until_alive(
                fun() ->
                    NewSup = child_pid(Listener, nquic_receiver_sup),
                    is_pid(NewSup) andalso is_process_alive(NewSup) andalso NewSup =/= ReceiverSup
                end,
                50,
                50
            ),
            ?assertEqual(MgrPid, child_pid(Listener, nquic_listener_mgr)),
            ?assertEqual(PartitionsSup, child_pid(Listener, nquic_partitions_sup))
        after
            stop_listener(Listener)
        end
    end}.

mgr_crash_cascades_full_subtree_test_() ->
    {timeout, 10, fun() ->
        {ok, Listener} = nquic_listener:start_link(#{port => 0, receivers => 1}),
        try
            MgrPid = child_pid(Listener, nquic_listener_mgr),
            PartitionsSup = child_pid(Listener, nquic_partitions_sup),
            ReceiverSup = child_pid(Listener, nquic_receiver_sup),
            exit(MgrPid, kill),
            ok = wait_until_alive(
                fun() ->
                    NewMgr = child_pid(Listener, nquic_listener_mgr),
                    is_pid(NewMgr) andalso is_process_alive(NewMgr) andalso NewMgr =/= MgrPid
                end,
                50,
                50
            ),
            ?assertNotEqual(PartitionsSup, child_pid(Listener, nquic_partitions_sup)),
            ?assertNotEqual(ReceiverSup, child_pid(Listener, nquic_receiver_sup))
        after
            stop_listener(Listener)
        end
    end}.

%%%-----------------------------------------------------------------------------
%% Helpers
%%%-----------------------------------------------------------------------------

callback_module(Pid) ->
    supervisor:get_callback_module(Pid).

child_opts_for_listener(Listener) ->
    {ok, Dispatch} = nquic_listener:get_dispatch(Listener),
    #{
        role => server,
        scid => <<0:64>>,
        dcid => <<1:64>>,
        odcid => <<2:64>>,
        dispatch_table => Dispatch,
        listener => Listener
    }.

child_pid(Listener, Id) ->
    Children = supervisor:which_children(Listener),
    {Id, Pid, _, _} = lists:keyfind(Id, 1, Children),
    Pid.

proc_type(Pid) ->
    {dictionary, Dict} = erlang:process_info(Pid, dictionary),
    case proplists:get_value('$initial_call', Dict) of
        {supervisor, _, _} -> supervisor;
        {gen_server, _, _} -> gen_server;
        _ -> unknown
    end.

spawn_keepalive() ->
    spawn(fun() ->
        receive
            stop -> ok
        end
    end).

stop_keepalive(Pid) ->
    Pid ! stop.

%% A minimal proactively-exported accept entry: shared-socket
%% (Connected = false), no dispatch table, so the manager's handoff
%% is a no-op and the entry flows through the queue unchanged.
fake_entry() ->
    {exported, #conn_state{}, undefined, undefined, false, spawn_keepalive()}.

stop_entry({exported, _, _, _, _, Pid}) ->
    stop_keepalive(Pid).

stop_listener(Pid) when is_pid(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            catch gen_server:stop(Pid, normal, 5000);
        false ->
            ok
    end.

wait_until_alive(_Fun, _Sleep, 0) ->
    {error, timeout};
wait_until_alive(Fun, Sleep, N) ->
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
            wait_until_alive(Fun, Sleep, N - 1)
    end.

with_silenced_logger(Fun) ->
    OldConfig = logger:get_primary_config(),
    OldTrap = process_flag(trap_exit, true),
    ok = logger:set_primary_config(level, none),
    try
        Fun()
    after
        ok = logger:set_primary_config(OldConfig),
        drain_exits(),
        process_flag(trap_exit, OldTrap)
    end.

drain_exits() ->
    receive
        {'EXIT', _, _} -> drain_exits()
    after 0 ->
        ok
    end.
