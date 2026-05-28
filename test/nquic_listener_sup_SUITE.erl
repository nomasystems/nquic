%%%-------------------------------------------------------------------
%%% @doc Verifies the listener supervision tree's `rest_for_one'
%%% restart contract end-to-end: each child is killed in turn, and
%%% the test asserts the surviving / restarted set matches the
%%% supervisor strategy. Also drives a real handshake after the
%%% surgery so we know the tree is still functional.
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_listener_sup_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-compile([export_all, nowarn_export_all]).

all() ->
    [
        which_children_returns_expected_tree_test,
        receiver_sup_kill_does_not_affect_mgr_test,
        partitions_sup_kill_restarts_receivers_test,
        mgr_kill_cascades_full_subtree_test,
        single_partition_kill_is_contained_test,
        handshake_works_after_full_restart_test
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

which_children_returns_expected_tree_test(_Config) ->
    {ok, Listener} = start_listener(),
    try
        Children = supervisor:which_children(Listener),
        Ids = lists:sort([Id || {Id, _, _, _} <- Children]),
        ?assertEqual(
            [
                nquic_listener_mgr,
                nquic_partitions_sup,
                nquic_receiver_sup
            ],
            Ids
        ),
        ?assertEqual(nquic_listener_sup, supervisor:get_callback_module(Listener))
    after
        stop_listener(Listener)
    end.

receiver_sup_kill_does_not_affect_mgr_test(_Config) ->
    {ok, Listener} = start_listener(),
    try
        MgrBefore = child(Listener, nquic_listener_mgr),
        PartitionsBefore = child(Listener, nquic_partitions_sup),
        ReceiverSupBefore = child(Listener, nquic_receiver_sup),
        exit(ReceiverSupBefore, kill),
        wait_until(fun() ->
            child(Listener, nquic_receiver_sup) =/= ReceiverSupBefore
        end),
        ?assertEqual(MgrBefore, child(Listener, nquic_listener_mgr)),
        ?assertEqual(PartitionsBefore, child(Listener, nquic_partitions_sup))
    after
        stop_listener(Listener)
    end.

partitions_sup_kill_restarts_receivers_test(_Config) ->
    {ok, Listener} = start_listener(),
    try
        MgrBefore = child(Listener, nquic_listener_mgr),
        PartitionsBefore = child(Listener, nquic_partitions_sup),
        ReceiverSupBefore = child(Listener, nquic_receiver_sup),
        exit(PartitionsBefore, kill),
        wait_until(fun() ->
            child(Listener, nquic_partitions_sup) =/= PartitionsBefore
        end),
        ?assertEqual(MgrBefore, child(Listener, nquic_listener_mgr)),
        ?assertNotEqual(ReceiverSupBefore, child(Listener, nquic_receiver_sup))
    after
        stop_listener(Listener)
    end.

mgr_kill_cascades_full_subtree_test(_Config) ->
    {ok, Listener} = start_listener(),
    try
        MgrBefore = child(Listener, nquic_listener_mgr),
        PartitionsBefore = child(Listener, nquic_partitions_sup),
        ReceiverSupBefore = child(Listener, nquic_receiver_sup),
        exit(MgrBefore, kill),
        wait_until(fun() -> child(Listener, nquic_listener_mgr) =/= MgrBefore end),
        ?assertNotEqual(PartitionsBefore, child(Listener, nquic_partitions_sup)),
        ?assertNotEqual(ReceiverSupBefore, child(Listener, nquic_receiver_sup))
    after
        stop_listener(Listener)
    end.

single_partition_kill_is_contained_test(_Config) ->
    %% Killing one partition under nquic_partitions_sup must NOT cascade
    %% out to the listener_sup tree (one_for_one inside partitions_sup).
    {ok, Listener} = start_listener(),
    try
        MgrBefore = child(Listener, nquic_listener_mgr),
        PartitionsSup = child(Listener, nquic_partitions_sup),
        ReceiverSupBefore = child(Listener, nquic_receiver_sup),
        [{Id, OldPid, _, _} | _] = supervisor:which_children(PartitionsSup),
        exit(OldPid, kill),
        wait_until(fun() ->
            {Id, NewPid, _, _} = lists:keyfind(Id, 1, supervisor:which_children(PartitionsSup)),
            is_pid(NewPid) andalso NewPid =/= OldPid
        end),
        ?assertEqual(MgrBefore, child(Listener, nquic_listener_mgr)),
        ?assertEqual(PartitionsSup, child(Listener, nquic_partitions_sup)),
        ?assertEqual(ReceiverSupBefore, child(Listener, nquic_receiver_sup)),
        %% New partition pid is republished into dispatch ETS by its init.
        {ok, Dispatch} = nquic_listener:get_dispatch(Listener),
        {partition, Idx} = Id,
        {Id, Pid2, _, _} = lists:keyfind(Id, 1, supervisor:which_children(PartitionsSup)),
        ?assertEqual(Pid2, nquic_dispatch:get_partition(Dispatch, Idx))
    after
        stop_listener(Listener)
    end.

handshake_works_after_full_restart_test(_Config) ->
    {ok, Listener} = start_listener(),
    try
        Mgr0 = child(Listener, nquic_listener_mgr),
        exit(Mgr0, kill),
        wait_until(fun() -> child(Listener, nquic_listener_mgr) =/= Mgr0 end),
        {ok, Port} = nquic:get_port(Listener),
        ConnectorParent = self(),
        spawn(fun() ->
            R = nquic_ctx_driver:connect(
                "127.0.0.1",
                Port,
                #{tls => #{alpn => [<<"h3">>], verify => verify_none}, timeout => 5000}
            ),
            ConnectorParent ! {connect_result, R}
        end),
        {ok, Server} = nquic_ctx_driver:accept(Listener, #{timeout => 5000}),
        ?assert(is_pid(Server)),
        receive
            {connect_result, {ok, Client}} ->
                nquic_ctx_driver:close(Client),
                nquic_ctx_driver:close(Server)
        after 5000 ->
            error(connect_timeout)
        end
    after
        stop_listener(Listener)
    end.

%%%-----------------------------------------------------------------------------
%% Helpers
%%%-----------------------------------------------------------------------------

child(Sup, Id) ->
    Children = supervisor:which_children(Sup),
    {Id, Pid, _, _} = lists:keyfind(Id, 1, Children),
    Pid.

conf_dir() ->
    SrcFile = code:which(?MODULE),
    ProjectRoot = find_project_root(filename:dirname(SrcFile)),
    filename:join([ProjectRoot, "test", "conf"]).

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> find_project_root(filename:dirname(Dir))
    end.

start_listener() ->
    nquic:listen(0, #{
        tls => #{
            certfile => filename:join(conf_dir(), "server.pem"),
            keyfile => filename:join(conf_dir(), "server.key"),
            alpn => [<<"h3">>]
        },
        receivers => 2
    }).

stop_listener(Pid) when is_pid(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            catch gen_server:stop(Pid, normal, 5000);
        false ->
            ok
    end.

wait_until(Fun) ->
    wait_until(Fun, 100, 50).

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
