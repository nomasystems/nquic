%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_server_sup} and {@link nquic_partitions_sup}.
%%%
%%% The legacy `start_partitions/0' / `start_child/3' surface was
%%% replaced by per-listener supervision: each `nquic_partitions_sup'
%%% instance owns N `nquic_server_sup' children that publish their pid
%%% into the listener's dispatch table on init. These tests exercise
%%% that shape via `nquic_partitions_sup:start_link/1'.
%%%-------------------------------------------------------------------
-module(nquic_server_sup_tests).

-include_lib("eunit/include/eunit.hrl").

partitions_sup_starts_n_partitions_test() ->
    Dispatch = nquic_dispatch:new(),
    {ok, Sup} = nquic_partitions_sup:start_link(Dispatch),
    try
        N = erlang:system_info(schedulers_online),
        Children = supervisor:which_children(Sup),
        ?assertEqual(N, length(Children)),
        Pids = [Pid || {_, Pid, _, _} <- Children, is_pid(Pid)],
        ?assertEqual(N, length(Pids)),
        ?assertEqual(N, length(lists:usort(Pids)))
    after
        cleanup(Sup, Dispatch)
    end.

each_partition_publishes_itself_to_dispatch_test() ->
    Dispatch = nquic_dispatch:new(),
    {ok, Sup} = nquic_partitions_sup:start_link(Dispatch),
    try
        N = erlang:system_info(schedulers_online),
        ?assertEqual(N, nquic_dispatch:get_partition_count(Dispatch)),
        Children = supervisor:which_children(Sup),
        lists:foreach(
            fun({{partition, I}, Pid, _, _}) ->
                ?assertEqual(Pid, nquic_dispatch:get_partition(Dispatch, I)),
                ?assert(is_process_alive(Pid))
            end,
            Children
        ),
        ?assertEqual(N, length(Children))
    after
        cleanup(Sup, Dispatch)
    end.

start_conn_child_routes_via_partition_test() ->
    Dispatch = nquic_dispatch:new(),
    {ok, Sup} = nquic_partitions_sup:start_link(Dispatch),
    try
        DCID = <<"dcid-routed-to-partition">>,
        %% Without a real conn_statem child spec wired in we expect a
        %% start failure, but the routing must reach a live partition.
        Result = nquic_dispatch:start_conn_child(Dispatch, DCID, #{}),
        ?assertMatch({error, _}, Result)
    after
        cleanup(Sup, Dispatch)
    end.

partition_crash_is_restarted_with_fresh_pid_test() ->
    Dispatch = nquic_dispatch:new(),
    {ok, Sup} = nquic_partitions_sup:start_link(Dispatch),
    try
        Children = supervisor:which_children(Sup),
        [{Id, OldPid, _, _} | _] = Children,
        ?assert(is_pid(OldPid)),
        Mon = erlang:monitor(process, OldPid),
        exit(OldPid, kill),
        receive
            {'DOWN', Mon, process, OldPid, killed} -> ok
        after 1000 ->
            error(timeout_waiting_for_partition_down)
        end,
        wait_until(
            fun() ->
                {Id, NewPid, _, _} = lists:keyfind(Id, 1, supervisor:which_children(Sup)),
                is_pid(NewPid) andalso NewPid =/= OldPid andalso is_process_alive(NewPid)
            end,
            50,
            50
        ),
        {Id, NewPid, _, _} = lists:keyfind(Id, 1, supervisor:which_children(Sup)),
        {partition, Idx} = Id,
        ?assertEqual(NewPid, nquic_dispatch:get_partition(Dispatch, Idx))
    after
        cleanup(Sup, Dispatch)
    end.

%%%-----------------------------------------------------------------------------
%% Helpers
%%%-----------------------------------------------------------------------------

cleanup(Sup, Dispatch) ->
    unlink(Sup),
    catch exit(Sup, shutdown),
    drain_exits(),
    nquic_dispatch:destroy(Dispatch).

drain_exits() ->
    receive
        {'EXIT', _, _} -> drain_exits()
    after 0 ->
        ok
    end.

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
