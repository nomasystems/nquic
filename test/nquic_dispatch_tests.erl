%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_dispatch}.
%%%-------------------------------------------------------------------
-module(nquic_dispatch_tests).

-include_lib("eunit/include/eunit.hrl").

new_default_test() ->
    D = nquic_dispatch:new(),
    ?assertEqual(0, nquic_dispatch:table_size(D)),
    nquic_dispatch:destroy(D).

new_custom_stripes_test() ->
    D = nquic_dispatch:new(4),
    ?assertEqual(0, nquic_dispatch:table_size(D)),
    nquic_dispatch:destroy(D).

register_lookup_test() ->
    D = nquic_dispatch:new(4),
    CID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Pid = self(),
    nquic_dispatch:register(D, CID, Pid),
    ?assertEqual(Pid, nquic_dispatch:lookup(D, CID)),
    ?assertEqual(1, nquic_dispatch:table_size(D)),
    nquic_dispatch:destroy(D).

lookup_not_found_test() ->
    D = nquic_dispatch:new(4),
    ?assertEqual(undefined, nquic_dispatch:lookup(D, <<0, 0, 0, 0, 0, 0, 0, 0>>)),
    nquic_dispatch:destroy(D).

unregister_test() ->
    D = nquic_dispatch:new(4),
    CID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    nquic_dispatch:register(D, CID, self()),
    ?assertEqual(self(), nquic_dispatch:lookup(D, CID)),
    nquic_dispatch:unregister(D, CID),
    ?assertEqual(undefined, nquic_dispatch:lookup(D, CID)),
    nquic_dispatch:destroy(D).

multiple_cids_test() ->
    D = nquic_dispatch:new(4),
    CID1 = <<1, 0, 0, 0, 0, 0, 0, 0>>,
    CID2 = <<2, 0, 0, 0, 0, 0, 0, 0>>,
    CID3 = <<3, 0, 0, 0, 0, 0, 0, 0>>,
    Pid = self(),
    nquic_dispatch:register(D, CID1, Pid),
    nquic_dispatch:register(D, CID2, Pid),
    nquic_dispatch:register(D, CID3, Pid),
    ?assertEqual(Pid, nquic_dispatch:lookup(D, CID1)),
    ?assertEqual(Pid, nquic_dispatch:lookup(D, CID2)),
    ?assertEqual(Pid, nquic_dispatch:lookup(D, CID3)),
    ?assertEqual(3, nquic_dispatch:table_size(D)),
    nquic_dispatch:destroy(D).

stripe_distribution_test() ->
    D = nquic_dispatch:new(4),
    CIDs = [<<I, 0, 0, 0, 0, 0, 0, 0>> || I <- lists:seq(1, 100)],
    lists:foreach(fun(CID) -> nquic_dispatch:register(D, CID, self()) end, CIDs),
    ?assertEqual(100, nquic_dispatch:table_size(D)),
    nquic_dispatch:destroy(D).

counters_test() ->
    C = nquic_dispatch:new_counters(2),
    ?assertEqual(0, nquic_dispatch:read_packets(C, 1)),
    ?assertEqual(0, nquic_dispatch:read_bytes(C, 1)),
    nquic_dispatch:inc_packets(C, 1),
    nquic_dispatch:inc_packets(C, 1),
    nquic_dispatch:inc_bytes(C, 1, 1500),
    ?assertEqual(2, nquic_dispatch:read_packets(C, 1)),
    ?assertEqual(1500, nquic_dispatch:read_bytes(C, 1)),
    ?assertEqual(0, nquic_dispatch:read_packets(C, 2)),
    ?assertEqual(0, nquic_dispatch:read_bytes(C, 2)).

counters_concurrent_test() ->
    C = nquic_dispatch:new_counters(1),
    Self = self(),
    Pids = [
        spawn(fun() ->
            lists:foreach(
                fun(_) -> nquic_dispatch:inc_packets(C, 1) end, lists:seq(1, 1000)
            ),
            Self ! {done, self()}
        end)
     || _ <- lists:seq(1, 10)
    ],
    lists:foreach(
        fun(P) ->
            receive
                {done, P} -> ok
            end
        end,
        Pids
    ),
    ?assertEqual(10000, nquic_dispatch:read_packets(C, 1)).

reregister_test() ->
    D = nquic_dispatch:new(4),
    OldPid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    NewPid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    CID1 = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    CID2 = <<9, 10, 11, 12, 13, 14, 15, 16>>,
    CID3 = <<17, 18, 19, 20, 21, 22, 23, 24>>,
    nquic_dispatch:register(D, CID1, OldPid),
    nquic_dispatch:register(D, CID2, OldPid),
    nquic_dispatch:register(D, CID3, self()),
    ?assertEqual(OldPid, nquic_dispatch:lookup(D, CID1)),
    ?assertEqual(OldPid, nquic_dispatch:lookup(D, CID2)),
    ?assertEqual(self(), nquic_dispatch:lookup(D, CID3)),
    ok = nquic_dispatch:reregister(D, OldPid, NewPid),
    ?assertEqual(NewPid, nquic_dispatch:lookup(D, CID1)),
    ?assertEqual(NewPid, nquic_dispatch:lookup(D, CID2)),
    ?assertEqual(self(), nquic_dispatch:lookup(D, CID3)),
    OldPid ! stop,
    NewPid ! stop,
    nquic_dispatch:destroy(D).

reregister_empty_test() ->
    D = nquic_dispatch:new(4),
    ok = nquic_dispatch:reregister(D, self(), self()),
    nquic_dispatch:destroy(D).

reregister_only_touches_target_pid_test() ->
    D = nquic_dispatch:new(4),
    Target = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    Other = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    NewPid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    TargetCIDs = [<<"T", I:8, 0:48>> || I <- lists:seq(1, 5)],
    OtherCIDs = [<<"O", I:8, 0:48>> || I <- lists:seq(1, 100)],
    [nquic_dispatch:register(D, C, Target) || C <- TargetCIDs],
    [nquic_dispatch:register(D, C, Other) || C <- OtherCIDs],
    ok = nquic_dispatch:reregister(D, Target, NewPid),
    [?assertEqual(NewPid, nquic_dispatch:lookup(D, C)) || C <- TargetCIDs],
    [?assertEqual(Other, nquic_dispatch:lookup(D, C)) || C <- OtherCIDs],
    Target ! stop,
    Other ! stop,
    NewPid ! stop,
    nquic_dispatch:destroy(D).

register_replaces_old_pid_test() ->
    D = nquic_dispatch:new(2),
    OldPid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    NewPid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    Decoy = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    CID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    nquic_dispatch:register(D, CID, OldPid),
    nquic_dispatch:register(D, CID, NewPid),
    ok = nquic_dispatch:reregister(D, OldPid, Decoy),
    ?assertEqual(NewPid, nquic_dispatch:lookup(D, CID)),
    OldPid ! stop,
    NewPid ! stop,
    Decoy ! stop,
    nquic_dispatch:destroy(D).

unregister_clears_reverse_index_test() ->
    D = nquic_dispatch:new(2),
    Pid = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    Decoy = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    CID = <<9, 9, 9, 9, 9, 9, 9, 9>>,
    nquic_dispatch:register(D, CID, Pid),
    nquic_dispatch:unregister(D, CID),
    ok = nquic_dispatch:reregister(D, Pid, Decoy),
    ?assertEqual(undefined, nquic_dispatch:lookup(D, CID)),
    Pid ! stop,
    Decoy ! stop,
    nquic_dispatch:destroy(D).
