-module(nquic_dispatch).
-moduledoc """
Striped connection dispatch table.

Distributes connection ID mappings across S ETS tables (one per stripe),
selected by hashing the DCID. This reduces write contention when many
connections register/unregister CIDs concurrently, while maintaining
O(1) lookup on the fast path.

Each stripe is an independent ETS `set` with `{read_concurrency, true}`
and `{write_concurrency, true}`. A separate `bag` table indexed by
owning Pid holds the reverse mapping so `reregister/3` can transfer a
single connection's CIDs in O(K) time (K = CIDs of that connection)
instead of O(N) (N = all registered CIDs across stripes).

Also provides atomics-based packet counters for lock-free telemetry.
""".

-export([new/0, new/1]).
-export([lookup/2, register/3, unregister/2]).
-export([owner_pids/1, reregister/3]).
-export([
    get_mgr/1,
    get_partition/2,
    get_partition_count/1,
    set_mgr/2,
    set_partition/3,
    set_partition_count/2,
    start_conn_child/3
]).
-export([destroy/1, table_size/1]).
-export([metrics/1]).
-export([
    inc_bytes/3,
    inc_packets/2,
    new_counters/1,
    read_bytes/2,
    read_packets/2
]).

-export_type([counters/0, t/0]).

-define(SLOTS_PER_RECEIVER, 2).
-define(PACKETS_IDX(I), (I - 1) * ?SLOTS_PER_RECEIVER + 1).
-define(BYTES_IDX(I), (I - 1) * ?SLOTS_PER_RECEIVER + 2).

-record(dispatch, {
    tables :: tuple(),
    stripes :: pos_integer(),
    pid_index :: ets:tid(),
    sups_table :: ets:tid(),
    metrics :: nquic_metrics:t() | undefined
}).

-record(counters, {
    ref :: atomics:atomics_ref(),
    n :: pos_integer()
}).

-type counters() :: #counters{}.
-type t() :: #dispatch{}.

%%%-----------------------------------------------------------------------------
%% DISPATCH TABLE API
%%%-----------------------------------------------------------------------------
-doc "Destroy all stripes. Only call during shutdown.".
-spec destroy(t()) -> ok.
destroy(#dispatch{
    tables = Tables,
    stripes = S,
    pid_index = PidIndex,
    sups_table = SupsTable,
    metrics = Metrics
}) ->
    ok = lists:foreach(
        fun(I) -> ets:delete(element(I, Tables)) end,
        lists:seq(1, S)
    ),
    ets:delete(PidIndex),
    ets:delete(SupsTable),
    case Metrics of
        undefined -> ok;
        _ -> nquic_metrics:destroy(Metrics)
    end,
    ok.

-doc "Return the per-listener metrics handle attached to this dispatch, if any.".
-spec metrics(t()) -> nquic_metrics:t() | undefined.
metrics(#dispatch{metrics = M}) -> M.

%%%-----------------------------------------------------------------------------
%% ATOMICS COUNTERS API
%%%-----------------------------------------------------------------------------
-doc """
Look up the listener manager (`nquic_listener_mgr`) pid published at
listener startup. Returns `undefined` before the mgr has registered
itself (during the brief boot window of `nquic_listener_sup`).
""".
-spec get_mgr(t()) -> pid() | undefined.
get_mgr(#dispatch{sups_table = T}) ->
    try ets:lookup_element(T, mgr, 2) of
        Pid -> Pid
    catch
        error:badarg -> undefined
    end.

-doc """
Look up the partition supervisor pid published under the given 1-based
index. Returns `undefined` if the slot is empty (e.g. between a
partition crash and the supervisor's restart).
""".
-spec get_partition(t(), pos_integer()) -> pid() | undefined.
get_partition(#dispatch{sups_table = T}, Idx) when is_integer(Idx), Idx > 0 ->
    try ets:lookup_element(T, {partition, Idx}, 2) of
        Pid -> Pid
    catch
        error:badarg -> undefined
    end.

-doc """
Return the published partition count, or `undefined` before
`nquic_partitions_sup:init/1` has run.
""".
-spec get_partition_count(t()) -> pos_integer() | undefined.
get_partition_count(#dispatch{sups_table = T}) ->
    try ets:lookup_element(T, partition_count, 2) of
        N -> N
    catch
        error:badarg -> undefined
    end.

-doc "Add ByteCount to byte counter for receiver I (1-based).".
-spec inc_bytes(counters(), pos_integer(), non_neg_integer()) -> ok.
inc_bytes(#counters{ref = Ref}, I, ByteCount) ->
    atomics:add(Ref, ?BYTES_IDX(I), ByteCount),
    ok.

-doc "Increment packet count for receiver I (1-based).".
-spec inc_packets(counters(), pos_integer()) -> ok.
inc_packets(#counters{ref = Ref}, I) ->
    atomics:add(Ref, ?PACKETS_IDX(I), 1),
    ok.

-doc "Look up the process for a connection ID.".
-spec lookup(t(), binary()) -> pid() | undefined.
lookup(#dispatch{tables = Tables, stripes = S}, DCID) ->
    Stripe = erlang:phash2(DCID, S) + 1,
    try
        ets:lookup_element(element(Stripe, Tables), DCID, 2)
    catch
        error:badarg -> undefined
    end.

-doc "Create a striped dispatch table with default stripe count (number of schedulers).".
-spec new() -> t().
new() ->
    new(erlang:system_info(schedulers)).

-doc "Create a striped dispatch table with S stripes.".
-spec new(pos_integer()) -> t().
new(Stripes) when is_integer(Stripes), Stripes > 0 ->
    Tables = list_to_tuple([
        ets:new(nquic_dispatch_stripe, [
            set,
            public,
            {read_concurrency, true},
            {write_concurrency, true}
        ])
     || _ <- lists:seq(1, Stripes)
    ]),
    PidIndex = ets:new(nquic_dispatch_pid_index, [
        bag,
        public,
        {write_concurrency, true},
        {read_concurrency, true}
    ]),
    SupsTable = ets:new(nquic_dispatch_sups, [
        set, public, {read_concurrency, true}
    ]),
    Metrics = nquic_metrics:new(),
    #dispatch{
        tables = Tables,
        stripes = Stripes,
        pid_index = PidIndex,
        sups_table = SupsTable,
        metrics = Metrics
    }.

-doc "Create packet counters for N receivers.".
-spec new_counters(pos_integer()) -> counters().
new_counters(N) when is_integer(N), N > 0 ->
    Ref = atomics:new(N * ?SLOTS_PER_RECEIVER, [{signed, false}]),
    #counters{ref = Ref, n = N}.

-doc """
Return the distinct owner pids currently registered across all CIDs.
Reads the per-pid reverse index (a `bag` of `{Pid, CID}`) and folds it
to a deduplicated pid list. Used only by the listener drain broadcast
(`nquic:stop_listener/1,2`, `mode => cascade`); never on the per-packet
path.
""".
-spec owner_pids(t()) -> [pid()].
owner_pids(#dispatch{pid_index = PidIndex}) ->
    lists:usort(ets:select(PidIndex, [{{'$1', '_'}, [], ['$1']}])).

-doc "Read byte count for receiver I (1-based).".
-spec read_bytes(counters(), pos_integer()) -> non_neg_integer().
read_bytes(#counters{ref = Ref}, I) ->
    atomics:get(Ref, ?BYTES_IDX(I)).

-doc "Read packet count for receiver I (1-based).".
-spec read_packets(counters(), pos_integer()) -> non_neg_integer().
read_packets(#counters{ref = Ref}, I) ->
    atomics:get(Ref, ?PACKETS_IDX(I)).

-doc "Register a connection ID to a process.".
-spec register(t(), binary(), pid()) -> true.
register(#dispatch{tables = Tables, stripes = S, pid_index = PidIndex}, DCID, Pid) ->
    Tab = element(erlang:phash2(DCID, S) + 1, Tables),
    case ets:lookup(Tab, DCID) of
        [{_, OldPid}] when OldPid =/= Pid ->
            ets:delete_object(PidIndex, {OldPid, DCID});
        _ ->
            ok
    end,
    ets:insert(Tab, {DCID, Pid}),
    ets:insert(PidIndex, {Pid, DCID}),
    true.

-doc """
Re-register all entries pointing to OldPid to NewPid.
Walks the per-pid reverse index for OldPid and updates only that
connection's CIDs (O(K)), instead of scanning every stripe (O(N)).
Used during connection export (accept_ctx) to transfer dispatch
entries from the gen_statem to the library-mode owner process.
""".
-spec reregister(t(), pid(), pid()) -> ok.
reregister(_Disp, SamePid, SamePid) ->
    ok;
reregister(#dispatch{tables = Tables, stripes = S, pid_index = PidIndex}, OldPid, NewPid) ->
    Entries = ets:lookup(PidIndex, OldPid),
    ok = lists:foreach(
        fun({_, DCID}) ->
            Tab = element(erlang:phash2(DCID, S) + 1, Tables),
            case ets:lookup(Tab, DCID) of
                [{_, OldPid}] ->
                    ets:insert(Tab, {DCID, NewPid}),
                    ets:insert(PidIndex, {NewPid, DCID});
                _ ->
                    ok
            end,
            ets:delete_object(PidIndex, {OldPid, DCID})
        end,
        Entries
    ),
    ok.

-doc """
Publish the listener manager pid. Called from `nquic_listener_mgr:init/1`
so receivers and protocol-level helpers can route accept/establishment
notifications via `nquic_dispatch:get_mgr/1`.
""".
-spec set_mgr(t(), pid()) -> true.
set_mgr(#dispatch{sups_table = T}, Pid) when is_pid(Pid) ->
    ets:insert(T, {mgr, Pid}).

-doc """
Publish a partition supervisor pid under its 1-based index. Each
`nquic_server_sup` partition calls this from its `init/1` (or after
restart) so `start_conn_child/3` can route work without a tuple
republish step. Avoids the `set_sups` tuple write-then-replace loop
that the legacy `nquic_listener` did on every partition restart.
""".
-spec set_partition(t(), pos_integer(), pid()) -> true.
set_partition(#dispatch{sups_table = T}, Idx, Pid) when is_integer(Idx), Idx > 0, is_pid(Pid) ->
    ets:insert(T, {{partition, Idx}, Pid}).

-doc """
Publish the total number of partition supervisors. Set once by
`nquic_partitions_sup:init/1` before any partition starts so
`start_conn_child/3` can hash the DCID into the right slot.
""".
-spec set_partition_count(t(), pos_integer()) -> true.
set_partition_count(#dispatch{sups_table = T}, N) when is_integer(N), N > 0 ->
    ets:insert(T, {partition_count, N}).

-doc """
Start a connection child under the partition supervisor selected by
hashing the DCID. Resolves the partition pid via two ETS reads (count
+ slot), so partition restart is observed immediately without any
republish step.
""".
-spec start_conn_child(t(), binary(), map()) ->
    {ok, pid()} | {ok, pid(), term()} | {error, term()}.
start_conn_child(#dispatch{sups_table = T}, DCID, ChildOpts) ->
    try ets:lookup_element(T, partition_count, 2) of
        N when is_integer(N), N > 0 ->
            Idx = erlang:phash2(DCID, N) + 1,
            try ets:lookup_element(T, {partition, Idx}, 2) of
                Sup when is_pid(Sup) ->
                    supervisor:start_child(Sup, [ChildOpts])
            catch
                error:badarg ->
                    {error, sups_not_ready}
            end
    catch
        error:badarg ->
            {error, sups_not_ready}
    end.

-doc "Return the total number of registered connection IDs across all stripes.".
-spec table_size(t()) -> non_neg_integer().
table_size(#dispatch{tables = Tables, stripes = S}) ->
    Total = lists:foldl(
        fun(I, Acc) ->
            case ets:info(element(I, Tables), size) of
                N when is_integer(N) -> Acc + N;
                _ -> Acc
            end
        end,
        0,
        lists:seq(1, S)
    ),
    erlang:floor(Total).

-doc "Remove a connection ID from the dispatch table.".
-spec unregister(t(), binary()) -> true.
unregister(#dispatch{tables = Tables, stripes = S, pid_index = PidIndex}, DCID) ->
    Tab = element(erlang:phash2(DCID, S) + 1, Tables),
    case ets:lookup(Tab, DCID) of
        [{_, Pid}] ->
            ets:delete(Tab, DCID),
            ets:delete_object(PidIndex, {Pid, DCID});
        [] ->
            true
    end.
