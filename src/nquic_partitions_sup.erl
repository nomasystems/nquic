-module(nquic_partitions_sup).
-moduledoc """
Container supervisor for the per-scheduler `nquic_server_sup` partitions.

Holds N partition supervisors as children under `one_for_one`. Each child
publishes its own pid to the listener's dispatch table on init, so a
partition crash + restart is observed by `nquic_dispatch:start_conn_child/3`
on its next call without any republish step from this supervisor.

The partition count is published once into the dispatch table from this
module's `init/1` so the routing hash sees a consistent N.
""".
-behaviour(supervisor).

-export([start_link/1]).
-export([init/1]).

-spec init(nquic_dispatch:t()) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(Dispatch) ->
    N = erlang:system_info(schedulers_online),
    nquic_dispatch:set_partition_count(Dispatch, N),
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 5
    },
    ChildSpecs = [
        #{
            id => {partition, I},
            start => {nquic_server_sup, start_link, [Dispatch, I]},
            restart => permanent,
            shutdown => infinity,
            type => supervisor,
            modules => [nquic_server_sup]
        }
     || I <- lists:seq(1, N)
    ],
    {ok, {SupFlags, ChildSpecs}}.

-doc "Start the partitions supervisor with the listener's dispatch handle.".
-spec start_link(nquic_dispatch:t()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Dispatch) ->
    supervisor:start_link(?MODULE, Dispatch).
