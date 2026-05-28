-module(nquic_server_sup).
-moduledoc """
Per-partition connection supervisor (`simple_one_for_one`).

One instance per scheduler is started under `nquic_partitions_sup`.
Connections are routed to a partition by hashing the DCID, distributing
supervision load across schedulers. Each partition publishes its pid to
the listener's dispatch table on init so `nquic_dispatch:start_conn_child/3`
can find it without going through a republish step on partition restart.
""".
-behaviour(supervisor).

-export([start_link/2]).
-export([init/1]).

-spec init({nquic_dispatch:t(), pos_integer()}) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init({Dispatch, Idx}) ->
    nquic_dispatch:set_partition(Dispatch, Idx, self()),
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 10,
        period => 5
    },
    ChildSpecs = [
        #{
            id => nquic_conn,
            start => {nquic_conn_launcher, start_link, []},
            restart => temporary,
            shutdown => 5000,
            type => worker,
            modules => [nquic_conn_launcher, nquic_conn_statem]
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.

-doc "Start one partition supervisor with its dispatch handle and 1-based index.".
-spec start_link(nquic_dispatch:t(), pos_integer()) ->
    {ok, pid()} | ignore | {error, term()}.
start_link(Dispatch, Idx) ->
    supervisor:start_link(?MODULE, {Dispatch, Idx}).
