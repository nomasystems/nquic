-module(nquic_receiver_sup).
-moduledoc """
Receiver supervisor.

Holds N `nquic_receiver` processes under `one_for_one`. Each receiver
owns one UDP socket. When N > 1 the receivers bind with `SO_REUSEPORT`
so the kernel distributes incoming datagrams across sockets by 4-tuple
hash.

Started as the last child of `nquic_listener_sup`. By the time `init/1`
runs the listener manager is already alive and has published itself to
the dispatch table, so the receiver child specs can carry the resolved
manager pid (`listener` opt) without extra round-trips.
""".
-behaviour(supervisor).

-export([start_link/1]).
-export([init/1]).

-spec init(map()) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(#{dispatch := Dispatch, opts := Opts}) ->
    N = maps:get(receivers, Opts, 1),
    Mgr = nquic_dispatch:get_mgr(Dispatch),
    {ok, Port} = nquic_listener_mgr:get_port(Mgr),
    {ok, StaticKey} = nquic_listener_mgr:get_static_key(Mgr),
    BaseOpts = Opts#{
        dispatch_table => Dispatch,
        listener => Mgr,
        static_key => StaticKey,
        port => Port,
        reuseport => N > 1
    },
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 5
    },
    ChildSpecs = [
        #{
            id => {receiver, I},
            start => {nquic_receiver, start_link, [BaseOpts]},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [nquic_receiver]
        }
     || I <- lists:seq(1, N)
    ],
    {ok, {SupFlags, ChildSpecs}}.

-doc "Start the receiver supervisor. `Args` carries the dispatch handle and resolved opts.".
-spec start_link(#{dispatch := nquic_dispatch:t(), opts := map()}) ->
    {ok, pid()} | ignore | {error, term()}.
start_link(Args) when is_map(Args) ->
    supervisor:start_link(?MODULE, Args).
