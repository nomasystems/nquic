-module(nquic_listener).
-moduledoc """
Public listener API shim.

Forwards user-facing calls to `nquic_listener_mgr`, the gen_server child
of `nquic_listener_sup` that holds the accept queue and the resolved
listen port. The handle returned by `start_link/1` (and by `nquic:listen/2`)
is the supervisor pid; the mgr child is resolved on demand via
`supervisor:which_children/1`. Hot-path dispatch helpers
(`dispatch_lookup/2`, `dispatch_register/3`, `dispatch_unregister/2`)
operate directly on the dispatch handle and never go through the mgr.
""".

-export([accept/2, connection_established/2, get_port/1, start_link/1, stop/3]).
-export([start_conn_child/3]).
-export([dispatch_lookup/2, dispatch_register/3, dispatch_unregister/2]).
-export([get_dispatch/1, get_metrics/1]).
-export([opt/2]).

-doc "Accept a new connection, blocking until one is available or timeout expires.".
-spec accept(pid(), timeout()) ->
    {ok, nquic_listener_mgr:accept_entry()} | {error, nquic_error:any_reason()}.
accept(Listener, Timeout) ->
    case mgr(Listener) of
        {ok, Mgr} -> nquic_listener_mgr:accept(Mgr, Timeout);
        {error, _} = Err -> Err
    end.

-doc "Hand a proactively exported, freshly handshaked connection to the listener manager.".
-spec connection_established(pid(), nquic_listener_mgr:accept_entry()) -> ok.
connection_established(Listener, Entry) ->
    case mgr(Listener) of
        {ok, Mgr} -> nquic_listener_mgr:connection_established(Mgr, Entry);
        {error, _} -> ok
    end.

-doc "Return the port number this listener is bound to.".
-spec get_port(pid()) -> {ok, inet:port_number()} | {error, nquic_error:any_reason()}.
get_port(Listener) ->
    case mgr(Listener) of
        {ok, Mgr} -> nquic_listener_mgr:get_port(Mgr);
        {error, _} = Err -> Err
    end.

-doc """
Start a new connection statem child under the partition supervisor
selected by hashing the DCID. Reads the partition pid directly from the
dispatch table, no `gen_server:call` required.
""".
-spec start_conn_child(pid(), binary(), map()) ->
    {ok, pid()} | {ok, pid(), term()} | {error, term()}.
start_conn_child(Listener, DCID, ChildOpts) ->
    case get_dispatch(Listener) of
        {ok, Dispatch} -> nquic_dispatch:start_conn_child(Dispatch, DCID, ChildOpts);
        {error, _} = Err -> Err
    end.

%%%-----------------------------------------------------------------------------
%% DISPATCH TABLE OPERATIONS
%%%-----------------------------------------------------------------------------
-doc "Look up the process for a connection ID, or return `undefined`.".
-spec dispatch_lookup(nquic_dispatch:t(), binary()) -> pid() | undefined.
dispatch_lookup(Dispatch, DCID) ->
    nquic_dispatch:lookup(Dispatch, DCID).

-doc "Register a connection ID to a process in the dispatch table.".
-spec dispatch_register(nquic_dispatch:t(), binary(), pid()) -> true.
dispatch_register(Dispatch, DCID, Pid) ->
    nquic_dispatch:register(Dispatch, DCID, Pid).

-doc "Remove a connection ID from the dispatch table.".
-spec dispatch_unregister(nquic_dispatch:t(), binary()) -> true.
dispatch_unregister(Dispatch, DCID) ->
    nquic_dispatch:unregister(Dispatch, DCID).

-doc "Return the dispatch table for external use (e.g., library-mode export).".
-spec get_dispatch(pid()) -> {ok, nquic_dispatch:t()} | {error, nquic_error:any_reason()}.
get_dispatch(Listener) ->
    case mgr(Listener) of
        {ok, Mgr} -> nquic_listener_mgr:get_dispatch(Mgr);
        {error, _} = Err -> Err
    end.

-doc """
Return the metrics handle for this listener. Cheap snapshot; looks up
the dispatch table once and reads the attached `nquic_metrics` handle.
""".
-spec get_metrics(pid()) -> {ok, nquic_metrics:t()} | {error, nquic_error:any_reason()}.
get_metrics(Listener) ->
    case mgr(Listener) of
        {ok, Mgr} -> nquic_listener_mgr:get_metrics(Mgr);
        {error, _} = Err -> Err
    end.

-doc """
Return a single listener option (e.g. `idle_timeout`, `receivers`) as
seen at startup.
""".
-spec opt(pid(), atom()) -> {ok, term()} | {error, nquic_error:any_reason()}.
opt(Listener, Key) when is_atom(Key) ->
    case mgr(Listener) of
        {ok, Mgr} -> nquic_listener_mgr:opt(Mgr, Key);
        {error, _} = Err -> Err
    end.

-doc """
Start a listener supervision tree with the given options. Returns the
supervisor pid; that pid is the public listener handle threaded through
all `nquic:*` calls.
""".
-spec start_link(map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Opts) when is_map(Opts) ->
    nquic_listener_sup:start_link(Opts).

-doc """
Stop a running listener.
`cascade` (the default behind `nquic:stop_listener/1`) stops accepting,
broadcasts `{quic_drain, Listener}` to every owner-held established
connection over the dispatch pid-index, then tears the supervision tree
down: the listen sockets are closed, the port is released, and the
handshake-phase `nquic_conn_statem` processes are terminated under the
supervisor shutdown budget. Owner-held connections close gracefully in
their own loop on the drain signal. No connection of either class
survives a `cascade`.
`detach` stops accepting and frees the port (terminates the receiver
sub-tree and the accept manager) but sends no drain signal: owner-held
established connections keep running until their own idle timeout, and
handshake-phase processes, now packet-starved, idle out. Use it to let
in-flight work finish.
The listener supervisor is started with `supervisor:start_link/2`, so
it is linked to whoever called `nquic:listen/2`. The stop is
synchronous and exits the supervisor with reason `normal`, so that
link never kills the owner. `cascade` also unlinks the *calling*
process first, so a caller that itself opened the listener is fully
detached once this returns. `Timeout` bounds the graceful `cascade`
shutdown before the supervisor is brutally killed. Calling stop on an
already-stopped listener is a no-op.
""".
-spec stop(pid(), cascade | detach, timeout()) -> ok.
stop(SupPid, cascade, Timeout) when is_pid(SupPid) ->
    true = unlink(SupPid),
    case is_process_alive(SupPid) of
        false ->
            ok;
        true ->
            ok = broadcast_drain(SupPid),
            stop_tree(SupPid, Timeout)
    end;
stop(SupPid, detach, _Timeout) when is_pid(SupPid) ->
    ok = terminate_child(SupPid, nquic_receiver_sup),
    ok = terminate_child(SupPid, nquic_listener_mgr),
    ok.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec broadcast_drain(pid()) -> ok.
broadcast_drain(SupPid) ->
    case get_dispatch(SupPid) of
        {ok, Dispatch} ->
            lists:foreach(
                fun(Pid) -> Pid ! {quic_drain, SupPid} end,
                nquic_dispatch:owner_pids(Dispatch)
            );
        {error, _} ->
            ok
    end.

-spec mgr(pid()) -> {ok, pid()} | {error, closed}.
mgr(SupPid) when is_pid(SupPid) ->
    try supervisor:which_children(SupPid) of
        Children ->
            case lists:keyfind(nquic_listener_mgr, 1, Children) of
                {nquic_listener_mgr, MgrPid, _, _} when is_pid(MgrPid) -> {ok, MgrPid};
                _ -> {error, closed}
            end
    catch
        exit:{noproc, _} -> {error, closed};
        exit:{normal, _} -> {error, closed};
        exit:{shutdown, _} -> {error, closed};
        exit:{_, {gen_server, call, _}} -> {error, closed}
    end.

-spec stop_tree(pid(), timeout()) -> ok.
stop_tree(SupPid, Timeout) ->
    try gen_server:stop(SupPid, normal, Timeout) of
        ok -> ok
    catch
        exit:timeout ->
            exit(SupPid, kill),
            ok;
        exit:{timeout, _} ->
            exit(SupPid, kill),
            ok;
        exit:_ ->
            ok
    end.

-spec terminate_child(pid(), atom()) -> ok.
terminate_child(SupPid, Id) ->
    try supervisor:terminate_child(SupPid, Id) of
        ok -> ok;
        {error, not_found} -> ok;
        {error, simple_one_for_one} -> ok
    catch
        exit:{noproc, _} -> ok;
        exit:{normal, _} -> ok;
        exit:{shutdown, _} -> ok;
        exit:{{shutdown, _}, _} -> ok
    end.
