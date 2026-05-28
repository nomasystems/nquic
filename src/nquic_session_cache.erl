-module(nquic_session_cache).
-moduledoc """
Per-instance session ticket cache for QUIC 0-RTT resumption.

Each cache is a `gen_server` that owns one named ETS table and runs a
periodic eviction sweep. Multiple caches can coexist on the same node
(one per logical client of the library), identified by the `Name` atom
passed to `start_link/1,2`.

## Usage

Start the cache under your own supervisor **before** using nquic:

```erlang
-spec children() -> [supervisor:child_spec()].
children() ->
    [nquic_session_cache:child_spec(my_quic_tickets, #{sweep_ms => 60_000})].
```

Then reference it in `connect` options:

```erlang
{ok, Conn} = nquic:connect(Host, Port, #{session_cache => my_quic_tickets}).
```

All cache functions fail loudly (`badarg` from the underlying ETS call)
if `Name` does not refer to a live cache. There is no auto-start: the
caller is responsible for initialising the cache synchronously before
any nquic connect is issued.

## Custom backends

The `session_cache` connect option also accepts `{module, Mod}` where
`Mod` exports the triple:

```erlang
store(Host, Port, Ticket) -> ok.
lookup(Host, Port)        -> {ok, Ticket} | {error, not_found}.
delete(Host, Port)        -> ok.
```

Use this to plug in an application-specific storage (Redis, Mnesia,
etc).
""".

-behaviour(gen_server).

-compile({no_auto_import, [size/1]}).

-export([
    child_spec/1,
    child_spec/2,
    clear/1,
    delete/3,
    lookup/3,
    maybe_load_ticket/3,
    size/1,
    start_link/1,
    start_link/2,
    stop/1,
    store/4
]).

-export([handle_call/3, handle_cast/2, handle_info/2, init/1, terminate/2]).

-export_type([cache_name/0, host/0]).

-type cache_name() :: atom().
-type host() :: inet:hostname() | inet:ip_address().

-define(DEFAULT_SWEEP_MS, 60_000).
-define(DEFAULT_TTL, 7200).

-record(state, {
    name :: cache_name(),
    sweep_ms :: pos_integer(),
    sweep_ref :: reference() | undefined
}).

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc "Standard child spec with the default sweep interval.".
-spec child_spec(cache_name()) -> supervisor:child_spec().
child_spec(Name) ->
    child_spec(Name, #{}).

-doc "Standard child spec with custom options.".
-spec child_spec(cache_name(), map()) -> supervisor:child_spec().
child_spec(Name, Opts) when is_atom(Name), is_map(Opts) ->
    #{
        id => {?MODULE, Name},
        start => {?MODULE, start_link, [Name, Opts]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [?MODULE]
    }.

-doc "Drop every entry in cache `Name`. Raises `badarg` if not started.".
-spec clear(cache_name()) -> ok.
clear(Name) when is_atom(Name) ->
    true = ets:delete_all_objects(Name),
    ok.

-doc "Delete a ticket from cache `Name`. Raises `badarg` if not started.".
-spec delete(cache_name(), host(), inet:port_number()) -> ok.
delete(Name, Host, Port) when is_atom(Name) ->
    Key = cache_key(Host, Port),
    true = ets:delete(Name, Key),
    ok.

-doc """
Look up a session ticket for `{Host, Port}` in cache `Name`.
Returns `{ok, Ticket}` for a live ticket, `{error, not_found}` for a
miss or an expired entry. Raises `badarg` if `Name` is not a live
cache.
""".
-spec lookup(cache_name(), host(), inet:port_number()) ->
    {ok, map()} | {error, not_found}.
lookup(Name, Host, Port) when is_atom(Name) ->
    Key = cache_key(Host, Port),
    case ets:lookup(Name, Key) of
        [{Key, TicketData, Expiry}] ->
            Now = erlang:system_time(second),
            case Now < Expiry of
                true ->
                    {ok, TicketData};
                false ->
                    ets:delete(Name, Key),
                    {error, not_found}
            end;
        [] ->
            {error, not_found}
    end.

-doc """
If `Opts` does not already carry a `session_ticket`, resolve the
configured `session_cache` selector and inject any cached ticket
into `Opts`. Returns `Opts` unchanged on miss or when no cache is
configured.
Accepts the same selector shape as the `connect/3,4` option:
`false` (no cache), an atom naming a started cache, or
`{module, Mod}` for a custom backend exporting `lookup/2`.
""".
-spec maybe_load_ticket(host(), inet:port_number(), map()) -> map().
maybe_load_ticket(Host, Port, Opts) ->
    case maps:get(session_ticket, Opts, undefined) of
        undefined ->
            case resolve_lookup(maps:get(session_cache, Opts, false), Host, Port) of
                {ok, Ticket} -> Opts#{session_ticket => Ticket};
                {error, _} -> Opts
            end;
        _ ->
            Opts
    end.

-doc "Return the number of entries in cache `Name`.".
-spec size(cache_name()) -> non_neg_integer().
size(Name) when is_atom(Name) ->
    ets:info(Name, size).

%%%-----------------------------------------------------------------------------
%% GEN_SERVER CALLBACKS
%%%-----------------------------------------------------------------------------
-spec handle_call(term(), gen_server:from(), #state{}) ->
    {reply, {error, unknown_request}, #state{}}.
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

-spec handle_cast(term(), #state{}) -> {noreply, #state{}}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(sweep | term(), #state{}) -> {noreply, #state{}}.
handle_info(sweep, #state{name = Name, sweep_ms = Ms} = State) ->
    sweep_expired(Name),
    Ref = schedule_sweep(Ms),
    {noreply, State#state{sweep_ref = Ref}};
handle_info(_Info, State) ->
    {noreply, State}.

-spec init({cache_name(), map()}) -> {ok, #state{}}.
init({Name, Opts}) ->
    process_flag(trap_exit, true),
    _ = ets:new(Name, [
        named_table,
        public,
        set,
        {read_concurrency, true},
        {write_concurrency, true},
        {decentralized_counters, true}
    ]),
    SweepMs = maps:get(sweep_ms, Opts, ?DEFAULT_SWEEP_MS),
    Ref = schedule_sweep(SweepMs),
    {ok, #state{name = Name, sweep_ms = SweepMs, sweep_ref = Ref}}.

-doc "Start a cache registered under `Name` with default options.".
-spec start_link(cache_name()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Name) ->
    start_link(Name, #{}).

-doc """
Start a cache registered under `Name`.
Accepted options:
* `sweep_ms` - eviction interval in milliseconds (default 60_000).
Returns `{error, {already_started, Pid}}` if a cache with this name is
already registered.
This call is synchronous: when it returns `{ok, _}` the ETS table is
live and ready for `store/4` / `lookup/3`.
""".
-spec start_link(cache_name(), map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Name, Opts) when is_atom(Name), is_map(Opts) ->
    gen_server:start_link({local, Name}, ?MODULE, {Name, Opts}, []).

-doc "Stop the cache and tear down its ETS table.".
-spec stop(cache_name()) -> ok.
stop(Name) when is_atom(Name) ->
    case whereis(Name) of
        undefined -> ok;
        _ -> gen_server:stop(Name)
    end.

-doc """
Store a session ticket under `{Host, Port}` for the cache `Name`.
Raises `badarg` if `Name` is not a live cache; start it via
`start_link/1,2` or `child_spec/1,2` first.
""".
-spec store(cache_name(), host(), inet:port_number(), map()) -> ok.
store(Name, Host, Port, TicketData) when is_atom(Name), is_map(TicketData) ->
    Key = cache_key(Host, Port),
    Lifetime = maps:get(lifetime, TicketData, ?DEFAULT_TTL),
    Expiry = erlang:system_time(second) + Lifetime,
    true = ets:insert(Name, {Key, TicketData, Expiry}),
    ok.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{name = Name}) ->
    case ets:info(Name) of
        undefined -> ok;
        _ -> ets:delete(Name)
    end,
    ok.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec cache_key(host(), inet:port_number()) -> {host(), inet:port_number()}.
cache_key(Host, Port) ->
    {Host, Port}.

-spec resolve_lookup(
    false | cache_name() | {module, module()},
    host(),
    inet:port_number()
) -> {ok, map()} | {error, not_found}.
resolve_lookup(false, _Host, _Port) ->
    {error, not_found};
resolve_lookup({module, Mod}, Host, Port) ->
    Mod:lookup(Host, Port);
resolve_lookup(Name, Host, Port) when is_atom(Name) ->
    lookup(Name, Host, Port).

%%%-----------------------------------------------------------------------------
%% TESTS
%%%-----------------------------------------------------------------------------
-spec schedule_sweep(pos_integer()) -> reference().
schedule_sweep(Ms) ->
    erlang:send_after(Ms, self(), sweep).

-spec sweep_expired(cache_name()) -> ok.
sweep_expired(Name) ->
    Now = erlang:system_time(second),
    _ = ets:select_delete(
        Name,
        [{{'_', '_', '$1'}, [{'=<', '$1', Now}], [true]}]
    ),
    ok.
