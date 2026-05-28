-module(nquic_token_cache).
-moduledoc """
Per-instance NEW_TOKEN cache for QUIC client reconnection (RFC 9000 §8.1.3).

Mirrors `nquic_session_cache`: each cache is a `gen_server` that owns
one named ETS table and runs a periodic eviction sweep. The cache is
opt-in; the caller starts it under its own supervisor and references
it by name on `nquic:connect/3`.

## Usage

```erlang
[nquic_token_cache:child_spec(my_quic_tokens, #{sweep_ms => 60_000})].
```

```erlang
{ok, Conn} = nquic:connect(Host, Port, #{token_cache => my_quic_tokens}).
```

The client records any NEW_TOKEN frame received from the server into
the cache. A subsequent `connect/4` to the same `{Host, Port}` reads
back the token and attaches it to the outgoing Initial; the server
validates it against its static key, treats the source address as
already-validated, and skips the Retry round-trip.

The cache stores raw token bytes; the server's HMAC binds the token
to a specific address + lifetime, so a stale or address-mismatched
token simply fails server-side validation and triggers a normal
Retry. Keep the client TTL shorter than the server's `Lifetime`
(default 24 h) to avoid presenting tokens the server will reject.

## Custom backends

The `token_cache` connect option also accepts `{module, Mod}` where
`Mod` exports:

```erlang
store(Host, Port, Token) -> ok.
lookup(Host, Port)       -> {ok, binary()} | {error, not_found}.
delete(Host, Port)       -> ok.
```
""".

-behaviour(gen_server).

-compile({no_auto_import, [size/1]}).

-export([
    child_spec/1,
    child_spec/2,
    clear/1,
    delete/3,
    lookup/3,
    maybe_load_token/3,
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
-define(DEFAULT_TTL, 86400).

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

-doc "Delete a token from cache `Name`. Raises `badarg` if not started.".
-spec delete(cache_name(), host(), inet:port_number()) -> ok.
delete(Name, Host, Port) when is_atom(Name) ->
    Key = cache_key(Host, Port),
    true = ets:delete(Name, Key),
    ok.

-doc """
Look up a NEW_TOKEN for `{Host, Port}` in cache `Name`.
Returns `{ok, Token}` for a live token, `{error, not_found}` for a
miss or an expired entry. Raises `badarg` if `Name` is not a live
cache.
""".
-spec lookup(cache_name(), host(), inet:port_number()) ->
    {ok, binary()} | {error, not_found}.
lookup(Name, Host, Port) when is_atom(Name) ->
    Key = cache_key(Host, Port),
    case ets:lookup(Name, Key) of
        [{Key, Token, Expiry}] ->
            Now = erlang:system_time(second),
            case Now < Expiry of
                true ->
                    {ok, Token};
                false ->
                    ets:delete(Name, Key),
                    {error, not_found}
            end;
        [] ->
            {error, not_found}
    end.

-doc """
If `Opts` does not already carry a `client_token`, resolve the
configured `token_cache` selector and inject any cached NEW_TOKEN
into `Opts`. Returns `Opts` unchanged on miss or when no cache is
configured.
Accepts the same selector shape as the `connect/3,4` option:
`false` (no cache), an atom naming a started cache, or
`{module, Mod}` for a custom backend exporting `lookup/2`.
""".
-spec maybe_load_token(host(), inet:port_number(), map()) -> map().
maybe_load_token(Host, Port, Opts) ->
    case maps:get(client_token, Opts, undefined) of
        undefined ->
            case resolve_lookup(maps:get(token_cache, Opts, false), Host, Port) of
                {ok, Token} -> Opts#{client_token => Token};
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
Store a NEW_TOKEN under `{Host, Port}` for the cache `Name`.
The optional `TTL` (seconds) bounds how long the cache will hand the
token back; default 24 h. Keep this less-than-or-equal to the
server's `new_token_lifetime` so the cache never serves a token the
server would reject.
""".
-spec store(cache_name(), host(), inet:port_number(), binary()) -> ok.
store(Name, Host, Port, Token) when is_atom(Name), is_binary(Token) ->
    Key = cache_key(Host, Port),
    Expiry = erlang:system_time(second) + ?DEFAULT_TTL,
    true = ets:insert(Name, {Key, Token, Expiry}),
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
) -> {ok, binary()} | {error, not_found}.
resolve_lookup(false, _Host, _Port) ->
    {error, not_found};
resolve_lookup({module, Mod}, Host, Port) ->
    Mod:lookup(Host, Port);
resolve_lookup(Name, Host, Port) when is_atom(Name) ->
    lookup(Name, Host, Port).

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
