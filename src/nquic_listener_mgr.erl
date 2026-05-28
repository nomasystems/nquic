-module(nquic_listener_mgr).
-moduledoc """
Listener manager gen_server.

Holds the mutable state that used to live inside the legacy `nquic_listener`
gen_server: the accept queue, the parked acceptors, the configured listen
options, and the resolved UDP port. Publishes its own pid to the listener's
dispatch table on init so receivers and connections can route the
`connection_established` notification through `nquic_dispatch:get_mgr/1`.

Started as the first child of `nquic_listener_sup` under a `rest_for_one`
strategy, so a crash here cascades into a fresh sub-tree below
(partitions, receivers) instead of leaving stale
references in the dispatch table.
""".
-behaviour(gen_server).

-export([
    accept/2,
    connection_established/2,
    get_dispatch/1,
    get_metrics/1,
    get_port/1,
    get_static_key/1,
    opt/2,
    start_link/1
]).
-export([handle_call/3, handle_cast/2, handle_info/2, init/1, terminate/2]).

-export_type([accept_entry/0]).
-type accept_entry() ::
    {exported, nquic_protocol:state(), nquic_socket:t(), nquic_dispatch:t() | undefined, boolean(),
        pid()}.

-record(state, {
    dispatch :: nquic_dispatch:t(),
    opts :: map(),
    port :: inet:port_number(),
    static_key :: binary(),
    accept_queue = queue:new() :: queue:queue(accept_entry()),
    waiting_acceptors = [] :: [gen_server:from()],
    max_accept_queue = 0 :: non_neg_integer()
}).

%%%-----------------------------------------------------------------------------
%% PUBLIC API
%%%-----------------------------------------------------------------------------
-doc "Accept a new connection, blocking until one is available or timeout expires.".
-spec accept(pid(), timeout()) -> {ok, accept_entry()} | {error, nquic_error:any_reason()}.
accept(Mgr, Timeout) ->
    try
        gen_server:call(Mgr, accept, Timeout)
    catch
        exit:{timeout, _} -> {error, timeout};
        exit:_ -> {error, closed}
    end.

-doc """
Hand a freshly handshaked, proactively exported connection to the
listener manager. The handshake `gen_statem` has already terminated;
`Entry` carries the protocol state, socket, dispatch handle, and the
per-conn-fd flag.
""".
-spec connection_established(pid(), accept_entry()) -> ok.
connection_established(Mgr, Entry) ->
    gen_server:cast(Mgr, {connection_established, Entry}).

-doc "Return the dispatch table for this listener.".
-spec get_dispatch(pid()) -> {ok, nquic_dispatch:t()} | {error, nquic_error:any_reason()}.
get_dispatch(Mgr) ->
    safe_call(Mgr, get_dispatch).

-doc "Return the metrics handle attached to this listener's dispatch table.".
-spec get_metrics(pid()) -> {ok, nquic_metrics:t()} | {error, nquic_error:any_reason()}.
get_metrics(Mgr) ->
    case safe_call(Mgr, get_dispatch) of
        {ok, Dispatch} ->
            case nquic_dispatch:metrics(Dispatch) of
                undefined -> {error, not_found};
                M -> {ok, M}
            end;
        {error, _} = Err ->
            Err
    end.

-doc "Return the UDP port number this listener is bound to.".
-spec get_port(pid()) -> {ok, inet:port_number()} | {error, nquic_error:any_reason()}.
get_port(Mgr) ->
    safe_call(Mgr, get_port).

-doc "Return the listener's static stateless-reset key.".
-spec get_static_key(pid()) -> {ok, binary()} | {error, nquic_error:any_reason()}.
get_static_key(Mgr) ->
    safe_call(Mgr, get_static_key).

-doc "Return a single listener option as seen at startup.".
-spec opt(pid(), atom()) -> {ok, term()} | {error, nquic_error:any_reason()}.
opt(Mgr, Key) when is_atom(Key) ->
    safe_call(Mgr, {opt, Key}).

-doc "Start the listener manager. `Args` carries the dispatch handle and resolved opts.".
-spec start_link(#{dispatch := nquic_dispatch:t(), opts := map()}) ->
    {ok, pid()} | ignore | {error, term()}.
start_link(Args) when is_map(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%%-----------------------------------------------------------------------------
%% GEN_SERVER CALLBACKS
%%%-----------------------------------------------------------------------------
-spec handle_call(term(), gen_server:from(), #state{}) ->
    {reply, term(), #state{}} | {noreply, #state{}}.
handle_call(accept, From, State) ->
    #state{accept_queue = Queue, waiting_acceptors = Waiters} = State,
    case queue:out(Queue) of
        {{value, Entry}, NewQueue} ->
            update_accept_queue_depth(State, NewQueue),
            Entry1 = handoff(Entry, acceptor_pid(From)),
            {reply, {ok, Entry1}, State#state{accept_queue = NewQueue}};
        {empty, NewQueue} ->
            {noreply, State#state{
                accept_queue = NewQueue,
                waiting_acceptors = [From | Waiters]
            }}
    end;
handle_call(get_dispatch, _From, #state{dispatch = D} = State) ->
    {reply, {ok, D}, State};
handle_call(get_port, _From, #state{port = Port} = State) ->
    {reply, {ok, Port}, State};
handle_call(get_static_key, _From, #state{static_key = K} = State) ->
    {reply, {ok, K}, State};
handle_call({opt, Key}, _From, #state{opts = Opts} = State) ->
    case maps:find(Key, Opts) of
        {ok, V} -> {reply, {ok, V}, State};
        error -> {reply, {error, not_found}, State}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

-spec handle_cast(term(), #state{}) -> {noreply, #state{}}.
handle_cast({connection_established, {exported, _, _, _, _, _} = Entry}, State) ->
    #state{
        accept_queue = Queue,
        waiting_acceptors = Waiters,
        max_accept_queue = MaxQ
    } = State,
    bump_metric(State, conns_established),
    case Waiters of
        [] ->
            case MaxQ > 0 andalso queue:len(Queue) >= MaxQ of
                true ->
                    refuse_entry(Entry),
                    {noreply, State};
                false ->
                    NewQueue = queue:in(Entry, Queue),
                    update_accept_queue_depth(State, NewQueue),
                    {noreply, State#state{accept_queue = NewQueue}}
            end;
        [Waiter | Rest] ->
            Entry1 = handoff(Entry, acceptor_pid(Waiter)),
            gen_server:reply(Waiter, {ok, Entry1}),
            {noreply, State#state{waiting_acceptors = Rest}}
    end;
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), #state{}) -> {noreply, #state{}}.
handle_info(_Info, State) ->
    {noreply, State}.

-spec init(map()) -> {ok, #state{}} | {stop, term()}.
init(#{dispatch := Dispatch, opts := Opts}) ->
    nquic_dispatch:set_mgr(Dispatch, self()),
    StaticKey = crypto:strong_rand_bytes(32),
    case resolve_port(maps:get(port, Opts, 4433)) of
        {ok, Port} ->
            MaxQ = maps:get(max_accept_queue, Opts, 0),
            {ok, #state{
                dispatch = Dispatch,
                opts = Opts#{port => Port, static_key => StaticKey},
                port = Port,
                static_key = StaticKey,
                max_accept_queue = MaxQ
            }};
        {error, Reason} ->
            {stop, {port_resolve_failed, Reason}}
    end.

-spec resolve_port(inet:port_number()) ->
    {ok, inet:port_number()} | {error, term()}.
resolve_port(0) ->
    case nquic_socket:open(0, #{reuseport => true}) of
        {ok, Probe} ->
            Result =
                case nquic_socket:port(Probe) of
                    {ok, _} = Ok -> Ok;
                    {error, _} = Err -> Err
                end,
            _ = nquic_socket:close(Probe),
            Result;
        {error, _} = Err ->
            Err
    end;
resolve_port(P) when is_integer(P), P > 0 ->
    {ok, P}.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, _State) ->
    ok.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec acceptor_pid(gen_server:from()) -> pid().
acceptor_pid(From) ->
    element(1, From).

-spec bump_metric(#state{}, nquic_metrics:slot()) -> ok.
bump_metric(#state{dispatch = Dispatch}, Slot) ->
    case nquic_dispatch:metrics(Dispatch) of
        undefined -> ok;
        M -> nquic_metrics:inc(M, Slot)
    end.

-doc """
Hand a queued/just-arrived connection to the accepting process.
Repoints every dispatch entry the handshake process registered (its
SCID, the receiver-registered DCID, any issued CIDs) from the now-dead
handshake pid to the acceptor via the dispatch pid-index, restoring
the proven `export_protocol` reregister-everything behaviour without
enumerating CIDs. A per-conn-fd connected socket (handed to this
manager before the handshake process terminated) is moved to the
acceptor here. Shared-socket connections carry no socket ownership.
""".
-spec handoff(accept_entry(), pid()) -> accept_entry().
handoff({exported, _, Socket, Table, Connected, ConnPid} = Entry, AcceptorPid) ->
    case Table of
        undefined -> ok;
        _ -> ok = nquic_dispatch:reregister(Table, ConnPid, AcceptorPid)
    end,
    _ =
        case Connected of
            true -> nquic_socket:controlling_process(Socket, AcceptorPid);
            false -> ok
        end,
    Entry.

-doc """
Reject a connection that arrived with the accept queue full: send
CONNECTION_CLOSE 0x02, then drop its dispatch registrations so the
receiver stops routing to it.
""".
-spec refuse_entry(accept_entry()) -> ok.
refuse_entry({exported, State, Socket, Table, Connected, _ConnPid}) ->
    Peer = nquic_protocol:peer(State),
    Ctx0 = nquic_ctx:new(State, Socket, Peer, Table),
    Ctx =
        case Connected of
            true -> nquic_ctx:set_connected(Ctx0, true);
            false -> Ctx0
        end,
    ok = nquic_lib:shutdown(Ctx, 16#02, <<"accept queue full">>),
    unregister_dispatch(State, Table).

-spec safe_call(pid(), term()) -> term() | {error, closed | timeout}.
safe_call(Pid, Req) ->
    try
        gen_server:call(Pid, Req)
    catch
        exit:{noproc, _} -> {error, closed};
        exit:{normal, _} -> {error, closed};
        exit:{timeout, _} -> {error, timeout};
        exit:{_, {gen_server, call, _}} -> {error, closed}
    end.

-spec unregister_dispatch(nquic_protocol:state(), nquic_dispatch:t() | undefined) -> ok.
unregister_dispatch(_State, undefined) ->
    ok;
unregister_dispatch(State, Table) ->
    ok = lists:foreach(
        fun(CID) -> nquic_listener:dispatch_unregister(Table, CID) end,
        nquic_protocol:local_cids(State)
    ),
    case nquic_protocol:odcid(State) of
        undefined ->
            ok;
        <<>> ->
            ok;
        ODCID ->
            _ = nquic_listener:dispatch_unregister(Table, ODCID),
            ok
    end.

-spec update_accept_queue_depth(#state{}, queue:queue(accept_entry())) -> ok.
update_accept_queue_depth(#state{dispatch = Dispatch}, Queue) ->
    case nquic_dispatch:metrics(Dispatch) of
        undefined ->
            ok;
        M ->
            Depth = queue:len(Queue),
            Current = nquic_metrics:get(M, accept_queue_depth),
            nquic_metrics:add(M, accept_queue_depth, Depth - Current)
    end.
