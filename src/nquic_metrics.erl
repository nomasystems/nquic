-module(nquic_metrics).
-moduledoc """
Per-listener observability primitives.

Owns one `atomics` ref for listener-wide counters (packets, conns,
handshakes, accept queue depth, ...) and one ETS table that holds a row
per tracked connection. Both are allocated by `new/0` when the listener's
dispatch table is built and destroyed on listener shutdown.

Counter increments are inline `atomics:add/3` calls (~10ns) so the hot
receive path stays cheap. The per-conn rows track identity, peer, and
lifecycle state for internal lookup; they are written on handshake
completion, state change, and connection termination.

Per-connection lifetime byte counters live in a smaller atomics ref
attached to the row, so the conn-statem can bump `bytes_in` /
`bytes_out` without rewriting the row.
""".

-export([
    add/3,
    destroy/1,
    get/2,
    inc/2,
    new/0,
    rcvbuf_errs/1,
    snapshot/1
]).

-export([
    delete_row/2,
    info_table/1,
    insert_row/2,
    list_rows/1,
    lookup_row/2,
    new_row/4,
    row_counters/1,
    row_dcid/1,
    row_pid/1,
    row_state/1,
    update_state/3
]).

-export([
    inc_bytes_in/2,
    inc_bytes_out/2,
    new_conn_counters/0,
    read_conn_counters/1,
    touch_last_packet/2
]).

-export_type([conn_counters/0, conn_row/0, t/0, slot/0]).

-type slot() ::
    packets_in
    | packets_dropped_mailbox
    | packets_dropped_ratelimit
    | conns_established
    | conns_closed_normal
    | conns_closed_idle_timeout
    | conns_closed_peer
    | conns_closed_protocol_error
    | handshakes_inflight
    | accept_queue_depth.

-define(SLOT_PACKETS_IN, 1).
-define(SLOT_PACKETS_DROPPED_MAILBOX, 2).
-define(SLOT_PACKETS_DROPPED_RATELIMIT, 3).
-define(SLOT_CONNS_ESTABLISHED, 4).
-define(SLOT_CONNS_CLOSED_NORMAL, 5).
-define(SLOT_CONNS_CLOSED_IDLE_TIMEOUT, 6).
-define(SLOT_CONNS_CLOSED_PEER, 7).
-define(SLOT_CONNS_CLOSED_PROTOCOL_ERROR, 8).
-define(SLOT_HANDSHAKES_INFLIGHT, 9).
-define(SLOT_ACCEPT_QUEUE_DEPTH, 10).
-define(N_SLOTS, 10).

-define(C_BYTES_IN, 1).
-define(C_BYTES_OUT, 2).
-define(C_LAST_PACKET_US, 3).
-define(C_DROPPED_IN, 4).
-define(N_CONN_SLOTS, 4).
-record(metrics, {
    counters :: atomics:atomics_ref(),
    info_table :: ets:tid(),
    start_monotonic_us :: integer(),
    rcvbuf_baseline :: non_neg_integer()
}).

-record(conn_row, {
    dcid :: binary(),
    pid :: pid(),
    peer :: nquic_socket:sockaddr() | undefined,
    state :: handshake | established | draining,
    counters :: conn_counters()
}).

-record(conn_counters, {
    ref :: atomics:atomics_ref()
}).

-type t() :: #metrics{}.
-type conn_counters() :: #conn_counters{}.
-type conn_row() :: #conn_row{}.

%%%-----------------------------------------------------------------------------
%% LISTENER-WIDE COUNTERS
%%%-----------------------------------------------------------------------------
-doc "Add `Delta` to the named counter.".
-spec add(t(), slot(), integer()) -> ok.
add(#metrics{counters = Ref}, Slot, Delta) ->
    atomics:add(Ref, slot_index(Slot), Delta),
    ok.

-doc "Destroy the info ETS table. The atomics ref is GC'd with the metrics record.".
-spec destroy(t()) -> ok.
destroy(#metrics{info_table = T}) ->
    ets:delete(T),
    ok.

-doc "Read a single counter value.".
-spec get(t(), slot()) -> integer().
get(#metrics{counters = Ref}, Slot) ->
    atomics:get(Ref, slot_index(Slot)).

-doc "Increment the named counter by 1.".
-spec inc(t(), slot()) -> ok.
inc(M, Slot) ->
    add(M, Slot, 1).

-doc "Allocate a fresh metrics handle (atomics ref + info ETS table).".
-spec new() -> t().
new() ->
    Ref = atomics:new(?N_SLOTS, [{signed, true}]),
    Tab = ets:new(nquic_metrics_info, [
        set,
        public,
        {keypos, #conn_row.dcid},
        {read_concurrency, true},
        {write_concurrency, true},
        {decentralized_counters, true}
    ]),
    #metrics{
        counters = Ref,
        info_table = Tab,
        start_monotonic_us = erlang:monotonic_time(microsecond),
        rcvbuf_baseline = sample_rcvbuf_errs()
    }.

-doc """
Return the current `InErrors` delta vs the baseline taken at listener
start. On non-Linux (no `/proc/net/snmp`) returns 0.
""".
-spec rcvbuf_errs(t()) -> non_neg_integer().
rcvbuf_errs(#metrics{rcvbuf_baseline = Base}) ->
    case sample_rcvbuf_errs() of
        Now when Now >= Base -> Now - Base;
        _ -> 0
    end.

-doc """
Return a snapshot of every counter plus `uptime_ms` and
`udp_rcvbuf_errs`.
""".
-spec snapshot(t()) -> #{atom() => integer()}.
snapshot(#metrics{counters = Ref, start_monotonic_us = T0} = M) ->
    UptimeMs = (erlang:monotonic_time(microsecond) - T0) div 1000,
    #{
        packets_in => atomics:get(Ref, ?SLOT_PACKETS_IN),
        packets_dropped_mailbox => atomics:get(Ref, ?SLOT_PACKETS_DROPPED_MAILBOX),
        packets_dropped_ratelimit => atomics:get(Ref, ?SLOT_PACKETS_DROPPED_RATELIMIT),
        conns_established => atomics:get(Ref, ?SLOT_CONNS_ESTABLISHED),
        conns_closed_normal => atomics:get(Ref, ?SLOT_CONNS_CLOSED_NORMAL),
        conns_closed_idle_timeout => atomics:get(Ref, ?SLOT_CONNS_CLOSED_IDLE_TIMEOUT),
        conns_closed_peer => atomics:get(Ref, ?SLOT_CONNS_CLOSED_PEER),
        conns_closed_protocol_error => atomics:get(Ref, ?SLOT_CONNS_CLOSED_PROTOCOL_ERROR),
        handshakes_inflight => atomics:get(Ref, ?SLOT_HANDSHAKES_INFLIGHT),
        accept_queue_depth => atomics:get(Ref, ?SLOT_ACCEPT_QUEUE_DEPTH),
        udp_rcvbuf_errs => rcvbuf_errs(M),
        uptime_ms => UptimeMs
    }.

%%%-----------------------------------------------------------------------------
%% PER-CONN INFO TABLE
%%%-----------------------------------------------------------------------------
-doc "Delete the row keyed by DCID. No-op if absent.".
-spec delete_row(t(), binary()) -> ok.
delete_row(#metrics{info_table = T}, DCID) ->
    ets:delete(T, DCID),
    ok.

-doc "Return the ETS tid for the info table (testing / advanced callers).".
-spec info_table(t()) -> ets:tid().
info_table(#metrics{info_table = T}) ->
    T.

-doc """
Insert (or replace) a row. Used on handshake completion and when peer
identity changes mid-connection.
""".
-spec insert_row(t(), conn_row()) -> true.
insert_row(#metrics{info_table = T}, #conn_row{} = Row) ->
    ets:insert(T, Row).

-doc "Return every row currently in the table.".
-spec list_rows(t()) -> [conn_row()].
list_rows(#metrics{info_table = T}) ->
    ets:tab2list(T).

-doc "Look up a single row by DCID.".
-spec lookup_row(t(), binary()) -> {ok, conn_row()} | {error, not_found}.
lookup_row(#metrics{info_table = T}, DCID) ->
    case ets:lookup(T, DCID) of
        [#conn_row{} = Row] -> {ok, Row};
        [] -> {error, not_found}
    end.

-doc "Build a fresh row with the given identity and a new counters block.".
-spec new_row(
    binary(),
    pid(),
    nquic_socket:sockaddr() | undefined,
    handshake | established | draining
) -> conn_row().
new_row(DCID, Pid, Peer, State) ->
    #conn_row{
        dcid = DCID,
        pid = Pid,
        peer = Peer,
        state = State,
        counters = new_conn_counters()
    }.

-doc "Return the row's lifetime counters block.".
-spec row_counters(conn_row()) -> conn_counters().
row_counters(#conn_row{counters = C}) -> C.

-doc "Return the row's initial DCID (the key).".
-spec row_dcid(conn_row()) -> binary().
row_dcid(#conn_row{dcid = D}) -> D.

-doc "Return the row's owning conn pid.".
-spec row_pid(conn_row()) -> pid().
row_pid(#conn_row{pid = P}) -> P.

-doc "Return the row's lifecycle state.".
-spec row_state(conn_row()) -> handshake | established | draining.
row_state(#conn_row{state = S}) -> S.

-doc "Update the lifecycle state field of an existing row.".
-spec update_state(t(), binary(), handshake | established | draining) -> ok.
update_state(#metrics{info_table = T}, DCID, State) when
    State =:= handshake; State =:= established; State =:= draining
->
    _ = ets:update_element(T, DCID, {#conn_row.state, State}),
    ok.

%%%-----------------------------------------------------------------------------
%% PER-CONN LIFETIME COUNTERS
%%%-----------------------------------------------------------------------------
-doc "Add `N` to the row's lifetime `bytes_in` total.".
-spec inc_bytes_in(conn_counters(), non_neg_integer()) -> ok.
inc_bytes_in(#conn_counters{ref = Ref}, N) when N >= 0 ->
    atomics:add(Ref, ?C_BYTES_IN, N),
    ok.

-doc "Add `N` to the row's lifetime `bytes_out` total.".
-spec inc_bytes_out(conn_counters(), non_neg_integer()) -> ok.
inc_bytes_out(#conn_counters{ref = Ref}, N) when N >= 0 ->
    atomics:add(Ref, ?C_BYTES_OUT, N),
    ok.

-doc "Allocate a fresh per-conn counters block.".
-spec new_conn_counters() -> conn_counters().
new_conn_counters() ->
    Ref = atomics:new(?N_CONN_SLOTS, [{signed, true}]),
    atomics:put(Ref, ?C_LAST_PACKET_US, erlang:monotonic_time(microsecond)),
    #conn_counters{ref = Ref}.

-doc "Read the full per-conn counters block as a map.".
-spec read_conn_counters(conn_counters()) -> #{atom() => integer()}.
read_conn_counters(#conn_counters{ref = Ref}) ->
    #{
        bytes_in => atomics:get(Ref, ?C_BYTES_IN),
        bytes_out => atomics:get(Ref, ?C_BYTES_OUT),
        last_packet_us => atomics:get(Ref, ?C_LAST_PACKET_US),
        dropped_in => atomics:get(Ref, ?C_DROPPED_IN)
    }.

-doc "Record `TsUs` (monotonic microseconds) as the last-packet timestamp.".
-spec touch_last_packet(conn_counters(), integer()) -> ok.
touch_last_packet(#conn_counters{ref = Ref}, TsUs) ->
    atomics:put(Ref, ?C_LAST_PACKET_US, TsUs),
    ok.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec binary_to_integer_safe(binary()) -> non_neg_integer().
binary_to_integer_safe(Bin) ->
    try binary_to_integer(Bin) of
        N when N >= 0 -> N;
        _ -> 0
    catch
        error:badarg -> 0
    end.

-spec index_of(binary(), [binary()], pos_integer()) -> pos_integer() | not_found.
index_of(_Needle, [], _Ix) ->
    not_found;
index_of(Needle, [Needle | _], Ix) ->
    Ix;
index_of(Needle, [_ | Rest], Ix) ->
    index_of(Needle, Rest, Ix + 1).

-spec nth_field(pos_integer(), [binary()]) -> binary() | undefined.
nth_field(_Ix, []) ->
    undefined;
nth_field(1, [V | _]) ->
    V;
nth_field(N, [_ | Rest]) ->
    nth_field(N - 1, Rest).

-spec parse_rcvbuf_errs(binary()) -> non_neg_integer().
parse_rcvbuf_errs(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    parse_rcvbuf_errs_lines(Lines, undefined).

-spec parse_rcvbuf_errs_lines([binary()], undefined | pos_integer()) ->
    non_neg_integer().
parse_rcvbuf_errs_lines([], _) ->
    0;
parse_rcvbuf_errs_lines([<<"Udp:", Rest/binary>> | Tail], undefined) ->
    Fields = binary:split(Rest, <<" ">>, [global, trim_all]),
    case index_of(<<"InErrors">>, Fields, 1) of
        not_found -> parse_rcvbuf_errs_lines(Tail, undefined);
        Idx -> parse_rcvbuf_errs_lines(Tail, Idx)
    end;
parse_rcvbuf_errs_lines([<<"Udp:", Rest/binary>> | _], Idx) ->
    Values = binary:split(Rest, <<" ">>, [global, trim_all]),
    case nth_field(Idx, Values) of
        undefined -> 0;
        Bin -> binary_to_integer_safe(Bin)
    end;
parse_rcvbuf_errs_lines([_ | Tail], Acc) ->
    parse_rcvbuf_errs_lines(Tail, Acc).

-spec sample_rcvbuf_errs() -> non_neg_integer().
sample_rcvbuf_errs() ->
    case file:read_file("/proc/net/snmp") of
        {ok, Bin} -> parse_rcvbuf_errs(Bin);
        {error, _} -> 0
    end.

-spec slot_index(slot()) -> pos_integer().
slot_index(packets_in) -> ?SLOT_PACKETS_IN;
slot_index(packets_dropped_mailbox) -> ?SLOT_PACKETS_DROPPED_MAILBOX;
slot_index(packets_dropped_ratelimit) -> ?SLOT_PACKETS_DROPPED_RATELIMIT;
slot_index(conns_established) -> ?SLOT_CONNS_ESTABLISHED;
slot_index(conns_closed_normal) -> ?SLOT_CONNS_CLOSED_NORMAL;
slot_index(conns_closed_idle_timeout) -> ?SLOT_CONNS_CLOSED_IDLE_TIMEOUT;
slot_index(conns_closed_peer) -> ?SLOT_CONNS_CLOSED_PEER;
slot_index(conns_closed_protocol_error) -> ?SLOT_CONNS_CLOSED_PROTOCOL_ERROR;
slot_index(handshakes_inflight) -> ?SLOT_HANDSHAKES_INFLIGHT;
slot_index(accept_queue_depth) -> ?SLOT_ACCEPT_QUEUE_DEPTH.
