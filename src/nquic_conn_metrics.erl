-module(nquic_conn_metrics).
-moduledoc """
Per-connection bridge between `#conn_state{}` and `nquic_metrics`.

Lives at the boundary between the connection state machine and the
listener-wide observability primitives so callers do not have to thread
the metrics handle through every state transition.

All functions are no-ops when:

* the connection has no `dispatch_table` (client-mode conns without a
  listener), or
* the listener was started before the metrics primitives existed and
  the dispatch has no metrics handle attached, or
* the row has not been opened yet (`metrics_counters` is `undefined`).
""".

-include("nquic_conn.hrl").
-export([
    bytes_in/2,
    bytes_out/2,
    classify_terminate/2,
    handshake_started/1,
    listener_established/1,
    mark_close/2,
    metrics/1,
    on_terminate/2,
    row_key/1
]).

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc "Add `N` bytes to the row's lifetime `bytes_in` counter.".
-spec bytes_in(#conn_state{}, non_neg_integer()) -> ok.
bytes_in(_Data, 0) ->
    ok;
bytes_in(#conn_state{metrics_counters = undefined}, _N) ->
    ok;
bytes_in(#conn_state{metrics_counters = C}, N) when N > 0 ->
    nquic_metrics:inc_bytes_in(C, N),
    nquic_metrics:touch_last_packet(C, erlang:monotonic_time(microsecond)),
    ok.

-doc "Add `N` bytes to the row's lifetime `bytes_out` counter.".
-spec bytes_out(#conn_state{}, non_neg_integer()) -> ok.
bytes_out(_Data, 0) ->
    ok;
bytes_out(#conn_state{metrics_counters = undefined}, _N) ->
    ok;
bytes_out(#conn_state{metrics_counters = C}, N) when N > 0 ->
    nquic_metrics:inc_bytes_out(C, N),
    ok.

-doc """
Pick the `conns_closed_*` counter for `Reason`.
Prefers an explicit `close_kind` set by the draining entry points; falls
back to inspecting the gen_statem terminate reason. `idle_timeout` is
preferred over `protocol_error` even when both apply because the operator
view of an idle close is more useful than the generic transport error.
""".
-spec classify_terminate(term(), #conn_state{}) -> nquic_metrics:slot().
classify_terminate({transport_error, idle_timeout}, _Data) ->
    conns_closed_idle_timeout;
classify_terminate({transport_error, _}, _Data) ->
    conns_closed_protocol_error;
classify_terminate(_Reason, #conn_state{close_kind = peer}) ->
    conns_closed_peer;
classify_terminate(_Reason, #conn_state{close_kind = local}) ->
    conns_closed_normal;
classify_terminate(_Reason, #conn_state{close_kind = idle_timeout}) ->
    conns_closed_idle_timeout;
classify_terminate(_Reason, #conn_state{close_kind = protocol_error}) ->
    conns_closed_protocol_error;
classify_terminate(normal, _Data) ->
    conns_closed_normal;
classify_terminate(shutdown, _Data) ->
    conns_closed_normal;
classify_terminate({shutdown, _}, _Data) ->
    conns_closed_normal;
classify_terminate(_Reason, _Data) ->
    conns_closed_protocol_error.

-doc """
Bump the listener-wide `handshakes_inflight` counter on conn-statem
init. Pair with `on_terminate/2` or `listener_established/1` which
decrement.
""".
-spec handshake_started(#conn_state{}) -> ok.
handshake_started(Data) ->
    case metrics(Data) of
        undefined -> ok;
        M -> nquic_metrics:inc(M, handshakes_inflight)
    end.

-doc """
Insert the info-table row and prime `metrics_counters`.
Called from
`nquic_conn_events:deliver_protocol_event(listener_established, _)` on
the server side after the handshake completes. Decrements
`handshakes_inflight` as the same call site since the handshake is done.
""".
-spec listener_established(#conn_state{}) -> #conn_state{}.
listener_established(#conn_state{} = Data) ->
    case metrics(Data) of
        undefined ->
            Data;
        M ->
            DCID = row_key(Data),
            Row = nquic_metrics:new_row(DCID, self(), Data#conn_state.peer, established),
            true = nquic_metrics:insert_row(M, Row),
            nquic_metrics:add(M, handshakes_inflight, -1),
            Data#conn_state{metrics_counters = nquic_metrics:row_counters(Row)}
    end.

-doc """
Record the originating cause for an upcoming draining/terminate
transition. Stored on `#conn_state.close_kind` for
`classify_terminate/2`.
""".
-spec mark_close(#conn_state{}, local | peer | idle_timeout | protocol_error) ->
    #conn_state{}.
mark_close(#conn_state{close_kind = undefined} = Data, Kind) ->
    case metrics(Data) of
        undefined -> ok;
        M -> nquic_metrics:update_state(M, row_key(Data), draining)
    end,
    Data#conn_state{close_kind = Kind};
mark_close(Data, _Kind) ->
    Data.

-doc "Return the `nquic_metrics` handle reachable from this conn, or `undefined`.".
-spec metrics(#conn_state{}) -> nquic_metrics:t() | undefined.
metrics(#conn_state{dispatch_table = undefined}) ->
    undefined;
metrics(#conn_state{dispatch_table = T}) ->
    nquic_dispatch:metrics(T).

-doc """
Bump the appropriate `conns_closed_*` counter, decrement
`handshakes_inflight` when the conn died before reaching established,
and remove the info-table row.
Idempotent: missing rows and `undefined` counters are no-ops.
""".
-spec on_terminate(term(), #conn_state{}) -> ok.
on_terminate(Reason, Data) ->
    case metrics(Data) of
        undefined ->
            ok;
        M ->
            Slot = classify_terminate(Reason, Data),
            nquic_metrics:inc(M, Slot),
            case Data#conn_state.metrics_counters of
                undefined ->
                    nquic_metrics:add(M, handshakes_inflight, -1);
                _ ->
                    ok
            end,
            nquic_metrics:delete_row(M, row_key(Data)),
            ok
    end.

-doc """
Pick the DCID used as the info-table key for this connection. Prefers
the original DCID (set by the listener when the conn was created) and
falls back to the local SCID for client-side conns.
""".
-spec row_key(#conn_state{}) -> binary().
row_key(#conn_state{odcid = ODCID}) when is_binary(ODCID), byte_size(ODCID) > 0 ->
    ODCID;
row_key(#conn_state{scid = SCID}) ->
    SCID.
