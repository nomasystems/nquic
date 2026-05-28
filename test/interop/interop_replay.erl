-module(interop_replay).
-moduledoc """
Test-only 0-RTT replay-protection callback for the interop endpoint.

Implements `nquic_zero_rtt:check/2` with the simplest correct
behaviour: accept any PSK identity exactly once, reject every
subsequent acceptance of the same identity. State lives in a single
named ETS table so the module is self-contained and the interop
endpoint does not need a supervision tree just to run the zerortt
testcase.

This is **not** production-grade. A real deployment must couple the
replay window to the ticket lifetime, persist state across nodes that
might serve the same PSK identity, and use constant-time lookups.
""".

-behaviour(nquic_zero_rtt).

-export([check/2, ensure_table/0, reset/0]).

-define(TABLE, ?MODULE).

-spec check(binary(), nquic_socket:sockaddr()) -> accept | reject.
check(Identity, _Peer) when is_binary(Identity) ->
    ensure_table(),
    case ets:insert_new(?TABLE, {Identity, erlang:system_time(second)}) of
        true -> accept;
        false -> reject
    end.

-spec ensure_table() -> ok.
ensure_table() ->
    case ets:whereis(?TABLE) of
        undefined ->
            try
                ?TABLE = ets:new(?TABLE, [named_table, public, set, {read_concurrency, true}]),
                ok
            catch
                error:badarg ->
                    ok
            end;
        _ ->
            ok
    end.

-spec reset() -> ok.
reset() ->
    case ets:whereis(?TABLE) of
        undefined ->
            ok;
        _ ->
            true = ets:delete_all_objects(?TABLE),
            ok
    end.
