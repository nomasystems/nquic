-module(nquic_metrics_tests).
-include_lib("eunit/include/eunit.hrl").

%%%-----------------------------------------------------------------------------
%% LISTENER-WIDE COUNTERS
%%%-----------------------------------------------------------------------------

new_snapshot_defaults_zero_test() ->
    M = nquic_metrics:new(),
    Snap = nquic_metrics:snapshot(M),
    ?assertEqual(0, maps:get(packets_in, Snap)),
    ?assertEqual(0, maps:get(packets_dropped_mailbox, Snap)),
    ?assertEqual(0, maps:get(packets_dropped_ratelimit, Snap)),
    ?assertEqual(0, maps:get(conns_established, Snap)),
    ?assertEqual(0, maps:get(conns_closed_normal, Snap)),
    ?assertEqual(0, maps:get(conns_closed_idle_timeout, Snap)),
    ?assertEqual(0, maps:get(conns_closed_peer, Snap)),
    ?assertEqual(0, maps:get(conns_closed_protocol_error, Snap)),
    ?assertEqual(0, maps:get(handshakes_inflight, Snap)),
    ?assertEqual(0, maps:get(accept_queue_depth, Snap)),
    ?assert(maps:get(uptime_ms, Snap) >= 0),
    ok = nquic_metrics:destroy(M).

inc_and_add_visible_in_snapshot_test() ->
    M = nquic_metrics:new(),
    ok = nquic_metrics:inc(M, packets_in),
    ok = nquic_metrics:inc(M, packets_in),
    ok = nquic_metrics:add(M, packets_in, 8),
    ok = nquic_metrics:inc(M, conns_established),
    Snap = nquic_metrics:snapshot(M),
    ?assertEqual(10, maps:get(packets_in, Snap)),
    ?assertEqual(1, maps:get(conns_established, Snap)),
    ok = nquic_metrics:destroy(M).

handshakes_inflight_can_decrement_test() ->
    M = nquic_metrics:new(),
    ok = nquic_metrics:inc(M, handshakes_inflight),
    ok = nquic_metrics:inc(M, handshakes_inflight),
    ok = nquic_metrics:add(M, handshakes_inflight, -1),
    ?assertEqual(1, nquic_metrics:get(M, handshakes_inflight)),
    ok = nquic_metrics:destroy(M).

accept_queue_depth_can_track_negative_delta_test() ->
    M = nquic_metrics:new(),
    ok = nquic_metrics:add(M, accept_queue_depth, 5),
    ok = nquic_metrics:add(M, accept_queue_depth, -2),
    ?assertEqual(3, nquic_metrics:get(M, accept_queue_depth)),
    ok = nquic_metrics:destroy(M).

destroy_drops_info_table_test() ->
    M = nquic_metrics:new(),
    T = nquic_metrics:info_table(M),
    ?assert(is_reference(T) orelse is_atom(T) orelse is_integer(T)),
    ?assertNotEqual(undefined, ets:info(T)),
    ok = nquic_metrics:destroy(M),
    ?assertEqual(undefined, ets:info(T)).

%%%-----------------------------------------------------------------------------
%% PER-CONN INFO ROWS
%%%-----------------------------------------------------------------------------

insert_lookup_delete_row_test() ->
    M = nquic_metrics:new(),
    DCID = <<1, 2, 3, 4>>,
    Row = nquic_metrics:new_row(DCID, self(), undefined, established),
    true = nquic_metrics:insert_row(M, Row),
    {ok, Looked} = nquic_metrics:lookup_row(M, DCID),
    ?assertEqual(DCID, nquic_metrics:row_dcid(Looked)),
    ?assertEqual(self(), nquic_metrics:row_pid(Looked)),
    ?assertEqual(established, nquic_metrics:row_state(Looked)),
    [Single] = nquic_metrics:list_rows(M),
    ?assertEqual(DCID, nquic_metrics:row_dcid(Single)),
    ok = nquic_metrics:delete_row(M, DCID),
    ?assertEqual({error, not_found}, nquic_metrics:lookup_row(M, DCID)),
    ?assertEqual([], nquic_metrics:list_rows(M)),
    ok = nquic_metrics:destroy(M).

update_state_test() ->
    M = nquic_metrics:new(),
    DCID = <<7, 7, 7, 7>>,
    Row = nquic_metrics:new_row(DCID, self(), undefined, established),
    true = nquic_metrics:insert_row(M, Row),
    ok = nquic_metrics:update_state(M, DCID, draining),
    {ok, Updated} = nquic_metrics:lookup_row(M, DCID),
    ?assertEqual(draining, nquic_metrics:row_state(Updated)),
    ok = nquic_metrics:update_state(M, <<"unknown">>, draining),
    ok = nquic_metrics:destroy(M).

conn_counters_bump_and_read_test() ->
    C = nquic_metrics:new_conn_counters(),
    ok = nquic_metrics:inc_bytes_in(C, 1200),
    ok = nquic_metrics:inc_bytes_in(C, 300),
    ok = nquic_metrics:inc_bytes_out(C, 700),
    ok = nquic_metrics:touch_last_packet(C, 5_000_000),
    Read = nquic_metrics:read_conn_counters(C),
    ?assertEqual(1500, maps:get(bytes_in, Read)),
    ?assertEqual(700, maps:get(bytes_out, Read)),
    ?assertEqual(5_000_000, maps:get(last_packet_us, Read)),
    ?assertEqual(0, maps:get(dropped_in, Read)).

%%%-----------------------------------------------------------------------------
%% RCVBUF SAMPLING
%%%-----------------------------------------------------------------------------

rcvbuf_errs_baseline_is_consistent_test() ->
    M1 = nquic_metrics:new(),
    M2 = nquic_metrics:new(),
    ?assert(nquic_metrics:rcvbuf_errs(M1) >= 0),
    ?assert(nquic_metrics:rcvbuf_errs(M2) >= 0),
    Snap = nquic_metrics:snapshot(M1),
    ?assertEqual(nquic_metrics:rcvbuf_errs(M1), maps:get(udp_rcvbuf_errs, Snap)),
    ok = nquic_metrics:destroy(M1),
    ok = nquic_metrics:destroy(M2).
