-module(nquic_conn_metrics_tests).
-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
%%%-----------------------------------------------------------------------------
%% classify_terminate/2 covers every documented branch
%%%-----------------------------------------------------------------------------

classify_idle_timeout_test() ->
    Data = base(),
    ?assertEqual(
        conns_closed_idle_timeout,
        nquic_conn_metrics:classify_terminate({transport_error, idle_timeout}, Data)
    ).

classify_other_transport_error_test() ->
    Data = base(),
    ?assertEqual(
        conns_closed_protocol_error,
        nquic_conn_metrics:classify_terminate(
            {transport_error, flow_control_error}, Data
        )
    ).

classify_uses_close_kind_peer_test() ->
    Data = (base())#conn_state{close_kind = peer},
    ?assertEqual(
        conns_closed_peer,
        nquic_conn_metrics:classify_terminate(normal, Data)
    ).

classify_uses_close_kind_local_test() ->
    Data = (base())#conn_state{close_kind = local},
    ?assertEqual(
        conns_closed_normal,
        nquic_conn_metrics:classify_terminate(normal, Data)
    ).

classify_uses_close_kind_protocol_error_test() ->
    Data = (base())#conn_state{close_kind = protocol_error},
    ?assertEqual(
        conns_closed_protocol_error,
        nquic_conn_metrics:classify_terminate(normal, Data)
    ).

classify_uses_close_kind_idle_timeout_test() ->
    Data = (base())#conn_state{close_kind = idle_timeout},
    ?assertEqual(
        conns_closed_idle_timeout,
        nquic_conn_metrics:classify_terminate(normal, Data)
    ).

classify_default_unknown_reason_test() ->
    Data = base(),
    ?assertEqual(
        conns_closed_protocol_error,
        nquic_conn_metrics:classify_terminate({some_unknown, oops}, Data)
    ).

classify_shutdown_variants_test() ->
    Data = base(),
    ?assertEqual(conns_closed_normal, nquic_conn_metrics:classify_terminate(shutdown, Data)),
    ?assertEqual(
        conns_closed_normal,
        nquic_conn_metrics:classify_terminate({shutdown, anything}, Data)
    ),
    ?assertEqual(conns_closed_normal, nquic_conn_metrics:classify_terminate(normal, Data)).

%%%-----------------------------------------------------------------------------
%% Lifecycle helpers tolerate undefined / missing metrics
%%%-----------------------------------------------------------------------------

no_metrics_helpers_are_noops_test() ->
    Data = base(),
    ?assertEqual(undefined, nquic_conn_metrics:metrics(Data)),
    ok = nquic_conn_metrics:handshake_started(Data),
    Data1 = nquic_conn_metrics:listener_established(Data),
    ?assertEqual(Data, Data1),
    ok = nquic_conn_metrics:bytes_in(Data, 1500),
    ok = nquic_conn_metrics:bytes_out(Data, 500),
    ok = nquic_conn_metrics:on_terminate(normal, Data).

mark_close_first_write_wins_test() ->
    Data = base(),
    Data1 = nquic_conn_metrics:mark_close(Data, local),
    ?assertEqual(local, Data1#conn_state.close_kind),
    Data2 = nquic_conn_metrics:mark_close(Data1, peer),
    ?assertEqual(local, Data2#conn_state.close_kind),
    Data3 = nquic_conn_metrics:mark_close(Data1, idle_timeout),
    ?assertEqual(local, Data3#conn_state.close_kind).

row_key_prefers_odcid_test() ->
    SCID = <<1, 1, 1, 1>>,
    ODCID = <<9, 9, 9, 9>>,
    Data = (base())#conn_state{scid = SCID, odcid = ODCID},
    ?assertEqual(ODCID, nquic_conn_metrics:row_key(Data)).

row_key_falls_back_to_scid_test() ->
    SCID = <<1, 2, 3, 4>>,
    Data = (base())#conn_state{scid = SCID, odcid = undefined},
    ?assertEqual(SCID, nquic_conn_metrics:row_key(Data)),
    Data2 = (base())#conn_state{scid = SCID, odcid = <<>>},
    ?assertEqual(SCID, nquic_conn_metrics:row_key(Data2)).

%%%-----------------------------------------------------------------------------
%% Lifecycle wired against a real metrics handle (no listener)
%%%-----------------------------------------------------------------------------

listener_established_inserts_row_and_decrements_inflight_test() ->
    Dispatch = nquic_dispatch:new(),
    M = nquic_dispatch:metrics(Dispatch),
    Data = (base())#conn_state{
        dispatch_table = Dispatch,
        odcid = <<"row-key-1">>,
        peer = #{family => inet, addr => {127, 0, 0, 1}, port => 1234}
    },
    ok = nquic_conn_metrics:handshake_started(Data),
    ?assertEqual(1, nquic_metrics:get(M, handshakes_inflight)),
    Data1 = nquic_conn_metrics:listener_established(Data),
    ?assertEqual(0, nquic_metrics:get(M, handshakes_inflight)),
    {ok, Row} = nquic_metrics:lookup_row(M, <<"row-key-1">>),
    ?assertEqual(established, nquic_metrics:row_state(Row)),
    ok = nquic_conn_metrics:bytes_in(Data1, 1200),
    ok = nquic_conn_metrics:bytes_out(Data1, 800),
    Read = nquic_metrics:read_conn_counters(nquic_metrics:row_counters(Row)),
    ?assertEqual(1200, maps:get(bytes_in, Read)),
    ?assertEqual(800, maps:get(bytes_out, Read)),
    ok = nquic_conn_metrics:on_terminate(normal, Data1),
    ?assertEqual({error, not_found}, nquic_metrics:lookup_row(M, <<"row-key-1">>)),
    ?assertEqual(1, nquic_metrics:get(M, conns_closed_normal)),
    nquic_dispatch:destroy(Dispatch).

on_terminate_pre_handshake_decrements_inflight_test() ->
    Dispatch = nquic_dispatch:new(),
    M = nquic_dispatch:metrics(Dispatch),
    Data = (base())#conn_state{
        dispatch_table = Dispatch,
        odcid = <<"row-key-2">>
    },
    ok = nquic_conn_metrics:handshake_started(Data),
    ?assertEqual(1, nquic_metrics:get(M, handshakes_inflight)),
    ok = nquic_conn_metrics:on_terminate(
        {transport_error, flow_control_error}, Data
    ),
    ?assertEqual(0, nquic_metrics:get(M, handshakes_inflight)),
    ?assertEqual(1, nquic_metrics:get(M, conns_closed_protocol_error)),
    nquic_dispatch:destroy(Dispatch).

mark_close_updates_row_state_to_draining_test() ->
    Dispatch = nquic_dispatch:new(),
    M = nquic_dispatch:metrics(Dispatch),
    Data = (base())#conn_state{
        dispatch_table = Dispatch,
        odcid = <<"row-key-3">>
    },
    ok = nquic_conn_metrics:handshake_started(Data),
    Data1 = nquic_conn_metrics:listener_established(Data),
    Data2 = nquic_conn_metrics:mark_close(Data1, peer),
    {ok, Row} = nquic_metrics:lookup_row(M, <<"row-key-3">>),
    ?assertEqual(draining, nquic_metrics:row_state(Row)),
    ok = nquic_conn_metrics:on_terminate(normal, Data2),
    nquic_dispatch:destroy(Dispatch).

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------

base() ->
    #conn_state{
        role = server,
        scid = <<"scid">>,
        dcid = <<"dcid">>,
        loss_state = nquic_loss:init()
    }.
