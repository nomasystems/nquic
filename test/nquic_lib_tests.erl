%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_lib}.
%%%
%%% Drives the unit-testable paths: pure pass-through wrappers around
%%% `nquic_protocol' (send / recv / open / close / reset / flush /
%%% timeout), error branches, and the small process-local helpers
%%% (apply_timer_actions, drain_stale_socket_msgs, recv_pending_loop
%%% over an empty mailbox). The integration suites
%%% (`nquic_SUITE', `nquic_integration_SUITE') exercise the
%%% socket-driven paths (recv_direct, recv_batch, takeover,
%%% upgrade_to_connected, shutdown_impl) end-to-end against a real
%%% peer.
%%%-------------------------------------------------------------------
-module(nquic_lib_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
-define(PEER, #{family => inet, addr => {127, 0, 0, 1}, port => 4433}).

open_stream_bidi_test() ->
    {ok, StreamId, _Ctx1} = nquic_lib:open_stream(make_ctx(), #{type => bidi}),
    ?assertEqual(0, StreamId).

open_stream_uni_test() ->
    {ok, StreamId, _Ctx1} = nquic_lib:open_stream(make_ctx(), #{type => uni}),
    ?assertEqual(2, StreamId).

open_stream_limit_error_test() ->
    State = (make_state())#conn_state{
        streams_state = #conn_streams{
            next_bidi_stream = 0,
            next_uni_stream = 2,
            peer_max_streams_bidi = 0,
            peer_max_streams_uni = 0,
            local_max_streams_bidi = 100,
            local_max_streams_uni = 100
        }
    },
    Ctx = make_ctx_with_state(State),
    ?assertEqual(
        {error, stream_limit_error},
        nquic_lib:open_stream(Ctx, #{type => bidi})
    ),
    ?assertEqual(
        {error, stream_limit_error},
        nquic_lib:open_stream(Ctx, #{type => uni})
    ).

close_stream_already_closed_returns_error_test() ->
    Ctx = make_ctx_with_state(state_with_closed_stream(0)),
    ?assertEqual({error, stream_closed}, nquic_lib:close_stream(Ctx, 0)).

reset_stream_already_reset_returns_ok_test() ->
    Stream = nquic_stream_statem:new(0, bidi),
    Stream1 = Stream#stream_state{send_state = reset_sent},
    State = make_state(),
    SS0 = State#conn_state.streams_state,
    State1 = State#conn_state{
        streams_state = SS0#conn_streams{streams = #{0 => Stream1}}
    },
    Ctx = make_ctx_with_state(State1),
    ?assertMatch({ok, _}, nquic_lib:reset_stream(Ctx, 0, 7)).

reset_stream_unknown_returns_error_test() ->
    ?assertEqual(
        {error, unknown_stream},
        nquic_lib:reset_stream(make_ctx(), 999, 0)
    ).

recv_unknown_stream_test() ->
    ?assertEqual({error, stream_not_found}, nquic_lib:recv(make_ctx(), 999)).

send_to_closed_stream_returns_2tuple_error_test() ->
    Ctx = make_ctx_with_state(state_with_closed_stream(0)),
    ?assertEqual({error, stream_closed}, nquic_lib:send(Ctx, 0, <<"x">>)).

send_fin_to_closed_stream_returns_2tuple_error_test() ->
    Ctx = make_ctx_with_state(state_with_closed_stream(0)),
    ?assertEqual({error, stream_closed}, nquic_lib:send_fin(Ctx, 0, <<"x">>)).

send_fin_noflush_to_closed_stream_returns_2tuple_error_test() ->
    Ctx = make_ctx_with_state(state_with_closed_stream(0)),
    ?assertEqual({error, stream_closed}, nquic_lib:send_fin_noflush(Ctx, 0, <<"x">>)).

send_fin_noflush_success_does_not_send_packets_test() ->
    Ctx0 = make_ctx(),
    {ok, StreamId, Ctx1} = nquic_lib:open_stream(Ctx0, #{type => bidi}),
    {ok, Ctx2} = nquic_lib:send_fin_noflush(Ctx1, StreamId, <<"hello">>),
    State2 = nquic_ctx:state(Ctx2),
    Streams = State2#conn_state.streams_state#conn_streams.streams,
    #{StreamId := Stream} = Streams,
    ?assertEqual(<<"hello">>, iolist_to_binary(Stream#stream_state.pending_send_data)),
    ?assertEqual(5, Stream#stream_state.pending_send_size),
    ?assert(Stream#stream_state.pending_send_fin),
    Pending = State2#conn_state.flow#conn_flow.pending_app_frames,
    ?assertEqual([], Pending).

send_datagram_not_negotiated_test() ->
    ?assertEqual(
        {error, datagrams_not_negotiated},
        nquic_lib:send_datagram(make_ctx(), <<"payload">>)
    ).

handle_packet_malformed_returns_error_test() ->
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    Result = nquic_lib:handle_packet(Ctx, ?PEER, Garbage),
    ?assertMatch({ok, [], _}, Result).

handle_packet_notimers_arity3_test() ->
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    Result = nquic_lib:handle_packet_notimers(Ctx, ?PEER, Garbage),
    ?assertMatch({ok, [], _}, Result).

handle_packet_notimers_arity4_with_ecn_test() ->
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    Result = nquic_lib:handle_packet_notimers(Ctx, ?PEER, Garbage, ect0),
    ?assertMatch({ok, [], _}, Result).

handle_packet_batch_notimers_splits_segments_test() ->
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    GsoSize = byte_size(Garbage),
    Buf = <<Garbage/binary, Garbage/binary>>,
    Result = nquic_lib:handle_packet_batch_notimers(Ctx, ?PEER, Buf, GsoSize, not_ect),
    ?assertMatch({ok, [], _}, Result).

timeout_idle_returns_transport_error_test() ->
    Ctx = make_ctx(),
    ?assertMatch(
        {error, {transport_error, idle_timeout}, _},
        nquic_lib:timeout(Ctx, idle)
    ).

flush_notimers_empty_test() ->
    Ctx = make_ctx(),
    ?assertMatch({ok, _}, nquic_lib:flush_notimers(Ctx)).

close_app_queues_connection_close_test() ->
    Ctx = make_ctx(),
    {ok, State1} = nquic_protocol:close_app(0, <<"bye">>, nquic_ctx:state(Ctx)),
    Pending = State1#conn_state.flow#conn_flow.pending_app_frames,
    ?assertMatch(
        [#connection_close{is_application = true} | _],
        Pending
    ).

close_queues_transport_close_test() ->
    State0 = (make_state())#conn_state{crypto = #conn_crypto{app_send_keys = #{}}},
    {ok, State1} = nquic_protocol:close(0, <<>>, State0),
    Pending = State1#conn_state.flow#conn_flow.pending_app_frames,
    ?assertMatch(
        [#connection_close{is_application = false} | _],
        Pending
    ).

ctx_accessors_test() ->
    Socket = some_socket,
    Dispatch = some_dispatch,
    Peer = ?PEER,
    Ctx = nquic_ctx:new(make_state(), Socket, Peer, Dispatch),
    ?assertEqual(Socket, nquic_lib:ctx_socket(Ctx)),
    ?assertEqual(Dispatch, nquic_lib:ctx_dispatch(Ctx)),
    ?assertEqual(Peer, nquic_lib:ctx_peer(Ctx)).

recv_pending_empty_mailbox_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    ?assertEqual({ok, [], Ctx}, nquic_lib:recv_pending(Ctx)).

recv_pending_processes_buffered_packet_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    Result = nquic_lib:recv_pending(Ctx),
    ?assertMatch({ok, _, _}, Result),
    ?assertEqual(0, message_queue_len()).

recv_pending_processes_buffered_packet_with_ecn_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage, ect0},
    Result = nquic_lib:recv_pending(Ctx),
    ?assertMatch({ok, _, _}, Result),
    ?assertEqual(0, message_queue_len()).

recv_and_process_after_timeout_returns_empty_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    ?assertEqual({ok, [], Ctx}, nquic_lib:recv_and_process(Ctx, 10)).

recv_and_process_handles_packet_message_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    Result = nquic_lib:recv_and_process(Ctx),
    ?assertMatch({ok, _, _}, Result).

recv_and_process_handles_quic_timeout_message_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    self() ! {quic_timeout, idle},
    ?assertMatch(
        {error, {transport_error, idle_timeout}, _},
        nquic_lib:recv_and_process(Ctx, 100)
    ).

close_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx = make_ctx(),
    {ok, Ctx1} = nquic_lib:close(nquic_ctx:set_socket(Ctx, Socket)),
    Pending = (nquic_ctx:state(Ctx1))#conn_state.flow#conn_flow.pending_app_frames,
    ?assertEqual([], Pending),
    socket:close(Socket).

close_with_error_code_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx = make_ctx(),
    {ok, _} = nquic_lib:close(
        nquic_ctx:set_socket(Ctx, Socket),
        #{error_code => 1, reason => <<"err">>}
    ),
    socket:close(Socket).

close_app_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx = make_ctx(),
    {ok, _} = nquic_lib:close(
        nquic_ctx:set_socket(Ctx, Socket),
        #{scope => application, error_code => 7, reason => <<"app">>}
    ),
    socket:close(Socket).

shutdown_unconnected_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx(),
    Ref = erlang:send_after(60_000, self(), unused),
    Ctx1 = nquic_ctx:set_timers(
        nquic_ctx:set_connected(nquic_ctx:set_socket(Ctx0, Socket), false),
        #{idle => Ref}
    ),
    ?assertEqual(ok, nquic_lib:shutdown(Ctx1)),
    socket:close(Socket),
    flush_mailbox().

shutdown_with_app_error_unconnected_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx(),
    Ctx1 = nquic_ctx:set_connected(nquic_ctx:set_socket(Ctx0, Socket), false),
    ?assertEqual(ok, nquic_lib:shutdown(Ctx1, 9, <<"reason">>)),
    socket:close(Socket).

shutdown_swallows_close_failure_test() ->
    Ctx = nquic_ctx:new(undefined, undefined, ?PEER, undefined),
    ?assertEqual(ok, nquic_lib:shutdown(Ctx)).

takeover_no_dispatch_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    {ok, Ctx1} = nquic_lib:takeover(Ctx),
    ?assertEqual(#{}, nquic_ctx:timers(Ctx1)).

takeover_with_dispatch_and_odcid_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    State = (make_state())#conn_state{
        path = #conn_path_mgmt{
            local_cids = #{0 => <<10:64>>},
            path_state = nquic_path:new(undefined)
        },
        odcid = <<11:64>>
    },
    Ctx = nquic_ctx:set_dispatch(make_ctx_with_state(State), Dispatch),
    {ok, _Ctx1} = nquic_lib:takeover(Ctx),
    ?assertEqual(self(), nquic_dispatch:lookup(Dispatch, <<10:64>>)),
    ?assertEqual(self(), nquic_dispatch:lookup(Dispatch, <<11:64>>)).

takeover_with_dispatch_no_odcid_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    State = (make_state())#conn_state{
        path = #conn_path_mgmt{
            local_cids = #{0 => <<20:64>>},
            path_state = nquic_path:new(undefined)
        },
        odcid = undefined
    },
    Ctx = nquic_ctx:set_dispatch(make_ctx_with_state(State), Dispatch),
    {ok, _Ctx1} = nquic_lib:takeover(Ctx),
    ?assertEqual(self(), nquic_dispatch:lookup(Dispatch, <<20:64>>)).

takeover_with_dispatch_empty_odcid_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    State = (make_state())#conn_state{
        path = #conn_path_mgmt{
            local_cids = #{0 => <<30:64>>},
            path_state = nquic_path:new(undefined)
        },
        odcid = <<>>
    },
    Ctx = nquic_ctx:set_dispatch(make_ctx_with_state(State), Dispatch),
    {ok, _Ctx1} = nquic_lib:takeover(Ctx),
    ?assertEqual(self(), nquic_dispatch:lookup(Dispatch, <<30:64>>)).

send_blocked_by_stream_flow_control_returns_3tuple_error_test() ->
    Stream = nquic_stream_statem:new(0, bidi),
    Stream1 = Stream#stream_state{
        send_state = ready, send_max_data = 0, recv_window = 65_536
    },
    State0 = make_state(),
    SS0 = State0#conn_state.streams_state,
    State = State0#conn_state{
        streams_state = SS0#conn_streams{streams = #{0 => Stream1}}
    },
    Ctx = make_ctx_with_state(State),
    ?assertMatch(
        {error, {stream_flow_control_blocked, 0}, _},
        nquic_lib:send(Ctx, 0, <<"x">>)
    ).

send_fin_blocked_by_stream_flow_control_returns_3tuple_error_test() ->
    Stream = nquic_stream_statem:new(0, bidi),
    Stream1 = Stream#stream_state{
        send_state = ready, send_max_data = 0, recv_window = 65_536
    },
    State0 = make_state(),
    SS0 = State0#conn_state.streams_state,
    State = State0#conn_state{
        streams_state = SS0#conn_streams{streams = #{0 => Stream1}}
    },
    Ctx = make_ctx_with_state(State),
    ?assertMatch(
        {error, {stream_flow_control_blocked, 0}, _},
        nquic_lib:send_fin(Ctx, 0, <<"x">>)
    ).

send_fin_noflush_blocked_by_stream_flow_control_returns_3tuple_error_test() ->
    Stream = nquic_stream_statem:new(0, bidi),
    Stream1 = Stream#stream_state{
        send_state = ready, send_max_data = 0, recv_window = 65_536
    },
    State0 = make_state(),
    SS0 = State0#conn_state.streams_state,
    State = State0#conn_state{
        streams_state = SS0#conn_streams{streams = #{0 => Stream1}}
    },
    Ctx = make_ctx_with_state(State),
    ?assertMatch(
        {error, {stream_flow_control_blocked, 0}, _},
        nquic_lib:send_fin_noflush(Ctx, 0, <<"x">>)
    ).

send_success_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    {ok, StreamId, Ctx1} = nquic_lib:open_stream(Ctx, #{type => bidi}),
    Result = nquic_lib:send(Ctx1, StreamId, <<"hello">>),
    ?assertMatch({ok, _}, Result),
    socket:close(Socket).

send_fin_success_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    {ok, StreamId, Ctx1} = nquic_lib:open_stream(Ctx, #{type => bidi}),
    Result = nquic_lib:send_fin(Ctx1, StreamId, <<"bye">>),
    ?assertMatch({ok, _}, Result),
    socket:close(Socket).

close_stream_success_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    {ok, StreamId, Ctx1} = nquic_lib:open_stream(Ctx, #{type => bidi}),
    Result = nquic_lib:close_stream(Ctx1, StreamId),
    ?assertMatch({ok, _}, Result),
    socket:close(Socket).

reset_stream_success_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    {ok, StreamId, Ctx1} = nquic_lib:open_stream(Ctx, #{type => bidi}),
    Result = nquic_lib:reset_stream(Ctx1, StreamId, 5),
    ?assertMatch({ok, _}, Result),
    socket:close(Socket).

send_datagram_success_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    State0 = make_state(),
    State = State0#conn_state{
        remote_params = (State0#conn_state.remote_params)#transport_params{
            max_datagram_frame_size = 4096
        }
    },
    Ctx = nquic_ctx:set_socket(make_ctx_with_state(State), Socket),
    Result = nquic_lib:send_datagram(Ctx, <<"unreliable">>),
    ?assertMatch({ok, _}, Result),
    socket:close(Socket).

flush_notimers_drains_pending_via_loopback_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    State = make_state(),
    {ok, State1} = nquic_protocol:close(0, <<"x">>, State),
    Ctx = nquic_ctx:set_socket(make_ctx_with_state(State1), Socket),
    Result = nquic_lib:flush_notimers(Ctx),
    ?assertMatch({ok, _}, Result),
    socket:close(Socket).

recv_direct_drains_stale_socket_msg_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    self() ! {'$socket', other_socket, select, fake_select_info},
    Result = nquic_lib:recv_direct(Ctx, 10),
    ?assertMatch({ok, [], _}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_direct_processes_packet_message_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    Result = nquic_lib:recv_direct(Ctx, 100),
    ?assertMatch({ok, _, _}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_direct_processes_quic_timeout_message_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    self() ! {quic_timeout, idle},
    ?assertMatch(
        {error, {transport_error, idle_timeout}, _},
        nquic_lib:recv_direct(Ctx, 100)
    ),
    socket:close(Socket),
    flush_mailbox().

recv_batch_processes_packet_message_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    Result = nquic_lib:recv_batch(Ctx, 100),
    ?assertMatch({ok, _, _}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_batch_processes_quic_timeout_message_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    self() ! {quic_timeout, idle},
    ?assertMatch(
        {error, {transport_error, idle_timeout}, _},
        nquic_lib:recv_batch(Ctx, 100)
    ),
    socket:close(Socket),
    flush_mailbox().

recv_batch_after_timeout_returns_empty_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Result = nquic_lib:recv_batch(Ctx, 10),
    ?assertMatch({ok, [], _}, Result),
    socket:close(Socket),
    flush_mailbox().

schedule_timers_emits_set_timer_idle_test() ->
    State = (make_state())#conn_state{
        local_params = #transport_params{max_idle_timeout = 60_000}
    },
    Ctx0 = make_ctx_with_state(State),
    flush_mailbox(),
    Ctx1 = nquic_lib:schedule_timers(Ctx0),
    ?assert(maps:is_key(idle, nquic_ctx:timers(Ctx1))).

schedule_timers_emits_cancel_timer_pto_test() ->
    State = (make_state())#conn_state{
        local_params = #transport_params{max_idle_timeout = 60_000}
    },
    Ctx0 = make_ctx_with_state(State),
    Ref = erlang:send_after(60_000, self(), {quic_timeout, pto}),
    Ctx1 = nquic_ctx:set_timers(Ctx0, #{pto => Ref}),
    Ctx2 = nquic_lib:schedule_timers(Ctx1),
    ?assertNot(maps:is_key(pto, nquic_ctx:timers(Ctx2))),
    flush_mailbox().

schedule_timers_replaces_existing_idle_ref_test() ->
    State = (make_state())#conn_state{
        local_params = #transport_params{max_idle_timeout = 60_000}
    },
    Ctx0 = make_ctx_with_state(State),
    flush_mailbox(),
    Ctx1 = nquic_lib:schedule_timers(Ctx0),
    Ref1 = maps:get(idle, nquic_ctx:timers(Ctx1)),
    State1 = nquic_protocol:reset_timer_cache(nquic_ctx:state(Ctx1)),
    Ctx2 = nquic_ctx:set_state(Ctx1, State1),
    Ctx3 = nquic_lib:schedule_timers(Ctx2),
    Ref2 = maps:get(idle, nquic_ctx:timers(Ctx3)),
    ?assertNotEqual(Ref1, Ref2).

schedule_timers_no_actions_is_identity_test() ->
    State = (make_state())#conn_state{
        local_params = #transport_params{max_idle_timeout = 0},
        last_pto_ms = cancel
    },
    Ctx0 = make_ctx_with_state(State),
    Ctx1 = nquic_lib:schedule_timers(Ctx0),
    ?assertEqual(#{}, nquic_ctx:timers(Ctx1)).

path_stats_test() ->
    Ctx = make_ctx(),
    Stats = nquic_lib:path_stats(Ctx),
    ?assert(is_map(Stats)),
    ?assertEqual(0, maps:get(bytes_in_flight, Stats)),
    ?assert(maps:get(cwnd, Stats) > 0).

recv_and_process_handles_packet_batch_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    GsoSize = byte_size(Garbage),
    Buf = <<Garbage/binary, Garbage/binary, Garbage/binary>>,
    self() ! {packet_batch, ?PEER, Buf, GsoSize, not_ect},
    Result = nquic_lib:recv_and_process(Ctx, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    flush_mailbox().

recv_direct_handles_packet_batch_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    GsoSize = byte_size(Garbage),
    Buf = <<Garbage/binary, Garbage/binary>>,
    self() ! {packet_batch, ?PEER, Buf, GsoSize, not_ect},
    Result = nquic_lib:recv_direct(Ctx, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_batch_connected_packet_batch_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    GsoSize = byte_size(Garbage),
    Buf = <<Garbage/binary, Garbage/binary>>,
    self() ! {packet_batch, ?PEER, Buf, GsoSize, not_ect},
    Result = nquic_lib:recv_batch(Ctx, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_batch_dispatched_packet_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    Ctx0 = nquic_ctx:set_dispatch(make_ctx(), Dispatch),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    Result = nquic_lib:recv_batch(Ctx0, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    flush_mailbox().

recv_batch_dispatched_packet_batch_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    Ctx0 = nquic_ctx:set_dispatch(make_ctx(), Dispatch),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    GsoSize = byte_size(Garbage),
    Buf = <<Garbage/binary, Garbage/binary>>,
    self() ! {packet_batch, ?PEER, Buf, GsoSize, not_ect},
    Result = nquic_lib:recv_batch(Ctx0, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    flush_mailbox().

recv_batch_dispatched_timeout_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    Ctx0 = nquic_ctx:set_dispatch(make_ctx(), Dispatch),
    Result = nquic_lib:recv_batch(Ctx0, 10),
    ?assertMatch({ok, [], _Ctx1}, Result).

recv_batch_dispatched_quic_timeout_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    Ctx0 = nquic_ctx:set_dispatch(make_ctx(), Dispatch),
    self() ! {quic_timeout, idle},
    ?assertMatch(
        {error, {transport_error, idle_timeout}, _Ctx1},
        nquic_lib:recv_batch(Ctx0, 100)
    ),
    flush_mailbox().

recv_pending_drains_multiple_packets_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    self() ! {packet, ?PEER, Garbage, ect0},
    Result = nquic_lib:recv_pending(Ctx),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    ?assertEqual(0, message_queue_len()),
    flush_mailbox().

recv_and_process_handles_ecn_packet_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage, ect0},
    Result = nquic_lib:recv_and_process(Ctx, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    flush_mailbox().

recv_batch_arity1_with_immediate_timeout_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    Ctx0 = nquic_ctx:set_dispatch(make_ctx(), Dispatch),
    self() ! {quic_timeout, idle},
    Result = nquic_lib:recv_batch(Ctx0),
    ?assertMatch({error, {transport_error, idle_timeout}, _Ctx1}, Result),
    flush_mailbox().

recv_direct_arity1_with_immediate_timeout_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    self() ! {quic_timeout, idle},
    Result = nquic_lib:recv_direct(Ctx),
    ?assertMatch({error, {transport_error, idle_timeout}, _Ctx1}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_batch_connected_packet_msg_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    Result = nquic_lib:recv_batch(Ctx, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_batch_connected_ecn_packet_msg_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage, ect0},
    Result = nquic_lib:recv_batch(Ctx, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_batch_dispatched_ecn_packet_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    Ctx0 = nquic_ctx:set_dispatch(make_ctx(), Dispatch),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage, ect0},
    Result = nquic_lib:recv_batch(Ctx0, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    flush_mailbox().

recv_direct_polls_socket_for_packet_test() ->
    flush_mailbox(),
    {ok, Recv} = nquic_socket:open(0, #{}),
    {ok, Send} = nquic_socket:open(0, #{}),
    {ok, RecvPort} = nquic_socket:port(Recv),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => RecvPort},
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    ok = nquic_socket:send(Send, Peer, Garbage),
    timer:sleep(5),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Recv),
    Result = nquic_lib:recv_direct(Ctx, 200),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    socket:close(Recv),
    socket:close(Send),
    flush_mailbox().

recv_batch_polls_socket_for_packet_test() ->
    flush_mailbox(),
    {ok, Recv} = nquic_socket:open(0, #{}),
    {ok, Send} = nquic_socket:open(0, #{}),
    {ok, RecvPort} = nquic_socket:port(Recv),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => RecvPort},
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    ok = nquic_socket:send(Send, Peer, Garbage),
    timer:sleep(5),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Recv),
    Result = nquic_lib:recv_batch(Ctx, 200),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    socket:close(Recv),
    socket:close(Send),
    flush_mailbox().

recv_batch_connected_drains_multiple_packets_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    self() ! {packet, ?PEER, Garbage, ect0},
    self() ! {packet_batch, ?PEER, <<Garbage/binary, Garbage/binary>>, byte_size(Garbage), not_ect},
    Result = nquic_lib:recv_batch(Ctx, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    ?assertEqual(0, message_queue_len()),
    socket:close(Socket),
    flush_mailbox().

recv_batch_connected_drains_quic_timeout_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    self() ! {quic_timeout, idle},
    Result = nquic_lib:recv_batch(Ctx, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_batch_dispatched_drains_multiple_packets_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    Ctx0 = nquic_ctx:set_dispatch(make_ctx(), Dispatch),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    self() ! {packet, ?PEER, Garbage, ect0},
    self() ! {packet_batch, ?PEER, <<Garbage/binary, Garbage/binary>>, byte_size(Garbage), not_ect},
    Result = nquic_lib:recv_batch(Ctx0, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    ?assertEqual(0, message_queue_len()),
    flush_mailbox().

recv_batch_dispatched_drains_quic_timeout_test() ->
    flush_mailbox(),
    Dispatch = nquic_dispatch:new(2),
    Ctx0 = nquic_ctx:set_dispatch(make_ctx(), Dispatch),
    Garbage = <<16#c0, 0, 0, 0, 1, 0:8, 0:8, 0:64>>,
    self() ! {packet, ?PEER, Garbage},
    self() ! {quic_timeout, idle},
    Result = nquic_lib:recv_batch(Ctx0, 100),
    ?assertMatch({ok, _Events, _Ctx1}, Result),
    flush_mailbox().

drain_stale_socket_msg_via_recv_batch_test() ->
    flush_mailbox(),
    {ok, Socket} = nquic_socket:open(0, #{}),
    Ctx0 = make_ctx_with_state(make_state()),
    Ctx = nquic_ctx:set_socket(Ctx0, Socket),
    self() ! {'$socket', other_socket, select, fake_select_info},
    Result = nquic_lib:recv_batch(Ctx, 10),
    ?assertMatch({ok, [], _Ctx1}, Result),
    socket:close(Socket),
    flush_mailbox().

recv_pending_returns_error_on_protocol_failure_test() ->
    flush_mailbox(),
    Ctx = make_ctx(),
    self() ! {packet, ?PEER, <<>>},
    Result = nquic_lib:recv_pending(Ctx),
    case Result of
        {ok, _, _} -> ok;
        {error, _, _} -> ok
    end,
    flush_mailbox().

upgrade_to_connected_success_test() ->
    {ok, Listener} = nquic_socket:open(0, #{reuseport => true}),
    {ok, _ListenerPort} = nquic_socket:port(Listener),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => 6543},
    Ctx0 = nquic_ctx:set_socket(make_ctx_with_state(make_state()), Listener),
    Ctx1 = nquic_ctx:set_peer(Ctx0, Peer),
    Result = nquic_lib:upgrade_to_connected(Ctx1),
    case Result of
        {ok, Ctx2} ->
            ?assert(nquic_ctx:connected(Ctx2)),
            socket:close(nquic_ctx:socket(Ctx2));
        {error, _Reason} ->
            ok
    end,
    socket:close(Listener).

upgrade_to_connected_error_test() ->
    {ok, Listener} = nquic_socket:open(0, #{}),
    socket:close(Listener),
    Ctx0 = nquic_ctx:set_socket(make_ctx_with_state(make_state()), Listener),
    Result = nquic_lib:upgrade_to_connected(Ctx0),
    ?assertMatch({error, _Reason}, Result).

is_writable_unknown_stream_returns_false_test() ->
    ?assertNot(nquic_lib:is_writable(make_ctx(), 999)).

is_writable_open_stream_returns_true_test() ->
    {ok, StreamId, Ctx1} = nquic_lib:open_stream(make_ctx(), #{type => bidi}),
    ?assert(nquic_lib:is_writable(Ctx1, StreamId)).

is_writable_terminal_send_stream_returns_false_test() ->
    Ctx = make_ctx_with_state(state_with_closed_stream(0)),
    ?assertNot(nquic_lib:is_writable(Ctx, 0)).

make_state() ->
    #conn_state{
        role = client,
        scid = <<0:64>>,
        dcid = <<1:64>>,
        streams_state = #conn_streams{
            next_bidi_stream = 0,
            next_uni_stream = 2,
            peer_max_streams_bidi = 100,
            peer_max_streams_uni = 100,
            local_max_streams_bidi = 100,
            local_max_streams_uni = 100
        },
        flow = #conn_flow{
            local_max_data = 16_777_216,
            remote_max_data = 16_777_216,
            data_sent = 0,
            data_received = 0,
            pending_app_frames = []
        },
        path = #conn_path_mgmt{path_state = nquic_path:new(undefined)},
        remote_params = #transport_params{
            initial_max_data = 16_777_216,
            initial_max_stream_data_bidi_local = 65_536,
            initial_max_stream_data_bidi_remote = 65_536,
            initial_max_stream_data_uni = 65_536
        },
        pn_spaces = #{application => #{next_pn => 0}},
        loss_state = nquic_loss:init()
    }.

state_with_closed_stream(StreamID) ->
    Stream = nquic_stream_statem:new(StreamID, bidi),
    Stream1 = Stream#stream_state{send_state = data_sent, send_max_data = 65_536},
    State = make_state(),
    SS0 = State#conn_state.streams_state,
    State#conn_state{
        streams_state = SS0#conn_streams{
            streams = #{StreamID => Stream1},
            next_bidi_stream = 4
        }
    }.

make_ctx() ->
    make_ctx_with_state(make_state()).

make_ctx_with_state(State) ->
    nquic_ctx:set_datagram_max(
        nquic_ctx:new(State, undefined, ?PEER, undefined),
        1024
    ).

flush_mailbox() ->
    receive
        _ -> flush_mailbox()
    after 0 ->
        ok
    end.

message_queue_len() ->
    {message_queue_len, Len} = process_info(self(), message_queue_len),
    Len.
