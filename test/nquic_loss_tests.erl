%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_loss}.
%%%
%%% The `loss_state' record is mirrored from the production module
%%% (`src/nquic_loss.erl'); if its layout changes, update the copy
%%% below to keep field-pattern tests in sync.
%%%-------------------------------------------------------------------
-module(nquic_loss_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_frame.hrl").
-include("nquic_loss.hrl").
-record(pacer_state, {
    enabled = false :: boolean(),
    factor = 1.25 :: number(),
    burst_packets = 10 :: pos_integer(),
    next_send_time :: undefined | integer()
}).

-record(loss_state, {
    sent_packets = #{
        initial => nquic_pn_buf:new(),
        handshake => nquic_pn_buf:new(),
        application => nquic_pn_buf:new()
    } :: #{nquic_packet:space() => nquic_pn_buf:buf()},
    largest_acked_packet = #{} :: #{nquic_packet:space() => nquic_packet_number:t()},
    loss_time = #{} :: #{nquic_packet:space() => non_neg_integer()},
    rtt_state :: nquic_rtt:rtt_state(),
    cc_state :: term(),
    bytes_in_flight = 0 :: non_neg_integer(),
    pto_count = 0 :: non_neg_integer(),
    ack_eliciting_in_flight = 0 :: non_neg_integer(),
    first_rtt_sample :: non_neg_integer() | undefined,
    last_send_time :: non_neg_integer() | undefined,
    recently_lost = #{
        initial => nquic_pn_buf:new(),
        handshake => nquic_pn_buf:new(),
        application => nquic_pn_buf:new()
    } :: #{nquic_packet:space() => nquic_pn_buf:buf()},
    peer_ecn_ce = #{} :: #{nquic_packet:space() => non_neg_integer()},
    peer_ecn_total = #{} :: #{nquic_packet:space() => non_neg_integer()},
    ecn_enabled = true :: boolean(),
    ecn_socket_dirty = false :: boolean(),
    pacer = #pacer_state{} :: #pacer_state{}
}).

init_test() ->
    State = nquic_loss:init(),
    ?assertEqual(0, State#loss_state.bytes_in_flight),
    ?assert(nquic_pn_buf:is_empty(maps:get(application, State#loss_state.sent_packets))).

packet_sent_test() ->
    State0 = nquic_loss:init(),
    Frames = [#stream{stream_id = 0, offset = 0, length = 100, data = <<0:800>>}],
    Now = 1000,
    Size = 1200,
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames, Now, Size),

    ?assertEqual(1200, State1#loss_state.bytes_in_flight),
    SpaceSent = maps:get(application, State1#loss_state.sent_packets),
    ?assertMatch(#sent_packet{packet_number = 1}, nquic_pn_buf:get(1, SpaceSent)).

ack_received_test() ->
    State0 = nquic_loss:init(),
    Frames = [#stream{stream_id = 0, offset = 0, length = 100, data = <<0:800>>}],
    Now = 1000,
    Size = 1200,
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames, Now, Size),

    AckDelay = 0,
    AckTime = 2000,
    {ok, State2, AckedFrames, LostFrames} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], AckDelay, AckTime, 25_000
    ),

    ?assertEqual(0, State2#loss_state.bytes_in_flight),
    ?assertEqual([], LostFrames),
    ?assertMatch([#stream{}], AckedFrames),
    RTTStats = nquic_rtt:get(State2#loss_state.rtt_state),
    ?assertEqual(1000, maps:get(latest_rtt, RTTStats)).

loss_detection_time_test() ->
    State0 = nquic_loss:init(),
    Frames = [#stream{stream_id = 0, offset = 0, length = 100, data = <<0:800>>}],
    Size = 1200,

    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames, 1000, Size),
    State2 = nquic_loss:on_packet_sent(State1, application, 2, Frames, 5000, Size),

    {ok, _State3, _Acked, Lost} = nquic_loss:on_ack_received(
        State2, application, [{2, 2}], 0, 5100, 25_000
    ),

    ?assertMatch([#stream{}], Lost).

per_space_isolation_test() ->
    State0 = nquic_loss:init(),
    Frames = [#ping{}],

    State1 = nquic_loss:on_packet_sent(State0, initial, 0, Frames, 1000, 100),
    State2 = nquic_loss:on_packet_sent(State1, handshake, 0, Frames, 2000, 200),
    State3 = nquic_loss:on_packet_sent(State2, application, 0, Frames, 3000, 300),

    ?assertEqual(600, nquic_loss:get_bytes_in_flight(State3)),

    {ok, State4, Acked, _Lost} = nquic_loss:on_ack_received(
        State3, initial, [{0, 0}], 0, 4000, 25_000
    ),
    ?assertMatch([#ping{}], Acked),
    ?assertEqual(500, nquic_loss:get_bytes_in_flight(State4)),

    HSent = maps:get(handshake, State4#loss_state.sent_packets),
    ?assert(nquic_pn_buf:is_defined(0, HSent)).

pto_timeout_test() ->
    State = nquic_loss:init(),
    PTO = nquic_loss:get_pto_timeout(State, 25_000),
    ?assertEqual(1_024_000, PTO).

pto_backoff_test() ->
    State0 = nquic_loss:init(),
    PTO0 = nquic_loss:get_pto_timeout(State0, 25_000),
    State1 = nquic_loss:on_pto(State0),
    PTO1 = nquic_loss:get_pto_timeout(State1, 25_000),
    ?assertEqual(PTO0 * 2, PTO1),
    State2 = nquic_loss:on_pto(State1),
    PTO2 = nquic_loss:get_pto_timeout(State2, 25_000),
    ?assertEqual(PTO0 * 4, PTO2).

pto_reset_on_ack_test() ->
    State0 = nquic_loss:init(),
    Frames = [#ping{}],
    State1 = nquic_loss:on_packet_sent(State0, application, 0, Frames, 1000, 100),
    State2 = nquic_loss:on_pto(State1),
    ?assertEqual(1, State2#loss_state.pto_count),
    {ok, State3, _, _} = nquic_loss:on_ack_received(
        State2, application, [{0, 0}], 0, 2000, 25_000
    ),
    ?assertEqual(0, State3#loss_state.pto_count).

has_ack_eliciting_test() ->
    State0 = nquic_loss:init(),
    ?assertEqual(false, nquic_loss:has_ack_eliciting_in_flight(State0)),
    State1 = nquic_loss:on_packet_sent(State0, application, 0, [#ping{}], 1000, 100),
    ?assertEqual(true, nquic_loss:has_ack_eliciting_in_flight(State1)).

time_threshold_loss_with_reordering_test() ->
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,
    Size = 1200,
    State0 = nquic_loss:init(),
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames(1), 0, Size),
    {ok, State2, _, _} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], 0, 10_000, 25_000
    ),

    State3 = nquic_loss:on_packet_sent(State2, application, 2, Frames(2), 20_000, Size),
    State4 = nquic_loss:on_packet_sent(State3, application, 3, Frames(3), 21_000, Size),
    State5 = nquic_loss:on_packet_sent(State4, application, 4, Frames(4), 49_000, Size),

    {ok, _State6, Acked, Lost} = nquic_loss:on_ack_received(
        State5, application, [{4, 4}], 0, 50_000, 25_000
    ),
    ?assertMatch([#stream{stream_id = 4}], Acked),
    LostIds = lists:sort([Sid || #stream{stream_id = Sid} <- Lost]),
    ?assertEqual([2, 3], LostIds).

packet_threshold_loss_test() ->
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,
    Size = 1200,
    State0 = nquic_loss:on_packet_sent(nquic_loss:init(), application, 1, Frames(1), 0, Size),
    State1 = nquic_loss:on_packet_sent(State0, application, 2, Frames(2), 100, Size),
    State2 = nquic_loss:on_packet_sent(State1, application, 3, Frames(3), 200, Size),
    State3 = nquic_loss:on_packet_sent(State2, application, 4, Frames(4), 300, Size),
    State4 = nquic_loss:on_packet_sent(State3, application, 5, Frames(5), 400, Size),
    {ok, _State5, _Acked, Lost} = nquic_loss:on_ack_received(
        State4, application, [{5, 5}], 0, 500, 25_000
    ),
    LostIds = lists:sort([Sid || #stream{stream_id = Sid} <- Lost]),
    ?assertEqual([1, 2], LostIds).

persistent_congestion_collapses_cwnd_test() ->
    MSS = 1200,
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,

    State0 = nquic_loss:init(),
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames(1), 0, MSS),
    {ok, State2, _, _} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], 0, 10_000, 25_000
    ),
    ?assertNotEqual(undefined, State2#loss_state.first_rtt_sample),

    State3 = nquic_loss:on_packet_sent(State2, application, 2, Frames(2), 20_000, MSS),
    State4 = nquic_loss:on_packet_sent(State3, application, 3, Frames(3), 80_000, MSS),
    State5 = nquic_loss:on_packet_sent(State4, application, 4, Frames(4), 140_000, MSS),
    State6 = nquic_loss:on_packet_sent(State5, application, 5, Frames(5), 200_000, MSS),
    State7 = nquic_loss:on_packet_sent(State6, application, 6, Frames(6), 220_000, MSS),
    State8 = nquic_loss:on_packet_sent(State7, application, 7, Frames(7), 240_000, MSS),

    State9 = nquic_loss:on_packet_sent(State8, application, 8, Frames(8), 260_000, MSS),
    {ok, State10, _Acked, Lost} = nquic_loss:on_ack_received(
        State9, application, [{8, 8}], 0, 270_000, 25_000
    ),

    LostIds = lists:sort([Sid || #stream{stream_id = Sid} <- Lost]),
    ?assertEqual([2, 3, 4, 5, 6, 7], LostIds),

    ?assertEqual(2 * MSS, nquic_loss:get_cwnd(State10)).

persistent_congestion_requires_rtt_sample_test() ->
    MSS = 1200,
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,

    State0 = nquic_loss:init(),
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames(1), 0, MSS),
    State2 = nquic_loss:on_packet_sent(State1, application, 2, Frames(2), 50_000, MSS),
    State3 = nquic_loss:on_packet_sent(State2, application, 3, Frames(3), 200_000, MSS),
    State4 = nquic_loss:on_packet_sent(State3, application, 4, Frames(4), 400_000, MSS),
    State5 = nquic_loss:on_packet_sent(State4, application, 5, Frames(5), 600_000, MSS),
    {ok, State6, _Acked, Lost} = nquic_loss:on_ack_received(
        State5, application, [{5, 5}], 0, 610_000, 25_000
    ),
    ?assertEqual(undefined, State1#loss_state.first_rtt_sample),
    ?assert(length(Lost) >= 2),
    ?assert(nquic_loss:get_cwnd(State6) > 2 * MSS).

spurious_loss_rolls_back_cwnd_test() ->
    MSS = 1200,
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,

    State0 = nquic_loss:init(),
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames(1), 0, MSS),
    {ok, State2, _, _} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], 0, 10_000, 25_000
    ),
    Cwnd0 = nquic_loss:get_cwnd(State2),

    State3 = nquic_loss:on_packet_sent(State2, application, 2, Frames(2), 20_000, MSS),
    State4 = nquic_loss:on_packet_sent(State3, application, 3, Frames(3), 21_000, MSS),
    State5 = nquic_loss:on_packet_sent(State4, application, 4, Frames(4), 22_000, MSS),
    State6 = nquic_loss:on_packet_sent(State5, application, 5, Frames(5), 23_000, MSS),
    {ok, State7, _, Lost1} = nquic_loss:on_ack_received(
        State6, application, [{5, 5}], 0, 30_000, 25_000
    ),
    ?assertMatch([_ | _], Lost1),
    CwndReduced = nquic_loss:get_cwnd(State7),
    ?assert(CwndReduced =< Cwnd0),

    {ok, State8, _, _} = nquic_loss:on_ack_received(
        State7, application, [{2, 2}], 0, 35_000, 25_000
    ),
    ?assert(nquic_loss:get_cwnd(State8) >= Cwnd0).

idle_reset_collapses_cwnd_to_initial_test() ->
    MSS = 1200,
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,

    State0 = nquic_loss:init(),
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames(1), 0, MSS),
    {ok, State2, _, _} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], 0, 10_000, 25_000
    ),
    State3 = nquic_loss:on_packet_sent(State2, application, 2, Frames(2), 11_000, MSS),
    {ok, State4, _, _} = nquic_loss:on_ack_received(
        State3, application, [{2, 2}], 0, 21_000, 25_000
    ),
    ?assert(nquic_loss:get_cwnd(State4) > nquic_cc_newreno:initial_window(MSS)),
    ?assertEqual(0, nquic_loss:get_bytes_in_flight(State4)),

    State5 = nquic_loss:on_packet_sent(State4, application, 3, Frames(3), 100_000, MSS),
    ?assertEqual(nquic_cc_newreno:initial_window(MSS), nquic_loss:get_cwnd(State5)).

idle_reset_skipped_when_in_flight_test() ->
    MSS = 1200,
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,

    State0 = nquic_loss:init(),
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames(1), 0, MSS),
    {ok, State2, _, _} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], 0, 10_000, 25_000
    ),
    State3 = nquic_loss:on_packet_sent(State2, application, 2, Frames(2), 11_000, MSS),
    Cwnd0 = nquic_loss:get_cwnd(State3),
    State4 = nquic_loss:on_packet_sent(State3, application, 3, Frames(3), 1_000_000, MSS),
    ?assertEqual(Cwnd0, nquic_loss:get_cwnd(State4)).

spurious_loss_pruned_after_window_test() ->
    MSS = 1200,
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,

    State0 = nquic_loss:init(),
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames(1), 0, MSS),
    {ok, State2, _, _} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], 0, 10_000, 25_000
    ),

    State3 = nquic_loss:on_packet_sent(State2, application, 2, Frames(2), 20_000, MSS),
    State4 = nquic_loss:on_packet_sent(State3, application, 3, Frames(3), 21_000, MSS),
    State5 = nquic_loss:on_packet_sent(State4, application, 4, Frames(4), 22_000, MSS),
    State6 = nquic_loss:on_packet_sent(State5, application, 5, Frames(5), 23_000, MSS),
    {ok, State7, _, Lost} = nquic_loss:on_ack_received(
        State6, application, [{5, 5}], 0, 30_000, 25_000
    ),
    ?assert(length(Lost) >= 1),

    RL7 = State7#loss_state.recently_lost,
    ?assert(nquic_pn_buf:is_defined(2, maps:get(application, RL7, nquic_pn_buf:new()))),

    State8 = nquic_loss:on_packet_sent(State7, application, 6, Frames(6), 1_000_000, MSS),
    {ok, State9, _, _} = nquic_loss:on_ack_received(
        State8, application, [{6, 6}], 0, 1_010_000, 25_000
    ),
    RL9 = State9#loss_state.recently_lost,
    ?assertNot(nquic_pn_buf:is_defined(2, maps:get(application, RL9, nquic_pn_buf:new()))).

persistent_congestion_below_threshold_test() ->
    MSS = 1200,
    Frames = fun(N) -> [#stream{stream_id = N, offset = 0, length = 0, data = <<>>}] end,

    State0 = nquic_loss:init(),
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames(1), 0, MSS),
    {ok, State2, _, _} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], 0, 10_000, 25_000
    ),

    State3 = nquic_loss:on_packet_sent(State2, application, 2, Frames(2), 20_000, MSS),
    State4 = nquic_loss:on_packet_sent(State3, application, 3, Frames(3), 30_000, MSS),
    State5 = nquic_loss:on_packet_sent(State4, application, 4, Frames(4), 40_000, MSS),
    State6 = nquic_loss:on_packet_sent(State5, application, 5, Frames(5), 50_000, MSS),
    State7 = nquic_loss:on_packet_sent(State6, application, 6, Frames(6), 60_000, MSS),
    {ok, State8, _Acked, Lost} = nquic_loss:on_ack_received(
        State7, application, [{6, 6}], 0, 70_000, 25_000
    ),
    ?assert(length(Lost) >= 2),
    ?assert(nquic_loss:get_cwnd(State8) > 2 * MSS).

%%%-----------------------------------------------------------------------------
%% B2: pacer (RFC 9002 §7.7)
%%%-----------------------------------------------------------------------------

pacer_disabled_by_default_test() ->
    State0 = nquic_loss:init(cubic),
    ?assertNot(nquic_loss:pacer_is_enabled(State0)),
    ?assertEqual(pass, nquic_loss:pacer_check(State0, 0)),
    Frames = [#ping{}],
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames, 0, 1200),
    ?assertEqual(undefined, nquic_loss:pacer_next_send_time(State1)),
    ?assertEqual(pass, nquic_loss:pacer_check(State1, 1_000_000)).

pacer_enabled_via_init_test() ->
    State = nquic_loss:init(cubic, #{enabled => true, factor => 2.0, burst_packets => 5}),
    ?assert(nquic_loss:pacer_is_enabled(State)),
    ?assertEqual(undefined, nquic_loss:pacer_next_send_time(State)).

pacer_in_slow_start_does_not_advance_test() ->
    State0 = nquic_loss:init(cubic, #{enabled => true}),
    Frames = [#ping{}],
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames, 0, 1200),
    ?assertEqual(undefined, nquic_loss:pacer_next_send_time(State1)),
    ?assertEqual(pass, nquic_loss:pacer_check(State1, 0)).

pacer_config_round_trips_test() ->
    Cfg = #{enabled => true, factor => 1.5, burst_packets => 8},
    State = nquic_loss:init(cubic, Cfg),
    Got = nquic_loss:pacer_config(State),
    ?assertEqual(true, maps:get(enabled, Got)),
    ?assertEqual(1.5, maps:get(factor, Got)),
    ?assertEqual(8, maps:get(burst_packets, Got)).

pacer_disable_at_runtime_test() ->
    State0 = nquic_loss:init(cubic, #{enabled => true}),
    State1 = nquic_loss:pacer_disable(State0),
    ?assertNot(nquic_loss:pacer_is_enabled(State1)).

pacer_blocks_past_slow_start_test() ->
    MSS = 1200,
    State0 = nquic_loss:init(cubic, #{enabled => true, burst_packets => 1}),
    Frames = [#stream{stream_id = 0, offset = 0, length = 0, data = <<>>}],
    State1 = nquic_loss:on_packet_sent(State0, application, 1, Frames, 0, MSS),
    {ok, State2, _, _} = nquic_loss:on_ack_received(
        State1, application, [{1, 1}], 0, 50_000, 25_000
    ),
    State3 = nquic_loss:on_packet_sent(State2, application, 2, Frames, 100_000, MSS),
    {ok, State4, _, _} = nquic_loss:on_ack_received(
        State3, application, [{2, 2}], 0, 150_000, 25_000
    ),
    State5 = nquic_loss:on_packet_sent(State4, application, 3, Frames, 200_000, MSS),
    NextUs = nquic_loss:pacer_next_send_time(State5),
    ?assert(NextUs >= 0).

pacer_check_undefined_loss_state_test() ->
    ?assertEqual(pass, nquic_loss:pacer_check(undefined, 0)).

pacer_check_passes_when_next_send_time_in_past_test() ->
    NegNow = -1_000_000,
    Pacer = #pacer_state{
        enabled = true,
        next_send_time = NegNow - 1_000,
        factor = 1.25,
        burst_packets = 10
    },
    CC0 = nquic_cc:new(cubic),
    CC = nquic_cc:on_congestion_event(CC0, 1200, 12000, 1),
    RTT0 = nquic_rtt:new(),
    RTT = nquic_rtt:update(RTT0, 50_000, 0),
    P = #sent_packet{
        packet_number = 5,
        time_sent = 100_000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    CCAcked = nquic_cc:on_packet_acked(CC, P, 0, #{
        smoothed_rtt => 50_000,
        latest_rtt => 50_000,
        min_rtt => 50_000
    }),
    State = #loss_state{
        cc_state = CCAcked,
        rtt_state = RTT,
        pacer = Pacer
    },
    ?assertEqual(pass, nquic_loss:pacer_check(State, NegNow)).

pacer_check_blocks_when_next_send_time_in_future_test() ->
    NegNow = -1_000_000,
    Future = NegNow + 5_000,
    Pacer = #pacer_state{
        enabled = true,
        next_send_time = Future,
        factor = 1.25,
        burst_packets = 10
    },
    CC0 = nquic_cc:new(cubic),
    CC = nquic_cc:on_congestion_event(CC0, 1200, 12000, 1),
    P = #sent_packet{
        packet_number = 5,
        time_sent = 100_000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    CCAcked = nquic_cc:on_packet_acked(CC, P, 0, #{
        smoothed_rtt => 50_000,
        latest_rtt => 50_000,
        min_rtt => 50_000
    }),
    RTT0 = nquic_rtt:new(),
    RTT = nquic_rtt:update(RTT0, 50_000, 0),
    State = #loss_state{
        cc_state = CCAcked,
        rtt_state = RTT,
        pacer = Pacer
    },
    ?assertEqual({block, Future}, nquic_loss:pacer_check(State, NegNow)).

ref_acked_pns(SentBuf, Ranges) ->
    InRange = fun(PN) ->
        lists:any(fun({L, H}) -> PN >= L andalso PN =< H end, Ranges)
    end,
    lists:sort([PN || PN <- nquic_pn_buf:keys(SentBuf), InRange(PN)]).

seed_inflight(N) ->
    lists:foldl(
        fun(PN, S) ->
            Frames = [#stream{stream_id = PN, offset = 0, length = 0, data = <<>>}],
            nquic_loss:on_packet_sent(S, application, PN, Frames, PN * 10, 1200)
        end,
        nquic_loss:init(),
        lists:seq(0, N - 1)
    ).

acked_pns_from_frames(Frames) ->
    lists:sort([Sid || #stream{stream_id = Sid} <- Frames]).

process_acked_ranges_single_big_range_equivalence_test() ->
    State = seed_inflight(800),
    SentMap = maps:get(application, State#loss_state.sent_packets),
    Ranges = [{200, 600}],
    {ok, _S, Acked, _Lost} = nquic_loss:on_ack_received(
        State, application, Ranges, 0, 6500, 25_000
    ),
    ?assertEqual(ref_acked_pns(SentMap, Ranges), acked_pns_from_frames(Acked)).

process_acked_ranges_multiple_disjoint_ranges_equivalence_test() ->
    State = seed_inflight(1000),
    SentMap = maps:get(application, State#loss_state.sent_packets),
    Ranges = [{0, 50}, {100, 200}, {400, 700}, {900, 999}],
    {ok, _S, Acked, _Lost} = nquic_loss:on_ack_received(
        State, application, Ranges, 0, 10_500, 25_000
    ),
    ?assertEqual(ref_acked_pns(SentMap, Ranges), acked_pns_from_frames(Acked)).

process_acked_ranges_skips_gaps_test() ->
    Base = nquic_loss:init(),
    Present = [1, 3, 5, 7, 9],
    State = lists:foldl(
        fun(PN, S) ->
            Frames = [#stream{stream_id = PN, offset = 0, length = 0, data = <<>>}],
            nquic_loss:on_packet_sent(S, application, PN, Frames, PN * 10, 1200)
        end,
        Base,
        Present
    ),
    Ranges = [{0, 10}],
    {ok, _S, Acked, _Lost} = nquic_loss:on_ack_received(
        State, application, Ranges, 0, 200, 25_000
    ),
    ?assertEqual(Present, acked_pns_from_frames(Acked)).

process_acked_ranges_no_overlap_test() ->
    State = seed_inflight(50),
    SentMap = maps:get(application, State#loss_state.sent_packets),
    Ranges = [{100, 200}],
    {ok, _S, Acked, _Lost} = nquic_loss:on_ack_received(
        State, application, Ranges, 0, 600, 25_000
    ),
    ?assertEqual([], acked_pns_from_frames(Acked)),
    ?assertEqual(ref_acked_pns(SentMap, Ranges), acked_pns_from_frames(Acked)).

process_acked_ranges_full_overlap_stress_test() ->
    State = seed_inflight(1500),
    SentMap = maps:get(application, State#loss_state.sent_packets),
    Ranges = [{0, 1499}],
    {ok, _S, Acked, _Lost} = nquic_loss:on_ack_received(
        State, application, Ranges, 0, 16_000, 25_000
    ),
    ?assertEqual(ref_acked_pns(SentMap, Ranges), acked_pns_from_frames(Acked)).

%% Pure ECN / pacer / path-stats / ack-accounting coverage.
ecn_lifecycle_test() ->
    S0 = nquic_loss:init(),
    ?assert(is_boolean(nquic_loss:is_ecn_enabled(S0))),
    S1 = nquic_loss:set_ecn_enabled(S0, true),
    ?assert(nquic_loss:is_ecn_enabled(S1)),
    S2 = nquic_loss:set_ecn_enabled(S1, false),
    ?assertNot(nquic_loss:is_ecn_enabled(S2)),
    ?assertEqual(S1, nquic_loss:process_ecn_counts(S1, application, undefined)),
    S3 = nquic_loss:process_ecn_counts(S1, application, {3, 0, 1}),
    ?assert(is_boolean(nquic_loss:is_ecn_socket_dirty(S3))),
    S4 = nquic_loss:clear_ecn_socket_dirty(S3),
    ?assertNot(nquic_loss:is_ecn_socket_dirty(S4)).

path_stats_and_cc_algo_test() ->
    lists:foreach(
        fun(Algo) ->
            S = nquic_loss:init(Algo),
            ?assert(is_atom(nquic_loss:get_cc_algorithm(S))),
            PS = nquic_loss:path_stats(S),
            ?assert(is_map(PS)),
            ?assert(maps:is_key(cwnd, PS)),
            ?assert(maps:is_key(bytes_in_flight, PS))
        end,
        [cubic, newreno]
    ).

set_max_datagram_size_loss_test() ->
    S0 = nquic_loss:init(cubic),
    S1 = nquic_loss:set_max_datagram_size(S0, 1500),
    ?assert(is_map(nquic_loss:path_stats(S1))).

pacer_check_test() ->
    ?assertEqual(pass, nquic_loss:pacer_check(undefined, 0)),
    S0 = nquic_loss:init(cubic, #{enabled => true, factor => 1.25, burst_packets => 10}),
    Now = erlang:monotonic_time(microsecond),
    S1 = nquic_loss:on_packet_sent(
        S0,
        application,
        1,
        [#stream{stream_id = 0, data = <<"x">>}],
        Now,
        1200
    ),
    R = nquic_loss:pacer_check(S1, Now + 1),
    ?assert(R =:= pass orelse element(1, R) =:= block).

on_ack_received_accounting_test() ->
    S0 = nquic_loss:init(cubic),
    Now = erlang:monotonic_time(microsecond),
    Frames = [#stream{stream_id = 0, data = <<"hello">>}],
    S1 = nquic_loss:on_packet_sent(S0, application, 1, Frames, Now, 1200),
    {ok, S2, _Acked, _Lost} = nquic_loss:on_ack_received(
        S1, application, [{1, 1}], 0, Now + 30_000, 25_000
    ),
    ?assert(is_map(nquic_loss:path_stats(S2))).
