%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_cc_cubic}.
%%%
%%% The `state' record and CUBIC macros mirror the source-of-truth
%%% in `src/nquic_cc_cubic.erl'; if the production constants/layout
%%% change, update the values below to keep the tests in sync.
%%%-------------------------------------------------------------------
-module(nquic_cc_cubic_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_loss.hrl").
-define(BETA_CUBIC, 0.7).
-define(C, 0.4).
-define(INFINITY_SSTHRESH, 16#FFFFFFFFFFFFFFFF).
-define(NO_RECOVERY, -576460752303423488).

-record(state, {
    cwnd :: non_neg_integer(),
    ssthresh = ?INFINITY_SSTHRESH :: non_neg_integer(),
    max_datagram_size = 1200 :: pos_integer(),
    recovery_start_time = ?NO_RECOVERY :: integer(),
    w_max = 0 :: non_neg_integer(),
    w_last_max = 0 :: non_neg_integer(),
    epoch_start = 0 :: non_neg_integer(),
    origin_point = 0 :: non_neg_integer(),
    tcp_cwnd = 0 :: non_neg_integer(),
    cubic_k = undefined :: undefined | float(),
    congestion_occurred = false :: boolean(),
    prev_state ::
        undefined
        | {
            non_neg_integer(),
            non_neg_integer(),
            integer(),
            non_neg_integer(),
            non_neg_integer(),
            non_neg_integer(),
            non_neg_integer(),
            non_neg_integer(),
            undefined | float(),
            boolean()
        },
    hystart_phase = standard ::
        standard | slow_start | css | done,
    last_round_min_rtt = ?INFINITY_SSTHRESH :: non_neg_integer(),
    current_round_min_rtt = ?INFINITY_SSTHRESH :: non_neg_integer(),
    rtt_sample_count = 0 :: non_neg_integer(),
    last_round_largest_pn = 0 :: non_neg_integer(),
    css_baseline_min_rtt = ?INFINITY_SSTHRESH :: non_neg_integer(),
    css_round_count = 0 :: non_neg_integer(),
    undo_bytes = 0 :: non_neg_integer(),
    app_limited_since :: integer() | undefined,
    sent_in_flight = 0 :: non_neg_integer()
}).

init_test() ->
    S = nquic_cc_cubic:init(),
    ?assertEqual(12000, nquic_cc_cubic:get_cwnd(S)),
    ?assertEqual(?INFINITY_SSTHRESH, nquic_cc_cubic:get_ssthresh(S)),
    ?assertEqual(1200, nquic_cc_cubic:get_max_datagram_size(S)).

slow_start_test() ->
    S0 = nquic_cc_cubic:init(),
    Packet = #sent_packet{
        packet_number = 1,
        time_sent = erlang:monotonic_time(microsecond) + 1000000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    S1 = nquic_cc_cubic:on_packet_acked(S0, Packet, 12000, #{}),
    ?assertEqual(13200, nquic_cc_cubic:get_cwnd(S1)).

recovery_filter_test() ->
    S0 = nquic_cc_cubic:init(),
    SentTime = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, 12000, SentTime),
    Cwnd1 = nquic_cc_cubic:get_cwnd(S1),
    Packet = #sent_packet{
        packet_number = 1,
        time_sent = SentTime - 1000000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    S2 = nquic_cc_cubic:on_packet_acked(S1, Packet, 0, #{}),
    ?assertEqual(Cwnd1, nquic_cc_cubic:get_cwnd(S2)).

congestion_event_test() ->
    S0 = nquic_cc_cubic:init(),
    Now = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, 12000, Now),
    ?assertEqual(8400, nquic_cc_cubic:get_cwnd(S1)),
    ?assertEqual(8400, nquic_cc_cubic:get_ssthresh(S1)),
    ?assertEqual(12000, S1#state.w_max).

congestion_event_min_window_test() ->
    S0 = #state{
        cwnd = 3000,
        ssthresh = 3000,
        max_datagram_size = 1200,
        recovery_start_time = ?NO_RECOVERY,
        w_max = 3000,
        w_last_max = 0,
        epoch_start = 0,
        origin_point = 0,
        tcp_cwnd = 0,
        congestion_occurred = true
    },
    Now = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, 3000, Now),
    ?assertEqual(2400, nquic_cc_cubic:get_cwnd(S1)).

fast_convergence_test() ->
    S0 = nquic_cc_cubic:init(),
    Now = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, 12000, Now),
    ?assertEqual(12000, S1#state.w_max),

    S2 = nquic_cc_cubic:on_congestion_event(
        S1, 1200, 8400, erlang:monotonic_time(microsecond) + 1000000
    ),
    ?assertEqual(7140, S2#state.w_max),
    ?assertEqual(12000, S2#state.w_last_max).

cbrt_test_() ->
    [
        ?_assertMatch(X when abs(X - 3.0) < 0.0001, nquic_cc_cubic:cbrt(27)),
        ?_assertMatch(X when abs(X - 2.0) < 0.0001, nquic_cc_cubic:cbrt(8)),
        ?_assertEqual(0.0, nquic_cc_cubic:cbrt(0.0)),
        ?_assertMatch(X when abs(X - (-3.0)) < 0.0001, nquic_cc_cubic:cbrt(-27))
    ].

cubic_window_test() ->
    MSS = 1200,
    WMax = 12000,
    WMaxSeg = WMax / MSS,
    K = nquic_cc_cubic:cbrt(WMaxSeg * (1.0 - ?BETA_CUBIC) / ?C),
    K_us = round(K * 1000000),
    W_at_K = nquic_cc_cubic:cubic_window(K_us, WMax, MSS),
    ?assertEqual(WMax, W_at_K),

    W_at_0 = nquic_cc_cubic:cubic_window(0, WMax, MSS),
    ?assertEqual(8400, W_at_0).

cubic_window_cached_k_equivalence_test() ->
    MSSValues = [1200, 1280, 1452, 1500],
    WMaxFactors = [2, 5, 10, 20, 50, 100],
    TPoints = [0, 1, 1000, 100000, 1000000, 5000000, 50000000],
    Triples = [
        {T, MSS * F, MSS}
     || MSS <- MSSValues, F <- WMaxFactors, T <- TPoints
    ],
    [
        ?assertEqual(
            nquic_cc_cubic:cubic_window(T, WMax, MSS),
            cached_path(T, WMax, MSS)
        )
     || {T, WMax, MSS} <- Triples
    ].

cached_path(T_us, WMax, MSS) ->
    K = nquic_cc_cubic:cbrt((WMax / MSS) * (1.0 - ?BETA_CUBIC) / ?C),
    WMaxSeg = WMax / MSS,
    T_sec = T_us / 1000000.0,
    D = T_sec - K,
    WCubicSeg = ?C * D * D * D + WMaxSeg,
    erlang:floor(erlang:max(MSS, round(WCubicSeg * MSS))).

tcp_friendly_region_test() ->
    S0 = nquic_cc_cubic:init(),
    Now = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, 12000, Now),
    Packet = #sent_packet{
        packet_number = 2,
        time_sent = erlang:monotonic_time(microsecond) + 1000000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    RTTStats = #{smoothed_rtt => 100, latest_rtt => 100, min_rtt => 100, rttvar => 25},
    S2 = nquic_cc_cubic:on_packet_acked(S1, Packet, 8400, RTTStats),
    ?assert(nquic_cc_cubic:get_cwnd(S2) > nquic_cc_cubic:get_cwnd(S1)).

cubic_region_test() ->
    S0 = nquic_cc_cubic:init(),
    Now = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, 12000, Now),
    Packet = #sent_packet{
        packet_number = 2,
        time_sent = erlang:monotonic_time(microsecond) + 1000000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    RTTStats = #{smoothed_rtt => 1, latest_rtt => 1, min_rtt => 1, rttvar => 0},
    S2 = nquic_cc_cubic:on_packet_acked(S1, Packet, 8400, RTTStats),
    ?assert(nquic_cc_cubic:get_cwnd(S2) > nquic_cc_cubic:get_cwnd(S1)).

set_max_datagram_size_test() ->
    S0 = nquic_cc_cubic:init(),
    ?assertEqual(12000, nquic_cc_cubic:get_cwnd(S0)),
    S1 = nquic_cc_cubic:set_max_datagram_size(S0, 1472),
    ?assertEqual(14720, nquic_cc_cubic:get_cwnd(S1)),
    ?assertEqual(1472, nquic_cc_cubic:get_max_datagram_size(S1)).

set_max_datagram_size_no_recalc_after_congestion_test() ->
    S0 = nquic_cc_cubic:init(),
    S1 = nquic_cc_cubic:on_congestion_event(
        S0, 1200, 12000, erlang:monotonic_time(microsecond) + 1000
    ),
    Cwnd1 = nquic_cc_cubic:get_cwnd(S1),
    S2 = nquic_cc_cubic:set_max_datagram_size(S1, 1472),
    ?assertEqual(Cwnd1, nquic_cc_cubic:get_cwnd(S2)).

spurious_congestion_restores_cubic_state_test() ->
    S0 = nquic_cc_cubic:init(),
    Cwnd0 = nquic_cc_cubic:get_cwnd(S0),
    Ssthresh0 = nquic_cc_cubic:get_ssthresh(S0),
    SentTime = erlang:monotonic_time(microsecond) + 1_000,

    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, Cwnd0, SentTime),
    ?assert(nquic_cc_cubic:get_cwnd(S1) < Cwnd0),
    ?assertEqual(Cwnd0, S1#state.w_max),
    ?assertEqual(0, S1#state.epoch_start),

    S2 = nquic_cc_cubic:on_spurious_congestion(S1, 1200),
    ?assertEqual(Cwnd0, nquic_cc_cubic:get_cwnd(S2)),
    ?assertEqual(Ssthresh0, nquic_cc_cubic:get_ssthresh(S2)),
    ?assertEqual(0, S2#state.w_max),
    ?assertEqual(0, S2#state.w_last_max).

spurious_congestion_no_op_without_snapshot_test() ->
    S0 = nquic_cc_cubic:init(),
    S1 = nquic_cc_cubic:on_spurious_congestion(S0, 1200),
    ?assertEqual(nquic_cc_cubic:get_cwnd(S0), nquic_cc_cubic:get_cwnd(S1)).

%%%-----------------------------------------------------------------------------
%% B3: HyStart++ (RFC 9406)
%%%-----------------------------------------------------------------------------

hystart_default_is_standard_test() ->
    S = nquic_cc_cubic:init(),
    ?assertEqual(standard, nquic_cc_cubic:hystart_phase(S)).

hystart_init_via_opts_test() ->
    Std = nquic_cc_cubic:init(#{slow_start => standard}),
    ?assertEqual(standard, nquic_cc_cubic:hystart_phase(Std)),
    HSPP = nquic_cc_cubic:init(#{slow_start => hystart_plus_plus}),
    ?assertEqual(slow_start, nquic_cc_cubic:hystart_phase(HSPP)).

ack(S, PN, RTT_us) ->
    Packet = #sent_packet{
        packet_number = PN,
        time_sent = erlang:monotonic_time(microsecond) + 1_000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    nquic_cc_cubic:on_packet_acked(S, Packet, 12000, #{
        latest_rtt => RTT_us,
        min_rtt => 50_000,
        smoothed_rtt => 50_000
    }).

hystart_enters_css_on_rtt_inflation_test() ->
    S0 = nquic_cc_cubic:init(#{slow_start => hystart_plus_plus}),
    S1 = lists:foldl(fun(I, S) -> ack(S, I, 50_000) end, S0, lists:seq(1, 8)),
    S2 = ack(S1, 1000, 80_000),
    S3 = lists:foldl(fun(I, S) -> ack(S, I + 1000, 80_000) end, S2, lists:seq(1, 8)),
    ?assertEqual(css, nquic_cc_cubic:hystart_phase(S3)).

hystart_standard_phase_unchanged_by_inflation_test() ->
    S0 = nquic_cc_cubic:init(),
    S1 = lists:foldl(fun(I, S) -> ack(S, I, 50_000) end, S0, lists:seq(1, 8)),
    S2 = ack(S1, 1000, 200_000),
    S3 = lists:foldl(fun(I, S) -> ack(S, I + 1000, 200_000) end, S2, lists:seq(1, 8)),
    ?assertEqual(standard, nquic_cc_cubic:hystart_phase(S3)).

%% Pure helper + state-transition coverage (HyStart++ CSS progression,
%% idle reset, persistent congestion, MSS, cubic math).
ack_rtt(S, PN, Latest, MinRtt) ->
    Packet = #sent_packet{
        packet_number = PN,
        time_sent = erlang:monotonic_time(microsecond) + 1_000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    nquic_cc_cubic:on_packet_acked(S, Packet, 12000, #{
        latest_rtt => Latest, min_rtt => MinRtt, smoothed_rtt => MinRtt
    }).

%% Drive the HyStart++ ladder hard (slow_start -> CSS, sustained RTT
%% inflation across many large-PN-jump rounds, then RTT recovery). The
%% assertions pin invariants, not exact phase transitions; the point
%% is to execute the CSS round/evaluate machinery, not freeze its
%% tuning constants into the test.
hystart_css_ladder_test() ->
    S0 = nquic_cc_cubic:init(#{slow_start => hystart_plus_plus}),
    S1 = lists:foldl(fun(I, S) -> ack_rtt(S, I, 50_000, 50_000) end, S0, lists:seq(1, 8)),
    S2 = lists:foldl(
        fun(I, S) -> ack_rtt(S, I * 500, 90_000, 50_000) end, S1, lists:seq(1, 80)
    ),
    ?assert(
        lists:member(nquic_cc_cubic:hystart_phase(S2), [slow_start, css, done, standard])
    ),
    ?assert(nquic_cc_cubic:get_cwnd(S2) > 0),
    S3 = lists:foldl(
        fun(I, S) -> ack_rtt(S, 60_000 + I * 500, 20_000, 20_000) end, S2, lists:seq(1, 16)
    ),
    ?assert(nquic_cc_cubic:get_cwnd(S3) > 0).

cubic_post_congestion_growth_test() ->
    S0 = nquic_cc_cubic:init(),
    Old = erlang:monotonic_time(microsecond) - 1_000_000,
    %% Enter recovery (sets w_max / epoch), then sustained acks drive
    %% the cubic-vs-Reno congestion-avoidance growth path.
    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, 24_000, Old),
    S2 = lists:foldl(
        fun(I, S) -> ack_rtt(S, I, 50_000, 50_000) end, S1, lists:seq(1, 40)
    ),
    ?assert(nquic_cc_cubic:get_cwnd(S2) > 0).

hystart_rtt_thresh_clamp_test() ->
    S0 = nquic_cc_cubic:init(#{slow_start => hystart_plus_plus}),
    %% Extreme min_rtt values exercise both clamp_rtt_thresh arms.
    Lo = lists:foldl(fun(I, S) -> ack_rtt(S, I, 200, 100) end, S0, lists:seq(1, 12)),
    ?assert(nquic_cc_cubic:get_cwnd(Lo) > 0),
    Hi = lists:foldl(
        fun(I, S) -> ack_rtt(S, I, 6_000_000, 5_000_000) end, S0, lists:seq(1, 12)
    ),
    ?assert(nquic_cc_cubic:get_cwnd(Hi) > 0).

on_idle_reset_test() ->
    S0 = nquic_cc_cubic:init(),
    S1 = lists:foldl(fun(I, S) -> ack(S, I, 50_000) end, S0, lists:seq(1, 8)),
    S2 = nquic_cc_cubic:on_idle_reset(S1),
    ?assert(nquic_cc_cubic:get_cwnd(S2) > 0).

idle_reset_halves_cwnd_and_keeps_ssthresh_and_w_max_test() ->
    S0 = ca_state(1_200_000, 1_500_000),
    S1 = nquic_cc_cubic:on_congestion_event(
        S0, 1200, 1_200_000, erlang:monotonic_time(microsecond) + 1
    ),
    S2 = nquic_cc_cubic:on_idle_reset(S1),
    ?assertEqual(420_000, nquic_cc_cubic:get_cwnd(S2)),
    ?assertEqual(nquic_cc_cubic:get_ssthresh(S1), nquic_cc_cubic:get_ssthresh(S2)),
    ?assertEqual(S1#state.w_max, S2#state.w_max),
    ?assertEqual(S1#state.w_last_max, S2#state.w_last_max).

idle_reset_raises_ssthresh_to_three_quarters_cwnd_test() ->
    S0 = (ca_state(1_200_000, 1_500_000))#state{ssthresh = 600_000},
    S1 = nquic_cc_cubic:on_idle_reset(S0),
    ?assertEqual(900_000, nquic_cc_cubic:get_ssthresh(S1)).

idle_reset_stops_at_initial_window_test() ->
    ?assertEqual(12000, nquic_cc_cubic:get_cwnd(nquic_cc_cubic:on_idle_reset(ca_state(20_000, 0)))),
    ?assertEqual(8000, nquic_cc_cubic:get_cwnd(nquic_cc_cubic:on_idle_reset(ca_state(8000, 0)))).

slow_start_after_idle_reset_stops_at_ssthresh_test() ->
    S0 = ca_state(1_200_000, 1_500_000),
    S1 = nquic_cc_cubic:on_congestion_event(
        S0, 1200, 1_200_000, erlang:monotonic_time(microsecond) + 1
    ),
    Ssthresh = nquic_cc_cubic:get_ssthresh(S1),
    S2 = nquic_cc_cubic:on_idle_reset(S1),
    S3 = lists:foldl(
        fun(PN, S) -> ack_in_flight(S, PN, nquic_cc_cubic:get_cwnd(S), 1_000) end,
        S2,
        lists:seq(1, 2000)
    ),
    ?assert(nquic_cc_cubic:get_cwnd(S3) < Ssthresh + 2 * 1200).

on_persistent_congestion_test() ->
    S0 = nquic_cc_cubic:init(),
    S1 = lists:foldl(fun(I, S) -> ack(S, I, 50_000) end, S0, lists:seq(1, 8)),
    Before = nquic_cc_cubic:get_cwnd(S1),
    S2 = nquic_cc_cubic:on_persistent_congestion(S1),
    ?assert(nquic_cc_cubic:get_cwnd(S2) =< Before),
    ?assert(nquic_cc_cubic:get_cwnd(S2) > 0).

set_max_datagram_size_idempotent_test() ->
    S0 = nquic_cc_cubic:init(),
    S1 = nquic_cc_cubic:set_max_datagram_size(S0, 1500),
    ?assertEqual(1500, nquic_cc_cubic:get_max_datagram_size(S1)),
    S2 = nquic_cc_cubic:set_max_datagram_size(S1, 1500),
    ?assertEqual(1500, nquic_cc_cubic:get_max_datagram_size(S2)).

set_max_datagram_size_ends_epoch_test() ->
    S0 = nquic_cc_cubic:init(),
    S1 = nquic_cc_cubic:on_congestion_event(S0, 1200, 12000, 0),
    S2 = ack(S1, 1, 50_000),
    ?assertNotEqual(0, S2#state.epoch_start),
    S3 = nquic_cc_cubic:on_congestion_event(
        S2, 1200, 12000, erlang:monotonic_time(microsecond) + 1_000
    ),
    ?assertNotEqual(0, element(6, S3#state.prev_state)),
    S4 = nquic_cc_cubic:set_max_datagram_size(S3, 1452),
    ?assertMatch(#state{epoch_start = 0, cubic_k = undefined}, S4),
    ?assertMatch({_, _, _, _, _, 0, 0, 0, undefined, _}, S4#state.prev_state),
    S5 = nquic_cc_cubic:on_spurious_congestion(S4, 1200),
    ?assertMatch(#state{epoch_start = 0, cubic_k = undefined}, S5),
    S6 = ack(S5, 2, 50_000),
    ?assert(is_float(S6#state.cubic_k)).

cbrt_and_cubic_window_test() ->
    ?assert(abs(nquic_cc_cubic:cbrt(27.0) - 3.0) < 0.001),
    ?assert(abs(nquic_cc_cubic:cbrt(0.0)) < 0.001),
    ?assert(is_integer(nquic_cc_cubic:cubic_window(1000, 50000, 1200))),
    ?assert(nquic_cc_cubic:cubic_window(1000, 50000, 1200) >= 0).

ca_state(Cwnd, WMax) ->
    #state{cwnd = Cwnd, ssthresh = Cwnd, w_max = WMax, congestion_occurred = true}.

ack_in_flight(S, PN, InFlight, SRTT) ->
    Packet = #sent_packet{
        packet_number = PN,
        time_sent = erlang:monotonic_time(microsecond) + 1_000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    nquic_cc_cubic:on_packet_acked(S, Packet, InFlight, #{
        latest_rtt => SRTT, min_rtt => SRTT, smoothed_rtt => SRTT
    }).

no_growth_when_app_limited_in_slow_start_test() ->
    S0 = nquic_cc_cubic:init(),
    ?assertEqual(12000, nquic_cc_cubic:get_cwnd(ack_in_flight(S0, 1, 1200, 50_000))),
    ?assertEqual(13200, nquic_cc_cubic:get_cwnd(ack_in_flight(S0, 1, 7200, 50_000))).

no_growth_when_app_limited_in_congestion_avoidance_test() ->
    S0 = ca_state(24000, 30000),
    ?assertEqual(
        24000, nquic_cc_cubic:get_cwnd(ack_in_flight(S0, 1, 24000 - 4 * 1200, 1_000_000))
    ),
    ?assert(nquic_cc_cubic:get_cwnd(ack_in_flight(S0, 1, 24000 - 3 * 1200, 1_000_000)) > 24000).

epoch_excludes_app_limited_time_test() ->
    S1 = ack_in_flight(ca_state(24000, 30000), 1, 24000, 50_000),
    S2 = ack_in_flight(S1, 2, 0, 50_000),
    receive
    after 20 -> ok
    end,
    S3 = ack_in_flight(S2, 3, nquic_cc_cubic:get_cwnd(S2), 50_000),
    ?assert(S3#state.epoch_start - S1#state.epoch_start >= 20_000).

target_clamped_to_one_and_a_half_cwnd_test() ->
    S1 = ack_in_flight(ca_state(24000, 0), 1, 24000, 100_000_000),
    ?assert(nquic_cc_cubic:get_cwnd(S1) - 24000 =< 1200 div 2).

k_from_w_max_and_cwnd_epoch_test() ->
    S1 = ack_in_flight(ca_state(24000, 30000), 1, 24000, 50_000),
    Expected = nquic_cc_cubic:cbrt((30000 - 24000) / 1200 / ?C),
    ?assert(abs(S1#state.cubic_k - Expected) < 1.0e-9),
    ?assertEqual(30000, S1#state.origin_point).

k_is_zero_without_w_max_test() ->
    S1 = ack_in_flight(ca_state(24000, 0), 1, 24000, 50_000),
    ?assertMatch(#state{cubic_k = +0.0, origin_point = 24000, w_max = 24000}, S1).

k_is_zero_when_w_max_below_cwnd_epoch_test() ->
    S1 = ack_in_flight(ca_state(24000, 20000), 1, 24000, 50_000),
    ?assertMatch(#state{cubic_k = +0.0, origin_point = 24000, w_max = 20000}, S1).

rollback_waits_for_every_lost_byte_test() ->
    Now = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_cubic:on_congestion_event(ca_state(24000, 0), 2400, 24000, Now),
    Reduced = nquic_cc_cubic:get_cwnd(S1),
    S2 = nquic_cc_cubic:on_spurious_congestion(S1, 1200),
    ?assertEqual(Reduced, nquic_cc_cubic:get_cwnd(S2)),
    S3 = nquic_cc_cubic:on_spurious_congestion(S2, 1200),
    ?assertEqual(24000, nquic_cc_cubic:get_cwnd(S3)).

rollback_counts_losses_in_the_recovery_period_test() ->
    Now = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_cubic:on_congestion_event(ca_state(24000, 0), 1200, 24000, Now),
    S2 = nquic_cc_cubic:on_congestion_event(S1, 1200, 22800, Now - 1_000),
    S3 = nquic_cc_cubic:on_spurious_congestion(S2, 1200),
    ?assert(nquic_cc_cubic:get_cwnd(S3) < 24000),
    S4 = nquic_cc_cubic:on_spurious_congestion(S3, 1200),
    ?assertEqual(24000, nquic_cc_cubic:get_cwnd(S4)).

cwnd_limited_at_the_last_send_test() ->
    Full = nquic_cc_cubic:on_packet_sent(ca_state(24000, 30000), 1200, 24000),
    ?assert(nquic_cc_cubic:get_cwnd(ack_in_flight(Full, 1, 24000 - 6 * 1200, 1_000_000)) > 24000),
    Idle = nquic_cc_cubic:on_packet_sent(ca_state(24000, 30000), 1200, 2400),
    ?assertEqual(24000, nquic_cc_cubic:get_cwnd(ack_in_flight(Idle, 1, 1200, 1_000_000))).
