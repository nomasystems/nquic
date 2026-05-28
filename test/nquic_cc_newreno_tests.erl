%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_cc_newreno}.
%%%-------------------------------------------------------------------
-module(nquic_cc_newreno_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_loss.hrl").
initial_window_test_() ->
    [
        ?_assertEqual(12000, nquic_cc_newreno:initial_window(1200)),
        ?_assertEqual(14720, nquic_cc_newreno:initial_window(1472)),
        ?_assertEqual(14720, nquic_cc_newreno:initial_window(1500)),
        ?_assertEqual(16000, nquic_cc_newreno:initial_window(8000))
    ].

set_max_datagram_size_recalc_test() ->
    S0 = nquic_cc_newreno:init(),
    ?assertEqual(12000, nquic_cc_newreno:get_cwnd(S0)),
    S1 = nquic_cc_newreno:set_max_datagram_size(S0, 1472),
    ?assertEqual(14720, nquic_cc_newreno:get_cwnd(S1)),
    ?assertEqual(1472, nquic_cc_newreno:get_max_datagram_size(S1)).

set_max_datagram_size_no_recalc_after_congestion_test() ->
    S0 = nquic_cc_newreno:init(),
    S1 = nquic_cc_newreno:on_congestion_event(
        S0, 1200, 12000, erlang:monotonic_time(microsecond) + 1000
    ),
    Cwnd1 = nquic_cc_newreno:get_cwnd(S1),
    S2 = nquic_cc_newreno:set_max_datagram_size(S1, 1472),
    ?assertEqual(Cwnd1, nquic_cc_newreno:get_cwnd(S2)).

min_window_uses_mss_test() ->
    S0 = nquic_cc_newreno:init(),
    S1 = nquic_cc_newreno:set_max_datagram_size(S0, 1472),
    S2 = nquic_cc_newreno:on_congestion_event(
        S1, 1472, 14720, erlang:monotonic_time(microsecond) + 1000
    ),
    ?assertEqual(7360, nquic_cc_newreno:get_cwnd(S2)).

spurious_congestion_restores_cwnd_test() ->
    S0 = nquic_cc_newreno:init(),
    Cwnd0 = nquic_cc_newreno:get_cwnd(S0),
    Ssthresh0 = nquic_cc_newreno:get_ssthresh(S0),

    SentTime = erlang:monotonic_time(microsecond) + 1_000,
    S1 = nquic_cc_newreno:on_congestion_event(S0, 1200, Cwnd0, SentTime),
    ?assert(nquic_cc_newreno:get_cwnd(S1) < Cwnd0),

    S2 = nquic_cc_newreno:on_spurious_congestion(S1),
    ?assertEqual(Cwnd0, nquic_cc_newreno:get_cwnd(S2)),
    ?assertEqual(Ssthresh0, nquic_cc_newreno:get_ssthresh(S2)).

spurious_congestion_no_op_without_snapshot_test() ->
    S0 = nquic_cc_newreno:init(),
    Cwnd0 = nquic_cc_newreno:get_cwnd(S0),
    S1 = nquic_cc_newreno:on_spurious_congestion(S0),
    ?assertEqual(Cwnd0, nquic_cc_newreno:get_cwnd(S1)).

spurious_snapshot_cleared_when_cwnd_grows_past_test() ->
    S0 = nquic_cc_newreno:init(),
    Cwnd0 = nquic_cc_newreno:get_cwnd(S0),
    SentTime = erlang:monotonic_time(microsecond),
    S1 = nquic_cc_newreno:on_congestion_event(S0, 1200, Cwnd0, SentTime),
    Pkt = #sent_packet{
        packet_number = 99,
        time_sent = SentTime + 1_000_000,
        size = Cwnd0,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    },
    SGrown = lists:foldl(
        fun(_, Acc) -> nquic_cc_newreno:on_packet_acked(Acc, Pkt, 0, #{}) end,
        S1,
        lists:seq(1, 20)
    ),
    ?assert(nquic_cc_newreno:get_cwnd(SGrown) >= Cwnd0),
    SAfter = nquic_cc_newreno:on_spurious_congestion(SGrown),
    ?assertEqual(nquic_cc_newreno:get_cwnd(SGrown), nquic_cc_newreno:get_cwnd(SAfter)).
