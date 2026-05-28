-module(nquic_cc_cubic).

-moduledoc """
CUBIC congestion control per RFC 8312.

CUBIC uses a cubic function for window growth during congestion avoidance,
achieving better bandwidth utilization on high-BDP paths than NewReno while
remaining TCP-friendly. Includes fast convergence (Section 4.6) and a
TCP-friendly region (Section 4.2) where W_est tracks standard TCP growth.
""".

-behaviour(nquic_cc).

-include("nquic_loss.hrl").
-export([
    get_cwnd/1,
    get_ssthresh/1,
    init/0,
    init/1,
    on_congestion_event/4,

    on_idle_reset/1,
    on_packet_acked/4,
    on_packet_sent/3,
    on_persistent_congestion/1,
    on_spurious_congestion/1
]).
-export([get_max_datagram_size/1, set_max_datagram_size/2]).
-export([cbrt/1, cubic_window/3]).
-export([hystart_phase/1]).

-define(C, 0.4).
-define(BETA_CUBIC, 0.7).
-define(ALPHA_CUBIC, (3.0 * (1.0 - ?BETA_CUBIC) / (1.0 + ?BETA_CUBIC))).
-define(INFINITY_SSTHRESH, 16#FFFFFFFFFFFFFFFF).
-define(NO_RECOVERY, -576460752303423488).

-define(HYSTART_RTT_SAMPLE_COUNT, 8).
-define(HYSTART_MIN_RTT_THRESH_US, 4_000).
-define(HYSTART_MAX_RTT_THRESH_US, 16_000).
-define(HYSTART_N_RTT_SAMPLE, 8).
-define(HYSTART_CSS_GROWTH_DIVISOR, 4).
-define(HYSTART_CSS_ROUNDS, 5).
-define(HYSTART_CSS_L, 8).

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
    css_round_count = 0 :: non_neg_integer()
}).

-spec cbrt(float()) -> float().
cbrt(+0.0) -> 0.0;
cbrt(X) when X > 0 -> math:pow(X, 1.0 / 3.0);
cbrt(X) -> -math:pow(-X, 1.0 / 3.0).

-spec clamp_rtt_thresh(non_neg_integer()) -> non_neg_integer().
clamp_rtt_thresh(T) when T < ?HYSTART_MIN_RTT_THRESH_US -> ?HYSTART_MIN_RTT_THRESH_US;
clamp_rtt_thresh(T) when T > ?HYSTART_MAX_RTT_THRESH_US -> ?HYSTART_MAX_RTT_THRESH_US;
clamp_rtt_thresh(T) -> T.

-spec compute_k(non_neg_integer(), pos_integer()) -> float().
compute_k(WMax, MSS) ->
    WMaxSeg = WMax / MSS,
    cbrt(WMaxSeg * (1.0 - ?BETA_CUBIC) / ?C).

-spec cubic_update(#state{}, non_neg_integer(), map()) -> #state{}.
cubic_update(State0, AckedBytes, RTTStats) ->
    #state{
        cwnd = Cwnd,
        max_datagram_size = MSS,
        epoch_start = EpochStart0,
        w_max = WMax0,
        origin_point = OriginPoint0,
        tcp_cwnd = TcpCwnd0,
        cubic_k = CubicK0
    } = State0,

    Now = erlang:monotonic_time(microsecond),

    {EpochStart, OriginPoint, TcpCwnd, WMax, CubicK} =
        case EpochStart0 of
            0 ->
                NewWMax =
                    case WMax0 of
                        0 -> Cwnd;
                        _ -> WMax0
                    end,
                {Now, NewWMax, Cwnd, NewWMax, compute_k(NewWMax, MSS)};
            _ ->
                {EpochStart0, OriginPoint0, TcpCwnd0, WMax0, CubicK0}
        end,

    State1 = State0#state{
        epoch_start = EpochStart,
        origin_point = OriginPoint,
        tcp_cwnd = TcpCwnd,
        w_max = WMax,
        cubic_k = CubicK
    },

    T_us = Now - EpochStart,

    SRTT_us = maps:get(smoothed_rtt, RTTStats, 0),

    WCubic = cubic_window_k(T_us + SRTT_us, WMax, MSS, CubicK),

    NewTcpCwnd =
        case TcpCwnd of
            0 ->
                Cwnd;
            _ ->
                TcpInc = trunc(?ALPHA_CUBIC * MSS * AckedBytes / TcpCwnd),
                TcpCwnd + max(1, TcpInc)
        end,

    NewCwnd =
        case WCubic < NewTcpCwnd of
            true ->
                NewTcpCwnd;
            false ->
                case WCubic > Cwnd of
                    true ->
                        Inc = (WCubic - Cwnd) * MSS div Cwnd,
                        Cwnd + max(1, Inc);
                    false ->
                        Cwnd
                end
        end,

    State1#state{cwnd = NewCwnd, tcp_cwnd = NewTcpCwnd}.

-spec cubic_window(non_neg_integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
cubic_window(T_us, WMax, MSS) ->
    cubic_window_k(T_us, WMax, MSS, compute_k(WMax, MSS)).

-spec cubic_window_k(non_neg_integer(), non_neg_integer(), pos_integer(), float()) ->
    non_neg_integer().
cubic_window_k(T_us, WMax, MSS, K) ->
    WMaxSeg = WMax / MSS,
    T_sec = T_us / 1000000.0,
    D = T_sec - K,
    WCubicSeg = ?C * D * D * D + WMaxSeg,
    erlang:floor(erlang:max(MSS, round(WCubicSeg * MSS))).

-doc "Get the current congestion window size in bytes.".
-spec get_cwnd(#state{}) -> non_neg_integer().
get_cwnd(#state{cwnd = Cwnd}) -> Cwnd.

-doc "Get the current maximum datagram size in bytes.".
-spec get_max_datagram_size(#state{}) -> pos_integer().
get_max_datagram_size(#state{max_datagram_size = Size}) -> Size.

-doc "Get the current slow start threshold.".
-spec get_ssthresh(#state{}) -> non_neg_integer().
get_ssthresh(#state{ssthresh = S}) -> S.

-spec hystart_evaluate(#state{}, map()) -> #state{}.
hystart_evaluate(#state{rtt_sample_count = Count} = State, _RTTStats) when
    Count < ?HYSTART_RTT_SAMPLE_COUNT
->
    State;
hystart_evaluate(#state{hystart_phase = slow_start} = State, RTTStats) ->
    #state{cwnd = Cwnd, last_round_min_rtt = LastMin, current_round_min_rtt = CurMin} = State,
    MinRTT = maps:get(min_rtt, RTTStats, LastMin),
    Thresh = clamp_rtt_thresh(MinRTT div ?HYSTART_N_RTT_SAMPLE),
    case CurMin > LastMin + Thresh of
        true ->
            State#state{
                hystart_phase = css,
                ssthresh = Cwnd,
                css_baseline_min_rtt = CurMin,
                css_round_count = 0
            };
        false ->
            State
    end;
hystart_evaluate(#state{hystart_phase = css} = State, _RTTStats) ->
    #state{current_round_min_rtt = CurMin, css_baseline_min_rtt = Baseline} = State,
    case CurMin < Baseline of
        true ->
            State#state{hystart_phase = slow_start, css_round_count = 0};
        false ->
            State
    end;
hystart_evaluate(State, _RTTStats) ->
    State.

-spec hystart_observe(#state{}, nquic_packet_number:t(), map()) -> #state{}.
hystart_observe(#state{hystart_phase = standard} = State, _PN, _RTTStats) ->
    State;
hystart_observe(#state{hystart_phase = done} = State, _PN, _RTTStats) ->
    State;
hystart_observe(State, PN, RTTStats) ->
    LatestRTT = maps:get(latest_rtt, RTTStats, 0),
    case LatestRTT of
        0 ->
            State;
        _ ->
            State1 = hystart_round_boundary(State, PN),
            State2 = hystart_update_round_min(State1, LatestRTT),
            hystart_evaluate(State2, RTTStats)
    end.

-doc """
Return the HyStart++ phase. `standard` means HyStart++ is disabled,
`slow_start` / `css` / `done` track the ladder. Used by tests and
diagnostic accessors; production code does not need to inspect it.
""".
-spec hystart_phase(#state{}) -> standard | slow_start | css | done.
hystart_phase(#state{hystart_phase = P}) -> P.

-spec hystart_round_boundary(#state{}, nquic_packet_number:t()) -> #state{}.
hystart_round_boundary(#state{last_round_largest_pn = Marker} = State, PN) when PN =< Marker ->
    State;
hystart_round_boundary(State, PN) ->
    #state{
        cwnd = Cwnd,
        max_datagram_size = MSS,
        current_round_min_rtt = CurMin,
        hystart_phase = Phase,
        css_round_count = CssRounds
    } = State,
    NewCssRounds =
        case Phase of
            css -> CssRounds + 1;
            _ -> CssRounds
        end,
    State1 = State#state{
        last_round_min_rtt = CurMin,
        current_round_min_rtt = ?INFINITY_SSTHRESH,
        rtt_sample_count = 0,
        last_round_largest_pn = PN + max(1, Cwnd div MSS),
        css_round_count = NewCssRounds
    },
    case Phase =:= css andalso NewCssRounds >= ?HYSTART_CSS_ROUNDS of
        true -> State1#state{hystart_phase = done, ssthresh = Cwnd};
        false -> State1
    end.

-spec hystart_update_round_min(#state{}, non_neg_integer()) -> #state{}.
hystart_update_round_min(
    #state{current_round_min_rtt = Cur, rtt_sample_count = Count} = State, LatestRTT
) ->
    State#state{
        current_round_min_rtt = min(Cur, LatestRTT),
        rtt_sample_count = Count + 1
    }.

-doc "Initialize CUBIC state with default 1200-byte MSS.".
-spec init() -> #state{}.
init() ->
    init(#{}).

-doc """
Initialize CUBIC state with options.
Recognises:
  * `mss`: pos_integer override of the 1200-byte default.
  * `slow_start`: `standard` (classic Reno-style slow start, the
    default) or `hystart_plus_plus` (RFC 9406, exits slow start on
    RTT inflation rather than waiting for loss).
""".
-spec init(map()) -> #state{}.
init(Opts) ->
    MSS = maps:get(mss, Opts, 1200),
    Phase =
        case maps:get(slow_start, Opts, standard) of
            standard -> standard;
            hystart_plus_plus -> slow_start;
            _ -> standard
        end,
    #state{
        cwnd = initial_window(MSS),
        max_datagram_size = MSS,
        hystart_phase = Phase
    }.

-spec initial_window(pos_integer()) -> non_neg_integer().
initial_window(MSS) ->
    erlang:floor(erlang:min(10 * MSS, erlang:max(14720, 2 * MSS))).

-spec maybe_clear_prev_state(#state{}) -> #state{}.
maybe_clear_prev_state(#state{prev_state = undefined} = S) ->
    S;
maybe_clear_prev_state(#state{cwnd = Cwnd, prev_state = Snap} = S) ->
    PrevCwnd = element(1, Snap),
    case Cwnd >= PrevCwnd of
        true -> S#state{prev_state = undefined};
        false -> S
    end.

-doc "Reduce the congestion window on a loss event.".
-spec on_congestion_event(#state{}, non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    #state{}.
on_congestion_event(State, _LostBytes, _BytesInFlight, SentTime) ->
    #state{
        cwnd = Cwnd,
        ssthresh = OldSsthresh,
        recovery_start_time = RecoveryStart,
        max_datagram_size = MSS,
        w_max = OldWMax,
        w_last_max = OldWLastMax,
        epoch_start = OldEpochStart,
        origin_point = OldOriginPoint,
        tcp_cwnd = OldTcpCwnd,
        cubic_k = OldCubicK,
        congestion_occurred = OldCongOcc
    } = State,
    case SentTime =< RecoveryStart of
        true ->
            State;
        false ->
            Now = erlang:monotonic_time(microsecond),
            MinWindow = 2 * MSS,
            NewWMax =
                case Cwnd < OldWMax of
                    true ->
                        (Cwnd * 17) div 20;
                    false ->
                        Cwnd
                end,
            NewSsthresh = max(MinWindow, trunc(Cwnd * ?BETA_CUBIC)),
            State#state{
                cwnd = NewSsthresh,
                ssthresh = NewSsthresh,
                recovery_start_time = Now,
                w_last_max = OldWMax,
                w_max = NewWMax,
                epoch_start = 0,
                origin_point = 0,
                tcp_cwnd = 0,
                cubic_k = undefined,
                congestion_occurred = true,
                prev_state =
                    {Cwnd, OldSsthresh, RecoveryStart, OldWMax, OldWLastMax, OldEpochStart,
                        OldOriginPoint, OldTcpCwnd, OldCubicK, OldCongOcc}
            }
    end.

-doc """
Reset CUBIC state to the initial window after an idle period (RFC 9002
Section 7.8). All recovery/epoch bookkeeping is cleared so the next
acked packet starts a fresh slow-start phase.
""".
-spec on_idle_reset(#state{}) -> #state{}.
on_idle_reset(#state{max_datagram_size = MSS} = State) ->
    State#state{
        cwnd = initial_window(MSS),
        ssthresh = ?INFINITY_SSTHRESH,
        recovery_start_time = ?NO_RECOVERY,
        w_max = 0,
        w_last_max = 0,
        epoch_start = 0,
        origin_point = 0,
        tcp_cwnd = 0,
        cubic_k = undefined,
        congestion_occurred = false,
        prev_state = undefined
    }.

-doc "Grow the congestion window when a packet is acknowledged.".
-spec on_packet_acked(#state{}, #sent_packet{}, non_neg_integer(), map()) -> #state{}.
on_packet_acked(
    State,
    #sent_packet{time_sent = SentTime, packet_number = PN, size = AckedBytes},
    _BytesInFlight,
    RTTStats
) ->
    #state{
        cwnd = Cwnd,
        ssthresh = Ssthresh,
        recovery_start_time = RecoveryStart
    } = State,
    case SentTime =< RecoveryStart of
        true ->
            State;
        false when Cwnd < Ssthresh ->
            State1 = hystart_observe(State, PN, RTTStats),
            slow_start_grow(State1, AckedBytes);
        false ->
            maybe_clear_prev_state(cubic_update(State, AckedBytes, RTTStats))
    end.

-doc "Handle a sent packet (no-op for CUBIC).".
-spec on_packet_sent(#state{}, non_neg_integer(), non_neg_integer()) -> #state{}.
on_packet_sent(State, _BytesSent, _BytesInFlight) ->
    State.

-doc """
Collapse the congestion window to the minimum (`2 * max_datagram_size`)
on persistent congestion (RFC 9002 Section 7.6.2).
The CUBIC epoch is also reset (`epoch_start`, `origin_point`, `tcp_cwnd`,
`w_max`) so the next ACK after recovery starts a fresh growth phase from
the collapsed window. `recovery_start_time` is reset so subsequent ACKs
for newly sent packets are not filtered by the previous recovery period.
Any pending spurious-loss snapshot is discarded.
""".
-spec on_persistent_congestion(#state{}) -> #state{}.
on_persistent_congestion(State) ->
    #state{max_datagram_size = MSS} = State,
    MinWindow = 2 * MSS,
    State#state{
        cwnd = MinWindow,
        recovery_start_time = ?NO_RECOVERY,
        epoch_start = 0,
        origin_point = 0,
        tcp_cwnd = 0,
        w_max = 0,
        cubic_k = undefined,
        congestion_occurred = true,
        prev_state = undefined
    }.

-doc """
Roll back the most recent congestion-event reduction (RFC 9002 Appendix
A.10). No-op when no rollback snapshot is available.
""".
-spec on_spurious_congestion(#state{}) -> #state{}.
on_spurious_congestion(#state{prev_state = undefined} = State) ->
    State;
on_spurious_congestion(#state{prev_state = Snap} = State) ->
    {Cwnd, Ssthresh, RST, WMax, WLastMax, EpochStart, OriginPoint, TcpCwnd, CubicK, CongOcc} =
        Snap,
    State#state{
        cwnd = Cwnd,
        ssthresh = Ssthresh,
        recovery_start_time = RST,
        w_max = WMax,
        w_last_max = WLastMax,
        epoch_start = EpochStart,
        origin_point = OriginPoint,
        tcp_cwnd = TcpCwnd,
        cubic_k = CubicK,
        congestion_occurred = CongOcc,
        prev_state = undefined
    }.

-doc "Set the maximum datagram size, recalculating cwnd if still at initial window.".
-spec set_max_datagram_size(#state{}, pos_integer()) -> #state{}.
set_max_datagram_size(State, Size) when Size >= 1200 ->
    #state{congestion_occurred = CongOccurred, max_datagram_size = OldMSS} = State,
    NewCubicK =
        case Size =:= OldMSS of
            true -> State#state.cubic_k;
            false -> undefined
        end,
    case CongOccurred of
        false ->
            OldInitial = initial_window(OldMSS),
            NewInitial = initial_window(Size),
            OldCwnd = State#state.cwnd,
            NewCwnd =
                case OldCwnd =:= OldInitial of
                    true -> NewInitial;
                    false -> OldCwnd
                end,
            State#state{max_datagram_size = Size, cwnd = NewCwnd, cubic_k = NewCubicK};
        true ->
            State#state{max_datagram_size = Size, cubic_k = NewCubicK}
    end.

-spec slow_start_grow(#state{}, non_neg_integer()) -> #state{}.
slow_start_grow(#state{hystart_phase = css, max_datagram_size = MSS} = State, AckedBytes) ->
    Capped = min(AckedBytes, ?HYSTART_CSS_L * MSS),
    Inc = max(1, MSS * Capped div (?HYSTART_CSS_GROWTH_DIVISOR * MSS)),
    maybe_clear_prev_state(State#state{cwnd = State#state.cwnd + Inc});
slow_start_grow(#state{cwnd = Cwnd} = State, AckedBytes) ->
    maybe_clear_prev_state(State#state{cwnd = Cwnd + AckedBytes}).
