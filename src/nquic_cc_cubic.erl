-module(nquic_cc_cubic).

-moduledoc """
CUBIC congestion control per RFC 9438.

CUBIC uses a cubic function for window growth during congestion avoidance,
achieving better bandwidth utilization on high-BDP paths than NewReno while
remaining TCP-friendly. Includes fast convergence (Section 4.7) and a
Reno-friendly region (Section 4.3) where W_est tracks standard TCP growth.

The window does not grow while the sender is application limited
(Section 5.8, RFC 9002 §7.8), and the elapsed time of the cubic curve
excludes those periods (Section 4.2).
""".

-behaviour(nquic_cc).

-include("nquic_cc_cubic.hrl").
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
    on_spurious_congestion/2
]).
-export([get_max_datagram_size/1, set_max_datagram_size/2]).
-export([cbrt/1, cubic_epoch/3, cubic_window/3]).
-export([hystart_phase/1]).

-define(C, 0.4).
-define(BETA_CUBIC, 0.7).
-define(ALPHA_CUBIC, (3.0 * (1.0 - ?BETA_CUBIC) / (1.0 + ?BETA_CUBIC))).
-define(MAX_TARGET_GROWTH, 1.5).
-define(CWND_LIMITED_SLACK_SEGMENTS, 3).
-define(SLOW_START_LIMITED_DIVISOR, 2).

-define(HYSTART_N_RTT_SAMPLE, 8).
-define(HYSTART_MIN_RTT_THRESH_US, 4_000).
-define(HYSTART_MAX_RTT_THRESH_US, 16_000).
-define(HYSTART_MIN_RTT_DIVISOR, 8).
-define(HYSTART_CSS_GROWTH_DIVISOR, 4).
-define(HYSTART_CSS_ROUNDS, 5).
-define(HYSTART_CSS_L, 8).

-spec add_undo_bytes(#state{}, non_neg_integer()) -> #state{}.
add_undo_bytes(#state{prev_state = undefined} = State, _LostBytes) ->
    State;
add_undo_bytes(#state{undo_bytes = Undo} = State, LostBytes) ->
    State#state{undo_bytes = Undo + LostBytes}.

-spec cbrt(float()) -> float().
cbrt(+0.0) -> 0.0;
cbrt(X) when X > 0 -> math:pow(X, 1.0 / 3.0);
cbrt(X) -> -math:pow(-X, 1.0 / 3.0).

-spec clamp_rtt_thresh(non_neg_integer()) -> non_neg_integer().
clamp_rtt_thresh(T) when T < ?HYSTART_MIN_RTT_THRESH_US -> ?HYSTART_MIN_RTT_THRESH_US;
clamp_rtt_thresh(T) when T > ?HYSTART_MAX_RTT_THRESH_US -> ?HYSTART_MAX_RTT_THRESH_US;
clamp_rtt_thresh(T) -> T.

-doc """
The cubic curve of a congestion avoidance stage that starts at a window of
`CwndEpoch` bytes: `K` in seconds and the origin point in bytes, where the
curve is flat (RFC 9438 §4.2). When `WMax` is at or below `CwndEpoch`,
`K` is 0 and the origin point is `CwndEpoch` (RFC 9438 §4.10). The curve
starts at `CwndEpoch` in both cases.
""".
-spec cubic_epoch(non_neg_integer(), non_neg_integer(), pos_integer()) ->
    {float(), non_neg_integer()}.
cubic_epoch(WMax, CwndEpoch, MSS) when WMax > CwndEpoch ->
    {cbrt((WMax - CwndEpoch) / MSS / ?C), WMax};
cubic_epoch(_WMax, CwndEpoch, _MSS) ->
    {0.0, CwndEpoch}.

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
                {K, Origin} = cubic_epoch(NewWMax, Cwnd, MSS),
                {Now, Origin, Cwnd, NewWMax, K};
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

    WCubic = cubic_window_k(T_us + SRTT_us, OriginPoint, MSS, CubicK),

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
                Target = min(WCubic, trunc(?MAX_TARGET_GROWTH * Cwnd)),
                case Target > Cwnd of
                    true ->
                        Inc = (Target - Cwnd) * MSS div Cwnd,
                        Cwnd + max(1, Inc);
                    false ->
                        Cwnd
                end
        end,

    State1#state{cwnd = NewCwnd, tcp_cwnd = NewTcpCwnd}.

-doc """
The cubic window in bytes `T_us` microseconds into a congestion avoidance
stage that starts after a reduction from `WMax`, that is at
`cwnd_epoch = beta_cubic * WMax` (RFC 9438 §4.2).
""".
-spec cubic_window(non_neg_integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
cubic_window(T_us, WMax, MSS) ->
    cubic_window_k(T_us, WMax, MSS, cbrt(WMax / MSS * (1.0 - ?BETA_CUBIC) / ?C)).

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
    Count < ?HYSTART_N_RTT_SAMPLE
->
    State;
hystart_evaluate(#state{hystart_phase = slow_start} = State, RTTStats) ->
    #state{cwnd = Cwnd, last_round_min_rtt = LastMin, current_round_min_rtt = CurMin} = State,
    MinRTT = maps:get(min_rtt, RTTStats, LastMin),
    Thresh = clamp_rtt_thresh(MinRTT div ?HYSTART_MIN_RTT_DIVISOR),
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
    MSS = maps:get(mss, Opts, ?MIN_UDP_PAYLOAD_SIZE),
    Phase =
        case maps:get(slow_start, Opts, standard) of
            standard -> standard;
            hystart_plus_plus -> slow_start;
            _ -> standard
        end,
    #state{
        cwnd = nquic_cc_newreno:initial_window(MSS),
        max_datagram_size = MSS,
        hystart_phase = Phase
    }.

-spec is_cwnd_limited(slow_start | congestion_avoidance, non_neg_integer(), #state{}) ->
    boolean().
is_cwnd_limited(Phase, AckInFlight, #state{sent_in_flight = SentInFlight} = State) ->
    is_window_full(Phase, max(AckInFlight, SentInFlight), State).

-spec is_window_full(slow_start | congestion_avoidance, non_neg_integer(), #state{}) ->
    boolean().
is_window_full(slow_start, BytesInFlight, #state{cwnd = Cwnd}) when
    BytesInFlight > Cwnd div ?SLOW_START_LIMITED_DIVISOR
->
    true;
is_window_full(_Phase, BytesInFlight, #state{cwnd = Cwnd, max_datagram_size = MSS}) ->
    BytesInFlight + ?CWND_LIMITED_SLACK_SEGMENTS * MSS >= Cwnd.

-spec maybe_clear_prev_state(#state{}) -> #state{}.
maybe_clear_prev_state(#state{prev_state = undefined} = S) ->
    S;
maybe_clear_prev_state(#state{cwnd = Cwnd, prev_state = Snap} = S) ->
    PrevCwnd = element(1, Snap),
    case Cwnd >= PrevCwnd of
        true -> S#state{prev_state = undefined};
        false -> S
    end.

-doc """
Reduce the congestion window on a loss event. A loss of packets sent
before the start of the recovery period does not reduce the window again.
Its bytes count toward the rollback of the current reduction
(`on_spurious_congestion/2`).
""".
-spec on_congestion_event(#state{}, non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    #state{}.
on_congestion_event(State, LostBytes, _BytesInFlight, SentTime) ->
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
            add_undo_bytes(State, LostBytes);
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
                        OldOriginPoint, OldTcpCwnd, OldCubicK, OldCongOcc},
                undo_bytes = LostBytes,
                app_limited_since = undefined
            }
    end.

-doc """
Restart the window after one restart timeout of idle time (RFC 9002
§7.8, RFC 5681 §4.1). The window halves, but not below the initial
window. `ssthresh` becomes at least 3/4 of the old window, so the
slow start after the idle period ends near the old operating point.
`w_max` stays. The epoch, the recovery period and the rollback snapshot
are cleared.
""".
-spec on_idle_reset(#state{}) -> #state{}.
on_idle_reset(#state{cwnd = Cwnd, ssthresh = Ssthresh, max_datagram_size = MSS} = State) ->
    State#state{
        cwnd = max(Cwnd div 2, min(nquic_cc_newreno:initial_window(MSS), Cwnd)),
        ssthresh = max(Ssthresh, (Cwnd * 3) div 4),
        recovery_start_time = ?NO_RECOVERY,
        epoch_start = 0,
        origin_point = 0,
        tcp_cwnd = 0,
        cubic_k = undefined,
        prev_state = undefined,
        undo_bytes = 0,
        app_limited_since = undefined
    }.

-doc """
Grow the congestion window when a packet is acknowledged.

`BytesInFlight` is the number of bytes in flight before the ACK. The
window grows only when the sender is congestion window limited: the
larger of `BytesInFlight` and the bytes in flight after the last send is
within three segments of the window, or above half the window in slow
start. The owner processes a batch of ACK frames before it sends again,
so the value after the last send keeps the later frames of a batch
cwnd-limited. Otherwise the sender is application limited and the window
stays (RFC 9438 §5.8, RFC 9002 §7.8).
""".
-spec on_packet_acked(#state{}, #sent_packet{}, non_neg_integer(), map()) -> #state{}.
on_packet_acked(
    State,
    #sent_packet{time_sent = SentTime, packet_number = PN, size = AckedBytes},
    BytesInFlight,
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
            case is_cwnd_limited(slow_start, BytesInFlight, State1) of
                true -> slow_start_grow(State1, AckedBytes);
                false -> State1
            end;
        false ->
            case is_cwnd_limited(congestion_avoidance, BytesInFlight, State) of
                true ->
                    maybe_clear_prev_state(
                        cubic_update(resume_epoch(State), AckedBytes, RTTStats)
                    );
                false ->
                    pause_epoch(State)
            end
    end.

-doc """
Record the bytes in flight after a send. An ACK uses the larger of this
value and its own bytes in flight to decide whether the sender is
congestion window limited.
""".
-spec on_packet_sent(#state{}, non_neg_integer(), non_neg_integer()) -> #state{}.
on_packet_sent(State, _BytesSent, BytesInFlight) ->
    State#state{sent_in_flight = BytesInFlight}.

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
Roll back the most recent congestion-event reduction when the bytes
declared lost since the reduction were all acknowledged later (RFC 9438
§4.9.2). `SpuriousBytes` is the size of the packets acknowledged after
they were declared lost. No-op when no rollback snapshot is available.
""".
-spec on_spurious_congestion(#state{}, non_neg_integer()) -> #state{}.
on_spurious_congestion(#state{prev_state = undefined} = State, _SpuriousBytes) ->
    State;
on_spurious_congestion(#state{undo_bytes = Undo} = State, SpuriousBytes) when
    SpuriousBytes < Undo
->
    State#state{undo_bytes = Undo - SpuriousBytes};
on_spurious_congestion(#state{prev_state = Snap} = State, _SpuriousBytes) ->
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
        prev_state = undefined,
        undo_bytes = 0
    }.

-spec pause_epoch(#state{}) -> #state{}.
pause_epoch(#state{epoch_start = EpochStart, app_limited_since = undefined} = State) when
    EpochStart =/= 0
->
    State#state{app_limited_since = erlang:monotonic_time(microsecond)};
pause_epoch(State) ->
    State.

-spec reset_epoch(#state{}) -> #state{}.
reset_epoch(#state{prev_state = Snap} = State) ->
    State#state{
        epoch_start = 0,
        origin_point = 0,
        tcp_cwnd = 0,
        cubic_k = undefined,
        prev_state = reset_snapshot_epoch(Snap)
    }.

-spec reset_snapshot_epoch(undefined | snapshot()) -> undefined | snapshot().
reset_snapshot_epoch(undefined) ->
    undefined;
reset_snapshot_epoch({Cwnd, Ssthresh, RST, WMax, WLastMax, _, _, _, _, CongOcc}) ->
    {Cwnd, Ssthresh, RST, WMax, WLastMax, 0, 0, 0, undefined, CongOcc}.

-spec resume_epoch(#state{}) -> #state{}.
resume_epoch(#state{app_limited_since = undefined} = State) ->
    State;
resume_epoch(#state{epoch_start = 0} = State) ->
    State#state{app_limited_since = undefined};
resume_epoch(#state{epoch_start = EpochStart, app_limited_since = Since} = State) ->
    State#state{
        epoch_start = EpochStart + erlang:monotonic_time(microsecond) - Since,
        app_limited_since = undefined
    }.

-doc """
Set the maximum datagram size. Before the first congestion event a
window still at the initial window follows the new size.

A change of size ends the current CUBIC epoch, also in the spurious-loss
snapshot. The next ACK in congestion avoidance starts a new epoch and
computes K from `w_max` and the new size.
""".
-spec set_max_datagram_size(#state{}, pos_integer()) -> #state{}.
set_max_datagram_size(#state{max_datagram_size = Size} = State, Size) ->
    State;
set_max_datagram_size(State, Size) when Size >= ?MIN_UDP_PAYLOAD_SIZE ->
    #state{congestion_occurred = CongOccurred, max_datagram_size = OldMSS, cwnd = OldCwnd} =
        State,
    NewCwnd =
        case not CongOccurred andalso OldCwnd =:= nquic_cc_newreno:initial_window(OldMSS) of
            true -> nquic_cc_newreno:initial_window(Size);
            false -> OldCwnd
        end,
    reset_epoch(State#state{max_datagram_size = Size, cwnd = NewCwnd}).

-spec slow_start_grow(#state{}, non_neg_integer()) -> #state{}.
slow_start_grow(#state{hystart_phase = css, max_datagram_size = MSS} = State, AckedBytes) ->
    Capped = min(AckedBytes, ?HYSTART_CSS_L * MSS),
    Inc = max(1, MSS * Capped div (?HYSTART_CSS_GROWTH_DIVISOR * MSS)),
    maybe_clear_prev_state(State#state{cwnd = State#state.cwnd + Inc});
slow_start_grow(#state{cwnd = Cwnd} = State, AckedBytes) ->
    maybe_clear_prev_state(State#state{cwnd = Cwnd + AckedBytes}).
