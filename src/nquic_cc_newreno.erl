-module(nquic_cc_newreno).

-moduledoc """
NewReno congestion control per RFC 9002 Section 7.3.

Implements slow start, congestion avoidance, and loss recovery with a
loss reduction factor of 0.5. Initial window follows RFC 9002 Section 7.2:
`min(10 * MSS, max(14720, 2 * MSS))`.
""".

-behaviour(nquic_cc).

-include("nquic_loss.hrl").
-export([
    get_cwnd/1,
    get_ssthresh/1,
    init/0,
    on_congestion_event/4,

    on_idle_reset/1,
    on_packet_acked/4,
    on_packet_sent/3,
    on_persistent_congestion/1,
    on_spurious_congestion/1
]).
-export([get_max_datagram_size/1, set_max_datagram_size/2]).
-export([initial_window/1]).

-define(K_LOSS_REDUCTION_FACTOR_NUM, 1).
-define(K_LOSS_REDUCTION_FACTOR_DEN, 2).

-record(state, {
    cwnd :: non_neg_integer(),
    ssthresh = 16#FFFFFFFFFFFFFFFF :: non_neg_integer(),
    recovery_start_time = -576460752303423488 :: integer(),
    max_datagram_size = 1200 :: pos_integer(),
    congestion_occurred = false :: boolean(),
    prev_state ::
        undefined | {non_neg_integer(), non_neg_integer(), integer(), boolean()}
}).

-doc "Get the current congestion window size in bytes.".
-spec get_cwnd(#state{}) -> non_neg_integer().
get_cwnd(#state{cwnd = Cwnd}) -> Cwnd.

-doc "Get the current maximum datagram size in bytes.".
-spec get_max_datagram_size(#state{}) -> pos_integer().
get_max_datagram_size(#state{max_datagram_size = Size}) -> Size.

-doc "Get the current slow start threshold.".
-spec get_ssthresh(#state{}) -> non_neg_integer().
get_ssthresh(#state{ssthresh = S}) -> S.

-doc "Initialize NewReno state with default 1200-byte MSS and computed initial window.".
-spec init() -> #state{}.
init() ->
    MSS = 1200,
    #state{cwnd = initial_window(MSS), max_datagram_size = MSS}.

-spec initial_window(pos_integer()) -> non_neg_integer().
initial_window(MSS) ->
    erlang:floor(erlang:min(10 * MSS, erlang:max(14720, 2 * MSS))).

-spec maybe_clear_prev_state(#state{}) -> #state{}.
maybe_clear_prev_state(#state{prev_state = undefined} = S) ->
    S;
maybe_clear_prev_state(#state{cwnd = Cwnd, prev_state = {PrevCwnd, _, _, _}} = S) when
    Cwnd >= PrevCwnd
->
    S#state{prev_state = undefined};
maybe_clear_prev_state(S) ->
    S.

-doc "Halve the congestion window on a loss event, entering a new recovery period.".
-spec on_congestion_event(#state{}, non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    #state{}.
on_congestion_event(State, _LostBytes, _BytesInFlight, SentTime) ->
    #state{
        cwnd = Cwnd,
        ssthresh = Ssthresh,
        recovery_start_time = RecoveryStart,
        max_datagram_size = MaxDatagramSize,
        congestion_occurred = CongOccurred
    } = State,

    case SentTime =< RecoveryStart of
        true ->
            State;
        false ->
            Now = erlang:monotonic_time(microsecond),
            MinWindow = 2 * MaxDatagramSize,
            NewSsthresh = max(
                MinWindow,
                (Cwnd * ?K_LOSS_REDUCTION_FACTOR_NUM) div ?K_LOSS_REDUCTION_FACTOR_DEN
            ),
            State#state{
                cwnd = NewSsthresh,
                ssthresh = NewSsthresh,
                recovery_start_time = Now,
                congestion_occurred = true,
                prev_state = {Cwnd, Ssthresh, RecoveryStart, CongOccurred}
            }
    end.

-doc """
Reset the congestion window to `initial_window(MSS)` after an idle
period (RFC 9002 Section 7.8). Recovery period and the spurious-loss
snapshot are also cleared since neither survives a fresh start.
""".
-spec on_idle_reset(#state{}) -> #state{}.
on_idle_reset(#state{max_datagram_size = MSS} = State) ->
    State#state{
        cwnd = initial_window(MSS),
        recovery_start_time = -576460752303423488,
        congestion_occurred = false,
        prev_state = undefined
    }.

-doc "Increase the congestion window on packet acknowledgement (slow start or congestion avoidance).".
-spec on_packet_acked(#state{}, #sent_packet{}, non_neg_integer(), map()) -> #state{}.
on_packet_acked(State, #sent_packet{time_sent = SentTime, size = Size}, _BytesInFlight, _RTTStats) ->
    #state{
        cwnd = Cwnd,
        ssthresh = Ssthresh,
        recovery_start_time = RecoveryStart,
        max_datagram_size = MaxDatagramSize
    } = State,

    case SentTime =< RecoveryStart of
        true ->
            State;
        false ->
            NewCwnd =
                if
                    Cwnd < Ssthresh ->
                        Cwnd + Size;
                    true ->
                        Cwnd + (Size * MaxDatagramSize) div Cwnd
                end,
            maybe_clear_prev_state(State#state{cwnd = NewCwnd})
    end.

-doc "Handle a sent packet (no-op for NewReno).".
-spec on_packet_sent(#state{}, non_neg_integer(), non_neg_integer()) -> #state{}.
on_packet_sent(State, _BytesSent, _BytesInFlight) ->
    State.

-doc """
Collapse the congestion window to the minimum (`2 * max_datagram_size`)
on persistent congestion (RFC 9002 Section 7.6.2).
The recovery period is also reset so that subsequent ACKs for newly sent
packets can grow the window again. Any pending spurious-loss snapshot is
discarded; by definition the loss was real.
""".
-spec on_persistent_congestion(#state{}) -> #state{}.
on_persistent_congestion(State) ->
    #state{max_datagram_size = MSS} = State,
    MinWindow = 2 * MSS,
    State#state{
        cwnd = MinWindow,
        recovery_start_time = -576460752303423488,
        congestion_occurred = true,
        prev_state = undefined
    }.

-doc """
Roll back the most recent congestion-event reduction (RFC 9002 Appendix
A.10) when a packet that was previously declared lost is later
acknowledged. No-op when no rollback snapshot is available (e.g. the
window has already grown past the saved value or the snapshot was
consumed).
""".
-spec on_spurious_congestion(#state{}) -> #state{}.
on_spurious_congestion(#state{prev_state = undefined} = State) ->
    State;
on_spurious_congestion(#state{prev_state = {Cwnd, Ssthresh, RST, CongOcc}} = State) ->
    State#state{
        cwnd = Cwnd,
        ssthresh = Ssthresh,
        recovery_start_time = RST,
        congestion_occurred = CongOcc,
        prev_state = undefined
    }.

-doc "Set the maximum datagram size, recalculating cwnd if still at the initial window.".
-spec set_max_datagram_size(#state{}, pos_integer()) -> #state{}.
set_max_datagram_size(State, Size) when Size >= 1200 ->
    #state{congestion_occurred = CongOccurred, max_datagram_size = OldMSS} = State,
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
            State#state{max_datagram_size = Size, cwnd = NewCwnd};
        true ->
            State#state{max_datagram_size = Size}
    end.
