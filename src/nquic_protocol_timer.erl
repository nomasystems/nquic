-module(nquic_protocol_timer).
-moduledoc """
Timer-action orchestration for the QUIC protocol state.

Pure functions over `#conn_state{}` that translate connection state
into the `set_timer` / `cancel_timer` actions the owner must schedule:
the ACK-delay timer, the idle timer (RFC 9000 Section 10.1), the loss
detection timer, the path-validation timer (RFC 9000 Section 8.2), and
the PMTUD probe timer (RFC 8899).

The loss detection timer uses the `pto` timer type. It runs to the loss
time of `nquic_loss:get_loss_timer/1` when one is set, and to the PTO
(RFC 9002 Section 6.2) otherwise, as in RFC 9002 Appendix A.8.

`compute_timer_actions/1` is the aggregate entry point used after
`nquic_protocol:handle_packet/3` and `nquic_protocol:flush/1`. The
idle and loss detection timer values are cached in `#conn_state{}` so
unchanged timers do not re-emit actions. External side effects are limited to
delegating into `nquic_loss`, `nquic_pmtud`, and `nquic_path`; the
idle bound is resolved via `nquic_protocol:get_idle_timeout/2`.
""".

-include("nquic_conn.hrl").
-include("nquic_transport.hrl").
-export([
    arm_pto_timer/1,
    compute_path_validation_timeout/1,
    compute_pto_timer_actions/1,
    compute_timer_actions/1,
    pto_deadline_ms/1
]).

-export_type([loss_detection_timer/0]).

-type loss_detection_timer() :: {loss, integer()} | pos_integer() | cancel.

-doc """
Compute the loss detection timer action unconditionally, and record it in
the cache that `compute_timer_actions/1` reads. Use it after a send of an
ack-eliciting packet or after the timer fired, where the timer restarts
even when its value did not change.
""".
-spec arm_pto_timer(nquic_protocol:state()) ->
    {[nquic_protocol:timeout_action()], nquic_protocol:state()}.
arm_pto_timer(State) ->
    Timer = loss_detection_timer(State),
    {[loss_detection_action(Timer)], State#conn_state{last_pto_ms = Timer}}.

-spec ceil_ms(integer()) -> integer().
ceil_ms(Us) ->
    erlang:convert_time_unit(Us + 999, microsecond, millisecond).

-spec compute_ack_delay_timer_acc(nquic_protocol:state(), [nquic_protocol:timeout_action()]) ->
    [nquic_protocol:timeout_action()].
compute_ack_delay_timer_acc(#conn_state{pending_ack_count = 0}, Acc) ->
    Acc;
compute_ack_delay_timer_acc(_State, Acc) ->
    [{set_timer, ack_delay, 1} | Acc].

-spec compute_idle_timer_cached(nquic_protocol:state(), [nquic_protocol:timeout_action()]) ->
    {[nquic_protocol:timeout_action()], nquic_protocol:state()}.
compute_idle_timer_cached(
    #conn_state{local_params = LP, remote_params = RP, last_idle_ms = Cached} = State, Acc
) ->
    Local = LP#transport_params.max_idle_timeout,
    Remote =
        case RP of
            undefined -> 0;
            #transport_params{max_idle_timeout = R} -> R
        end,
    case nquic_protocol:get_idle_timeout(Local, Remote) of
        infinity when Cached =:= infinity ->
            {Acc, State};
        infinity ->
            {Acc, State#conn_state{last_idle_ms = infinity}};
        Timeout when Timeout =:= Cached ->
            {Acc, State};
        Timeout ->
            {[{set_timer, idle, Timeout} | Acc], State#conn_state{last_idle_ms = Timeout}}
    end.

-spec compute_path_timer_acc(nquic_protocol:state(), [nquic_protocol:timeout_action()]) ->
    [nquic_protocol:timeout_action()].
compute_path_timer_acc(#conn_state{path = #conn_path_mgmt{path_state = undefined}}, Acc) ->
    Acc;
compute_path_timer_acc(#conn_state{path = #conn_path_mgmt{path_state = PS}} = State, Acc) ->
    case nquic_path:is_validating(PS) of
        true ->
            [{set_timer, path_validation, compute_path_validation_timeout(State)} | Acc];
        false ->
            Acc
    end.

-spec compute_path_validation_timeout(nquic_protocol:state()) -> non_neg_integer().
compute_path_validation_timeout(#conn_state{loss_state = LS, remote_params = RP}) ->
    MadUs =
        case RP of
            undefined -> 0;
            #transport_params{max_ack_delay = M} -> M * 1000
        end,
    PtoUs = nquic_loss:get_pto_timeout(LS, MadUs),
    max(1, ((3 * PtoUs) + 999) div 1000).

-spec compute_pmtud_timer_acc(nquic_protocol:state(), [nquic_protocol:timeout_action()]) ->
    [nquic_protocol:timeout_action()].
compute_pmtud_timer_acc(#conn_state{pmtud = undefined}, Acc) ->
    Acc;
compute_pmtud_timer_acc(#conn_state{pmtud = PS}, Acc) ->
    case nquic_pmtud:get_timer_ms(PS) of
        infinity -> Acc;
        Ms -> [{set_timer, pmtud, Ms} | Acc]
    end.

-spec compute_pto_ms(nquic_loss:loss_state(), #transport_params{} | undefined) ->
    pos_integer().
compute_pto_ms(LS, RP) ->
    MadUs =
        case RP of
            undefined -> 0;
            #transport_params{max_ack_delay = M} -> M * 1000
        end,
    PtoUs = nquic_loss:get_pto_timeout(LS, MadUs),
    max(1, (PtoUs + 999) div 1000).

-spec compute_pto_timer_actions(nquic_protocol:state()) -> [nquic_protocol:timeout_action()].
compute_pto_timer_actions(State) ->
    [loss_detection_action(loss_detection_timer(State))].

-spec compute_pto_timer_cached(nquic_protocol:state(), [nquic_protocol:timeout_action()]) ->
    {[nquic_protocol:timeout_action()], nquic_protocol:state()}.
compute_pto_timer_cached(#conn_state{last_pto_ms = Cached} = State, Acc) ->
    case loss_detection_timer(State) of
        Cached -> {Acc, State};
        Timer -> {[loss_detection_action(Timer) | Acc], State#conn_state{last_pto_ms = Timer}}
    end.

-spec is_client_awaiting_handshake_ack(nquic_protocol:state()) -> boolean().
is_client_awaiting_handshake_ack(#conn_state{role = Role, loss_state = LS, crypto = Crypto}) ->
    Role =:= client andalso
        not nquic_loss:has_received_ack(LS, handshake) andalso
        not is_handshake_confirmed(Crypto).

-spec is_handshake_confirmed(#conn_crypto{}) -> boolean().
is_handshake_confirmed(#conn_crypto{keys = Keys}) ->
    not maps:is_key(initial, Keys) andalso not maps:is_key(handshake, Keys).

-spec is_pto_armed(nquic_protocol:state()) -> boolean().
is_pto_armed(#conn_state{loss_state = LS} = State) ->
    nquic_loss:has_ack_eliciting_in_flight(LS) orelse is_client_awaiting_handshake_ack(State).

-doc """
Compute timer actions based on current state.
Returns idle and PTO timer actions the caller should schedule.
Call after `nquic_protocol:handle_packet/3` or `nquic_protocol:flush/1`
to keep timers up to date. Caches idle and PTO values to skip
unchanged timer actions. Uses accumulator to avoid `++` overhead.
""".
-spec compute_timer_actions(nquic_protocol:state()) ->
    {[nquic_protocol:timeout_action()], nquic_protocol:state()}.
compute_timer_actions(State) ->
    Acc0 = compute_ack_delay_timer_acc(State, []),
    Acc1 = compute_path_timer_acc(State, Acc0),
    Acc2 = compute_pmtud_timer_acc(State, Acc1),
    {Acc3, State1} = compute_pto_timer_cached(State, Acc2),
    {Acc4, State2} = compute_idle_timer_cached(State1, Acc3),
    {Acc4, State2}.

-doc """
Get the deadline of the loss detection timer in
`erlang:monotonic_time(millisecond)` units, or `cancel` when the timer
must not run. A pending loss time (`nquic_loss:get_loss_timer/1`) is the
deadline, rounded up to the next millisecond. Otherwise the timer is the
PTO.

The deadline is one PTO period after `nquic_loss:get_pto_base_time/1`
(RFC 9002 Appendix A.8). A recompute that sees no new ack-eliciting
packet gives the same deadline, so received datagrams do not push the
timer out. With nothing in flight, which is the client anti-deadlock
PTO, the deadline is one PTO period after now.
""".
-spec pto_deadline_ms(nquic_protocol:state()) -> integer() | cancel.
pto_deadline_ms(#conn_state{loss_state = LS} = State) ->
    case loss_detection_timer(State) of
        {loss, LossTimeUs} -> ceil_ms(LossTimeUs);
        cancel -> cancel;
        PtoMs -> pto_base_ms(nquic_loss:get_pto_base_time(LS)) + PtoMs
    end.

-spec loss_detection_action(loss_detection_timer()) -> nquic_protocol:timeout_action().
loss_detection_action({loss, LossTimeUs}) ->
    {set_timer, pto, max(0, ceil_ms(LossTimeUs - erlang:monotonic_time(microsecond)))};
loss_detection_action(cancel) ->
    {cancel_timer, pto};
loss_detection_action(PtoMs) ->
    {set_timer, pto, PtoMs}.

-spec loss_detection_timer(nquic_protocol:state()) -> loss_detection_timer().
loss_detection_timer(#conn_state{loss_state = LS, remote_params = RP} = State) ->
    case nquic_loss:get_loss_timer(LS) of
        {LossTimeUs, _Space} ->
            {loss, LossTimeUs};
        undefined ->
            case is_pto_armed(State) of
                true -> compute_pto_ms(LS, RP);
                false -> cancel
            end
    end.

-spec pto_base_ms(integer() | undefined) -> integer().
pto_base_ms(undefined) ->
    erlang:monotonic_time(millisecond);
pto_base_ms(BaseUs) ->
    erlang:convert_time_unit(BaseUs, microsecond, millisecond).
