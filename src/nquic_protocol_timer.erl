-module(nquic_protocol_timer).
-moduledoc """
Timer-action orchestration for the QUIC protocol state.

Pure functions over `#conn_state{}` that translate connection state
into the `set_timer` / `cancel_timer` actions the owner must schedule:
the ACK-delay timer, the idle timer (RFC 9000 Section 10.1), the PTO
timer (RFC 9002 Section 6.2), the path-validation timer (RFC 9000
Section 8.2), and the PMTUD probe timer (RFC 8899).

`compute_timer_actions/1` is the aggregate entry point used after
`nquic_protocol:handle_packet/3` and `nquic_protocol:flush/1`. The
idle and PTO values are cached in `#conn_state{}` so unchanged timers
do not re-emit actions. External side effects are limited to
delegating into `nquic_loss`, `nquic_pmtud`, and `nquic_path`; the
idle bound is resolved via `nquic_protocol:get_idle_timeout/2`.
""".

-include("nquic_conn.hrl").
-include("nquic_transport.hrl").
-export([
    compute_path_validation_timeout/1,
    compute_pto_timer_actions/1,
    compute_timer_actions/1
]).

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
compute_pto_timer_actions(#conn_state{loss_state = LS, remote_params = RP}) ->
    case nquic_loss:has_ack_eliciting_in_flight(LS) of
        true ->
            PtoMs = compute_pto_ms(LS, RP),
            [{set_timer, pto, PtoMs}];
        false ->
            [{cancel_timer, pto}]
    end.

-spec compute_pto_timer_cached(nquic_protocol:state(), [nquic_protocol:timeout_action()]) ->
    {[nquic_protocol:timeout_action()], nquic_protocol:state()}.
compute_pto_timer_cached(
    #conn_state{loss_state = LS, remote_params = RP, last_pto_ms = Cached} = State, Acc
) ->
    case nquic_loss:has_ack_eliciting_in_flight(LS) of
        true ->
            PtoMs = compute_pto_ms(LS, RP),
            case Cached of
                PtoMs -> {Acc, State};
                _ -> {[{set_timer, pto, PtoMs} | Acc], State#conn_state{last_pto_ms = PtoMs}}
            end;
        false ->
            case Cached of
                cancel -> {Acc, State};
                _ -> {[{cancel_timer, pto} | Acc], State#conn_state{last_pto_ms = cancel}}
            end
    end.

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
