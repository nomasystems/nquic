-module(nquic_conn_timers).
-moduledoc """
gen_statem timer adapters for the QUIC connection state machine.

Translates `nquic_protocol`'s abstract timer actions into gen_statem
timeout actions, computes the idle / PTO timer values for the
current state, and runs the PTO probe handler for the
initial / handshake states (the established state delegates PTO to
`nquic_protocol:handle_timeout/2`).
""".

-include("nquic_conn.hrl").
-include("nquic_transport.hrl").
-export([
    ensure_handshake_timers/1,
    handle_pto/2,
    idle_timeout_to_param/1,
    set_idle_timer/1,
    set_pto_timer/1,
    timer_actions_to_statem/1
]).

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc """
Ensure idle + PTO timers are armed on a handler result.

Used after the client's first Initial send so the loss-detection
timer is armed even if no packet arrived synchronously (the send-only
path skips `process_datagram`, which is where these timers are
normally set). Subsequent PTO or `process_datagram` calls replace
these actions idempotently.
""".
-spec ensure_handshake_timers(
    gen_statem:event_handler_result(nquic_conn_statem:state_name(), #conn_state{})
) -> gen_statem:event_handler_result(nquic_conn_statem:state_name(), #conn_state{}).
ensure_handshake_timers({keep_state, Data, Actions}) ->
    {keep_state, Data, Actions ++ set_pto_timer(Data) ++ set_idle_timer(Data)};
ensure_handshake_timers({keep_state, Data}) ->
    {keep_state, Data, set_pto_timer(Data) ++ set_idle_timer(Data)};
ensure_handshake_timers({next_state, NextState, Data, Actions}) ->
    {next_state, NextState, Data, Actions ++ set_pto_timer(Data) ++ set_idle_timer(Data)};
ensure_handshake_timers({stop, _, _} = Stop) ->
    Stop.

-doc """
Handle the loss detection timer in the initial / handshake states.
Services it with `nquic_protocol_send:handle_handshake_timer/2`, which
retransmits the packets lost at the loss time or queues the PTO probes,
then flushes and restarts the timer. The established state delegates
the timer to `nquic_protocol:handle_timeout/2` instead.
""".
-spec handle_pto(initial | handshake, #conn_state{}) ->
    gen_statem:event_handler_result(term()).
handle_pto(StateName, Data) ->
    Data1 = nquic_protocol_send:handle_handshake_timer(StateName, Data),
    {Data2, _Timers} = nquic_conn_statem:flush_and_send(Data1),
    {keep_state, Data2, set_pto_timer(Data2)}.

-doc """
Convert a user-facing `idle_timeout` option to the transport-parameter
value: `infinity` becomes `0` (RFC 9000 §18.2: "no limit advertised").
""".
-spec idle_timeout_to_param(timeout() | non_neg_integer()) -> non_neg_integer().
idle_timeout_to_param(infinity) -> 0;
idle_timeout_to_param(Ms) when is_integer(Ms), Ms >= 0 -> Ms.

-doc """
Compute the gen_statem `idle_timeout` action for the current state.
RFC 9000 §10.1: effective timeout is `min(local, remote)`; `0` means
disabled, in which case no timer is armed (returned as an empty list).
""".
-spec set_idle_timer(#conn_state{}) -> [gen_statem:action()].
set_idle_timer(#conn_state{local_params = LocalParams, remote_params = RemoteParams}) ->
    Local = LocalParams#transport_params.max_idle_timeout,
    Remote =
        case RemoteParams of
            undefined -> 0;
            #transport_params{max_idle_timeout = R} -> R
        end,
    case nquic_protocol:get_idle_timeout(Local, Remote) of
        infinity -> [];
        Timeout -> [{{timeout, idle_timeout}, Timeout, idle_fire}]
    end.

-doc """
Compute the gen_statem `pto_timeout` action for the current state: an
absolute timeout at `nquic_protocol_timer:pto_deadline_ms/1`, or a PTO
cancellation.
""".
-spec set_pto_timer(#conn_state{}) -> [gen_statem:action()].
set_pto_timer(Data) ->
    case nquic_protocol_timer:pto_deadline_ms(Data) of
        cancel -> [{{timeout, pto_timeout}, infinity, undefined}];
        DeadlineMs -> [{{timeout, pto_timeout}, DeadlineMs, pto_fire, [{abs, true}]}]
    end.

-doc """
Translate `nquic_protocol`'s timer actions into gen_statem timeout actions.
Tail-recursive with accumulator; order doesn't matter for gen_statem
actions. `nquic_protocol` only emits `cancel_timer` for the PTO timer
today; other timers replace themselves implicitly when re-armed. If
the protocol starts cancelling more types, Dialyzer flags the missing
clauses.
""".
-spec timer_actions_to_statem([nquic_protocol:timeout_action()]) -> [gen_statem:action()].
timer_actions_to_statem(Actions) ->
    timer_actions_to_statem(Actions, []).

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec timer_actions_to_statem([nquic_protocol:timeout_action()], [gen_statem:action()]) ->
    [gen_statem:action()].
timer_actions_to_statem([], Acc) ->
    Acc;
timer_actions_to_statem([{set_timer, idle, Ms} | Rest], Acc) ->
    timer_actions_to_statem(Rest, [{{timeout, idle_timeout}, Ms, idle_fire} | Acc]);
timer_actions_to_statem([{set_timer, pto, Ms} | Rest], Acc) ->
    timer_actions_to_statem(Rest, [{{timeout, pto_timeout}, Ms, pto_fire} | Acc]);
timer_actions_to_statem([{set_timer, path_validation, Ms} | Rest], Acc) ->
    timer_actions_to_statem(Rest, [{{timeout, path_validation}, Ms, path_validation_fire} | Acc]);
timer_actions_to_statem([{set_timer, ack_delay, Ms} | Rest], Acc) ->
    timer_actions_to_statem(Rest, [{{timeout, ack_delay}, Ms, ack_delay_fire} | Acc]);
timer_actions_to_statem([{cancel_timer, pto} | Rest], Acc) ->
    timer_actions_to_statem(Rest, [{{timeout, pto_timeout}, infinity, undefined} | Acc]).
