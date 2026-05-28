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
-include("nquic_frame.hrl").
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
-spec ensure_handshake_timers(gen_statem:event_handler_result(dynamic())) ->
    gen_statem:event_handler_result(dynamic()).
ensure_handshake_timers({keep_state, Data, Actions}) ->
    {keep_state, Data, Actions ++ set_pto_timer(Data) ++ set_idle_timer(Data)};
ensure_handshake_timers({keep_state, Data}) ->
    {keep_state, Data, set_pto_timer(Data) ++ set_idle_timer(Data)};
ensure_handshake_timers({next_state, NextState, Data, Actions}) ->
    {next_state, NextState, Data, Actions ++ set_pto_timer(Data) ++ set_idle_timer(Data)};
ensure_handshake_timers({stop, _, _} = Stop) ->
    Stop.

-doc """
Handle a PTO firing in the initial / handshake states.
Queues a PING probe at the relevant encryption level, flushes, and
restarts the PTO timer. The established state delegates PTO to
`nquic_protocol:handle_timeout/2` instead.
""".
-spec handle_pto(initial | handshake, #conn_state{}) ->
    gen_statem:event_handler_result(term()).
handle_pto(StateName, Data) ->
    LossState0 = Data#conn_state.loss_state,
    LossState1 = nquic_loss:on_pto(LossState0),
    Data1 = Data#conn_state{loss_state = LossState1},
    PingFrame = #ping{},
    Data2 =
        case StateName of
            initial ->
                Keys = (Data1#conn_state.crypto)#conn_crypto.keys,
                case maps:is_key(initial, Keys) of
                    true ->
                        {ok, D} = nquic_protocol_send_queues:queue_initial_frame(PingFrame, Data1),
                        D;
                    false ->
                        Data1
                end;
            handshake ->
                {ok, D} = nquic_protocol_send_queues:queue_handshake_frame(PingFrame, Data1),
                D
        end,
    {Data3, _Timers} = nquic_conn_statem:flush_and_send(Data2),
    Actions = set_pto_timer(Data3),
    {keep_state, Data3, Actions}.

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
Compute the gen_statem `pto_timeout` action for the current state.
When no ack-eliciting packet is in flight, returns a PTO cancellation.
""".
-spec set_pto_timer(#conn_state{}) -> [gen_statem:action()].
set_pto_timer(#conn_state{loss_state = LossState, remote_params = RemoteParams}) ->
    case nquic_loss:has_ack_eliciting_in_flight(LossState) of
        true ->
            MaxAckDelayUs = remote_max_ack_delay_us(RemoteParams),
            PtoUs = nquic_loss:get_pto_timeout(LossState, MaxAckDelayUs),
            PtoMs = max(1, (PtoUs + 999) div 1000),
            [{{timeout, pto_timeout}, PtoMs, pto_fire}];
        false ->
            [{{timeout, pto_timeout}, infinity, undefined}]
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
-spec remote_max_ack_delay_us(#transport_params{} | undefined) -> non_neg_integer().
remote_max_ack_delay_us(undefined) ->
    0;
remote_max_ack_delay_us(#transport_params{max_ack_delay = MAD}) ->
    MAD * 1000.

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
