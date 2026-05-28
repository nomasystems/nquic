-module(nquic_lib_timer).
-moduledoc false.

%% Timer scheduling and migration finalisation for `nquic_lib'.
%%
%% Internal glue behind the `nquic_lib' facade. Owns the
%% `erlang:send_after' / `erlang:cancel_timer' bookkeeping for QUIC
%% protocol timers, the egress-ECN socket transition, and the
%% post-self-migration dispatch-table cleanup. Runs in the owner
%% process. `self()' is the connection owner.

-include("nquic_conn.hrl").
-export([
    absorb_migration_events/2,
    apply_timer_actions/2,
    maybe_apply_ecn_transition/2
]).

-spec absorb_migration_events([nquic_protocol:event()], nquic:ctx()) ->
    {[nquic_protocol:event()], nquic:ctx()}.
absorb_migration_events([], Ctx) ->
    {[], Ctx};
absorb_migration_events(Events, Ctx) ->
    absorb_migration_events(Events, Ctx, []).

-spec absorb_migration_events(
    [nquic_protocol:event()], nquic:ctx(), [nquic_protocol:event()]
) -> {[nquic_protocol:event()], nquic:ctx()}.
absorb_migration_events([], Ctx, Acc) ->
    {lists:reverse(Acc), Ctx};
absorb_migration_events([local_migration_validated | Rest], Ctx, Acc) ->
    absorb_migration_events(Rest, finalize_self_migration(Ctx), Acc);
absorb_migration_events([Event | Rest], Ctx, Acc) ->
    absorb_migration_events(Rest, Ctx, [Event | Acc]).

-spec apply_timer_actions(nquic:ctx(), [nquic_protocol:timeout_action()]) -> nquic:ctx().
apply_timer_actions(Ctx, []) ->
    Ctx;
apply_timer_actions(Ctx, [{set_timer, Type, Ms} | Rest]) ->
    Timers = nquic_ctx:timers(Ctx),
    _ = cancel_timer_if_set(Type, Timers),
    Ref = erlang:send_after(Ms, self(), {quic_timeout, Type}),
    apply_timer_actions(nquic_ctx:set_timers(Ctx, Timers#{Type => Ref}), Rest);
apply_timer_actions(Ctx, [{cancel_timer, Type} | Rest]) ->
    Timers = nquic_ctx:timers(Ctx),
    _ = cancel_timer_if_set(Type, Timers),
    apply_timer_actions(nquic_ctx:set_timers(Ctx, maps:remove(Type, Timers)), Rest).

-spec cancel_timer_if_set(nquic_protocol:timer_type(), #{
    nquic_protocol:timer_type() => reference()
}) -> ok.
cancel_timer_if_set(Type, Timers) ->
    case maps:find(Type, Timers) of
        {ok, Ref} ->
            _ = erlang:cancel_timer(Ref, [{async, true}, {info, false}]),
            ok;
        error ->
            ok
    end.

-spec finalize_self_migration(nquic:ctx()) -> nquic:ctx().
finalize_self_migration(Ctx) ->
    State0 = nquic_ctx:state(Ctx),
    {Table, State1} = nquic_protocol:clear_dispatch_table(State0),
    case Table of
        undefined ->
            nquic_ctx:set_state(Ctx, State1);
        _ ->
            ok = lists:foreach(
                fun(CID) -> nquic_listener:dispatch_unregister(Table, CID) end,
                nquic_protocol:local_cids(State1)
            ),
            case nquic_protocol:odcid(State1) of
                undefined ->
                    ok;
                <<>> ->
                    ok;
                ODCID ->
                    _ = nquic_listener:dispatch_unregister(Table, ODCID),
                    ok
            end,
            Ctx1 = nquic_ctx:set_state(Ctx, State1),
            nquic_ctx:set_dispatch(Ctx1, undefined)
    end.

-spec maybe_apply_ecn_transition(nquic_socket:t(), nquic_protocol:state()) ->
    nquic_protocol:state().
maybe_apply_ecn_transition(Socket, #conn_state{loss_state = LS} = State) ->
    case nquic_loss:is_ecn_socket_dirty(LS) of
        false ->
            State;
        true ->
            Mark =
                case nquic_loss:is_ecn_enabled(LS) of
                    true -> ect0;
                    false -> not_ect
                end,
            ok = nquic_socket:set_egress_ecn(Socket, Mark),
            State#conn_state{loss_state = nquic_loss:clear_ecn_socket_dirty(LS)}
    end.
