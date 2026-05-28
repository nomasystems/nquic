-module(nquic_conn_send_waiters).
-moduledoc """
Sync-send backpressure for handshake-phase stream writes in
`m:nquic_conn_statem`.

A send gates on the per-stream `send_buffer_high_water` mark.
When a sync caller's bytes don't all fit, the unsent tail is parked
here as a `t()`. Each call to `wake/1` (run after every
flush in established state) tries to push more of each waiter's
bytes into the stream's buffer. Fully-served waiters get an `ok`
reply; the configured `send_timeout` delivers `{error, send_timeout}`
if the wait runs too long.
""".

-include("nquic_conn.hrl").
-export([
    handle_sync_send/5,
    handle_sync_send/6,
    pop/3,
    wake/1
]).

-export_type([t/0]).

-type t() ::
    {gen_statem:from(), nquic:stream_id(), binary(), boolean(), reference() | undefined}.

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc """
Sync `send_stream` / `send_fin` entry point, parking with the
connection-level `send_timeout`.

Queues as much of `DataBin` as fits under the per-stream
`send_buffer_high_water`; if a tail is left over, parks the caller
as a `t()` that `wake/1` (or the `send_wait_timeout`
timer) eventually resolves.
""".
-spec handle_sync_send(
    gen_statem:from(), nquic:stream_id(), iodata(), fin | nofin, #conn_state{}
) -> gen_statem:event_handler_result(nquic_conn_statem:state_name()).
handle_sync_send(From, StreamID, DataBin, Fin, Data) ->
    SS = Data#conn_state.streams_state,
    handle_sync_send(From, StreamID, DataBin, Fin, SS#conn_streams.send_timeout, Data).

-doc """
Same as `handle_sync_send/5` but with an explicit per-call
`Timeout` for the parked waiter, overriding the connection-level
`send_timeout`.
""".
-spec handle_sync_send(
    gen_statem:from(), nquic:stream_id(), iodata(), fin | nofin, timeout(), #conn_state{}
) -> gen_statem:event_handler_result(nquic_conn_statem:state_name()).
handle_sync_send(From, StreamID, DataBin, Fin, Timeout, Data) ->
    case nquic_protocol:send_stream_capped(StreamID, DataBin, Fin, Data) of
        {ok, BytesQueued, Data1} ->
            DataLen = iolist_size(DataBin),
            case BytesQueued of
                DataLen ->
                    finish_full(From, Data1);
                _ ->
                    Bin = iolist_to_binary(DataBin),
                    <<_:BytesQueued/binary, Tail/binary>> = Bin,
                    Data2 = park(From, StreamID, Tail, Fin =:= fin, Timeout, Data1),
                    finish_partial(Data2)
            end;
        {error, Reason, Data1} ->
            {keep_state, Data1, [{reply, From, {error, Reason}}]};
        {error, _} = Err ->
            {keep_state, Data, [{reply, From, Err}]}
    end.

-doc """
Pop the waiter whose `From` and timer ref both match.
The ref check guards against a stale `{timeout, _, _}` message that
was already in flight when we asynchronously cancelled the timer
(e.g. the waiter was just woken by `wake/1`).
""".
-spec pop(gen_statem:from(), reference(), queue:queue(tuple())) ->
    {ok, queue:queue(tuple())} | not_found.
pop(From, TimerRef, Q) ->
    L = queue:to_list(Q),
    case lists:keyfind(From, 1, L) of
        {From, _StreamID, _RemBin, _IsFin, TR} when TR =:= TimerRef ->
            {ok, queue:from_list(lists:keydelete(From, 1, L))};
        _ ->
            not_found
    end.

-doc """
Walk the parked waiters in FIFO order and try to queue more of each
waiter's bytes onto its stream.
Returns `{NewData, ReplyActions}`; the caller (typically the
post-flush path) prepends the reply actions to the gen_statem
actions list.
""".
-spec wake(#conn_state{}) -> {#conn_state{}, [gen_statem:action()]}.
wake(Data) ->
    SS = Data#conn_state.streams_state,
    Q = SS#conn_streams.send_waiters,
    case queue:is_empty(Q) of
        true ->
            {Data, []};
        false ->
            wake_loop(queue:to_list(Q), Data, [], [])
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec cancel_timer(reference() | undefined) -> ok.
cancel_timer(undefined) ->
    ok;
cancel_timer(TimerRef) when is_reference(TimerRef) ->
    _ = erlang:cancel_timer(TimerRef, [{async, true}, {info, false}]),
    ok.

-spec finish_full(gen_statem:from(), #conn_state{}) ->
    gen_statem:event_handler_result(nquic_conn_statem:state_name()).
finish_full(From, Data) ->
    {Data1, FlushTimerActions} = nquic_conn_statem:flush_and_send(Data),
    {Data2, ReplyActions} = wake(Data1),
    {AllTimerActions, Data3} = nquic_protocol_timer:compute_timer_actions(Data2),
    StatemActions = nquic_conn_timers:timer_actions_to_statem(
        FlushTimerActions ++ AllTimerActions
    ),
    {keep_state, Data3, [{reply, From, ok} | ReplyActions ++ StatemActions]}.

-spec finish_partial(#conn_state{}) ->
    gen_statem:event_handler_result(nquic_conn_statem:state_name()).
finish_partial(Data) ->
    {Data1, FlushTimerActions} = nquic_conn_statem:flush_and_send(Data),
    {Data2, ReplyActions} = wake(Data1),
    {AllTimerActions, Data3} = nquic_protocol_timer:compute_timer_actions(Data2),
    StatemActions = nquic_conn_timers:timer_actions_to_statem(
        FlushTimerActions ++ AllTimerActions
    ),
    {keep_state, Data3, ReplyActions ++ StatemActions}.

-spec park(
    gen_statem:from(), nquic:stream_id(), binary(), boolean(), timeout(), #conn_state{}
) -> #conn_state{}.
park(From, StreamID, RemainingBin, IsFin, Timeout, Data) ->
    SS0 = Data#conn_state.streams_state,
    TimerRef =
        case Timeout of
            Ms when is_integer(Ms), Ms >= 0 ->
                erlang:start_timer(Ms, self(), {send_wait_timeout, From});
            _ ->
                undefined
        end,
    Waiter = {From, StreamID, RemainingBin, IsFin, TimerRef},
    SS1 = SS0#conn_streams{
        send_waiters = queue:in(Waiter, SS0#conn_streams.send_waiters)
    },
    Data#conn_state{streams_state = SS1}.

-spec wake_loop(
    [tuple()], #conn_state{}, [tuple()], [gen_statem:action()]
) -> {#conn_state{}, [gen_statem:action()]}.
wake_loop([], Data, RemAcc, ReplyAcc) ->
    SS = Data#conn_state.streams_state,
    SS1 = SS#conn_streams{send_waiters = queue:from_list(lists:reverse(RemAcc))},
    {Data#conn_state{streams_state = SS1}, lists:reverse(ReplyAcc)};
wake_loop([Waiter | Rest], Data, RemAcc, ReplyAcc) ->
    {From, StreamID, RemBin, IsFin, TimerRef} = Waiter,
    Fin =
        case IsFin of
            true -> fin;
            false -> nofin
        end,
    case nquic_protocol:send_stream_capped(StreamID, RemBin, Fin, Data) of
        {ok, 0, Data1} ->
            wake_loop(Rest, Data1, [Waiter | RemAcc], ReplyAcc);
        {ok, N, Data1} ->
            <<_:N/binary, Tail/binary>> = RemBin,
            case Tail of
                <<>> ->
                    cancel_timer(TimerRef),
                    Reply = {reply, From, ok},
                    wake_loop(Rest, Data1, RemAcc, [Reply | ReplyAcc]);
                _ ->
                    NewWaiter = {From, StreamID, Tail, IsFin, TimerRef},
                    wake_loop(Rest, Data1, [NewWaiter | RemAcc], ReplyAcc)
            end;
        {error, Reason, Data1} ->
            cancel_timer(TimerRef),
            Reply = {reply, From, {error, Reason}},
            wake_loop(Rest, Data1, RemAcc, [Reply | ReplyAcc]);
        {error, _Reason} = Err ->
            cancel_timer(TimerRef),
            Reply = {reply, From, Err},
            wake_loop(Rest, Data, RemAcc, [Reply | ReplyAcc])
    end.
