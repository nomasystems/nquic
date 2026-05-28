%%%-------------------------------------------------------------------
%%% @doc Reference `conn_handler' echo server (owner-from-first-packet).
%%%
%%% Started by `nquic_conn_launcher' under the partition supervisor when
%%% a listener is opened with `conn_handler => ?MODULE'. The process is
%%% the connection owner from the first packet: it seeds the server
%%% `#conn_state{}' with `nquic_lib:server_accept_init/1', registers its
%%% own CIDs, drives the handshake (`initial -> handshake ->
%%% established') itself, then echoes peer bidi streams. There is no
%%% export, accept queue, or takeover, so the connection's CID never
%%% resolves to a non-owner.
%%%
%%% This is the test-side model of what `nhttp_conn_h3' becomes under
%%% Option 1b (see `nhttp_changes.md').
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_echo_handler).

-export([start_link/1, init/1]).

-spec start_link(map()) -> {ok, pid()}.
start_link(Opts) ->
    proc_lib:start_link(?MODULE, init, [Opts]).

-spec init(map()) -> no_return().
init(Opts) ->
    process_flag(trap_exit, true),
    {ok, Ctx} = nquic_lib:server_accept_init(Opts),
    proc_lib:init_ack({ok, self()}),
    handshake_loop(Ctx, initial).

%%%-------------------------------------------------------------------
%%% Handshake phase: drive initial -> handshake -> established.
%%%-------------------------------------------------------------------

handshake_loop(Ctx, Phase) ->
    receive
        {packet, Source, Bin} ->
            hs_packet(nquic_lib:handle_packet(Ctx, Source, Bin), Phase);
        {packet, Source, Bin, ECN} ->
            hs_packet(nquic_lib:handle_packet(Ctx, Source, Bin, ECN), Phase);
        {immediate_packet, Source, Bin} ->
            hs_packet(nquic_lib:handle_packet(Ctx, Source, Bin), Phase);
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            hs_packet(nquic_lib:handle_packet_batch(Ctx, Source, Buf, GsoSize, ECN), Phase);
        {quic_timeout, Type} ->
            hs_timeout(nquic_lib:handshake_timeout(Ctx, Phase, Type), Phase);
        {quic_drain, _Listener} ->
            close(Ctx);
        stop ->
            close(Ctx);
        {'EXIT', _From, _Reason} ->
            close(Ctx);
        _Other ->
            handshake_loop(Ctx, Phase)
    end.

hs_packet({ok, Events, Ctx1}, Phase) ->
    {ok, Ctx2} = nquic_lib:flush(Ctx1),
    hs_dispatch(Events, Ctx2, Phase);
hs_packet({error, Reason, Ctx1}, _Phase) ->
    close_error(Ctx1, Reason).

hs_timeout({ok, Events, Ctx1}, Phase) ->
    hs_dispatch(Events, Ctx1, Phase);
hs_timeout({error, Reason, Ctx1}, _Phase) ->
    close_error(Ctx1, Reason).

hs_dispatch(Events, Ctx, Phase) ->
    case lists:member(connected, Events) of
        true ->
            serve_loop(echo_events(Events, Ctx));
        false ->
            handshake_loop(Ctx, next_phase(Events, Phase))
    end.

next_phase(Events, Phase) ->
    case lists:keyfind(state_transition, 1, Events) of
        {state_transition, handshake} -> handshake;
        _ -> Phase
    end.

%%%-------------------------------------------------------------------
%%% Established phase: echo peer bidi streams.
%%%-------------------------------------------------------------------

serve_loop(Ctx) ->
    receive
        {packet, Source, Bin} ->
            serve_after(nquic_lib:handle_packet(Ctx, Source, Bin));
        {packet, Source, Bin, ECN} ->
            serve_after(nquic_lib:handle_packet(Ctx, Source, Bin, ECN));
        {immediate_packet, Source, Bin} ->
            serve_after(nquic_lib:handle_packet(Ctx, Source, Bin));
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            serve_after(nquic_lib:handle_packet_batch(Ctx, Source, Buf, GsoSize, ECN));
        {quic_timeout, Type} ->
            serve_after(nquic_lib:timeout(Ctx, Type));
        {quic_drain, _Listener} ->
            close(Ctx);
        stop ->
            close(Ctx);
        {'EXIT', _From, _Reason} ->
            close(Ctx);
        _Other ->
            serve_loop(Ctx)
    end.

serve_after({ok, Events, Ctx1}) ->
    {ok, Ctx2} = nquic_lib:flush(Ctx1),
    case lists:member(connection_closed, Events) of
        true -> close(Ctx2);
        false -> serve_loop(echo_events(Events, Ctx2))
    end;
serve_after({error, Reason, Ctx1}) ->
    close_error(Ctx1, Reason).

echo_events([], Ctx) ->
    Ctx;
echo_events([{stream_data, Sid} | Rest], Ctx) ->
    echo_events(Rest, maybe_echo(Sid, Ctx));
echo_events([{stream_opened, Sid} | Rest], Ctx) ->
    echo_events(Rest, maybe_echo(Sid, Ctx));
echo_events([_ | Rest], Ctx) ->
    echo_events(Rest, Ctx).

maybe_echo(Sid, Ctx) ->
    case nquic_lib:recv(Ctx, Sid) of
        {ok, Data, true, Ctx1} when byte_size(Data) > 0 ->
            {ok, Ctx2} = nquic_lib:send_fin(Ctx1, Sid, Data),
            {ok, Ctx3} = nquic_lib:flush(Ctx2),
            Ctx3;
        {ok, _Data, _Fin, Ctx1} ->
            Ctx1;
        {error, _} ->
            Ctx
    end.

close(Ctx) ->
    _ = (catch nquic_lib:close(Ctx)),
    exit(normal).

close_error(Ctx, Reason) ->
    CloseOpts = #{
        error_code => nquic_protocol:error_code(Reason),
        reason => nquic_protocol:error_to_reason_phrase(Reason)
    },
    _ = (catch nquic_lib:close(Ctx, CloseOpts)),
    exit(normal).
