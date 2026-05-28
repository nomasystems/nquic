-module(nquic_lib).
-moduledoc """
Library-mode API for nquic.

Library mode exposes the QUIC protocol as pure functions over an
opaque `nquic:ctx()` value. The owning process drives the socket,
receives packets, and flushes outgoing data. Compared to
`gen_statem` mode this avoids every `gen_statem` round trip on the
hot path.

Production use requires the caller to understand the protocol
carefully; the compiler will not stop you from calling the library
functions out of order.

## Typical usage

```erlang
{ok, Ctx}  = nquic:accept(Listener),
{ok, Ctx1} = nquic_lib:takeover(Ctx),
{ok, Ctx2} = nquic_lib:upgrade_to_connected(Ctx1),
loop(Ctx2).

loop(Ctx) ->
    case nquic_lib:recv_and_process(Ctx, 5000) of
        {ok, Events, Ctx1} -> handle(Events), loop(Ctx1);
        {error, _Reason, _} -> ok
    end.
```

## Listener drain

A server connection's owner process is sent
`{quic_drain, Listener}` when its listener is torn down via
`nquic:stop_listener/1,2` with `mode => cascade` (the default).
The owner SHOULD handle this message by closing the connection
(`shutdown/1` for a graceful CONNECTION_CLOSE) and terminating.
An owner that ignores it is not leaked indefinitely (the connection
still closes on its idle timeout), but a prompt `cascade` depends on
owners honouring the signal. Client connections own their socket,
have no listener, and never receive it.
""".

-include("nquic_conn.hrl").
-export([
    buffer_events/2,
    close/1,
    close/2,
    close_stream/2,
    flush/1,
    flush_notimers/1,
    handle_packet/3,
    handle_packet/4,
    handle_packet_batch/5,
    handle_packet_batch_notimers/5,
    handle_packet_notimers/3,
    handle_packet_notimers/4,

    handshake_timeout/3,
    initiate_key_update/1,
    is_writable/2,
    open_stream/2,
    path_stats/1,
    recv/2,
    recv_and_process/1,
    recv_and_process/2,
    recv_batch/1,
    recv_batch/2,
    recv_datagram/1,
    recv_direct/1,
    recv_direct/2,
    recv_pending/1,
    reset_stream/3,
    schedule_timers/1,
    send/3,
    send_datagram/2,
    send_fin/3,
    send_fin_noflush/3,
    server_accept_init/1,

    shutdown/1,
    shutdown/3,
    takeover/1,
    timeout/2,
    upgrade_to_connected/1
]).

-export([ctx_connected/1, ctx_dispatch/1, ctx_peer/1, ctx_socket/1, ctx_state/1, ctx_timers/1]).

%%%-----------------------------------------------------------------------------
%% SEND / RECV
%%%-----------------------------------------------------------------------------
-doc """
Buffer protocol events into the context.

Moves `{datagram_received, Data}` events into the datagram buffer
(bounded, drops oldest on overflow). Returns remaining non-datagram
events and the updated context.
""".
-spec buffer_events([nquic_protocol:event()], nquic:ctx()) ->
    {[nquic_protocol:event()], nquic:ctx()}.
buffer_events(Events, Ctx) ->
    buffer_events(Events, Ctx, []).

-spec buffer_events([nquic_protocol:event()], nquic:ctx(), [nquic_protocol:event()]) ->
    {[nquic_protocol:event()], nquic:ctx()}.
buffer_events([], Ctx, OtherAcc) ->
    {lists:reverse(OtherAcc), Ctx};
buffer_events([{datagram_received, Data} | Rest], Ctx, OtherAcc) ->
    Buf = nquic_ctx:datagram_buffer(Ctx),
    Size = nquic_ctx:datagram_buffer_size(Ctx),
    Max = nquic_ctx:datagram_buffer_max(Ctx),
    {Buf1, Size1} =
        case Size >= Max of
            true ->
                {{value, _}, Buf2} = queue:out(Buf),
                {queue:in(Data, Buf2), Size};
            false ->
                {queue:in(Data, Buf), Size + 1}
        end,
    Ctx1 = nquic_ctx:set_datagram(Ctx, Buf1, Size1),
    buffer_events(Rest, Ctx1, OtherAcc);
buffer_events([Event | Rest], Ctx, OtherAcc) ->
    buffer_events(Rest, Ctx, [Event | OtherAcc]).

-doc """
Read available data from a stream buffer.
Does not block. Returns `{ok, Data, IsFin, Ctx}` where `IsFin` marks
end of stream.
""".
-spec recv(nquic:ctx(), nquic:stream_id()) ->
    {ok, binary(), boolean(), nquic:ctx()} | {error, term()}.
recv(Ctx, StreamId) ->
    case nquic_protocol:read_stream(StreamId, nquic_ctx:state(Ctx)) of
        {ok, Data, IsFin, State1} ->
            {ok, Data, IsFin, nquic_ctx:set_state(Ctx, State1)};
        {error, _} = Err ->
            Err
    end.

-doc """
Receive a buffered DATAGRAM.
Returns the oldest datagram from the buffer, or `{error, empty}` if
none are available. Use `buffer_events/2` after `handle_packet/3` to
move received datagrams into the buffer.
""".
-spec recv_datagram(nquic:ctx()) -> {ok, binary(), nquic:ctx()} | {error, empty}.
recv_datagram(Ctx) ->
    Buf = nquic_ctx:datagram_buffer(Ctx),
    case queue:out(Buf) of
        {{value, Data}, Buf1} ->
            Size = nquic_ctx:datagram_buffer_size(Ctx),
            {ok, Data, nquic_ctx:set_datagram(Ctx, Buf1, Size - 1)};
        {empty, _} ->
            {error, empty}
    end.

-doc """
Send data on a stream.
Queues the data, flushes pending frames into packets, and writes them
to the socket.
""".
-spec send(nquic:ctx(), nquic:stream_id(), iodata()) ->
    {ok, nquic:ctx()} | {error, term(), nquic:ctx()} | {error, term()}.
send(Ctx, StreamId, Data) ->
    case nquic_protocol:send_stream(StreamId, Data, nofin, nquic_ctx:state(Ctx)) of
        {ok, State1} ->
            flush_ctx(nquic_ctx:set_state(Ctx, State1));
        {error, Reason, State1} ->
            {error, Reason, nquic_ctx:set_state(Ctx, State1)};
        {error, _} = Err ->
            Err
    end.

-doc "Send an unreliable DATAGRAM frame.".
-spec send_datagram(nquic:ctx(), binary()) -> {ok, nquic:ctx()} | {error, nquic_error:any_reason()}.
send_datagram(Ctx, Data) ->
    case nquic_protocol:send_datagram(Data, nquic_ctx:state(Ctx)) of
        {ok, State1} ->
            flush_ctx(nquic_ctx:set_state(Ctx, State1));
        {error, _} = Err ->
            Err
    end.

-doc "Send data with FIN on a stream.".
-spec send_fin(nquic:ctx(), nquic:stream_id(), iodata()) ->
    {ok, nquic:ctx()} | {error, term(), nquic:ctx()} | {error, term()}.
send_fin(Ctx, StreamId, Data) ->
    case nquic_protocol:send_stream(StreamId, Data, fin, nquic_ctx:state(Ctx)) of
        {ok, State1} ->
            flush_ctx(nquic_ctx:set_state(Ctx, State1));
        {error, Reason, State1} ->
            {error, Reason, nquic_ctx:set_state(Ctx, State1)};
        {error, _} = Err ->
            Err
    end.

-doc """
Queue data + FIN on a stream without flushing.
Use to batch multiple stream sends into a single subsequent `flush/1`
call.
""".
-spec send_fin_noflush(nquic:ctx(), nquic:stream_id(), iodata()) ->
    {ok, nquic:ctx()} | {error, term(), nquic:ctx()} | {error, term()}.
send_fin_noflush(Ctx, StreamId, Data) ->
    case nquic_protocol:send_stream(StreamId, Data, fin, nquic_ctx:state(Ctx)) of
        {ok, State1} ->
            {ok, nquic_ctx:set_state(Ctx, State1)};
        {error, Reason, State1} ->
            {error, Reason, nquic_ctx:set_state(Ctx, State1)};
        {error, _} = Err ->
            Err
    end.

%%%-----------------------------------------------------------------------------
%% STREAM LIFECYCLE
%%%-----------------------------------------------------------------------------
-doc "Close a stream.".
-spec close_stream(nquic:ctx(), nquic:stream_id()) ->
    {ok, nquic:ctx()} | {error, nquic_error:any_reason()}.
close_stream(Ctx, StreamId) ->
    case nquic_protocol:close_stream(StreamId, nquic_ctx:state(Ctx)) of
        {ok, State1} ->
            flush_ctx(nquic_ctx:set_state(Ctx, State1));
        {error, _} = Err ->
            Err
    end.

-doc "Open a new stream.".
-spec open_stream(nquic:ctx(), nquic:stream_opts()) ->
    {ok, nquic:stream_id(), nquic:ctx()} | {error, term()}.
open_stream(Ctx, Opts) ->
    case nquic_protocol:open_stream(Opts, nquic_ctx:state(Ctx)) of
        {ok, StreamId, State1} ->
            {ok, StreamId, nquic_ctx:set_state(Ctx, State1)};
        {error, _} = Err ->
            Err
    end.

-doc "Reset a stream with an error code.".
-spec reset_stream(nquic:ctx(), nquic:stream_id(), non_neg_integer()) ->
    {ok, nquic:ctx()} | {error, term()}.
reset_stream(Ctx, StreamId, ErrorCode) ->
    case nquic_protocol:reset_stream(StreamId, ErrorCode, nquic_ctx:state(Ctx)) of
        {ok, State1} ->
            flush_ctx(nquic_ctx:set_state(Ctx, State1));
        {error, _} = Err ->
            Err
    end.

%%%-----------------------------------------------------------------------------
%% KEY UPDATE
%%%-----------------------------------------------------------------------------
-doc """
Initiate a client-side key update (RFC 9001 Section 6).
Rotates the 1-RTT traffic secrets and flips the key phase so the next
sent 1-RTT packet carries the new keys. No frame is emitted and no
packet is sent here; the owner's next `flush/1` (or any send) carries
the rotation, and the peer's reply confirms it. Returns
`{error, key_update_pending}` if a previously initiated update has not
yet been confirmed by the peer.
""".
-spec initiate_key_update(nquic:ctx()) ->
    {ok, nquic:ctx()} | {error, key_update_pending}.
initiate_key_update(Ctx) ->
    case nquic_protocol_key_update:initiate_key_update(nquic_ctx:state(Ctx)) of
        {ok, State1} ->
            {ok, nquic_ctx:set_state(Ctx, State1)};
        {error, key_update_pending} = Err ->
            Err
    end.

%%%-----------------------------------------------------------------------------
%% PACKET PROCESSING
%%%-----------------------------------------------------------------------------
-doc """
Flush pending frames into packets and send them.
Encrypts queued frames, sends the resulting packets via the socket,
and schedules any timer updates.
""".
-spec flush(nquic:ctx()) -> {ok, nquic:ctx()}.
flush(Ctx) ->
    flush_ctx(Ctx).

-doc """
Flush pending frames without scheduling timers.
Use this when the caller will immediately call a recv function that
handles timers; avoids redundant `cancel_timer` / `send_after`
syscalls.
""".
-spec flush_notimers(nquic:ctx()) -> {ok, nquic:ctx()}.
flush_notimers(Ctx) ->
    State = nquic_ctx:state(Ctx),
    case nquic_protocol:flush(State) of
        {ok, Packets, State1, _TimerActions} ->
            Socket = nquic_ctx:socket(Ctx),
            State2 = nquic_lib_timer:maybe_apply_ecn_transition(Socket, State1),
            nquic_conn_metrics:bytes_out(State2, iolist_size(Packets)),
            nquic_lib_socket:send_packets(
                Socket,
                State2#conn_state.peer,
                nquic_ctx:connected(Ctx),
                State2#conn_state.gso_size,
                Packets
            ),
            {ok, nquic_ctx:set_state(Ctx, State2)};
        {ok, State1} ->
            {ok, nquic_ctx:set_state(Ctx, State1)}
    end.

-doc """
Process an incoming packet.
Decrypts, decodes, and handles every frame in the packet. Returns the
protocol events and the context with timers scheduled.
""".
-spec handle_packet(nquic:ctx(), nquic_socket:sockaddr(), binary()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
handle_packet(Ctx, Source, Bin) ->
    handle_packet(Ctx, Source, Bin, not_ect).

-doc "Like `handle_packet/3` but carries the inbound ECN codepoint.".
-spec handle_packet(
    nquic:ctx(), nquic_socket:sockaddr(), binary(), nquic_socket:ecn_mark()
) -> {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
handle_packet(Ctx, Source, Bin, ECN) ->
    nquic_conn_metrics:bytes_in(nquic_ctx:state(Ctx), byte_size(Bin)),
    case nquic_protocol:handle_packet(Bin, Source, nquic_ctx:state(Ctx), ECN) of
        {ok, Events, State1, TimerActions} ->
            Ctx1 = nquic_lib_timer:apply_timer_actions(
                nquic_ctx:set_state(Ctx, State1), TimerActions
            ),
            {Events1, Ctx2} = nquic_lib_timer:absorb_migration_events(Events, Ctx1),
            {ok, Events1, Ctx2};
        {error, Reason, State1} ->
            {error, Reason, nquic_ctx:set_state(Ctx, State1)}
    end.

-doc """
Process an incoming packet without scheduling timers.
Use for batch processing: call this once per packet, then call
`schedule_timers/1` once at the end before flushing.
""".
-spec handle_packet_notimers(nquic:ctx(), nquic_socket:sockaddr(), binary()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
handle_packet_notimers(Ctx, Source, Bin) ->
    handle_packet_notimers(Ctx, Source, Bin, not_ect).

-doc "Like `handle_packet_notimers/3` but carries an ECN mark.".
-spec handle_packet_notimers(
    nquic:ctx(), nquic_socket:sockaddr(), binary(), nquic_socket:ecn_mark()
) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
handle_packet_notimers(Ctx, Source, Bin, ECN) ->
    nquic_conn_metrics:bytes_in(nquic_ctx:state(Ctx), byte_size(Bin)),
    case nquic_protocol:handle_packet_notimers(Bin, Source, nquic_ctx:state(Ctx), ECN) of
        {ok, Events, State1} ->
            {Events1, Ctx1} = nquic_lib_timer:absorb_migration_events(
                Events, nquic_ctx:set_state(Ctx, State1)
            ),
            {ok, Events1, Ctx1};
        {error, Reason, State1} ->
            {error, Reason, nquic_ctx:set_state(Ctx, State1)}
    end.

-doc """
Compute and schedule timer actions for the current protocol state.
Call this after a batch of `handle_packet_notimers/3` calls and before
`flush/1`. Computes loss detection, idle, and ACK delay timers and
schedules them as `erlang:send_after` messages.
""".
-spec schedule_timers(nquic:ctx()) -> nquic:ctx().
schedule_timers(Ctx) ->
    {TimerActions, State1} = nquic_protocol_timer:compute_timer_actions(nquic_ctx:state(Ctx)),
    nquic_lib_timer:apply_timer_actions(nquic_ctx:set_state(Ctx, State1), TimerActions).

-doc """
Handle a QUIC timer expiration.
Called when a `{quic_timeout, Type}` message is received by the owner.
Processes the timeout (loss detection, idle, path validation),
flushes any resulting packets, and returns protocol events.
""".
-spec timeout(nquic:ctx(), nquic_protocol:timer_type()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
timeout(Ctx, Type) ->
    case nquic_protocol:handle_timeout(Type, nquic_ctx:state(Ctx)) of
        {ok, Events, State1, TimerActions} ->
            {ok, Ctx1} = flush_ctx(nquic_ctx:set_state(Ctx, State1)),
            Ctx2 = nquic_lib_timer:apply_timer_actions(Ctx1, TimerActions),
            {ok, Events, Ctx2};
        {error, Reason, State1} ->
            {error, Reason, nquic_ctx:set_state(Ctx, State1)}
    end.

%%%-----------------------------------------------------------------------------
%% SERVER HANDSHAKE (OWNER-FROM-FIRST-PACKET)
%%%-----------------------------------------------------------------------------
-doc """
Handle a `{quic_timeout, Type}` expiration during the server handshake.
`Phase` is the encryption level the owner is currently driving
(`initial` until it observes `{state_transition, handshake}`, then
`handshake`). On a PTO this sends the probe at that level; the
established `timeout/2` (which probes 1-RTT) is wrong before the
connection is established. Switch to `timeout/2` once `connected` is
observed.
""".
-spec handshake_timeout(nquic:ctx(), initial | handshake, nquic_protocol:timer_type()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
handshake_timeout(Ctx, Phase, Type) ->
    case nquic_protocol:handle_handshake_timeout(Phase, Type, nquic_ctx:state(Ctx)) of
        {ok, Events, State1, TimerActions} ->
            {ok, Ctx1} = flush_ctx(nquic_ctx:set_state(Ctx, State1)),
            Ctx2 = nquic_lib_timer:apply_timer_actions(Ctx1, TimerActions),
            {ok, Events, Ctx2};
        {error, Reason, State1} ->
            {error, Reason, nquic_ctx:set_state(Ctx, State1)}
    end.

-doc """
Seed a server-side `t:nquic:ctx/0` for an owner that drives the
handshake itself, from the first Initial packet's options.
`Opts` is the option map the receiver builds for a new connection
(role, socket, peer, dcid/odcid, version, dispatch_table, listener,
certs, alpn, static_key, transport params, ...). Builds the same
`#conn_state{}` as `nquic_conn_statem:init/1` (via
`nquic_conn_init:new_conn_state/1`), registers `SCID -> self()` in the
dispatch table so the connection's own CIDs route to this owner, and
returns a context in the `initial` phase.
The owner then drives `initial -> handshake -> established` by calling
`handle_packet/3,4` + `flush/1` on inbound `{packet, _}` messages and
`handshake_timeout/3` on `{quic_timeout, _}`, until `handle_packet`
emits `connected`. There is no export, accept queue, or takeover: the
owner is the registrant from the first packet, so the connection's CID
never resolves to a non-owner.
""".
-spec server_accept_init(map()) -> {ok, nquic:ctx()}.
server_accept_init(Opts) ->
    State = nquic_conn_init:new_conn_state(Opts#{role => server}),
    #conn_state{scid = SCID, socket = Socket, peer = Peer, dispatch_table = Dispatch} = State,
    case Dispatch of
        undefined -> ok;
        Table -> nquic_listener:dispatch_register(Table, SCID, self())
    end,
    nquic_conn_metrics:handshake_started(State),
    {ok, nquic_ctx:new(State, Socket, Peer, Dispatch)}.

%%%-----------------------------------------------------------------------------
%% HIGH-LEVEL RECV / RECV_AND_PROCESS
%%%-----------------------------------------------------------------------------
-spec ctx_owns_socket(nquic:ctx()) -> boolean().
ctx_owns_socket(Ctx) ->
    case nquic_ctx:dispatch(Ctx) of
        undefined -> true;
        _ -> nquic_ctx:connected(Ctx)
    end.

-doc """
Process a GRO-coalesced datagram delivered as a single
`{packet_batch, Source, Buf, GsoSize, ECN}` message.
Splits the buffer per GsoSize bytes and runs `handle_packet/4` on each
segment, consolidating events. Schedules timers once at the end.
""".
-spec handle_packet_batch(
    nquic:ctx(),
    nquic_socket:sockaddr(),
    binary(),
    pos_integer(),
    nquic_socket:ecn_mark()
) -> {ok, [nquic_protocol:event()], nquic:ctx()}.
handle_packet_batch(Ctx, Source, Buf, GsoSize, ECN) ->
    {Ctx1, EventsAcc} = nquic_lib_batch:drain_packet_batch(Ctx, Source, Buf, GsoSize, ECN, []),
    Ctx2 = schedule_timers(Ctx1),
    {ok, lists:reverse(EventsAcc), Ctx2}.

-doc """
Like `handle_packet_batch/5` but without scheduling timers.
For callers that drain many datagrams per wakeup and call
`schedule_timers/1` once at the end before flushing (the batch sibling of
`handle_packet_notimers/3`). Per-segment decode errors are dropped rather
than fatal, mirroring `drain_packet_batch/6`: an undecryptable packet in a
GRO-coalesced buffer must not tear down the connection (RFC 9000 §12.2).
""".
-spec handle_packet_batch_notimers(
    nquic:ctx(),
    nquic_socket:sockaddr(),
    binary(),
    pos_integer(),
    nquic_socket:ecn_mark()
) -> {ok, [nquic_protocol:event()], nquic:ctx()}.
handle_packet_batch_notimers(Ctx, Source, Buf, GsoSize, ECN) ->
    {Ctx1, EventsAcc} = nquic_lib_batch:drain_packet_batch(Ctx, Source, Buf, GsoSize, ECN, []),
    {ok, lists:reverse(EventsAcc), Ctx1}.

-doc """
Receive and process the next packet or timeout.
Waits for either a `{packet, Source, Bin}` message or a
`{quic_timeout, Type}` timer expiration. Equivalent to
`recv_and_process(Ctx, infinity)`.
""".
-spec recv_and_process(nquic:ctx()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_and_process(Ctx) ->
    recv_and_process(Ctx, infinity).

-doc """
Receive and process the next packet or timeout, with timeout.
Returns `{ok, [], Ctx}` if no message arrives within `Timeout` ms.
""".
-spec recv_and_process(nquic:ctx(), timeout()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_and_process(Ctx, Timeout) ->
    receive
        {packet, Source, PacketBin} ->
            handle_packet(Ctx, Source, PacketBin);
        {packet, Source, PacketBin, ECN} ->
            handle_packet(Ctx, Source, PacketBin, ECN);
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            handle_packet_batch(Ctx, Source, Buf, GsoSize, ECN);
        {quic_timeout, Type} ->
            timeout(Ctx, Type)
    after Timeout ->
        {ok, [], Ctx}
    end.

-doc """
Receive and process ALL available packets, then schedule timers and
flush once.
For ctxs upgraded with `upgrade_to_connected/1`, drains both the
mailbox and the kernel queue (via non-blocking `socket:recvfrom/3`).
For dispatched-mode ctxs (sharing the listener socket), drains only
the mailbox; polling the shared socket would steal packets routed
to sibling connections. Blocks up to `Timeout` ms for the first
packet if none are available.
The batch equivalent of `recv_direct/1` / `recv_and_process/1`.
Amortises timer scheduling and flushing across many packets.
""".
-spec recv_batch(nquic:ctx()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_batch(Ctx) ->
    recv_batch(Ctx, infinity).

-doc "Like `recv_batch/1` with a timeout on the first packet.".
-spec recv_batch(nquic:ctx(), timeout()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_batch(Ctx, Timeout) ->
    case ctx_owns_socket(Ctx) of
        true -> nquic_lib_batch:recv_batch_connected(Ctx, Timeout);
        false -> nquic_lib_batch:recv_batch_dispatched(Ctx, Timeout)
    end.

-doc """
Receive and process the next packet directly from the socket.
For connections that called `upgrade_to_connected/1`, reads packets
directly via `socket:recvfrom/3` instead of waiting for `{packet,...}`
messages. Also services timer expirations.
""".
-spec recv_direct(nquic:ctx()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_direct(Ctx) ->
    recv_direct(Ctx, infinity).

-doc "Like `recv_direct/1` with a timeout.".
-spec recv_direct(nquic:ctx(), timeout()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_direct(Ctx, Timeout) ->
    Socket = nquic_ctx:socket(Ctx),
    nquic_lib_socket:drain_stale_socket_msgs(Socket),
    receive
        {packet, Source, PacketBin} ->
            handle_packet(Ctx, Source, PacketBin);
        {packet, Source, PacketBin, ECN} ->
            handle_packet(Ctx, Source, PacketBin, ECN);
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            handle_packet_batch(Ctx, Source, Buf, GsoSize, ECN);
        {quic_timeout, Type} ->
            timeout(Ctx, Type)
    after 0 ->
        case nquic_lib_socket:socket_recv_for_ctx(Socket) of
            {ok, Source, Buf, undefined} ->
                handle_packet(Ctx, Source, Buf);
            {ok, Source, Buf, GsoSize} ->
                handle_packet_batch(Ctx, Source, Buf, GsoSize, not_ect);
            {select, SelectInfo} ->
                receive
                    {'$socket', Socket, select, _SI} ->
                        recv_direct_ready(Ctx, Socket);
                    {packet, Src, Bin} ->
                        _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                        handle_packet(Ctx, Src, Bin);
                    {packet, Src, Bin, ECN} ->
                        _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                        handle_packet(Ctx, Src, Bin, ECN);
                    {packet_batch, Src, Buf, GsoSize, ECN} ->
                        _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                        handle_packet_batch(Ctx, Src, Buf, GsoSize, ECN);
                    {quic_timeout, Type} ->
                        _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                        timeout(Ctx, Type)
                after Timeout ->
                    _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                    {ok, [], Ctx}
                end;
            {error, Reason} ->
                {error, Reason, Ctx}
        end
    end.

-doc """
Upgrade the context to use a connected UDP socket.
Opens a new UDP socket on the same port as the listener, then
`connect(2)`s it to the peer. The kernel routes packets from this peer
directly to the new socket, bypassing the receiver dispatch entirely.
After this call, use `recv_direct/1,2` instead of
`recv_and_process/1,2`.
> #### Warning: handshake race under burst load {: .warning}
>
> The connected socket must bind to the listener's port with
> `SO_REUSEPORT` (Linux requires all sockets sharing a port to have it
> if any does). Each upgraded connection adds another member to the
> reuseport group. For a new client's Initial (no existing 4-tuple
> match), Linux hashes across the group and may land on a connected
> socket whose peer does not match; `compute_score()` returns -1 and
> the kernel drops the packet rather than retrying another slot. The
> new client then stalls until `wait_established` times out.
>
> Under sequential-but-bursty connects the observed loss rate is ~1%
> per new handshake once many connections are held open. The proper
> fix is an `SO_ATTACH_REUSEPORT_CBPF` filter pinning fallback hashes
> to the listener slot (exact 4-tuple matches bypass it and keep the
> fast path). OTP 28's `socket` module does not yet expose this option
> and `setopt_native` cannot marshal the required `struct sock_fprog`
> pointer, so the fix is pending.
>
> Callers that accept many concurrent connections should avoid this
> helper until the library-level fix lands, or tolerate the rare
> timeout at the accept layer.
""".
-spec upgrade_to_connected(nquic:ctx()) ->
    {ok, nquic:ctx()} | {error, term()}.
upgrade_to_connected(Ctx) ->
    OldSocket = nquic_ctx:socket(Ctx),
    Peer = nquic_ctx:peer(Ctx),
    maybe
        {ok, ListenerPort} ?= nquic_socket:port(OldSocket),
        {ok, ConnSocket} ?= nquic_socket:open_connected(ListenerPort, Peer),
        {ok, nquic_ctx:set_socket_connected(Ctx, ConnSocket, true)}
    else
        {error, _} = Err ->
            Err
    end.

%%%-----------------------------------------------------------------------------
%% CLOSE / SHUTDOWN
%%%-----------------------------------------------------------------------------
-doc "Close the connection gracefully (transport scope, error code 0, empty reason).".
-spec close(nquic:ctx()) -> {ok, nquic:ctx()}.
close(Ctx) ->
    close(Ctx, #{}).

-doc """
Close the connection with the given options.
`scope => transport` (default) emits CONNECTION_CLOSE type 0x1c;
`application` emits type 0x1d (RFC 9000 §19.19).
""".
-spec close(nquic:ctx(), nquic:close_opts()) -> {ok, nquic:ctx()}.
close(Ctx, Opts) ->
    Scope = maps:get(scope, Opts, transport),
    ErrorCode = maps:get(error_code, Opts, 0),
    Reason = maps:get(reason, Opts, <<>>),
    State0 = nquic_ctx:state(Ctx),
    {ok, State1} =
        case Scope of
            transport -> nquic_protocol:close(ErrorCode, Reason, State0);
            application -> nquic_protocol:close_app(ErrorCode, Reason, State0)
        end,
    flush_ctx(nquic_ctx:set_state(Ctx, State1)).

-doc """
Shut down a library-mode connection.
Sends CONNECTION_CLOSE with error code 0, flushes pending packets,
cancels all timers, and explicitly closes the connected UDP socket
(if any). Idempotent. Always returns `ok`.
The caller is expected to clean up dispatch table entries and exit
the process itself after this returns.
""".
-spec shutdown(nquic:ctx()) -> ok.
shutdown(Ctx) ->
    shutdown_impl(fun close/1, Ctx).

-doc "Like `shutdown/1` but sends an application error code.".
-spec shutdown(nquic:ctx(), non_neg_integer(), binary()) -> ok.
shutdown(Ctx, ErrorCode, Reason) ->
    CloseOpts = #{scope => application, error_code => ErrorCode, reason => Reason},
    CloseFn = fun(C) -> close(C, CloseOpts) end,
    shutdown_impl(CloseFn, Ctx).

-spec shutdown_impl(fun((nquic:ctx()) -> {ok, nquic:ctx()}), nquic:ctx()) -> ok.
shutdown_impl(CloseFn, Ctx) ->
    _ =
        try CloseFn(Ctx) of
            {ok, Ctx1} ->
                try flush(Ctx1) of
                    {ok, _} -> ok
                catch
                    error:_ -> ok
                end
        catch
            error:_ -> ok
        end,
    ok = maps:foreach(
        fun(_Type, Ref) ->
            _ = erlang:cancel_timer(Ref, [{async, true}, {info, false}])
        end,
        nquic_ctx:timers(Ctx)
    ),
    _ =
        case nquic_ctx:connected(Ctx) of
            true -> socket:close(nquic_ctx:socket(Ctx));
            false -> ok
        end,
    ok.

%%%-----------------------------------------------------------------------------
%% CID TAKEOVER / PENDING DRAIN
%%%-----------------------------------------------------------------------------
-doc """
Process every buffered `{packet, Source, Bin}` message in the current
process mailbox.
Call after `takeover/1` and/or `upgrade_to_connected/1` to handle
packets that arrived during the ownership transition window. Returns
accumulated events, or `{error, Reason, Ctx}` on transport error.
""".
-spec recv_pending(nquic:ctx()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_pending(Ctx) ->
    recv_pending_loop(Ctx, []).

-spec recv_pending_loop(nquic:ctx(), [nquic_protocol:event()]) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_pending_loop(Ctx, AccEvents) ->
    receive
        {packet, Source, Bin} ->
            case handle_packet(Ctx, Source, Bin) of
                {ok, Events, Ctx1} ->
                    recv_pending_loop(Ctx1, AccEvents ++ Events);
                {error, Reason, Ctx1} ->
                    {error, Reason, Ctx1}
            end;
        {packet, Source, Bin, _ECN} ->
            case handle_packet(Ctx, Source, Bin) of
                {ok, Events, Ctx1} ->
                    recv_pending_loop(Ctx1, AccEvents ++ Events);
                {error, Reason, Ctx1} ->
                    {error, Reason, Ctx1}
            end
    after 0 ->
        {ok, AccEvents, Ctx}
    end.

-doc """
Take ownership of a library-mode context in this process.
Re-registers all local connection IDs in the dispatch table to point to
`self()`. Call this when a process receives a `nquic:ctx()` from another
process (e.g. an accept loop handing off to a per-connection handler).
After `takeover/1`, call `recv_pending/1` to process any packets that
were buffered in the previous owner's mailbox during the transition.
""".
-spec takeover(nquic:ctx()) -> {ok, nquic:ctx()}.
takeover(Ctx) ->
    State = nquic_ctx:state(Ctx),
    case nquic_ctx:dispatch(Ctx) of
        undefined ->
            Ctx1 = nquic_ctx:set_state(Ctx, nquic_protocol:reset_timer_cache(State)),
            {ok, schedule_timers(Ctx1)};
        Dispatch ->
            CIDs = nquic_protocol:local_cids(State),
            Self = self(),
            ok = lists:foreach(
                fun(CID) -> nquic_dispatch:register(Dispatch, CID, Self) end,
                CIDs
            ),
            case nquic_protocol:odcid(State) of
                undefined -> ok;
                <<>> -> ok;
                ODCID -> nquic_dispatch:register(Dispatch, ODCID, Self)
            end,
            Ctx1 = nquic_ctx:set_state(Ctx, nquic_protocol:reset_timer_cache(State)),
            {ok, schedule_timers(Ctx1)}
    end.

%%%-----------------------------------------------------------------------------
%% CONTEXT ACCESSORS
%%%-----------------------------------------------------------------------------
-doc false.
-spec ctx_connected(nquic:ctx()) -> boolean().
ctx_connected(Ctx) -> nquic_ctx:connected(Ctx).

-doc false.
-spec ctx_dispatch(nquic:ctx()) -> nquic_dispatch:t() | undefined.
ctx_dispatch(Ctx) -> nquic_ctx:dispatch(Ctx).

-doc false.
-spec ctx_peer(nquic:ctx()) -> nquic_socket:sockaddr().
ctx_peer(Ctx) -> nquic_ctx:peer(Ctx).

-doc false.
-spec ctx_socket(nquic:ctx()) -> nquic_socket:t().
ctx_socket(Ctx) -> nquic_ctx:socket(Ctx).

-doc false.
-spec ctx_state(nquic:ctx()) -> nquic_protocol:state().
ctx_state(Ctx) -> nquic_ctx:state(Ctx).

-doc false.
-spec ctx_timers(nquic:ctx()) -> #{nquic_protocol:timer_type() => reference()}.
ctx_timers(Ctx) -> nquic_ctx:timers(Ctx).

-doc """
Point-in-time stream writability probe on a library-mode context.
Pure projection on the conn_state held inside the `nquic:ctx()`:
returns `true` when the stream exists, its send side is not
terminal, and one byte fits under current connection-flow,
stream-flow, and congestion limits. `false` otherwise (including
unknown streams). A `false` does not guarantee the next send
succeeds, and a `true` can be stale before the caller acts; it is a
between-recv-turns probe, not a poll loop.
""".
-spec is_writable(nquic:ctx(), nquic:stream_id()) -> boolean().
is_writable(Ctx, StreamId) ->
    nquic_protocol_streams_send:is_writable(StreamId, nquic_ctx:state(Ctx)).

-doc """
Project path-level statistics from a library-mode context.
Pure projection on the conn_state held inside the `nquic:ctx()`. No
message hops, no syscalls. See `nquic_conn:path_stats/1` for the field
list.
""".
-spec path_stats(nquic:ctx()) -> nquic_loss:path_stats().
path_stats(Ctx) ->
    nquic_protocol:path_stats(nquic_ctx:state(Ctx)).

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec flush_ctx(nquic:ctx()) -> {ok, nquic:ctx()}.
flush_ctx(Ctx) ->
    State = nquic_ctx:state(Ctx),
    case nquic_protocol:flush(State) of
        {ok, Packets, State1, TimerActions} ->
            Socket = nquic_ctx:socket(Ctx),
            State2 = nquic_lib_timer:maybe_apply_ecn_transition(Socket, State1),
            nquic_conn_metrics:bytes_out(State2, iolist_size(Packets)),
            nquic_lib_socket:send_packets(
                Socket,
                State2#conn_state.peer,
                nquic_ctx:connected(Ctx),
                State2#conn_state.gso_size,
                Packets
            ),
            Ctx1 = nquic_lib_timer:apply_timer_actions(
                nquic_ctx:set_state(Ctx, State2), TimerActions
            ),
            {ok, Ctx1};
        {ok, State1} ->
            {ok, nquic_ctx:set_state(Ctx, State1)}
    end.

-spec recv_direct_ready(nquic:ctx(), nquic_socket:t()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_direct_ready(Ctx, Socket) ->
    case nquic_lib_socket:socket_recv_for_ctx(Socket) of
        {ok, Source, Buf, undefined} ->
            handle_packet(Ctx, Source, Buf);
        {ok, Source, Buf, GsoSize} ->
            handle_packet_batch(Ctx, Source, Buf, GsoSize, not_ect);
        {select, _} ->
            {ok, [], Ctx};
        {error, Reason} ->
            {error, Reason, Ctx}
    end.
