-module(nquic_lib_batch).
-moduledoc false.

%% Receive-batch / mailbox-drain engine for `nquic_lib'.
%%
%% Internal glue behind the `nquic_lib' facade. Implements the
%% amortised receive path: drain every available packet (mailbox and,
%% for connected sockets, the kernel queue), process each without
%% scheduling timers, then schedule timers and flush exactly once.
%% Runs in the owner process. Calls back into the frozen `nquic_lib'
%% public API (`handle_packet_notimers/3,4', `timeout/2',
%% `schedule_timers/1', `flush/1') for the per-packet protocol step.

-export([
    drain_packet_batch/6,
    recv_batch_connected/2,
    recv_batch_dispatched/2
]).

-spec batch_drain_loop_connected(nquic:ctx(), [nquic_protocol:event()]) ->
    {ok, [nquic_protocol:event()], nquic:ctx()}.
batch_drain_loop_connected(Ctx, EventsAcc) ->
    Socket = nquic_ctx:socket(Ctx),
    receive
        {packet, Source, PacketBin, ECN} ->
            case nquic_lib:handle_packet_notimers(Ctx, Source, PacketBin, ECN) of
                {ok, [], Ctx1} ->
                    batch_drain_loop_connected(Ctx1, EventsAcc);
                {ok, Events, Ctx1} ->
                    batch_drain_loop_connected(Ctx1, lists:reverse(Events, EventsAcc));
                {error, _Reason, Ctx1} ->
                    batch_drain_loop_connected(Ctx1, EventsAcc)
            end;
        {packet, Source, PacketBin} ->
            case nquic_lib:handle_packet_notimers(Ctx, Source, PacketBin) of
                {ok, [], Ctx1} ->
                    batch_drain_loop_connected(Ctx1, EventsAcc);
                {ok, Events, Ctx1} ->
                    batch_drain_loop_connected(Ctx1, lists:reverse(Events, EventsAcc));
                {error, _Reason, Ctx1} ->
                    batch_drain_loop_connected(Ctx1, EventsAcc)
            end;
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            {Ctx1, EventsAcc1} = drain_packet_batch(Ctx, Source, Buf, GsoSize, ECN, EventsAcc),
            batch_drain_loop_connected(Ctx1, EventsAcc1);
        {quic_timeout, _Type} ->
            batch_finish(Ctx, EventsAcc)
    after 0 ->
        case nquic_lib_socket:socket_recv_for_ctx(Socket) of
            {ok, Source, Buf, undefined} ->
                case nquic_lib:handle_packet_notimers(Ctx, Source, Buf) of
                    {ok, [], Ctx1} ->
                        batch_drain_loop_connected(Ctx1, EventsAcc);
                    {ok, Events, Ctx1} ->
                        batch_drain_loop_connected(Ctx1, lists:reverse(Events, EventsAcc));
                    {error, _Reason, Ctx1} ->
                        batch_drain_loop_connected(Ctx1, EventsAcc)
                end;
            {ok, Source, Buf, GsoSize} ->
                {Ctx1, EventsAcc1} = drain_packet_batch(
                    Ctx, Source, Buf, GsoSize, not_ect, EventsAcc
                ),
                batch_drain_loop_connected(Ctx1, EventsAcc1);
            {select, SelectInfo} ->
                _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                batch_finish(Ctx, EventsAcc);
            {error, _Reason} ->
                batch_finish(Ctx, EventsAcc)
        end
    end.

-spec batch_drain_loop_dispatched(nquic:ctx(), [nquic_protocol:event()]) ->
    {ok, [nquic_protocol:event()], nquic:ctx()}.
batch_drain_loop_dispatched(Ctx, EventsAcc) ->
    receive
        {packet, Source, PacketBin, ECN} ->
            case nquic_lib:handle_packet_notimers(Ctx, Source, PacketBin, ECN) of
                {ok, [], Ctx1} ->
                    batch_drain_loop_dispatched(Ctx1, EventsAcc);
                {ok, Events, Ctx1} ->
                    batch_drain_loop_dispatched(Ctx1, lists:reverse(Events, EventsAcc));
                {error, _Reason, Ctx1} ->
                    batch_drain_loop_dispatched(Ctx1, EventsAcc)
            end;
        {packet, Source, PacketBin} ->
            case nquic_lib:handle_packet_notimers(Ctx, Source, PacketBin) of
                {ok, [], Ctx1} ->
                    batch_drain_loop_dispatched(Ctx1, EventsAcc);
                {ok, Events, Ctx1} ->
                    batch_drain_loop_dispatched(Ctx1, lists:reverse(Events, EventsAcc));
                {error, _Reason, Ctx1} ->
                    batch_drain_loop_dispatched(Ctx1, EventsAcc)
            end;
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            {Ctx1, EventsAcc1} = drain_packet_batch(Ctx, Source, Buf, GsoSize, ECN, EventsAcc),
            batch_drain_loop_dispatched(Ctx1, EventsAcc1);
        {quic_timeout, _Type} ->
            batch_finish(Ctx, EventsAcc)
    after 0 ->
        batch_finish(Ctx, EventsAcc)
    end.

-spec batch_finish(nquic:ctx(), [nquic_protocol:event()]) ->
    {ok, [nquic_protocol:event()], nquic:ctx()}.
batch_finish(Ctx, EventsAcc) ->
    Ctx1 = nquic_lib:schedule_timers(Ctx),
    {ok, Ctx2} = nquic_lib:flush(Ctx1),
    {ok, lists:reverse(EventsAcc), Ctx2}.

-spec batch_first_packet(nquic:ctx(), nquic_socket:sockaddr(), binary()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
batch_first_packet(Ctx, Source, PacketBin) ->
    case nquic_lib:handle_packet_notimers(Ctx, Source, PacketBin) of
        {ok, Events, Ctx1} ->
            batch_drain_loop_connected(Ctx1, Events);
        {error, _Reason, Ctx1} ->
            batch_drain_loop_connected(Ctx1, [])
    end.

-spec batch_first_packet_batch(
    nquic:ctx(),
    nquic_socket:sockaddr(),
    binary(),
    pos_integer(),
    nquic_socket:ecn_mark(),
    connected | dispatched
) -> {ok, [nquic_protocol:event()], nquic:ctx()}.
batch_first_packet_batch(Ctx, Source, Buf, GsoSize, ECN, Mode) ->
    {Ctx1, EventsAcc} = drain_packet_batch(Ctx, Source, Buf, GsoSize, ECN, []),
    case Mode of
        connected -> batch_drain_loop_connected(Ctx1, EventsAcc);
        dispatched -> batch_drain_loop_dispatched(Ctx1, EventsAcc)
    end.

-spec batch_first_packet_msg(nquic:ctx(), nquic_socket:sockaddr(), binary()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
batch_first_packet_msg(Ctx, Source, PacketBin) ->
    case nquic_lib:handle_packet_notimers(Ctx, Source, PacketBin) of
        {ok, Events, Ctx1} ->
            batch_drain_loop_dispatched(Ctx1, Events);
        {error, _Reason, Ctx1} ->
            batch_drain_loop_dispatched(Ctx1, [])
    end.

-spec batch_first_ready(nquic:ctx(), nquic_socket:t()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
batch_first_ready(Ctx, Socket) ->
    case nquic_lib_socket:socket_recv_for_ctx(Socket) of
        {ok, Source, Buf, undefined} ->
            batch_first_packet(Ctx, Source, Buf);
        {ok, Source, Buf, GsoSize} ->
            batch_first_packet_batch(Ctx, Source, Buf, GsoSize, not_ect, connected);
        {select, _} ->
            {ok, [], Ctx};
        {error, Reason} ->
            {error, Reason, Ctx}
    end.

-spec drain_packet_batch(
    nquic:ctx(),
    nquic_socket:sockaddr(),
    binary(),
    pos_integer(),
    nquic_socket:ecn_mark(),
    [nquic_protocol:event()]
) -> {nquic:ctx(), [nquic_protocol:event()]}.
drain_packet_batch(Ctx, Source, Buf, GsoSize, ECN, EventsAcc) when byte_size(Buf) =< GsoSize ->
    case nquic_lib:handle_packet_notimers(Ctx, Source, Buf, ECN) of
        {ok, [], Ctx1} -> {Ctx1, EventsAcc};
        {ok, Events, Ctx1} -> {Ctx1, lists:reverse(Events, EventsAcc)};
        {error, _Reason, Ctx1} -> {Ctx1, EventsAcc}
    end;
drain_packet_batch(Ctx, Source, Buf, GsoSize, ECN, EventsAcc) ->
    <<Segment:GsoSize/binary, Rest/binary>> = Buf,
    case nquic_lib:handle_packet_notimers(Ctx, Source, Segment, ECN) of
        {ok, [], Ctx1} ->
            drain_packet_batch(Ctx1, Source, Rest, GsoSize, ECN, EventsAcc);
        {ok, Events, Ctx1} ->
            drain_packet_batch(Ctx1, Source, Rest, GsoSize, ECN, lists:reverse(Events, EventsAcc));
        {error, _Reason, Ctx1} ->
            drain_packet_batch(Ctx1, Source, Rest, GsoSize, ECN, EventsAcc)
    end.

-spec recv_batch_connected(nquic:ctx(), timeout()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_batch_connected(Ctx, Timeout) ->
    Socket = nquic_ctx:socket(Ctx),
    nquic_lib_socket:drain_stale_socket_msgs(Socket),
    receive
        {packet, Source, PacketBin} ->
            batch_first_packet(Ctx, Source, PacketBin);
        {packet, Source, PacketBin, _ECN} ->
            batch_first_packet(Ctx, Source, PacketBin);
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            batch_first_packet_batch(Ctx, Source, Buf, GsoSize, ECN, connected);
        {quic_timeout, Type} ->
            nquic_lib:timeout(Ctx, Type)
    after 0 ->
        case nquic_lib_socket:socket_recv_for_ctx(Socket) of
            {ok, Source, Buf, undefined} ->
                batch_first_packet(Ctx, Source, Buf);
            {ok, Source, Buf, GsoSize} ->
                batch_first_packet_batch(Ctx, Source, Buf, GsoSize, not_ect, connected);
            {select, SelectInfo} ->
                receive
                    {'$socket', Socket, select, _SI} ->
                        batch_first_ready(Ctx, Socket);
                    {packet, Src, Bin} ->
                        _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                        batch_first_packet(Ctx, Src, Bin);
                    {packet, Src, Bin, _ECN} ->
                        _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                        batch_first_packet(Ctx, Src, Bin);
                    {packet_batch, Src, Buf, GsoSize, ECN} ->
                        _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                        batch_first_packet_batch(Ctx, Src, Buf, GsoSize, ECN, connected);
                    {quic_timeout, Type} ->
                        _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                        nquic_lib:timeout(Ctx, Type)
                after Timeout ->
                    _ = nquic_socket:recv_cancel(Socket, SelectInfo),
                    {ok, [], Ctx}
                end;
            {error, Reason} ->
                {error, Reason, Ctx}
        end
    end.

-spec recv_batch_dispatched(nquic:ctx(), timeout()) ->
    {ok, [nquic_protocol:event()], nquic:ctx()} | {error, term(), nquic:ctx()}.
recv_batch_dispatched(Ctx, Timeout) ->
    receive
        {packet, Source, PacketBin} ->
            batch_first_packet_msg(Ctx, Source, PacketBin);
        {packet, Source, PacketBin, _ECN} ->
            batch_first_packet_msg(Ctx, Source, PacketBin);
        {packet_batch, Source, Buf, GsoSize, ECN} ->
            batch_first_packet_batch(Ctx, Source, Buf, GsoSize, ECN, dispatched);
        {quic_timeout, Type} ->
            nquic_lib:timeout(Ctx, Type)
    after Timeout ->
        {ok, [], Ctx}
    end.
