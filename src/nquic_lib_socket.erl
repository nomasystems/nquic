-module(nquic_lib_socket).
-moduledoc false.

%% Low-level socket receive and send glue for `nquic_lib'.
%%
%% Internal glue behind the `nquic_lib' facade. Wraps the raw
%% `socket' syscalls used by the owner loop: a single non-blocking
%% `recvmsg' (with GSO-size extraction from control messages), the
%% packet send path (connected vs. unconnected, with GSO run
%% coalescing), and stale `'$socket'' message draining after a socket
%% swap. Runs in the owner process.

-include("nquic_frame.hrl").
-include("nquic_socket.hrl").
-export([
    drain_stale_socket_msgs/1,
    send_packets/5,
    socket_recv_for_ctx/1
]).

-spec drain_stale_socket_msgs(nquic_socket:t()) -> ok.
drain_stale_socket_msgs(Socket) ->
    receive
        {'$socket', S, _, _} when S =/= Socket ->
            drain_stale_socket_msgs(Socket)
    after 0 ->
        ok
    end.

-spec send_one(nquic_socket:t(), nquic_socket:sockaddr(), boolean(), iodata()) ->
    ok | {error, term()}.
send_one(Socket, _Peer, true, Data) ->
    nquic_socket:send_connected(Socket, Data);
send_one(Socket, Peer, false, Data) ->
    nquic_socket:send(Socket, Peer, Data).

-spec send_packets(
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    boolean(),
    undefined | pos_integer(),
    [iodata()]
) -> ok.
send_packets(_Socket, _Peer, _Connected, _GsoSize, []) ->
    ok;
send_packets(Socket, _Peer, true, undefined, [Pkt | Rest]) ->
    _ = nquic_socket:send_connected(Socket, Pkt),
    send_packets(Socket, _Peer, true, undefined, Rest);
send_packets(Socket, Peer, false, undefined, [Pkt | Rest]) ->
    _ = nquic_socket:send(Socket, Peer, Pkt),
    send_packets(Socket, Peer, false, undefined, Rest);
send_packets(Socket, Peer, Connected, GsoSize, [Pkt | Rest]) ->
    case iolist_size(Pkt) of
        GsoSize ->
            {Group, Rest1} = take_gso_run(
                Rest, GsoSize, ?GSO_BATCH_BUDGET - GsoSize, [Pkt]
            ),
            _ = send_one(Socket, Peer, Connected, Group),
            send_packets(Socket, Peer, Connected, GsoSize, Rest1);
        _ ->
            _ = send_one(Socket, Peer, Connected, Pkt),
            send_packets(Socket, Peer, Connected, GsoSize, Rest)
    end.

-spec socket_recv_for_ctx(nquic_socket:t()) ->
    {ok, nquic_socket:sockaddr(), binary(), undefined | pos_integer()}
    | {select, nquic_socket:select_info()}
    | {error, term()}.
socket_recv_for_ctx(Socket) ->
    case socket:recvmsg(Socket, ?NQUIC_MAX_DATAGRAM, 256, [], nowait) of
        {ok, #{addr := Source, iov := [Bin], ctrl := Ctrl}} when is_binary(Bin) ->
            {ok, Source, Bin, nquic_socket:get_gso_size_from_cmsg(Ctrl)};
        {ok, #{addr := Source, iov := IOV, ctrl := Ctrl}} ->
            {ok, Source, iolist_to_binary(IOV), nquic_socket:get_gso_size_from_cmsg(Ctrl)};
        {select, _} = S ->
            S;
        {error, _} = E ->
            E
    end.

-spec take_gso_run([iodata()], pos_integer(), integer(), [iodata(), ...]) ->
    {[iodata(), ...], [iodata()]}.
take_gso_run([], _GsoSize, _Budget, Acc) ->
    {lists:reverse(Acc), []};
take_gso_run([Pkt | Rest], GsoSize, Budget, Acc) ->
    case iolist_size(Pkt) of
        GsoSize when Budget >= GsoSize ->
            take_gso_run(Rest, GsoSize, Budget - GsoSize, [Pkt | Acc]);
        Smaller when Smaller < GsoSize, Budget >= Smaller ->
            {lists:reverse([Pkt | Acc]), Rest};
        _ ->
            {lists:reverse(Acc), [Pkt | Rest]}
    end.
