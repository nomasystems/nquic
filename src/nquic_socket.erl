-module(nquic_socket).
-moduledoc """
UDP socket abstraction using OTP socket module.

Provides a high-level interface for UDP socket operations optimized for QUIC.
Uses completion-based async I/O for efficient packet reception.

## Example Usage

```erlang
{ok, Socket} = nquic_socket:open(4433, #{}),

{select, SelectInfo} = nquic_socket:recv_start(Socket),

handle_info({'$socket', Socket, select, _Info}, State) ->
    case nquic_socket:recv_now(Socket) of
        {ok, {Source, Data}} ->
            {noreply, State};
        {select, NewSelectInfo} ->
            {noreply, State#state{select_info = NewSelectInfo}}
    end.
```
""".

-include("nquic_frame.hrl").
-export([open/1, open/2]).
-export([send/3, send_connected/2]).
-export([recv_cancel/2, recv_now/1, recv_start/1]).
-export([recv_msg_now/1, recv_msg_start/1]).
-export([open_connected/2, open_ephemeral/2]).
-export([port/1, sockname/1]).
-export([controlling_process/2]).
-export([close/1]).
-export([rebind/2]).
-export([make_sockaddr/2, sockaddr_to_tuple/1]).
-export([get_ecn_from_cmsg/1, set_ecn/2, set_egress_ecn/2]).
-export([send_connected_with_ecn/3, send_with_ecn/4]).
-export([capabilities/0, get_gso_size_from_cmsg/1, set_gro/2, set_gso_size/2]).

-export_type([capabilities/0, ecn_mark/0, open_opts/0, select_info/0, sockaddr/0, t/0]).

-type capabilities() :: #{gso := boolean(), gro := boolean()}.
-type ecn_mark() :: not_ect | ect0 | ect1 | ce.
-type open_opts() :: #{
    port => inet:port_number(),
    ip => inet:ip_address() | any,
    recbuf => pos_integer(),
    sndbuf => pos_integer(),
    reuseaddr => boolean(),
    reuseport => boolean(),
    ipv6_v6only => boolean(),
    ecn => boolean(),
    gso => boolean() | pos_integer(),
    gro => boolean()
}.
-type select_info() :: socket:select_info().
-type sockaddr() :: socket:sockaddr_in() | socket:sockaddr_in6().
-type t() :: socket:socket().

-define(DEFAULT_RECBUF, 2 * 1024 * 1024).
-define(DEFAULT_SNDBUF, 2 * 1024 * 1024).

-define(SOL_UDP, 17).
-define(UDP_SEGMENT, 103).
-define(UDP_GRO, 104).

-define(DEFAULT_GSO_SIZE, 1200).

-define(CAPABILITIES_KEY, {?MODULE, capabilities}).

%%%-----------------------------------------------------------------------------
%% API FUNCTIONS
%%%-----------------------------------------------------------------------------
-doc "Close the socket.".
-spec close(t()) -> ok | {error, nquic_error:any_reason()}.
close(Socket) ->
    socket:close(Socket).

-doc "Transfer socket ownership to another process.".
-spec controlling_process(t(), pid()) -> ok | {error, nquic_error:any_reason()}.
controlling_process(Socket, Pid) ->
    socket:setopt(Socket, otp, controlling_process, Pid).

-doc "Create a sockaddr from IP and port.".
-spec make_sockaddr(inet:ip_address(), inet:port_number()) -> sockaddr().
make_sockaddr({A, B, C, D}, Port) when
    is_integer(A),
    is_integer(B),
    is_integer(C),
    is_integer(D),
    is_integer(Port),
    Port >= 0,
    Port =< 65535
->
    #{family => inet, addr => {A, B, C, D}, port => Port};
make_sockaddr({A, B, C, D, E, F, G, H}, Port) when
    is_integer(A),
    is_integer(B),
    is_integer(C),
    is_integer(D),
    is_integer(E),
    is_integer(F),
    is_integer(G),
    is_integer(H),
    is_integer(Port),
    Port >= 0,
    Port =< 65535
->
    #{family => inet6, addr => {A, B, C, D, E, F, G, H}, port => Port}.

-doc "Open a UDP socket on an ephemeral port.".
-spec open(open_opts()) -> {ok, t()} | {error, nquic_error:any_reason()}.
open(Opts) ->
    open(0, Opts).

-doc "Open a UDP socket on a specific port.".
-spec open(inet:port_number(), open_opts()) -> {ok, t()} | {error, nquic_error:any_reason()}.
open(Port, Opts) ->
    Family = determine_family(Opts),
    maybe
        {ok, Socket} ?= socket:open(Family, dgram, udp),
        ok ?= set_socket_opts(Socket, Opts),
        ok ?= bind_socket(Socket, Port, Family, Opts),
        {ok, Socket}
    else
        {error, _} = Err ->
            Err
    end.

-doc """
Open a connected UDP socket bound to the same port as the listener.
Creates a new UDP socket on `ListenerPort`, then calls `socket:connect/2`
to bind it to `Peer`. The kernel will route datagrams from `Peer` to this
socket (higher priority than the unconnected listener socket). This enables
direct recv on the connection owner process, bypassing the receiver dispatch.
GRO is left off here; callers that expect bursty replies enable it
adaptively via `set_gro/2` once the reply pattern warrants it (a coalesced
datagram is then split per `get_gso_size_from_cmsg/1`).
""".
-spec open_connected(inet:port_number(), sockaddr()) ->
    {ok, t()} | {error, nquic_error:any_reason()}.
open_connected(ListenerPort, Peer) ->
    Opts = #{reuseaddr => true, reuseport => true},
    maybe
        {ok, Socket} ?= open(ListenerPort, Opts),
        ok ?= socket:connect(Socket, Peer),
        {ok, Socket}
    else
        {error, _} = Err ->
            Err
    end.

-doc """
Open an ephemeral connected UDP socket for server-side per-conn FDs.
Binds to a kernel-chosen local port (no SO_REUSEPORT) on the same family
as the peer, then `connect(2)`s the socket to `Peer`. The kernel then
delivers any datagram whose 4-tuple matches (peer addr/port, local
addr/port) directly to this socket, bypassing the listener's
SO_REUSEPORT group entirely. Used post-handshake to migrate a server
connection off the shared listener FD onto its own 4-tuple
(RFC 9000 §9).
`Opts` lets the caller inherit socket-level features (ECN, GSO, GRO,
rcvbuf, sndbuf) from the listener configuration; the function forces
`reuseaddr => false` and `reuseport => false` so the new socket owns
its 4-tuple exclusively.
""".
-spec open_ephemeral(sockaddr(), open_opts()) ->
    {ok, t()} | {error, nquic_error:any_reason()}.
open_ephemeral(#{family := Family} = Peer, Opts) ->
    BindIP =
        case Family of
            inet -> {0, 0, 0, 0};
            inet6 -> {0, 0, 0, 0, 0, 0, 0, 0}
        end,
    SockOpts = (maps:without([reuseaddr, reuseport, ip], Opts))#{
        reuseaddr => false,
        reuseport => false,
        ip => BindIP
    },
    maybe
        {ok, Socket} ?= open(0, SockOpts),
        ok ?= socket:connect(Socket, Peer),
        {ok, Socket}
    else
        {error, _} = Err ->
            Err
    end.

-doc "Get the local port number of the socket.".
-spec port(t()) -> {ok, inet:port_number()} | {error, nquic_error:any_reason()}.
port(Socket) ->
    case socket:sockname(Socket) of
        {ok, #{port := Port}} ->
            {ok, Port};
        {error, _} = Err ->
            Err
    end.

-doc """
Rebind a socket to a new local address for connection migration.
Opens a new socket on the new address, closes the old one, returns the new socket.
""".
-spec rebind(t(), sockaddr()) -> {ok, t()} | {error, nquic_error:any_reason()}.
rebind(OldSocket, NewAddr) ->
    Port = maps:get(port, NewAddr, 0),
    Addr = maps:get(addr, NewAddr, any),
    Opts = #{ip => Addr},
    maybe
        {ok, NewSocket} ?= open(Port, Opts),
        ok ?= close(OldSocket),
        {ok, NewSocket}
    end.

-doc "Cancel a pending async receive.".
-spec recv_cancel(t(), select_info()) -> ok | {error, nquic_error:any_reason()}.
recv_cancel(Socket, SelectInfo) ->
    case socket:cancel(Socket, SelectInfo) of
        ok -> ok;
        {error, closed} -> ok;
        {error, _} = Err -> Err
    end.

-doc "Receive data with ancillary data without blocking. Same as `recv_msg_start/1`.".
-spec recv_msg_now(t()) ->
    {ok, {sockaddr(), binary(), list()}}
    | {select, select_info()}
    | {error, nquic_error:any_reason()}.
recv_msg_now(Socket) ->
    recv_msg_start(Socket).

-doc """
Start async receive with ancillary data (for ECN marks).
Uses `socket:recvmsg` to receive control messages alongside the packet data.
When IP_RECVTOS is set (via `set_ecn/2`), the control messages include the
TOS byte. Use `get_ecn_from_cmsg/1` to extract the ECN codepoint.
""".
-spec recv_msg_start(t()) ->
    {ok, {sockaddr(), binary(), list()}}
    | {select, select_info()}
    | {error, nquic_error:any_reason()}.
recv_msg_start(Socket) ->
    case socket:recvmsg(Socket, ?NQUIC_MAX_DATAGRAM, 256, [], nowait) of
        {ok, #{addr := Source, iov := IOV, ctrl := Ctrl}} ->
            Data = iolist_to_binary(IOV),
            {ok, {Source, Data, Ctrl}};
        {select, _} = Select ->
            Select;
        {error, _} = Err ->
            Err
    end.

-doc """
Receive data without blocking. Call this after receiving a select message.
Returns:
- `{ok, {Source, Data}}` - Packet received
- `{select, SelectInfo}` - No data ready, wait for next select message
- `{error, Reason}` - Error occurred
""".
-spec recv_now(t()) ->
    {ok, {sockaddr(), binary()}}
    | {select, select_info()}
    | {select_read, {select_info(), {sockaddr(), binary()}}}
    | {completion, socket:completion_info()}
    | {error, nquic_error:any_reason()}.
recv_now(Socket) ->
    socket:recvfrom(Socket, ?NQUIC_MAX_DATAGRAM, nowait).

-doc """
Start async receive. Returns {select, Info} when waiting for data.
After calling this, the process will receive a message of the form:
`{'$socket', Socket, select, SelectInfo}` when data is available.
Then call `recv_now/1` to get the actual data.
""".
-spec recv_start(t()) ->
    {ok, {sockaddr(), binary()}}
    | {select, select_info()}
    | {select_read, {select_info(), {sockaddr(), binary()}}}
    | {completion, socket:completion_info()}
    | {error, nquic_error:any_reason()}.
recv_start(Socket) ->
    socket:recvfrom(Socket, ?NQUIC_MAX_DATAGRAM, nowait).

-doc "Send data to a destination address.".
-spec send(t(), sockaddr(), iodata()) -> ok | {error, nquic_error:any_reason()}.
send(Socket, Dest, Data) ->
    case socket:sendto(Socket, Data, Dest) of
        ok ->
            ok;
        {ok, _RestData} ->
            {error, partial_send};
        {error, _} = Err ->
            Err
    end.

-doc "Send data on a connected socket (no destination needed).".
-spec send_connected(t(), iodata()) -> ok | {error, nquic_error:any_reason()}.
send_connected(Socket, Data) ->
    case socket:send(Socket, Data) of
        ok -> ok;
        {ok, _RestData} -> {error, partial_send};
        {error, _} = Err -> Err
    end.

-doc "Convert a sockaddr to {IP, Port} tuple for compatibility.".
-spec sockaddr_to_tuple(sockaddr()) -> {inet:ip_address(), inet:port_number()}.
sockaddr_to_tuple(#{addr := Addr, port := Port}) ->
    {Addr, Port}.

%%%-----------------------------------------------------------------------------
%% ECN SUPPORT (RFC 9000 S13 4)
%%%-----------------------------------------------------------------------------
-spec ecn_from_tos(non_neg_integer() | atom() | binary()) -> not_ect | ect0 | ect1 | ce.
ecn_from_tos(TOS) when is_integer(TOS) ->
    case TOS band 16#03 of
        0 -> not_ect;
        1 -> ect1;
        2 -> ect0;
        3 -> ce
    end;
ecn_from_tos(default) ->
    not_ect;
ecn_from_tos(lowdelay) ->
    not_ect;
ecn_from_tos(throughput) ->
    not_ect;
ecn_from_tos(reliability) ->
    not_ect;
ecn_from_tos(mincost) ->
    ect0;
ecn_from_tos(<<TOS:8, _/binary>>) ->
    ecn_from_tos(TOS);
ecn_from_tos(_) ->
    not_ect.

-spec ecn_to_tos(not_ect | ect0 | ect1 | ce) -> non_neg_integer().
ecn_to_tos(not_ect) -> 0;
ecn_to_tos(ect1) -> 1;
ecn_to_tos(ect0) -> 2;
ecn_to_tos(ce) -> 3.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec bind_socket(t(), inet:port_number(), inet | inet6, open_opts()) ->
    ok | {error, nquic_error:any_reason()}.
bind_socket(Socket, Port, Family, Opts) ->
    IP = maps:get(ip, Opts, any),
    SockAddr = make_bind_addr(Family, IP, Port),
    socket:bind(Socket, SockAddr).

-spec determine_family(open_opts()) -> inet | inet6.
determine_family(Opts) ->
    case maps:get(ip, Opts, any) of
        {_, _, _, _, _, _, _, _} -> inet6;
        _ -> inet
    end.

-spec ecn_ctrl_for_dest(sockaddr(), non_neg_integer()) -> [map()].
ecn_ctrl_for_dest(#{family := inet6}, TOS) ->
    [#{level => ipv6, type => tclass, value => TOS}];
ecn_ctrl_for_dest(_, TOS) ->
    [#{level => ip, type => tos, value => TOS}].

-spec ecn_ctrl_for_socket(t(), non_neg_integer()) -> [map()].
ecn_ctrl_for_socket(Socket, TOS) ->
    case socket:sockname(Socket) of
        {ok, #{family := inet6}} ->
            [#{level => ipv6, type => tclass, value => TOS}];
        _ ->
            [#{level => ip, type => tos, value => TOS}]
    end.

-doc """
Extract the ECN codepoint from recvmsg control messages.
Returns `not_ect` (0), `ect1` (1), `ect0` (2), or `ce` (3).
""".
-spec get_ecn_from_cmsg(list() | undefined) -> not_ect | ect0 | ect1 | ce.
get_ecn_from_cmsg(undefined) ->
    not_ect;
get_ecn_from_cmsg([]) ->
    not_ect;
get_ecn_from_cmsg([#{level := ip, type := tos, value := TOS} | _]) ->
    ecn_from_tos(TOS);
get_ecn_from_cmsg([#{level := ipv6, type := tclass, value := TC} | _]) ->
    ecn_from_tos(TC);
get_ecn_from_cmsg([_ | Rest]) ->
    get_ecn_from_cmsg(Rest).

-spec make_bind_addr(inet | inet6, inet:ip_address() | any, inet:port_number()) ->
    sockaddr().
make_bind_addr(inet, any, Port) ->
    #{family => inet, addr => any, port => Port};
make_bind_addr(inet, {_, _, _, _} = Addr, Port) ->
    #{family => inet, addr => Addr, port => Port};
make_bind_addr(inet6, any, Port) ->
    #{family => inet6, addr => any, port => Port};
make_bind_addr(inet6, {_, _, _, _, _, _, _, _} = Addr, Port) ->
    #{family => inet6, addr => Addr, port => Port}.

-spec maybe_set_ecn(t(), open_opts()) -> ok | {error, nquic_error:any_reason()}.
maybe_set_ecn(Socket, Opts) ->
    case maps:get(ecn, Opts, false) of
        true -> set_ecn(Socket, true);
        false -> ok
    end.

-spec maybe_set_gro(t(), open_opts()) -> ok.
maybe_set_gro(Socket, Opts) ->
    case maps:get(gro, Opts, false) of
        true -> set_gro(Socket, true);
        false -> ok
    end.

-spec maybe_set_gso(t(), open_opts()) -> ok.
maybe_set_gso(Socket, Opts) ->
    case maps:get(gso, Opts, false) of
        false -> ok;
        true -> set_gso_size(Socket, ?DEFAULT_GSO_SIZE);
        Size when is_integer(Size), Size > 0 -> set_gso_size(Socket, Size);
        _ -> ok
    end.

-spec maybe_set_reuseport(t(), open_opts()) -> ok | {error, nquic_error:any_reason()}.
maybe_set_reuseport(Socket, Opts) ->
    case maps:get(reuseport, Opts, false) of
        true -> socket:setopt(Socket, socket, reuseport, true);
        false -> ok
    end.

-doc """
Send data on a connected socket with a specific ECN codepoint.
Uses sendmsg with an `IP_TOS` / `IPV6_TCLASS` cmsg. Slower than
`send_connected/2` because of the extra cmsg processing, so the hot path
relies on socket-level TOS pre-stamping (see `set_ecn/2`) and only falls
back to this primitive when per-packet control is required. Future work
(GSO batching, pacing) is the expected caller.
`iolist_to_iovec/1` flattens the iolist into a list of binaries without
materialising a single concatenated binary, preserving the zero-copy
property of the encrypt path.
""".
-spec send_connected_with_ecn(t(), iodata(), ecn_mark()) ->
    ok | {error, nquic_error:any_reason()}.
send_connected_with_ecn(Socket, Data, ECN) ->
    TOS = ecn_to_tos(ECN),
    Ctrl = ecn_ctrl_for_socket(Socket, TOS),
    Msg = #{iov => erlang:iolist_to_iovec(Data), ctrl => Ctrl},
    case socket:sendmsg(Socket, Msg) of
        ok -> ok;
        {ok, _} -> ok;
        {error, _} = Err -> Err
    end.

-doc "Send data with a specific ECN codepoint using sendmsg. See `send_connected_with_ecn/3`.".
-spec send_with_ecn(t(), sockaddr(), iodata(), ecn_mark()) ->
    ok | {error, nquic_error:any_reason()}.
send_with_ecn(Socket, Dest, Data, ECN) ->
    TOS = ecn_to_tos(ECN),
    Ctrl = ecn_ctrl_for_dest(Dest, TOS),
    Msg = #{
        addr => Dest,
        iov => erlang:iolist_to_iovec(Data),
        ctrl => Ctrl
    },
    case socket:sendmsg(Socket, Msg) of
        ok -> ok;
        {ok, _} -> ok;
        {error, _} = Err -> Err
    end.

-doc """
Enable ECN on a socket.
Configures both directions:
- Inbound: `IP_RECVTOS` / `IPV6_RECVTCLASS` so `recvmsg` returns the TOS
  / traffic-class byte in ancillary data. The receiver decodes it via
  `get_ecn_from_cmsg/1` and feeds the per-packet ECN counts into the
  protocol layer.
- Outbound: `IP_TOS = 2` / `IPV6_TCLASS = 2` so the kernel stamps every
  outgoing datagram as ECT(0) without per-packet `sendmsg` overhead.
  Validation failure flips this back to 0 via `set_egress_ecn/2`.
Errors from setopt are tolerated per-option when the family is not
present (a v4-only socket cannot accept `ipv6/*` and vice versa).
""".
-spec set_ecn(t(), boolean()) -> ok | {error, nquic_error:any_reason()}.
set_ecn(Socket, true) ->
    _ = socket:setopt(Socket, ip, recvtos, true),
    _ = socket:setopt(Socket, ipv6, recvtclass, true),
    ok = set_egress_ecn(Socket, ect0),
    ok;
set_ecn(Socket, false) ->
    _ = socket:setopt(Socket, ip, recvtos, false),
    _ = socket:setopt(Socket, ipv6, recvtclass, false),
    ok = set_egress_ecn(Socket, not_ect),
    ok.

-doc """
Flip the socket-level egress ECN mark.
Use after a path validation failure (RFC 9000 §13.4.2.1) to stop
emitting ECT-marked packets on this path. Best-effort: errors from the
non-matching family are ignored.
""".
-spec set_egress_ecn(t(), ecn_mark()) -> ok.
set_egress_ecn(Socket, Mark) ->
    TOS = ecn_to_tos(Mark),
    _ = socket:setopt(Socket, ip, tos, TOS),
    _ = socket:setopt(Socket, ipv6, tclass, TOS),
    ok.

-spec set_ipv6_opts(t(), open_opts()) -> ok | {error, nquic_error:any_reason()}.
set_ipv6_opts(Socket, Opts) ->
    case maps:get(ipv6_v6only, Opts, undefined) of
        undefined ->
            ok;
        V6Only ->
            socket:setopt(Socket, ipv6, v6only, V6Only)
    end.

-spec set_socket_opts(t(), open_opts()) -> ok | {error, nquic_error:any_reason()}.
set_socket_opts(Socket, Opts) ->
    RecBuf = maps:get(recbuf, Opts, ?DEFAULT_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_SNDBUF),
    ReuseAddr = maps:get(reuseaddr, Opts, true),
    maybe
        ok ?= socket:setopt(Socket, socket, reuseaddr, ReuseAddr),
        ok ?= socket:setopt(Socket, socket, rcvbuf, RecBuf),
        ok ?= socket:setopt(Socket, socket, sndbuf, SndBuf),
        ok ?= maybe_set_reuseport(Socket, Opts),
        ok ?= set_ipv6_opts(Socket, Opts),
        ok ?= maybe_set_ecn(Socket, Opts),
        ok = maybe_set_gso(Socket, Opts),
        ok = maybe_set_gro(Socket, Opts),
        ok
    end.

-doc "Get the local address of the socket.".
-spec sockname(t()) -> {ok, sockaddr()} | {error, nquic_error:any_reason()}.
sockname(Socket) ->
    socket:sockname(Socket).

%%%-----------------------------------------------------------------------------
%% UDP BATCHING (GSO / GRO, RFC-NA, LINUX-SPECIFIC KERNEL OFFLOAD)
%%%-----------------------------------------------------------------------------
-doc """
Probe the running kernel for UDP_SEGMENT (GSO) and UDP_GRO support.
Result is cached in `persistent_term`; the probe runs at most once per
node. On non-Linux platforms (or older kernels missing one or both
features) the corresponding capability comes back `false`. Callers can
treat the result as opaque and pass `gso => true` / `gro => true` only
when the matching capability is set; the open path silently no-ops if
the kernel rejects the setsockopt.
""".
-spec capabilities() -> capabilities().
capabilities() ->
    case persistent_term:get(?CAPABILITIES_KEY, undefined) of
        undefined ->
            Caps = probe_capabilities(),
            persistent_term:put(?CAPABILITIES_KEY, Caps),
            Caps;
        Caps ->
            Caps
    end.

-doc """
Extract the GRO segment size from a `recvmsg` control-message list.
Returns the segment size in bytes when the kernel coalesced the recv,
`undefined` otherwise. The 16-bit segment-size value sits in the lower
two bytes of the cmsg payload, which the kernel pads to a 4-byte
multiple, so the trailing bytes are matched as a wildcard.
""".
-spec get_gso_size_from_cmsg(list() | undefined) -> undefined | pos_integer().
get_gso_size_from_cmsg(undefined) ->
    undefined;
get_gso_size_from_cmsg([]) ->
    undefined;
get_gso_size_from_cmsg([
    #{level := udp, type := ?UDP_GRO, data := <<Size:16/native, _/binary>>} | _
]) when Size > 0 ->
    Size;
get_gso_size_from_cmsg([_ | Rest]) ->
    get_gso_size_from_cmsg(Rest).

-spec probe_capabilities() -> capabilities().
probe_capabilities() ->
    case socket:open(inet, dgram, udp) of
        {ok, S} ->
            GSO =
                case socket:setopt_native(S, {?SOL_UDP, ?UDP_SEGMENT}, <<1200:32/native>>) of
                    ok -> true;
                    _ -> false
                end,
            GRO =
                case socket:setopt_native(S, {?SOL_UDP, ?UDP_GRO}, <<1:32/native>>) of
                    ok -> true;
                    _ -> false
                end,
            _ = socket:close(S),
            #{gso => GSO, gro => GRO};
        {error, _} ->
            #{gso => false, gro => false}
    end.

-doc """
Enable UDP_GRO on a socket.
Once GRO is on, the kernel coalesces consecutive equal-size datagrams of
the same flow into a single buffer; `socket:recvmsg/5` then returns a
control message with `#{level => udp, type => 104, data => <<Size:16/native, _/binary>>}`
that the caller must use to split the buffer back into per-packet
chunks. See `get_gso_size_from_cmsg/1`.
""".
-spec set_gro(t(), boolean()) -> ok.
set_gro(Socket, true) ->
    _ = socket:setopt_native(Socket, {?SOL_UDP, ?UDP_GRO}, <<1:32/native>>),
    ok;
set_gro(Socket, false) ->
    _ = socket:setopt_native(Socket, {?SOL_UDP, ?UDP_GRO}, <<0:32/native>>),
    ok.

-doc """
Configure sticky UDP_SEGMENT (GSO) on a socket.
After this call, any `socket:send/sendto` whose payload exceeds `Size`
will be split by the kernel into segments of `Size` bytes each (the
final segment may be shorter). `Size = 0` disables segmentation.
Returns `ok` even when the kernel rejects the option, mirroring
`set_ecn/2`'s best-effort policy: callers who care must check
`capabilities/0` first.
Pair with `set_gro/2` on the peer's receive socket: without GRO,
the coalesced segments arrive as individual datagrams that overrun
the UDP receive buffer on loopback / fast paths, causing 2-3x
retransmissions and a net throughput regression versus the
un-offloaded send path.
""".
-spec set_gso_size(t(), non_neg_integer()) -> ok.
set_gso_size(Socket, Size) when is_integer(Size), Size >= 0 ->
    _ = socket:setopt_native(Socket, {?SOL_UDP, ?UDP_SEGMENT}, <<Size:32/native>>),
    ok.
