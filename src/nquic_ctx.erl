-module(nquic_ctx).

%% Opaque library-mode connection context.
%%
%% Owns the `#quic_ctx{}' record. The record is intentionally defined
%% inside this module rather than in a header so no other module can
%% pattern-match or update it directly: callers must go through the
%% accessors and setters exported here.
%%
%% The opaque `t()' type is the externally visible handle. `nquic'
%% re-exports it as `nquic:ctx()' for API ergonomics.

-export([
    connected/1,
    datagram_buffer/1,
    datagram_buffer_max/1,
    datagram_buffer_size/1,
    dispatch/1,
    new/4,
    peer/1,
    set_connected/2,
    set_datagram/3,
    set_datagram_max/2,
    set_dispatch/2,
    set_peer/2,
    set_socket/2,
    set_socket_connected/3,
    set_state/2,
    set_timers/2,
    socket/1,
    state/1,
    timers/1
]).
-export_type([t/0]).

-record(quic_ctx, {
    state :: nquic_protocol:state(),
    socket :: nquic_socket:t(),
    peer :: nquic_socket:sockaddr(),
    dispatch :: nquic_dispatch:t() | undefined,
    timers = #{} :: #{nquic_protocol:timer_type() => reference()},
    connected = false :: boolean(),
    datagram_buffer = queue:new() :: queue:queue(binary()),
    datagram_buffer_size = 0 :: non_neg_integer(),
    datagram_buffer_max = 100 :: pos_integer()
}).

-opaque t() :: #quic_ctx{}.

%%%-----------------------------------------------------------------------------
%% CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc false.
-spec new(
    nquic_protocol:state(),
    nquic_socket:t(),
    nquic_socket:sockaddr(),
    nquic_dispatch:t() | undefined
) -> t().
new(State, Socket, Peer, Dispatch) ->
    #quic_ctx{
        state = State,
        socket = Socket,
        peer = Peer,
        dispatch = Dispatch
    }.

%%%-----------------------------------------------------------------------------
%% ACCESSORS
%%%-----------------------------------------------------------------------------
-doc false.
-spec connected(t()) -> boolean().
connected(#quic_ctx{connected = Connected}) -> Connected.

-doc false.
-spec datagram_buffer(t()) -> queue:queue(binary()).
datagram_buffer(#quic_ctx{datagram_buffer = Buf}) -> Buf.

-doc false.
-spec datagram_buffer_max(t()) -> pos_integer().
datagram_buffer_max(#quic_ctx{datagram_buffer_max = Max}) -> Max.

-doc false.
-spec datagram_buffer_size(t()) -> non_neg_integer().
datagram_buffer_size(#quic_ctx{datagram_buffer_size = Size}) -> Size.

-doc false.
-spec dispatch(t()) -> nquic_dispatch:t() | undefined.
dispatch(#quic_ctx{dispatch = Dispatch}) -> Dispatch.

-doc false.
-spec peer(t()) -> nquic_socket:sockaddr().
peer(#quic_ctx{peer = Peer}) -> Peer.

-doc false.
-spec socket(t()) -> nquic_socket:t().
socket(#quic_ctx{socket = Socket}) -> Socket.

-doc false.
-spec state(t()) -> nquic_protocol:state().
state(#quic_ctx{state = State}) -> State.

-doc false.
-spec timers(t()) -> #{nquic_protocol:timer_type() => reference()}.
timers(#quic_ctx{timers = Timers}) -> Timers.

%%%-----------------------------------------------------------------------------
%% SETTERS
%%%-----------------------------------------------------------------------------
-doc false.
-spec set_connected(t(), boolean()) -> t().
set_connected(Ctx, Connected) ->
    Ctx#quic_ctx{connected = Connected}.

-doc false.
-spec set_datagram(t(), queue:queue(binary()), non_neg_integer()) -> t().
set_datagram(Ctx, Buf, Size) ->
    Ctx#quic_ctx{datagram_buffer = Buf, datagram_buffer_size = Size}.

-doc false.
-spec set_datagram_max(t(), pos_integer()) -> t().
set_datagram_max(Ctx, Max) ->
    Ctx#quic_ctx{datagram_buffer_max = Max}.

-doc false.
-spec set_dispatch(t(), nquic_dispatch:t() | undefined) -> t().
set_dispatch(Ctx, Dispatch) ->
    Ctx#quic_ctx{dispatch = Dispatch}.

-doc false.
-spec set_peer(t(), nquic_socket:sockaddr()) -> t().
set_peer(Ctx, Peer) ->
    Ctx#quic_ctx{peer = Peer}.

-doc false.
-spec set_socket(t(), nquic_socket:t()) -> t().
set_socket(Ctx, Socket) ->
    Ctx#quic_ctx{socket = Socket}.

-doc false.
-spec set_socket_connected(t(), nquic_socket:t(), boolean()) -> t().
set_socket_connected(Ctx, Socket, Connected) ->
    Ctx#quic_ctx{socket = Socket, connected = Connected}.

-doc false.
-spec set_state(t(), nquic_protocol:state()) -> t().
set_state(Ctx, State) ->
    Ctx#quic_ctx{state = State}.

-doc false.
-spec set_timers(t(), #{nquic_protocol:timer_type() => reference()}) -> t().
set_timers(Ctx, Timers) ->
    Ctx#quic_ctx{timers = Timers}.
