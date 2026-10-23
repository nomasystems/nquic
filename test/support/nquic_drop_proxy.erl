-module(nquic_drop_proxy).
-moduledoc """
UDP proxy between one QUIC client and one server that drops chosen
datagrams.

The client sends to the front port. The proxy forwards each client
datagram to the server from its back socket, and forwards each server
datagram to the address of the last client datagram. Datagrams are
counted per direction from 1. A datagram whose `{Direction, Index}` is
in the drop list is discarded.
""".
-behaviour(gen_server).

-export([start_link/2, stop/1, dropped/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-export_type([direction/0, drop/0]).

-type direction() :: client | server.
-type drop() :: {direction(), pos_integer()}.

-define(LOOPBACK, {127, 0, 0, 1}).

-record(st, {
    front :: gen_udp:socket(),
    back :: gen_udp:socket(),
    server_port :: inet:port_number(),
    client :: {inet:ip_address(), inet:port_number()} | undefined,
    drops :: [drop()],
    counts = #{client => 0, server => 0} :: #{direction() => non_neg_integer()},
    dropped = [] :: [drop()]
}).

-doc """
Start a proxy in front of the server at `127.0.0.1:ServerPort`.
Returns the front port that the client connects to.
""".
-spec start_link(inet:port_number(), [drop()]) ->
    {ok, pid(), inet:port_number()} | {error, inet:posix()}.
start_link(ServerPort, Drops) ->
    case gen_server:start_link(?MODULE, {ServerPort, Drops}, []) of
        {ok, Pid} ->
            {ok, FrontPort} = gen_server:call(Pid, front_port),
            {ok, Pid, FrontPort};
        {error, _} = Error ->
            Error
    end.

-doc "Stop the proxy and close its sockets.".
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

-doc "Return the datagrams that the proxy dropped, in drop order.".
-spec dropped(pid()) -> [drop()].
dropped(Pid) ->
    gen_server:call(Pid, dropped).

-doc false.
-spec init({inet:port_number(), [drop()]}) -> {ok, #st{}} | {stop, inet:posix()}.
init({ServerPort, Drops}) ->
    Opts = [binary, {ip, ?LOOPBACK}, {active, true}],
    maybe
        {ok, Front} ?= gen_udp:open(0, Opts),
        {ok, Back} ?= gen_udp:open(0, Opts),
        {ok, #st{front = Front, back = Back, server_port = ServerPort, drops = Drops}}
    else
        {error, Reason} -> {stop, Reason}
    end.

-doc false.
-spec handle_call(front_port | dropped, gen_server:from(), #st{}) ->
    {reply, {ok, inet:port_number()} | [drop()], #st{}}.
handle_call(front_port, _From, #st{front = Front} = St) ->
    {ok, Port} = inet:port(Front),
    {reply, {ok, Port}, St};
handle_call(dropped, _From, #st{dropped = Dropped} = St) ->
    {reply, lists:reverse(Dropped), St}.

-doc false.
-spec handle_cast(term(), #st{}) -> {noreply, #st{}}.
handle_cast(_Msg, St) ->
    {noreply, St}.

-doc false.
-spec handle_info(
    {udp, gen_udp:socket(), inet:ip_address(), inet:port_number(), binary()}, #st{}
) -> {noreply, #st{}}.
handle_info({udp, Front, IP, Port, Bin}, #st{front = Front} = St) ->
    {noreply, relay(client, Bin, St#st{client = {IP, Port}})};
handle_info({udp, Back, _IP, _Port, Bin}, #st{back = Back} = St) ->
    {noreply, relay(server, Bin, St)}.

-spec relay(direction(), binary(), #st{}) -> #st{}.
relay(Dir, Bin, #st{counts = Counts, drops = Drops, dropped = Dropped} = St) ->
    Index = maps:get(Dir, Counts) + 1,
    St1 = St#st{counts = Counts#{Dir := Index}},
    case lists:member({Dir, Index}, Drops) of
        true ->
            St1#st{dropped = [{Dir, Index} | Dropped]};
        false ->
            ok = forward(Dir, Bin, St1),
            St1
    end.

-spec forward(direction(), binary(), #st{}) -> ok.
forward(client, Bin, #st{back = Back, server_port = ServerPort}) ->
    send_ignoring_refused(gen_udp:send(Back, ?LOOPBACK, ServerPort, Bin));
forward(server, Bin, #st{front = Front, client = {IP, Port}}) ->
    send_ignoring_refused(gen_udp:send(Front, IP, Port, Bin)).

-spec send_ignoring_refused(ok | {error, term()}) -> ok.
send_ignoring_refused(ok) -> ok;
send_ignoring_refused({error, econnrefused}) -> ok.
