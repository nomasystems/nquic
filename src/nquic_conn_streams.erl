-module(nquic_conn_streams).
-moduledoc """
Owner-waiter stream delivery for the handshake state machine.

Services `recv_stream` / `accept_stream` calls and wakes parked
waiters when peer data or peer-opened streams arrive. Functions take
`#conn_state{}` and return a library-shaped result; they never build
gen_statem transitions or action lists; `nquic_conn_statem` wraps the
`reply_result()` into the FSM result and owns the flush. The one
exception is `maybe_notify_recv_waiter/2`'s stream-cleanup path, which
flushes via the shared `nquic_conn_statem:flush_and_send/1` helper
(the same cross-module helper `nquic_conn_send_waiters` and
`nquic_conn_timers` use) because it runs inside the protocol-event
fold, not a statem adapter.
""".

-include("nquic_conn.hrl").
-export([
    accept_stream/2,
    cache_new_token/2,
    maybe_notify_recv_waiter/2,
    notify_or_queue_stream/2,
    recv_stream/3,
    store_token/4
]).

-export_type([reply_result/0]).

-type reply_result() ::
    {reply, term(), #conn_state{}}
    | {reply, term(), #conn_state{}, flush}
    | {wait, #conn_state{}}.

-spec accept_stream(gen_statem:from(), #conn_state{}) -> reply_result().
accept_stream(From, Data) ->
    #conn_state{streams_state = SS} = Data,
    #conn_streams{pending_streams = Pending, accept_stream_waiters = Waiters} = SS,
    case queue:out(Pending) of
        {{value, StreamID}, Rest} ->
            NewSS = SS#conn_streams{pending_streams = Rest},
            {reply, {ok, StreamID}, Data#conn_state{streams_state = NewSS}};
        {empty, _} ->
            NewWaiters = queue:in(From, Waiters),
            NewSS = SS#conn_streams{accept_stream_waiters = NewWaiters},
            {wait, Data#conn_state{streams_state = NewSS}}
    end.

-spec cache_new_token(binary(), #conn_state{}) -> ok.
cache_new_token(
    Token,
    #conn_state{
        crypto = #conn_crypto{
            token_cache = Cache,
            hostname = Host
        },
        peer = Peer
    }
) when Cache =/= false, Host =/= undefined, Peer =/= undefined ->
    Port = maps:get(port, Peer, 0),
    store_token(Cache, Host, Port, Token);
cache_new_token(_Token, _Data) ->
    ok.

-doc """
Deliver buffered data to a parked `recv` waiter, if one exists.
The `size_known` clause delivers the FIN marker and runs the stream
cleanup path.
""".
-spec maybe_notify_recv_waiter(nquic:stream_id(), #conn_state{}) -> #conn_state{}.
maybe_notify_recv_waiter(StreamID, Data) ->
    #conn_state{streams_state = SS} = Data,
    #conn_streams{recv_waiters = Waiters, streams = Streams} = SS,
    case maps:find(StreamID, Waiters) of
        error ->
            Data;
        {ok, From} ->
            case maps:find(StreamID, Streams) of
                {ok, #stream_state{app_buffer = AppBuf, app_buffer_size = BufSize} = Stream} when
                    BufSize > 0
                ->
                    {NewRecvState, Fin} =
                        case Stream#stream_state.recv_state of
                            size_known -> {data_read, fin};
                            Other -> {Other, nofin}
                        end,
                    NewStream = Stream#stream_state{
                        app_buffer = [], app_buffer_size = 0, recv_state = NewRecvState
                    },
                    NewStreams = Streams#{StreamID => NewStream},
                    gen_statem:reply(From, {ok, iolist_to_binary(AppBuf), Fin}),
                    NewSS = SS#conn_streams{
                        streams = NewStreams,
                        recv_waiters = maps:remove(StreamID, Waiters)
                    },
                    Data#conn_state{streams_state = NewSS};
                {ok, #stream_state{recv_state = size_known} = FinStream0} ->
                    FinStream = FinStream0#stream_state{recv_state = data_read},
                    gen_statem:reply(From, {ok, <<>>, fin}),
                    NewSS = SS#conn_streams{
                        streams = Streams#{StreamID => FinStream},
                        recv_waiters = maps:remove(StreamID, Waiters)
                    },
                    Data1 = Data#conn_state{streams_state = NewSS},
                    Data2 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(
                        StreamID, FinStream, Data1
                    ),
                    {Data3, _} = nquic_conn_statem:flush_and_send(Data2),
                    Data3;
                _ ->
                    Data
            end
    end.

-doc """
Hand a peer-initiated stream to a parked `accept_stream` waiter,
or queue it for the next call.
""".
-spec notify_or_queue_stream(nquic:stream_id(), #conn_state{}) -> #conn_state{}.
notify_or_queue_stream(StreamID, Data) ->
    #conn_state{streams_state = SS} = Data,
    #conn_streams{accept_stream_waiters = Waiters, pending_streams = Pending} = SS,
    case queue:out(Waiters) of
        {{value, From}, Rest} ->
            gen_statem:reply(From, {ok, StreamID}),
            Data#conn_state{streams_state = SS#conn_streams{accept_stream_waiters = Rest}};
        {empty, _} ->
            Data#conn_state{
                streams_state = SS#conn_streams{
                    pending_streams = queue:in(StreamID, Pending)
                }
            }
    end.

-spec recv_stream(gen_statem:from(), nquic:stream_id(), #conn_state{}) -> reply_result().
recv_stream(From, StreamID, Data) ->
    #conn_state{streams_state = SS} = Data,
    #conn_streams{streams = Streams, recv_waiters = Waiters} = SS,
    case maps:find(StreamID, Streams) of
        error ->
            {reply, {error, stream_not_found}, Data};
        {ok, #stream_state{
            app_buffer = AppBuf,
            app_buffer_size = BufSize,
            recv_state = RState
        }} when
            BufSize > 0
        ->
            Stream = maps:get(StreamID, Streams),
            {NewRecvState, Fin} =
                case RState of
                    size_known -> {data_read, fin};
                    _ -> {RState, nofin}
                end,
            NewStream = Stream#stream_state{
                app_buffer = [], app_buffer_size = 0, recv_state = NewRecvState
            },
            NewStreams = Streams#{StreamID => NewStream},
            NewSS = SS#conn_streams{streams = NewStreams},
            {reply, {ok, iolist_to_binary(AppBuf), Fin}, Data#conn_state{streams_state = NewSS}};
        {ok, #stream_state{recv_state = size_known} = Stream0} ->
            Stream = Stream0#stream_state{recv_state = data_read},
            NewStreams = Streams#{StreamID => Stream},
            Data0 = Data#conn_state{streams_state = SS#conn_streams{streams = NewStreams}},
            Data1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(StreamID, Stream, Data0),
            {reply, {ok, <<>>, fin}, Data1, flush};
        {ok, #stream_state{recv_state = data_read} = Stream} ->
            Data1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(StreamID, Stream, Data),
            {reply, {error, fin}, Data1, flush};
        {ok, #stream_state{recv_state = reset_recvd} = Stream} ->
            Data1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(StreamID, Stream, Data),
            {reply, {error, stream_reset}, Data1, flush};
        {ok, #stream_state{recv_state = reset_read} = Stream} ->
            Data1 = nquic_protocol_streams_lifecycle:maybe_cleanup_stream(StreamID, Stream, Data),
            {reply, {error, stream_reset}, Data1, flush};
        {ok, _} ->
            NewWaiters = Waiters#{StreamID => From},
            NewSS = SS#conn_streams{recv_waiters = NewWaiters},
            {wait, Data#conn_state{streams_state = NewSS}}
    end.

-spec store_token(
    atom() | {module, module()}, inet:hostname() | inet:ip_address(), inet:port_number(), binary()
) -> ok.
store_token({module, Mod}, Host, Port, Token) ->
    Mod:store(Host, Port, Token);
store_token(Name, Host, Port, Token) when is_atom(Name) ->
    nquic_token_cache:store(Name, Host, Port, Token).
