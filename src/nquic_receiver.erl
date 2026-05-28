-module(nquic_receiver).
-moduledoc """
QUIC packet receiver process.

Each receiver owns one UDP socket and runs an async recv loop using
completion-based I/O. Multiple receivers can share the same port via
SO_REUSEPORT. Incoming packets are dispatched via ETS lookup: existing
connections get a direct message (fast path), new connections are
spawned in a separate process (slow path).
""".
-behaviour(gen_server).

-include("nquic_packet.hrl").
-include("nquic_transport.hrl").
-export([get_port/1, start_link/1]).
-export([handle_call/3, handle_cast/2, handle_info/2, init/1, terminate/2]).

-export([
    bump_rate/1,
    check_rate_limit/1,
    dispatch_packet/3,
    fast_dispatch/2,
    get_dcid/1,
    maybe_retry/3,
    slow_dispatch/4
]).

-record(state, {
    socket :: nquic_socket:t(),
    select_info :: nquic_socket:select_info() | undefined,
    dispatch_table :: nquic_dispatch:t(),
    listener :: pid(),
    opts :: map(),
    static_key :: binary(),
    max_new_conns_per_sec = 0 :: non_neg_integer(),
    rate_count = 0 :: non_neg_integer(),
    rate_window_start = 0 :: integer(),
    retry = false :: boolean(),
    retry_token_lifetime = 30 :: pos_integer(),
    ecn = false :: boolean(),
    gro = false :: boolean()
}).

-doc "Return the port number this receiver's socket is bound to.".
-spec get_port(pid()) -> {ok, inet:port_number()} | {error, nquic_error:any_reason()}.
get_port(Pid) ->
    gen_server:call(Pid, get_port).

%%%-----------------------------------------------------------------------------
%% GEN_SERVER CALLBACKS
%%%-----------------------------------------------------------------------------
-spec handle_call(get_port | term(), gen_server:from(), #state{}) ->
    {reply, term(), #state{}}.
handle_call(get_port, _From, #state{socket = Socket} = State) ->
    {reply, nquic_socket:port(Socket), State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

-spec handle_cast(term(), #state{}) -> {noreply, #state{}}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), #state{}) -> {noreply, #state{}}.
handle_info({'$socket', Socket, select, _SelectInfo}, #state{socket = Socket} = State) ->
    NewState = recv_loop(State),
    {noreply, NewState};
handle_info({immediate_packet, Source, Data}, State) ->
    State1 = dispatch_packet(Source, Data, State),
    NewState = recv_loop(State1),
    {noreply, NewState};
handle_info({immediate_packet_ecn, Source, Data, ECN}, State) ->
    State1 = dispatch_packet_ecn(Source, Data, ECN, State),
    NewState = recv_loop(State1),
    {noreply, NewState};
handle_info({immediate_packet_cmsg, Source, Data, ECN, GsoSize}, State) ->
    State1 = dispatch_with_gro(Source, Data, ECN, GsoSize, State),
    NewState = recv_loop(State1),
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

-spec init(map()) -> {ok, #state{}} | {stop, term()}.
init(Opts) ->
    Port = maps:get(port, Opts, 4433),
    RecvOpts = maps:get(recv_opts, Opts, #{}),
    ReusePort = maps:get(reuseport, Opts, false),
    ECN = maps:get(ecn, Opts, false),
    GSO = maps:get(gso, Opts, false),
    GRO = maps:get(gro, Opts, false),
    SockOpts = nquic_recv:socket_options(RecvOpts#{
        reuseport => ReusePort,
        ecn => ECN,
        gso => GSO,
        gro => GRO
    }),
    case nquic_socket:open(Port, SockOpts) of
        {ok, Socket} ->
            MaxRate = maps:get(max_new_conns_per_sec, Opts, 0),
            State = #state{
                socket = Socket,
                dispatch_table = maps:get(dispatch_table, Opts),
                listener = maps:get(listener, Opts),
                opts = Opts,
                static_key = maps:get(static_key, Opts),
                max_new_conns_per_sec = MaxRate,
                rate_window_start = erlang:monotonic_time(second),
                retry = maps:get(retry, Opts, false),
                retry_token_lifetime = maps:get(retry_token_lifetime, Opts, 30),
                ecn = ECN,
                gro = GRO
            },
            start_recv(State);
        {error, Reason} ->
            {stop, Reason}
    end.

-doc "Start a receiver process with the given options.".
-spec start_link(map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

-spec start_recv(#state{}) ->
    {ok, #state{}} | {stop, term()}.
start_recv(#state{gro = true, socket = Socket} = State) ->
    case nquic_socket:recv_msg_start(Socket) of
        {select, SelectInfo} ->
            {ok, State#state{select_info = SelectInfo}};
        {ok, {Source, Data, Ctrl}} ->
            ECN = ecn_from_ctrl(State, Ctrl),
            GsoSize = nquic_socket:get_gso_size_from_cmsg(Ctrl),
            self() ! {immediate_packet_cmsg, Source, Data, ECN, GsoSize},
            {ok, State};
        {error, Reason} ->
            _ = nquic_socket:close(Socket),
            {stop, Reason}
    end;
start_recv(#state{ecn = true, socket = Socket} = State) ->
    case nquic_socket:recv_msg_start(Socket) of
        {select, SelectInfo} ->
            {ok, State#state{select_info = SelectInfo}};
        {ok, {Source, Data, Ctrl}} ->
            ECNMark = nquic_socket:get_ecn_from_cmsg(Ctrl),
            self() ! {immediate_packet_ecn, Source, Data, ECNMark},
            {ok, State};
        {error, Reason} ->
            _ = nquic_socket:close(Socket),
            {stop, Reason}
    end;
start_recv(#state{socket = Socket} = State) ->
    case nquic_socket:recv_start(Socket) of
        {select, SelectInfo} ->
            {ok, State#state{select_info = SelectInfo}};
        {ok, {Source, Data}} ->
            self() ! {immediate_packet, Source, Data},
            {ok, State};
        {error, Reason} ->
            _ = nquic_socket:close(Socket),
            {stop, Reason}
    end.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{socket = Socket}) when Socket =/= undefined ->
    _ = nquic_socket:close(Socket),
    ok;
terminate(_Reason, _State) ->
    ok.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec bump_packets_in(nquic_dispatch:t()) -> ok.
bump_packets_in(Table) ->
    case nquic_dispatch:metrics(Table) of
        undefined -> ok;
        M -> nquic_metrics:inc(M, packets_in)
    end.

-spec bump_packets_in_n(nquic_dispatch:t(), non_neg_integer()) -> ok.
bump_packets_in_n(_Table, N) when N =< 0 ->
    ok;
bump_packets_in_n(Table, N) ->
    case nquic_dispatch:metrics(Table) of
        undefined -> ok;
        M -> nquic_metrics:add(M, packets_in, N)
    end.

-spec bump_rate(#state{}) -> #state{}.
bump_rate(#state{rate_count = C} = State) ->
    State#state{rate_count = C + 1}.

-spec check_rate_limit(#state{}) -> {boolean(), #state{}}.
check_rate_limit(#state{max_new_conns_per_sec = 0} = State) ->
    {true, State};
check_rate_limit(
    #state{
        max_new_conns_per_sec = Max,
        rate_count = Count,
        rate_window_start = WindowStart
    } = State
) ->
    Now = erlang:monotonic_time(second),
    case Now > WindowStart of
        true ->
            {true, State#state{rate_count = 0, rate_window_start = Now}};
        false ->
            {Count < Max, State}
    end.

-spec dispatch_initial(
    proceed | {retry, nquic:connection_id()} | send_retry,
    nquic_socket:sockaddr(),
    binary(),
    nquic:connection_id(),
    nquic:connection_id(),
    non_neg_integer(),
    #state{},
    nquic_dispatch:t(),
    pid()
) -> ok.
dispatch_initial(proceed, Source, Bin, DCID, SCID, Version, State, Table, Listener) ->
    start_new_connection(Source, Bin, DCID, SCID, Version, State, Table, Listener);
dispatch_initial({retry, ODCID}, Source, Bin, DCID, SCID, Version, State, Table, Listener) ->
    start_new_connection_with_odcid(
        Source, Bin, DCID, SCID, ODCID, Version, State, Table, Listener
    );
dispatch_initial(send_retry, Source, _Bin, DCID, SCID, Version, State, _Table, _Listener) ->
    send_retry_packet(Source, DCID, SCID, Version, State).

-spec dispatch_packet(nquic_socket:sockaddr(), binary(), #state{}) -> #state{}.
dispatch_packet(Source, Bin, #state{dispatch_table = Table} = State) ->
    bump_packets_in(Table),
    case fast_dispatch(Bin, Table) of
        {ok, Pid} ->
            nquic_conn_statem:handle_packet_event(Pid, {packet, Source, Bin}),
            State;
        slow ->
            slow_dispatch(Source, Bin, Table, State)
    end.

-spec dispatch_packet_ecn(
    nquic_socket:sockaddr(), binary(), nquic_socket:ecn_mark(), #state{}
) -> #state{}.
dispatch_packet_ecn(Source, Bin, ECN, #state{dispatch_table = Table} = State) ->
    bump_packets_in(Table),
    case fast_dispatch(Bin, Table) of
        {ok, Pid} ->
            nquic_conn_statem:handle_packet_event(Pid, {packet, Source, Bin, ECN}),
            State;
        slow ->
            slow_dispatch(Source, Bin, Table, State)
    end.

-spec dispatch_per_segment_gro(
    nquic_socket:sockaddr(),
    binary(),
    nquic_socket:ecn_mark(),
    pos_integer(),
    #state{}
) -> #state{}.
dispatch_per_segment_gro(Source, Data, ECN, GsoSize, State) when byte_size(Data) =< GsoSize ->
    dispatch_packet_ecn(Source, Data, ECN, State);
dispatch_per_segment_gro(Source, Data, ECN, GsoSize, State) ->
    <<Segment:GsoSize/binary, Rest/binary>> = Data,
    State1 = dispatch_packet_ecn(Source, Segment, ECN, State),
    dispatch_per_segment_gro(Source, Rest, ECN, GsoSize, State1).

-spec dispatch_with_gro(
    nquic_socket:sockaddr(),
    binary(),
    nquic_socket:ecn_mark(),
    undefined | pos_integer(),
    #state{}
) -> #state{}.
dispatch_with_gro(Source, Data, ECN, undefined, State) ->
    dispatch_packet_ecn(Source, Data, ECN, State);
dispatch_with_gro(Source, Data, ECN, GsoSize, State) when byte_size(Data) =< GsoSize ->
    dispatch_packet_ecn(Source, Data, ECN, State);
dispatch_with_gro(Source, Data, ECN, GsoSize, #state{dispatch_table = Table} = State) ->
    case fast_dispatch(Data, Table) of
        {ok, Pid} ->
            bump_packets_in_n(Table, (byte_size(Data) + GsoSize - 1) div GsoSize),
            nquic_conn_statem:handle_packet_event(
                Pid, {packet_batch, Source, Data, GsoSize, ECN}
            ),
            State;
        slow ->
            dispatch_per_segment_gro(Source, Data, ECN, GsoSize, State)
    end.

-spec ecn_from_ctrl(#state{}, list()) -> nquic_socket:ecn_mark().
ecn_from_ctrl(#state{ecn = true}, Ctrl) -> nquic_socket:get_ecn_from_cmsg(Ctrl);
ecn_from_ctrl(_, _) -> not_ect.

-spec fast_dispatch(binary(), nquic_dispatch:t()) -> {ok, pid()} | slow.
fast_dispatch(<<0:1, 1:1, _:6, DCID:8/binary, _/binary>>, Table) ->
    case nquic_listener:dispatch_lookup(Table, DCID) of
        Pid when is_pid(Pid) ->
            {ok, Pid};
        undefined ->
            slow
    end;
fast_dispatch(_, _) ->
    slow.

-spec get_dcid(#long_header{} | #short_header{}) -> binary().
get_dcid(#long_header{dcid = DCID}) -> DCID;
get_dcid(#short_header{dcid = DCID}) -> DCID.

-spec handle_initial(
    boolean(),
    nquic_socket:sockaddr(),
    binary(),
    #long_header{},
    #state{},
    nquic_dispatch:t(),
    pid()
) -> ok.
handle_initial(false, Source, _Bin, #long_header{dcid = DCID, scid = SCID}, State, _, _) ->
    VNPacket = nquic_packet:encode_version_negotiation(
        SCID, DCID, nquic_packet:supported_versions()
    ),
    _ = nquic_socket:send(State#state.socket, Source, VNPacket),
    ok;
handle_initial(
    true,
    Source,
    Bin,
    #long_header{version = Version, dcid = DCID, scid = SCID, token = Token},
    State,
    Table,
    Listener
) ->
    dispatch_initial(
        maybe_retry(Token, Source, State),
        Source,
        Bin,
        DCID,
        SCID,
        Version,
        State,
        Table,
        Listener
    ).

-spec handle_new_conn(
    nquic_socket:sockaddr(),
    binary(),
    #long_header{} | #short_header{},
    #state{},
    nquic_dispatch:t(),
    pid()
) -> ok.
handle_new_conn(
    Source,
    Bin,
    #long_header{type = initial, version = Version} = Header,
    State,
    Table,
    Listener
) ->
    handle_initial(
        nquic_packet:is_supported_version(Version),
        Source,
        Bin,
        Header,
        State,
        Table,
        Listener
    );
handle_new_conn(Source, _Bin, #short_header{dcid = DCID}, State, _Table, _Listener) ->
    Token = nquic_stateless_reset:generate_token(State#state.static_key, DCID),
    Packet = nquic_stateless_reset:build_packet(Token),
    _ = nquic_socket:send(State#state.socket, Source, Packet),
    ok;
handle_new_conn(_Source, _Bin, _Header, _State, _Table, _Listener) ->
    ok.

-spec maybe_retry(binary() | undefined, nquic_socket:sockaddr(), #state{}) ->
    proceed | {retry, nquic:connection_id()} | send_retry.
maybe_retry(_Token, _Source, #state{retry = false}) ->
    proceed;
maybe_retry(undefined, _Source, #state{retry = true}) ->
    send_retry;
maybe_retry(<<>>, _Source, #state{retry = true}) ->
    send_retry;
maybe_retry(Token, Source, #state{
    retry = true, static_key = Key, retry_token_lifetime = TTL, opts = Opts
}) ->
    case nquic_retry:validate_token(Token, Key, Source, TTL) of
        {ok, ODCID} ->
            {retry, ODCID};
        {error, _} ->
            NewTokenTTL = maps:get(new_token_lifetime, Opts, 86400),
            case nquic_new_token:validate(Token, Key, Source, NewTokenTTL) of
                ok -> proceed;
                {error, _} -> send_retry
            end
    end.

-spec recv_loop(#state{}) -> #state{}.
recv_loop(#state{gro = true, socket = Socket} = State) ->
    case nquic_socket:recv_msg_now(Socket) of
        {ok, {Source, Data, Ctrl}} ->
            ECN = ecn_from_ctrl(State, Ctrl),
            GsoSize = nquic_socket:get_gso_size_from_cmsg(Ctrl),
            State1 = dispatch_with_gro(Source, Data, ECN, GsoSize, State),
            recv_loop(State1);
        {select, SelectInfo} ->
            State#state{select_info = SelectInfo};
        {error, _Reason} ->
            State
    end;
recv_loop(#state{ecn = true, socket = Socket} = State) ->
    case nquic_socket:recv_msg_now(Socket) of
        {ok, {Source, Data, Ctrl}} ->
            ECN = nquic_socket:get_ecn_from_cmsg(Ctrl),
            State1 = dispatch_packet_ecn(Source, Data, ECN, State),
            recv_loop(State1);
        {select, SelectInfo} ->
            State#state{select_info = SelectInfo};
        {error, _Reason} ->
            State
    end;
recv_loop(#state{socket = Socket} = State) ->
    case nquic_socket:recv_now(Socket) of
        {ok, {Source, Data}} ->
            State1 = dispatch_packet(Source, Data, State),
            recv_loop(State1);
        {select, SelectInfo} ->
            State#state{select_info = SelectInfo};
        {error, _Reason} ->
            State
    end.

-spec send_retry_packet(
    nquic_socket:sockaddr(),
    nquic:connection_id(),
    nquic:connection_id(),
    non_neg_integer(),
    #state{}
) -> ok.
send_retry_packet(Source, ClientDCID, ClientSCID, Version, State) ->
    NewSCID = nquic_keys:generate_connection_id(8),
    Token = nquic_retry:generate_token(
        State#state.static_key, ClientDCID, Source, State#state.retry_token_lifetime
    ),
    Packet = nquic_retry:encode_retry_packet(ClientSCID, NewSCID, ClientDCID, Token, Version),
    _ = nquic_socket:send(State#state.socket, Source, Packet),
    ok.

-spec slow_dispatch(nquic_socket:sockaddr(), binary(), nquic_dispatch:t(), #state{}) ->
    #state{}.
slow_dispatch(Source, Bin, Table, State) ->
    ExpectedDCIDLen = 8,
    case nquic_packet:parse_header(Bin, ExpectedDCIDLen) of
        {ok, Header, _Rest} ->
            DCID = get_dcid(Header),
            case nquic_listener:dispatch_lookup(Table, DCID) of
                Pid when is_pid(Pid) ->
                    nquic_conn_statem:handle_packet_event(
                        Pid, {packet, Source, Bin}
                    ),
                    State;
                undefined ->
                    spawn_slow_path(Source, Bin, Header, State)
            end;
        _ ->
            State
    end.

-spec spawn_slow_path(
    nquic_socket:sockaddr(),
    binary(),
    #long_header{} | #short_header{},
    #state{}
) -> #state{}.
spawn_slow_path(Source, Bin, Header, State) ->
    case check_rate_limit(State) of
        {false, State1} ->
            case nquic_dispatch:metrics(State1#state.dispatch_table) of
                undefined -> ok;
                M -> nquic_metrics:inc(M, packets_dropped_ratelimit)
            end,
            State1;
        {true, State1} ->
            Table = State1#state.dispatch_table,
            Listener = State1#state.listener,
            try
                handle_new_conn(Source, Bin, Header, State1, Table, Listener)
            catch
                Class:Reason:Stack ->
                    logger:error(
                        "nquic_receiver new-conn handler crashed: "
                        "~p:~p~nheader=~p~nstack=~p",
                        [Class, Reason, Header, Stack]
                    )
            end,
            bump_rate(State1)
    end.

-spec start_new_connection(
    nquic_socket:sockaddr(),
    binary(),
    nquic:connection_id(),
    nquic:connection_id(),
    non_neg_integer(),
    #state{},
    nquic_dispatch:t(),
    pid()
) -> ok.
start_new_connection(Source, Bin, DCID, SCID, Version, State, Table, Listener) ->
    CertOpts =
        case maps:get(cert_der, State#state.opts, undefined) of
            undefined ->
                #{
                    certfile => maps:get(certfile, State#state.opts, undefined),
                    keyfile => maps:get(keyfile, State#state.opts, undefined)
                };
            CertDER ->
                #{
                    cert_der => CertDER,
                    cert_chain => maps:get(cert_chain, State#state.opts, []),
                    key_decoded => maps:get(key_decoded, State#state.opts),
                    cacerts => maps:get(cacerts, State#state.opts, [])
                }
        end,
    Opts = CertOpts#{
        role => server,
        socket => State#state.socket,
        peer => Source,
        dcid => SCID,
        odcid => DCID,
        version => Version,
        transport_params => maps:get(
            transport_params, State#state.opts, #transport_params{}
        ),
        dispatch_table => Table,
        listener => Listener,
        alpn => maps:get(alpn, State#state.opts, undefined),
        static_key => State#state.static_key,
        congestion_control => maps:get(congestion_control, State#state.opts, cubic),
        cipher_suites => maps:get(cipher_suites, State#state.opts, undefined),
        replay_protection => maps:get(replay_protection, State#state.opts, undefined),
        idle_timeout => maps:get(idle_timeout, State#state.opts, 0),
        send_buffer => maps:get(send_buffer, State#state.opts, 1048576),
        send_timeout => maps:get(send_timeout, State#state.opts, infinity),
        gso => maps:get(gso, State#state.opts, false),
        pacing => maps:get(pacing, State#state.opts, false),
        pacing_factor => maps:get(pacing_factor, State#state.opts, 1.25),
        pacing_burst => maps:get(pacing_burst, State#state.opts, 10),
        slow_start => maps:get(slow_start, State#state.opts, standard),
        spin_bit => maps:get(spin_bit, State#state.opts, false),
        new_token => maps:get(new_token, State#state.opts, true),
        new_token_lifetime => maps:get(new_token_lifetime, State#state.opts, 86400),
        qlog => maps:get(qlog, State#state.opts, undefined),
        max_payload_size => maps:get(max_payload_size, State#state.opts, 1200),
        server_per_conn_fd => maps:get(server_per_conn_fd, State#state.opts, false),
        version_preference => maps:get(version_preference, State#state.opts, [1]),
        conn_handler => maps:get(conn_handler, State#state.opts, undefined),
        conn_handler_opts => maps:get(conn_handler_opts, State#state.opts, undefined)
    },
    case nquic_dispatch:start_conn_child(Table, DCID, Opts) of
        {ok, Pid} ->
            nquic_listener:dispatch_register(Table, DCID, Pid),
            nquic_conn_statem:handle_packet_event(Pid, {packet, Source, Bin});
        {error, _Reason} ->
            ok
    end.

-spec start_new_connection_with_odcid(
    nquic_socket:sockaddr(),
    binary(),
    nquic:connection_id(),
    nquic:connection_id(),
    nquic:connection_id(),
    non_neg_integer(),
    #state{},
    nquic_dispatch:t(),
    pid()
) -> ok.
start_new_connection_with_odcid(Source, Bin, DCID, SCID, ODCID, Version, State, Table, Listener) ->
    CertOpts =
        case maps:get(cert_der, State#state.opts, undefined) of
            undefined ->
                #{
                    certfile => maps:get(certfile, State#state.opts, undefined),
                    keyfile => maps:get(keyfile, State#state.opts, undefined)
                };
            CertDER ->
                #{
                    cert_der => CertDER,
                    cert_chain => maps:get(cert_chain, State#state.opts, []),
                    key_decoded => maps:get(key_decoded, State#state.opts),
                    cacerts => maps:get(cacerts, State#state.opts, [])
                }
        end,
    BaseParams = maps:get(transport_params, State#state.opts, #transport_params{}),
    Params = BaseParams#transport_params{retry_source_connection_id = DCID},
    Opts = CertOpts#{
        role => server,
        socket => State#state.socket,
        peer => Source,
        dcid => SCID,
        odcid => ODCID,
        version => Version,
        transport_params => Params,
        dispatch_table => Table,
        listener => Listener,
        alpn => maps:get(alpn, State#state.opts, undefined),
        static_key => State#state.static_key,
        congestion_control => maps:get(congestion_control, State#state.opts, cubic),
        cipher_suites => maps:get(cipher_suites, State#state.opts, undefined),
        replay_protection => maps:get(replay_protection, State#state.opts, undefined),
        idle_timeout => maps:get(idle_timeout, State#state.opts, 0),
        send_buffer => maps:get(send_buffer, State#state.opts, 1048576),
        send_timeout => maps:get(send_timeout, State#state.opts, infinity),
        gso => maps:get(gso, State#state.opts, false),
        pacing => maps:get(pacing, State#state.opts, false),
        pacing_factor => maps:get(pacing_factor, State#state.opts, 1.25),
        pacing_burst => maps:get(pacing_burst, State#state.opts, 10),
        slow_start => maps:get(slow_start, State#state.opts, standard),
        spin_bit => maps:get(spin_bit, State#state.opts, false),
        new_token => maps:get(new_token, State#state.opts, true),
        new_token_lifetime => maps:get(new_token_lifetime, State#state.opts, 86400),
        qlog => maps:get(qlog, State#state.opts, undefined),
        max_payload_size => maps:get(max_payload_size, State#state.opts, 1200),
        server_per_conn_fd => maps:get(server_per_conn_fd, State#state.opts, false),
        version_preference => maps:get(version_preference, State#state.opts, [1]),
        conn_handler => maps:get(conn_handler, State#state.opts, undefined),
        conn_handler_opts => maps:get(conn_handler_opts, State#state.opts, undefined)
    },
    case nquic_dispatch:start_conn_child(Table, DCID, Opts) of
        {ok, Pid} ->
            nquic_listener:dispatch_register(Table, DCID, Pid),
            nquic_conn_statem:handle_packet_event(Pid, {packet, Source, Bin});
        {error, _Reason} ->
            ok
    end.
