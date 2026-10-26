%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_receiver}.
%%%
%%% The `state' record mirrors the source-of-truth in
%%% `src/nquic_receiver.erl'; if the production layout changes,
%%% update the copy below to keep these tests in sync.
%%%-------------------------------------------------------------------
-module(nquic_receiver_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_packet.hrl").
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

get_dcid_long_header_test() ->
    DCID = <<1, 2, 3, 4>>,
    Header = #long_header{
        type = initial,
        version = 1,
        dcid = DCID,
        scid = <<5, 6>>,
        token = <<>>,
        payload_len = 100,
        packet_number = 0
    },
    ?assertEqual(DCID, nquic_receiver:get_dcid(Header)).

get_dcid_short_header_test() ->
    DCID = <<7, 8, 9, 10>>,
    Header = #short_header{dcid = DCID, packet_number = 1, key_phase = false},
    ?assertEqual(DCID, nquic_receiver:get_dcid(Header)).

handle_info_unknown_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>
    },
    ?assertEqual({noreply, State}, nquic_receiver:handle_info(unknown_msg, State)).

handle_call_unknown_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>
    },
    ?assertEqual(
        {reply, {error, unknown_request}, State},
        nquic_receiver:handle_call(any_request, {self(), make_ref()}, State)
    ).

handle_cast_unknown_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>
    },
    ?assertEqual({noreply, State}, nquic_receiver:handle_cast(any_msg, State)).

terminate_with_socket_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    State = #state{
        socket = Socket,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>
    },
    ?assertEqual(ok, nquic_receiver:terminate(normal, State)).

terminate_without_socket_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>
    },
    ?assertEqual(ok, nquic_receiver:terminate(normal, State)).

fast_dispatch_short_header_found_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Table = nquic_dispatch:new(1),
    nquic_dispatch:register(Table, DCID, self()),
    Packet = <<16#40, DCID/binary, 0, 0, 0, 0>>,
    ?assertEqual({ok, self()}, nquic_receiver:fast_dispatch(Packet, Table)),
    nquic_dispatch:destroy(Table).

fast_dispatch_short_header_not_found_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Table = nquic_dispatch:new(1),
    Packet = <<16#40, DCID/binary, 0, 0, 0, 0>>,
    ?assertEqual(slow, nquic_receiver:fast_dispatch(Packet, Table)),
    nquic_dispatch:destroy(Table).

fast_dispatch_long_header_test() ->
    Packet = <<16#C0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0>>,
    Table = nquic_dispatch:new(1),
    ?assertEqual(slow, nquic_receiver:fast_dispatch(Packet, Table)),
    nquic_dispatch:destroy(Table).

fast_dispatch_too_short_test() ->
    ?assertEqual(slow, nquic_receiver:fast_dispatch(<<>>, undefined)).

check_rate_limit_disabled_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        max_new_conns_per_sec = 0
    },
    {true, State} = nquic_receiver:check_rate_limit(State).

check_rate_limit_under_limit_test() ->
    Now = erlang:monotonic_time(second),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        max_new_conns_per_sec = 10,
        rate_count = 5,
        rate_window_start = Now
    },
    {true, State} = nquic_receiver:check_rate_limit(State).

check_rate_limit_at_limit_test() ->
    Now = erlang:monotonic_time(second),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        max_new_conns_per_sec = 10,
        rate_count = 10,
        rate_window_start = Now
    },
    {false, State} = nquic_receiver:check_rate_limit(State).

check_rate_limit_new_window_test() ->
    Past = erlang:monotonic_time(second) - 2,
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        max_new_conns_per_sec = 10,
        rate_count = 10,
        rate_window_start = Past
    },
    {true, State1} = nquic_receiver:check_rate_limit(State),
    ?assertEqual(0, State1#state.rate_count).

bump_rate_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        rate_count = 3
    },
    State1 = nquic_receiver:bump_rate(State),
    ?assertEqual(4, State1#state.rate_count).

dispatch_packet_fast_path_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Table = nquic_dispatch:new(1),
    nquic_dispatch:register(Table, DCID, self()),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = Table,
        listener = undefined,
        opts = #{},
        static_key = <<>>
    },
    Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Packet = <<16#40, DCID/binary, 0, 0, 0, 0>>,
    State = nquic_receiver:dispatch_packet(Source, Packet, State),
    receive
        {packet, Source, Packet} -> ok
    after 100 -> ?assert(false)
    end,
    nquic_dispatch:destroy(Table).

slow_dispatch_bad_packet_test() ->
    Table = nquic_dispatch:new(1),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = Table,
        listener = undefined,
        opts = #{},
        static_key = <<>>
    },
    Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    State = nquic_receiver:slow_dispatch(Source, <<0>>, Table, State),
    nquic_dispatch:destroy(Table).

maybe_retry_disabled_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        retry = false
    },
    ?assertEqual(proceed, nquic_receiver:maybe_retry(<<"token">>, #{}, State)).

maybe_retry_enabled_no_token_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        retry = true,
        retry_token_lifetime = 30
    },
    ?assertEqual(send_retry, nquic_receiver:maybe_retry(<<>>, #{}, State)).

maybe_retry_enabled_undefined_token_test() ->
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        retry = true,
        retry_token_lifetime = 30
    },
    ?assertEqual(send_retry, nquic_receiver:maybe_retry(undefined, #{}, State)).

maybe_retry_valid_token_test() ->
    Key = crypto:strong_rand_bytes(32),
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Token = nquic_retry:generate_token(Key, ODCID, Peer, 30),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = Key,
        retry = true,
        retry_token_lifetime = 30
    },
    ?assertMatch({retry, ODCID}, nquic_receiver:maybe_retry(Token, Peer, State)).

maybe_retry_invalid_token_test() ->
    Key = crypto:strong_rand_bytes(32),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{},
        static_key = Key,
        retry = true,
        retry_token_lifetime = 30
    },
    ?assertEqual(send_retry, nquic_receiver:maybe_retry(<<"bad_token">>, Peer, State)).

maybe_retry_valid_new_token_test() ->
    Key = crypto:strong_rand_bytes(32),
    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    NewToken = nquic_new_token:generate(Key, Peer, 86400),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = undefined,
        listener = undefined,
        opts = #{new_token_lifetime => 86400},
        static_key = Key,
        retry = true,
        retry_token_lifetime = 30
    },
    ?assertEqual(proceed, nquic_receiver:maybe_retry(NewToken, Peer, State)).

slow_dispatch_long_header_existing_dcid_test() ->
    DCID = <<10, 11, 12, 13, 14, 15, 16, 17>>,
    Table = nquic_dispatch:new(1),
    nquic_dispatch:register(Table, DCID, self()),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = Table,
        listener = undefined,
        opts = #{},
        static_key = <<>>
    },
    Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Packet =
        <<16#C0, 0, 0, 0, 1, 8, DCID/binary, 0, 0, 1, 0:8>>,
    NewState = nquic_receiver:slow_dispatch(Source, Packet, Table, State),
    ?assertEqual(State, NewState),
    receive
        {packet, Source, Packet} -> ok
    after 100 ->
        ?assert(false)
    end,
    nquic_dispatch:destroy(Table).

slow_dispatch_rate_limited_drops_test() ->
    DCID = <<20, 21, 22, 23, 24, 25, 26, 27>>,
    Table = nquic_dispatch:new(1),
    Now = erlang:monotonic_time(second),
    State = #state{
        socket = undefined,
        select_info = undefined,
        dispatch_table = Table,
        listener = undefined,
        opts = #{},
        static_key = <<>>,
        max_new_conns_per_sec = 1,
        rate_count = 1,
        rate_window_start = Now
    },
    Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    Packet = <<16#C0, 0, 0, 0, 1, 8, DCID/binary, 0, 0, 1, 0:8>>,
    NewState = nquic_receiver:slow_dispatch(Source, Packet, Table, State),
    ?assertEqual(State, NewState),
    nquic_dispatch:destroy(Table).

real_receiver_handles_unknown_packet_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            {ok, Port} = nquic_receiver:get_port(RecvPid),
            ?assert(Port > 0),
            {ok, SendSocket} = nquic_socket:open(0, #{}),
            Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port),
            ok = nquic_socket:send(SendSocket, Peer, <<"garbage">>),
            timer:sleep(50),
            socket:close(SendSocket),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

real_receiver_with_ecn_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0,
            ecn => true
        },
        case nquic_receiver:start_link(Opts) of
            {ok, RecvPid} ->
                try
                    {ok, Port} = nquic_receiver:get_port(RecvPid),
                    {ok, SendSocket} = nquic_socket:open(0, #{}),
                    Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port),
                    ok = nquic_socket:send(SendSocket, Peer, <<"garbage">>),
                    timer:sleep(50),
                    socket:close(SendSocket),
                    ?assert(is_process_alive(RecvPid))
                after
                    unlink(RecvPid),
                    gen_server:stop(RecvPid, normal, 5000),
                    nquic_dispatch:destroy(Dispatch)
                end;
            {error, _Reason} ->
                nquic_dispatch:destroy(Dispatch),
                ok
        end
    end}.

real_receiver_drives_slow_path_with_initial_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            {ok, Port} = nquic_receiver:get_port(RecvPid),
            {ok, SendSocket} = nquic_socket:open(0, #{}),
            Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port),
            DCID = <<30, 31, 32, 33, 34, 35, 36, 37>>,
            Packet =
                <<16#C0, 0, 0, 0, 1, 8, DCID/binary, 0, 0, 1, 0:8>>,
            ok = nquic_socket:send(SendSocket, Peer, Packet),
            timer:sleep(100),
            socket:close(SendSocket),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

real_receiver_handles_unsupported_version_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            {ok, Port} = nquic_receiver:get_port(RecvPid),
            {ok, SendSocket} = nquic_socket:open(0, #{}),
            Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port),
            DCID = <<40, 41, 42, 43, 44, 45, 46, 47>>,
            Packet = <<16#C0, 16#DE, 16#AD, 16#BE, 16#EF, 8, DCID/binary, 0, 0, 1, 0:8>>,
            ok = nquic_socket:send(SendSocket, Peer, Packet),
            timer:sleep(100),
            socket:close(SendSocket),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

real_receiver_handles_short_header_unknown_dcid_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            {ok, Port} = nquic_receiver:get_port(RecvPid),
            {ok, SendSocket} = nquic_socket:open(0, #{}),
            Peer = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port),
            DCID = <<50, 51, 52, 53, 54, 55, 56, 57>>,
            Packet = <<16#40, DCID/binary, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
            ok = nquic_socket:send(SendSocket, Peer, Packet),
            timer:sleep(100),
            socket:close(SendSocket),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

handle_info_immediate_packet_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            RecvPid ! {immediate_packet, Source, <<"garbage">>},
            timer:sleep(50),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

handle_info_immediate_packet_ecn_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            RecvPid ! {immediate_packet_ecn, Source, <<"garbage">>, ect0},
            timer:sleep(50),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

handle_info_immediate_packet_cmsg_undef_gso_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            RecvPid ! {immediate_packet_cmsg, Source, <<"garbage">>, ect0, undefined},
            timer:sleep(50),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

handle_info_immediate_packet_cmsg_small_buf_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            RecvPid ! {immediate_packet_cmsg, Source, <<"abc">>, ect0, 100},
            timer:sleep(50),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

handle_info_immediate_packet_cmsg_split_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            Buf = list_to_binary(lists:duplicate(30, $a)),
            RecvPid ! {immediate_packet_cmsg, Source, Buf, ect0, 10},
            timer:sleep(50),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

dispatch_packet_ecn_fast_path_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            DCID = <<60, 61, 62, 63, 64, 65, 66, 67>>,
            nquic_dispatch:register(Dispatch, DCID, self()),
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            Packet = <<16#40, DCID/binary, 0, 0, 0, 0, 0, 0, 0, 0>>,
            RecvPid ! {immediate_packet_ecn, Source, Packet, ect0},
            receive
                {packet, Source, Packet, ect0} -> ok
            after 200 -> ct:fail(no_packet_received)
            end,
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

dispatch_with_gro_fast_path_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            DCID = <<70, 71, 72, 73, 74, 75, 76, 77>>,
            nquic_dispatch:register(Dispatch, DCID, self()),
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            Segment = <<16#40, DCID/binary, 0, 0, 0>>,
            GsoSize = byte_size(Segment),
            Buf = <<Segment/binary, Segment/binary>>,
            RecvPid ! {immediate_packet_cmsg, Source, Buf, ect1, GsoSize},
            receive
                {packet_batch, Source, Buf, GsoSize, ect1} -> ok
            after 200 -> ct:fail(no_batch_received)
            end,
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

dispatch_with_gro_slow_path_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            UnknownDCID = <<200, 201, 202, 203, 204, 205, 206, 207>>,
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            Segment = <<16#40, UnknownDCID/binary, 0, 0, 0>>,
            GsoSize = byte_size(Segment),
            Buf = <<Segment/binary, Segment/binary>>,
            RecvPid ! {immediate_packet_cmsg, Source, Buf, ect1, GsoSize},
            timer:sleep(50),
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.

dispatch_with_gro_undefined_gsosize_test_() ->
    {timeout, 10, fun() ->
        Dispatch = nquic_dispatch:new(),
        StaticKey = crypto:strong_rand_bytes(32),
        Opts = #{
            dispatch_table => Dispatch,
            listener => self(),
            static_key => StaticKey,
            port => 0
        },
        {ok, RecvPid} = nquic_receiver:start_link(Opts),
        try
            DCID = <<80, 81, 82, 83, 84, 85, 86, 87>>,
            nquic_dispatch:register(Dispatch, DCID, self()),
            Source = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
            Packet = <<16#40, DCID/binary, 0, 0, 0>>,
            RecvPid ! {immediate_packet_cmsg, Source, Packet, ect0, undefined},
            receive
                {packet, Source, Packet, ect0} -> ok
            after 200 -> ct:fail(no_packet_received)
            end,
            ?assert(is_process_alive(RecvPid))
        after
            unlink(RecvPid),
            gen_server:stop(RecvPid, normal, 5000),
            nquic_dispatch:destroy(Dispatch)
        end
    end}.
