%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_socket}.
%%%-------------------------------------------------------------------
-module(nquic_socket_tests).

-include_lib("eunit/include/eunit.hrl").

open_ephemeral_port_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    {ok, Port} = nquic_socket:port(Socket),
    ?assert(Port > 0),
    ?assertEqual(ok, nquic_socket:close(Socket)).

open_specific_port_test() ->
    TestPort = 44330 + rand:uniform(100),
    {ok, Socket} = nquic_socket:open(TestPort, #{}),
    {ok, ActualPort} = nquic_socket:port(Socket),
    ?assertEqual(TestPort, ActualPort),
    ?assertEqual(ok, nquic_socket:close(Socket)).

open_with_custom_buffers_test() ->
    Opts = #{recbuf => 1024 * 1024, sndbuf => 512 * 1024},
    {ok, Socket} = nquic_socket:open(Opts),
    ?assertEqual(ok, nquic_socket:close(Socket)).

make_sockaddr_ipv4_test() ->
    Addr = nquic_socket:make_sockaddr({127, 0, 0, 1}, 4433),
    ?assertEqual(#{family => inet, addr => {127, 0, 0, 1}, port => 4433}, Addr).

make_sockaddr_ipv6_test() ->
    Addr = nquic_socket:make_sockaddr({0, 0, 0, 0, 0, 0, 0, 1}, 4433),
    ?assertEqual(#{family => inet6, addr => {0, 0, 0, 0, 0, 0, 0, 1}, port => 4433}, Addr).

sockaddr_to_tuple_test() ->
    SockAddr = #{family => inet, addr => {192, 168, 1, 1}, port => 8080},
    ?assertEqual({{192, 168, 1, 1}, 8080}, nquic_socket:sockaddr_to_tuple(SockAddr)).

send_recv_test() ->
    {ok, Socket1} = nquic_socket:open(#{}),
    {ok, Socket2} = nquic_socket:open(#{}),
    {ok, Port1} = nquic_socket:port(Socket1),
    {ok, Port2} = nquic_socket:port(Socket2),

    Dest = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port1),
    TestData = <<"hello quic">>,
    ok = nquic_socket:send(Socket2, Dest, TestData),

    timer:sleep(10),
    case nquic_socket:recv_now(Socket1) of
        {ok, {Source, RecvData}} ->
            ?assertEqual(TestData, RecvData),
            ?assertEqual(Port2, maps:get(port, Source));
        {select, _} ->
            timer:sleep(50),
            {ok, {Source, RecvData}} = nquic_socket:recv_now(Socket1),
            ?assertEqual(TestData, RecvData),
            ?assertEqual(Port2, maps:get(port, Source))
    end,

    ?assertEqual(ok, nquic_socket:close(Socket1)),
    ?assertEqual(ok, nquic_socket:close(Socket2)).

recv_start_select_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    case nquic_socket:recv_start(Socket) of
        {select, {select_info, _Tag, Ref}} ->
            ?assert(is_reference(Ref));
        {ok, _} ->
            ok
    end,
    ?assertEqual(ok, nquic_socket:close(Socket)).

controlling_process_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    Self = self(),
    Pid = spawn(fun() ->
        receive
            {transfer_back, S, From} ->
                ok = nquic_socket:controlling_process(S, From),
                From ! transferred
        end
    end),
    ?assertEqual(ok, nquic_socket:controlling_process(Socket, Pid)),
    Pid ! {transfer_back, Socket, Self},
    receive
        transferred -> ok
    after 1000 ->
        ?assert(false)
    end,
    ?assertEqual(ok, nquic_socket:close(Socket)).

sockname_test() ->
    TestPort = 44400 + rand:uniform(100),
    {ok, Socket} = nquic_socket:open(TestPort, #{ip => {127, 0, 0, 1}}),
    {ok, SockAddr} = nquic_socket:sockname(Socket),
    ?assertEqual(TestPort, maps:get(port, SockAddr)),
    ?assertEqual({127, 0, 0, 1}, maps:get(addr, SockAddr)),
    ?assertEqual(ok, nquic_socket:close(Socket)).

reuseport_two_sockets_test() ->
    TestPort = 44500 + rand:uniform(100),
    {ok, S1} = nquic_socket:open(TestPort, #{reuseport => true}),
    {ok, S2} = nquic_socket:open(TestPort, #{reuseport => true}),
    {ok, P1} = nquic_socket:port(S1),
    {ok, P2} = nquic_socket:port(S2),
    ?assertEqual(TestPort, P1),
    ?assertEqual(TestPort, P2),
    ?assertEqual(ok, nquic_socket:close(S1)),
    ?assertEqual(ok, nquic_socket:close(S2)).

close_already_closed_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    ?assertEqual(ok, nquic_socket:close(Socket)),
    ?assertMatch({error, _}, nquic_socket:close(Socket)).

rebind_changes_socket_test() ->
    {ok, Socket1} = nquic_socket:open(#{}),
    NewAddr = nquic_socket:make_sockaddr({127, 0, 0, 1}, 0),
    {ok, Socket2} = nquic_socket:rebind(Socket1, NewAddr),
    ?assertNotEqual(Socket1, Socket2),
    ?assertMatch({error, _}, nquic_socket:port(Socket1)),
    {ok, Port2} = nquic_socket:port(Socket2),
    ?assert(Port2 > 0),
    ?assertEqual(ok, nquic_socket:close(Socket2)).

get_ecn_from_cmsg_undefined_test() ->
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(undefined)).

get_ecn_from_cmsg_empty_test() ->
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg([])).

get_ecn_from_cmsg_ipv4_int_test() ->
    Ctrl = [#{level => ip, type => tos, value => 2}],
    ?assertEqual(ect0, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_ipv4_int_ce_test() ->
    Ctrl = [#{level => ip, type => tos, value => 3}],
    ?assertEqual(ce, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_ipv4_int_ect1_test() ->
    Ctrl = [#{level => ip, type => tos, value => 1}],
    ?assertEqual(ect1, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_ipv4_int_not_ect_test() ->
    Ctrl = [#{level => ip, type => tos, value => 0}],
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_ipv6_test() ->
    Ctrl = [#{level => ipv6, type => tclass, value => 2}],
    ?assertEqual(ect0, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_atom_default_test() ->
    Ctrl = [#{level => ip, type => tos, value => default}],
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_atom_lowdelay_test() ->
    Ctrl = [#{level => ip, type => tos, value => lowdelay}],
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_atom_throughput_test() ->
    Ctrl = [#{level => ip, type => tos, value => throughput}],
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_atom_reliability_test() ->
    Ctrl = [#{level => ip, type => tos, value => reliability}],
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_atom_mincost_test() ->
    Ctrl = [#{level => ip, type => tos, value => mincost}],
    ?assertEqual(ect0, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_binary_test() ->
    Ctrl = [#{level => ip, type => tos, value => <<2:8, 0:24>>}],
    ?assertEqual(ect0, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_unknown_skips_test() ->
    Ctrl = [
        #{level => socket, type => timestamp, value => {0, 0}},
        #{level => ip, type => tos, value => 2}
    ],
    ?assertEqual(ect0, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_ecn_from_cmsg_unknown_terminates_not_ect_test() ->
    Ctrl = [#{level => socket, type => timestamp, value => {0, 0}}],
    ?assertEqual(not_ect, nquic_socket:get_ecn_from_cmsg(Ctrl)).

get_gso_size_from_cmsg_undefined_test() ->
    ?assertEqual(undefined, nquic_socket:get_gso_size_from_cmsg(undefined)).

get_gso_size_from_cmsg_empty_test() ->
    ?assertEqual(undefined, nquic_socket:get_gso_size_from_cmsg([])).

get_gso_size_from_cmsg_hit_test() ->
    Ctrl = [
        #{level => udp, type => 104, data => <<1200:16/native, 0:16>>}
    ],
    ?assertEqual(1200, nquic_socket:get_gso_size_from_cmsg(Ctrl)).

get_gso_size_from_cmsg_skips_other_test() ->
    Ctrl = [
        #{level => ip, type => tos, value => 0},
        #{level => udp, type => 104, data => <<512:16/native, 0:16>>}
    ],
    ?assertEqual(512, nquic_socket:get_gso_size_from_cmsg(Ctrl)).

set_ecn_true_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    ?assertEqual(ok, nquic_socket:set_ecn(Socket, true)),
    socket:close(Socket).

set_ecn_false_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    ?assertEqual(ok, nquic_socket:set_ecn(Socket, false)),
    socket:close(Socket).

set_egress_ecn_each_mark_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    ?assertEqual(ok, nquic_socket:set_egress_ecn(Socket, not_ect)),
    ?assertEqual(ok, nquic_socket:set_egress_ecn(Socket, ect0)),
    ?assertEqual(ok, nquic_socket:set_egress_ecn(Socket, ect1)),
    ?assertEqual(ok, nquic_socket:set_egress_ecn(Socket, ce)),
    socket:close(Socket).

set_gso_size_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    ?assertEqual(ok, nquic_socket:set_gso_size(Socket, 1200)),
    ?assertEqual(ok, nquic_socket:set_gso_size(Socket, 0)),
    socket:close(Socket).

set_gro_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    ?assertEqual(ok, nquic_socket:set_gro(Socket, true)),
    ?assertEqual(ok, nquic_socket:set_gro(Socket, false)),
    socket:close(Socket).

open_with_ecn_test() ->
    {ok, Socket} = nquic_socket:open(#{ecn => true}),
    socket:close(Socket).

open_with_gso_true_test() ->
    {ok, Socket} = nquic_socket:open(#{gso => true}),
    socket:close(Socket).

open_with_gso_int_test() ->
    {ok, Socket} = nquic_socket:open(#{gso => 800}),
    socket:close(Socket).

open_with_gso_invalid_test() ->
    {ok, Socket} = nquic_socket:open(#{gso => bogus}),
    socket:close(Socket).

open_with_gro_test() ->
    {ok, Socket} = nquic_socket:open(#{gro => true}),
    socket:close(Socket).

capabilities_returns_map_test() ->
    Caps = nquic_socket:capabilities(),
    ?assert(is_map(Caps)),
    ?assert(maps:is_key(gso, Caps)),
    ?assert(maps:is_key(gro, Caps)),
    ?assertEqual(Caps, nquic_socket:capabilities()).

open_connected_loopback_test() ->
    {ok, Listener} = nquic_socket:open(0, #{reuseport => true}),
    {ok, ListenerPort} = nquic_socket:port(Listener),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => 6999},
    case nquic_socket:open_connected(ListenerPort, Peer) of
        {ok, Conn} -> socket:close(Conn);
        {error, _} -> ok
    end,
    socket:close(Listener).

open_ephemeral_inet_test() ->
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => 6998},
    {ok, Socket} = nquic_socket:open_ephemeral(Peer, #{}),
    socket:close(Socket).

open_ephemeral_overrides_reuseport_test() ->
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => 6997},
    {ok, Socket} = nquic_socket:open_ephemeral(Peer, #{reuseport => true, reuseaddr => true}),
    socket:close(Socket).

determine_family_inet_test() ->
    {ok, Socket} = nquic_socket:open(0, #{ip => {127, 0, 0, 1}}),
    {ok, SockAddr} = nquic_socket:sockname(Socket),
    ?assertEqual(inet, maps:get(family, SockAddr)),
    socket:close(Socket).

recv_msg_now_select_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    ?assertMatch({select, _}, nquic_socket:recv_msg_now(Socket)),
    socket:close(Socket).

recv_msg_now_data_test() ->
    {ok, Recv} = nquic_socket:open(#{}),
    {ok, Send} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(Recv),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => RecvPort},
    ok = nquic_socket:send(Send, Peer, <<"data">>),
    timer:sleep(10),
    case nquic_socket:recv_msg_now(Recv) of
        {ok, {_Source, Data, _Ctrl}} ->
            ?assertEqual(<<"data">>, Data);
        {select, _} ->
            timer:sleep(50),
            {ok, {_Source, Data, _Ctrl}} = nquic_socket:recv_msg_now(Recv),
            ?assertEqual(<<"data">>, Data)
    end,
    socket:close(Recv),
    socket:close(Send).

recv_cancel_pending_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    {select, SelectInfo} = nquic_socket:recv_start(Socket),
    ?assertEqual(ok, nquic_socket:recv_cancel(Socket, SelectInfo)),
    socket:close(Socket).

recv_cancel_closed_socket_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    {select, SelectInfo} = nquic_socket:recv_start(Socket),
    socket:close(Socket),
    ?assertEqual(ok, nquic_socket:recv_cancel(Socket, SelectInfo)).

send_with_ecn_unconnected_test() ->
    {ok, Send} = nquic_socket:open(#{}),
    {ok, Recv} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(Recv),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => RecvPort},
    Result = nquic_socket:send_with_ecn(Send, Peer, <<"ecn">>, ect0),
    ?assert(Result =:= ok orelse element(1, Result) =:= error),
    socket:close(Send),
    socket:close(Recv).

send_connected_with_ecn_test() ->
    {ok, Send} = nquic_socket:open(#{}),
    {ok, Recv} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(Recv),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => RecvPort},
    ok = socket:connect(Send, Peer),
    Result = nquic_socket:send_connected_with_ecn(Send, <<"ecn">>, ect0),
    ?assert(Result =:= ok orelse element(1, Result) =:= error),
    socket:close(Send),
    socket:close(Recv).

send_connected_test() ->
    {ok, Send} = nquic_socket:open(#{}),
    {ok, Recv} = nquic_socket:open(#{}),
    {ok, RecvPort} = nquic_socket:port(Recv),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => RecvPort},
    ok = socket:connect(Send, Peer),
    ?assertEqual(ok, nquic_socket:send_connected(Send, <<"connected">>)),
    socket:close(Send),
    socket:close(Recv).

send_to_closed_socket_returns_error_test() ->
    {ok, Socket} = nquic_socket:open(#{}),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => 7000},
    socket:close(Socket),
    ?assertMatch({error, _}, nquic_socket:send(Socket, Peer, <<"x">>)).

%% Exercise the send / ECN / connected-socket / IPv6 / recv-cancel
%% paths deterministically over loopback.
send_recv_ecn_loopback_test() ->
    {ok, S1} = nquic_socket:open(#{}),
    {ok, S2} = nquic_socket:open(#{}),
    {ok, P2} = nquic_socket:port(S2),
    Dest = #{family => inet, addr => {127, 0, 0, 1}, port => P2},
    ?assertEqual(ok, nquic_socket:send(S1, Dest, <<"hello-udp">>)),
    ?assertEqual(ok, nquic_socket:set_egress_ecn(S1, ect0)),
    ?assertEqual(ok, nquic_socket:set_egress_ecn(S1, not_ect)),
    timer:sleep(20),
    case nquic_socket:recv_start(S2) of
        {ok, {_Src, <<"hello-udp">>}} ->
            ok;
        {select, SI} ->
            _ = nquic_socket:recv_cancel(S2, SI),
            ok;
        _ ->
            ok
    end,
    ?assertEqual(ok, nquic_socket:close(S1)),
    ?assertEqual(ok, nquic_socket:close(S2)).

open_connected_loopback_send_test() ->
    {ok, Srv} = nquic_socket:open(#{}),
    {ok, SrvPort} = nquic_socket:port(Srv),
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => SrvPort},
    {ok, C} = nquic_socket:open_connected(SrvPort, Peer),
    ?assertEqual(ok, nquic_socket:send_connected(C, <<"connected-udp">>)),
    ?assertMatch({ok, _}, nquic_socket:sockname(C)),
    ?assertEqual(ok, nquic_socket:close(C)),
    ?assertEqual(ok, nquic_socket:close(Srv)).

open_ipv6_family_test() ->
    case nquic_socket:open(#{family => inet6}) of
        {ok, S} ->
            ?assertMatch({ok, _}, nquic_socket:port(S)),
            ?assertEqual(ok, nquic_socket:close(S));
        {error, _} ->
            %% No IPv6 on the host: the inet6 family/bind branch still ran.
            ok
    end.

send_connected_unbound_errors_test() ->
    {ok, S} = nquic_socket:open(#{}),
    %% Not connect(2)-bound: send_connected must surface an error, not crash.
    ?assertMatch({error, _}, nquic_socket:send_connected(S, <<"x">>)),
    ?assertEqual(ok, nquic_socket:close(S)).
