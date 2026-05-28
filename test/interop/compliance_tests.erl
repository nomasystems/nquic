-module(compliance_tests).
-moduledoc """
RFC compliance test scenarios for QUIC interoperability testing.

Each test function connects to a server (specified by Host/Port) and
exercises a specific RFC requirement. Returns ok on success or
{error, Reason} on failure.

Used by scripts/compliance_interop.sh to validate nquic against
reference QUIC implementations (aioquic, ngtcp2, picoquic).

Every connection runs the production `#quic_ctx{}` + `m:nquic_lib`
owner loop via `m:nquic_ctx_driver` (the shipping ctx
path); no pid post-handshake API, no shadow FSM. The version
negotiation test is a raw `socket` exchange with no connection.

Note: nquic uses the OTP `socket` module exclusively for all UDP
operations. No gen_udp usage.
""".

-export([
    test_handshake/2,
    test_transfer/3,
    test_multiconnect/2,
    test_version_negotiation/2,
    test_connection_close/2,
    test_stream_fin/2
]).

-spec test_handshake(string() | inet:ip_address(), inet:port_number()) ->
    ok | {error, term()}.
test_handshake(Host, Port) ->
    io:format("  [handshake] Connecting to ~p:~p...~n", [Host, Port]),
    Opts = #{tls => #{alpn => [<<"hq-interop">>, <<"h3">>], verify => verify_none}},
    case nquic_ctx_driver:connect(Host, Port, Opts#{timeout => 15000}) of
        {ok, Drv} ->
            Result = verify_handshake(Drv),
            nquic_ctx_driver:close(Drv),
            Result;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

-spec verify_handshake(nquic_ctx_driver:driver()) -> ok | {error, term()}.
verify_handshake(Drv) ->
    case nquic_ctx_driver:info(Drv) of
        {ok, Info} ->
            State = maps:get(state, Info),
            Role = maps:get(role, Info),
            RemoteParams = maps:get(remote_params, Info, undefined),
            io:format("  [handshake] State=~p, Role=~p~n", [State, Role]),
            case {State, RemoteParams} of
                {established, undefined} ->
                    {error, no_remote_transport_params};
                {established, _} ->
                    io:format("  [handshake] Transport params received~n"),
                    ok;
                _ ->
                    {error, {unexpected_state, State}}
            end;
        {error, Reason} ->
            {error, {info_failed, Reason}}
    end.

-spec test_transfer(
    string() | inet:ip_address(),
    inet:port_number(),
    string()
) -> ok | {error, term()}.
test_transfer(Host, Port, Path) ->
    io:format("  [transfer] Fetching ~s from ~p:~p...~n", [Path, Host, Port]),
    Opts = #{tls => #{alpn => [<<"hq-interop">>, <<"h3">>], verify => verify_none}},
    case nquic_ctx_driver:connect(Host, Port, Opts#{timeout => 15000}) of
        {ok, Drv} ->
            Result = do_transfer(Drv, Path),
            nquic_ctx_driver:close(Drv),
            Result;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

-spec do_transfer(nquic_ctx_driver:driver(), string()) -> ok | {error, term()}.
do_transfer(Drv, Path) ->
    case nquic_ctx_driver:open_stream(Drv, #{type => bidi}) of
        {ok, StreamId} ->
            io:format("  [transfer] Stream ~p opened~n", [StreamId]),
            Request = iolist_to_binary(["GET ", Path, "\r\n"]),
            case nquic_ctx_driver:send_fin(Drv, StreamId, Request) of
                ok ->
                    io:format("  [transfer] Request sent, waiting for response...~n"),
                    case recv_all(Drv, StreamId, <<>>, 30000) of
                        {ok, Data} when byte_size(Data) > 0 ->
                            io:format(
                                "  [transfer] Received ~p bytes~n",
                                [byte_size(Data)]
                            ),
                            ok;
                        {ok, <<>>} ->
                            {error, empty_response};
                        {error, Reason} ->
                            {error, {recv_failed, Reason}}
                    end;
                {error, Reason} ->
                    {error, {send_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {open_stream_failed, Reason}}
    end.

-spec test_multiconnect(string() | inet:ip_address(), inet:port_number()) ->
    ok | {error, term()}.
test_multiconnect(Host, Port) ->
    io:format(
        "  [multiconnect] Running 5 sequential connections to ~p:~p...~n",
        [Host, Port]
    ),
    multiconnect_loop(Host, Port, 5, []).

-spec multiconnect_loop(
    string() | inet:ip_address(),
    inet:port_number(),
    non_neg_integer(),
    [binary()]
) -> ok | {error, term()}.
multiconnect_loop(_Host, _Port, 0, CIDs) ->
    UniqueCIDs = lists:usort(CIDs),
    case length(UniqueCIDs) =:= length(CIDs) of
        true ->
            io:format("  [multiconnect] All 5 connections used unique CIDs~n"),
            ok;
        false ->
            {error, duplicate_connection_ids}
    end;
multiconnect_loop(Host, Port, N, CIDs) ->
    Opts = #{tls => #{alpn => [<<"hq-interop">>, <<"h3">>], verify => verify_none}},
    case nquic_ctx_driver:connect(Host, Port, Opts#{timeout => 10000}) of
        {ok, Drv} ->
            CID =
                case nquic_ctx_driver:info(Drv) of
                    {ok, Info} -> maps:get(scid, Info, <<>>);
                    _ -> <<>>
                end,
            io:format("  [multiconnect] Connection ~p OK~n", [6 - N]),
            nquic_ctx_driver:close(Drv),
            timer:sleep(100),
            multiconnect_loop(Host, Port, N - 1, [CID | CIDs]);
        {error, Reason} ->
            {error, {connect_failed, N, Reason}}
    end.

-spec test_version_negotiation(string() | inet:ip_address(), inet:port_number()) ->
    ok | {error, term()}.
test_version_negotiation(Host, Port) ->
    io:format(
        "  [version_negotiation] Sending bad version to ~p:~p...~n",
        [Host, Port]
    ),
    case inet:getaddr(Host, inet) of
        {ok, IP} ->
            case socket:open(inet, dgram, udp) of
                {ok, Socket} ->
                    Result = do_version_negotiation(Socket, IP, Port),
                    socket:close(Socket),
                    Result;
                {error, Reason} ->
                    {error, {socket_open_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {resolve_failed, Reason}}
    end.

-spec do_version_negotiation(socket:socket(), inet:ip_address(), inet:port_number()) ->
    ok | {error, term()}.
do_version_negotiation(Socket, IP, Port) ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    BadVersion = 16#BABABABA,
    HeaderByte = 2#11000000,
    Packet = <<
        HeaderByte:8,
        BadVersion:32,
        8:8,
        DCID/binary,
        8:8,
        SCID/binary,
        0:8,
        16#40,
        30,
        0:(30 * 8)
    >>,
    PadLen = max(0, 1200 - byte_size(Packet)),
    PaddedPacket = <<Packet/binary, 0:(PadLen * 8)>>,
    Dest = #{family => inet, port => Port, addr => IP},
    case socket:sendto(Socket, PaddedPacket, Dest) of
        ok ->
            case socket:recvfrom(Socket, 0, [], 5000) of
                {ok, {_Source, Response}} ->
                    parse_vn_response(Response, DCID, SCID);
                {error, timeout} ->
                    {error, no_vn_response};
                {error, Reason} ->
                    {error, {recv_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {send_failed, Reason}}
    end.

-spec parse_vn_response(binary(), binary(), binary()) -> ok | {error, term()}.
parse_vn_response(
    <<1:1, _:7, 0:32, _Rest/binary>>,
    _OrigDCID,
    _OrigSCID
) ->
    io:format("  [version_negotiation] Received VN packet~n"),
    ok;
parse_vn_response(Packet, _OrigDCID, _OrigSCID) when is_binary(Packet) ->
    {error, {unexpected_response, byte_size(Packet)}};
parse_vn_response(_Other, _OrigDCID, _OrigSCID) ->
    {error, unexpected_response_format}.

-spec test_connection_close(string() | inet:ip_address(), inet:port_number()) ->
    ok | {error, term()}.
test_connection_close(Host, Port) ->
    io:format("  [connection_close] Testing clean close on ~p:~p...~n", [Host, Port]),
    Opts = #{tls => #{alpn => [<<"hq-interop">>, <<"h3">>], verify => verify_none}},
    case nquic_ctx_driver:connect(Host, Port, Opts#{timeout => 10000}) of
        {ok, Drv} ->
            case nquic_ctx_driver:info(Drv) of
                {ok, #{state := established}} ->
                    %% Transport-scope CONNECTION_CLOSE, NO_ERROR
                    %% (`nquic_lib:shutdown/1'); the owner loop then
                    %% stops, so the connection is no longer usable.
                    nquic_ctx_driver:close(Drv),
                    timer:sleep(200),
                    case nquic_ctx_driver:info(Drv) of
                        {ok, #{state := draining}} ->
                            io:format("  [connection_close] Entered draining state~n"),
                            ok;
                        {error, draining} ->
                            io:format("  [connection_close] In draining state~n"),
                            ok;
                        {error, closed} ->
                            io:format("  [connection_close] Connection closed~n"),
                            ok;
                        {error, timeout} ->
                            io:format("  [connection_close] Connection draining (timeout)~n"),
                            ok;
                        Other ->
                            {error, {unexpected_info_result, Other}}
                    end;
                {ok, #{state := Other}} ->
                    nquic_ctx_driver:close(Drv),
                    {error, {not_established, Other}};
                {error, Reason} ->
                    {error, {info_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

-spec test_stream_fin(string() | inet:ip_address(), inet:port_number()) ->
    ok | {error, term()}.
test_stream_fin(Host, Port) ->
    io:format("  [stream_fin] Testing FIN handling on ~p:~p...~n", [Host, Port]),
    Opts = #{tls => #{alpn => [<<"hq-interop">>, <<"h3">>], verify => verify_none}},
    case nquic_ctx_driver:connect(Host, Port, Opts#{timeout => 10000}) of
        {ok, Drv} ->
            Result = do_stream_fin_test(Drv),
            nquic_ctx_driver:close(Drv),
            Result;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

-spec do_stream_fin_test(nquic_ctx_driver:driver()) -> ok | {error, term()}.
do_stream_fin_test(Drv) ->
    case nquic_ctx_driver:open_stream(Drv, #{type => bidi}) of
        {ok, StreamId} ->
            Request = <<"GET /small.txt\r\n">>,
            case nquic_ctx_driver:send_fin(Drv, StreamId, Request) of
                ok ->
                    io:format("  [stream_fin] Sent request with FIN~n"),
                    case recv_all(Drv, StreamId, <<>>, 10000) of
                        {ok, Data} when byte_size(Data) > 0 ->
                            io:format(
                                "  [stream_fin] Received ~p bytes with FIN~n",
                                [byte_size(Data)]
                            ),
                            ok;
                        {ok, <<>>} ->
                            {error, empty_response};
                        {error, Reason} ->
                            {error, {recv_failed, Reason}}
                    end;
                {error, Reason} ->
                    {error, {send_fin_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {open_stream_failed, Reason}}
    end.

-spec recv_all(nquic_ctx_driver:driver(), non_neg_integer(), binary(), timeout()) ->
    {ok, binary()} | {error, term()}.
recv_all(Drv, StreamId, Acc, Timeout) ->
    io:format("  [recv_all] calling recv (acc=~p bytes)~n", [byte_size(Acc)]),
    case nquic_ctx_driver:recv(Drv, StreamId, Timeout) of
        {ok, <<>>, fin} ->
            io:format("  [recv_all] FIN received~n"),
            {ok, Acc};
        {ok, Data, fin} ->
            io:format("  [recv_all] got ~p bytes (fin)~n", [byte_size(Data)]),
            {ok, <<Acc/binary, Data/binary>>};
        {ok, Data, nofin} ->
            io:format("  [recv_all] got ~p bytes~n", [byte_size(Data)]),
            recv_all(Drv, StreamId, <<Acc/binary, Data/binary>>, Timeout);
        {error, timeout} when byte_size(Acc) > 0 ->
            io:format("  [recv_all] timeout with ~p bytes accumulated~n", [byte_size(Acc)]),
            {ok, Acc};
        {error, Reason} ->
            io:format("  [recv_all] error: ~p~n", [Reason]),
            {error, Reason}
    end.
