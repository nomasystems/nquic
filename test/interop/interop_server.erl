-module(interop_server).
-moduledoc """
hq-interop server for QUIC interoperability testing.

Implements HTTP/0.9 over QUIC (hq-interop protocol) as used by the
quic-interop-runner. Accepts streams, parses GET /path requests,
and returns file contents with FIN.

Usage:
    rebar3 as interop shell
    > interop_server:start().
    > interop_server:start(443, "/www").
""".

-export([start/0, start/2]).
-spec start() -> no_return().
start() ->
    Port = list_to_integer(os:getenv("PORT", "443")),
    WwwDir = os:getenv("WWWDIR", default_www_dir()),
    start(Port, WwwDir).

-spec start(inet:port_number(), string()) -> no_return().
start(Port, WwwDir) ->
    io:format("Starting nquic hq-interop server...~n"),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(crypto),
    application:load(nquic),

    {ActualCert, ActualKey} = find_certs(),
    TestCase = os:getenv("TESTCASE", "handshake"),

    BaseOpts0 = #{
        tls => #{
            certfile => ActualCert,
            keyfile => ActualKey,
            alpn => [<<"hq-interop">>, <<"h3">>]
        }
    },
    Opts = apply_testcase_opts(TestCase, BaseOpts0),

    case nquic:listen(Port, Opts) of
        {ok, Listener} ->
            io:format("Listening on 0.0.0.0:~p (www: ~s)~n", [Port, WwwDir]),
            accept_loop(Listener, WwwDir);
        {error, Reason} ->
            io:format("Failed to listen: ~p~n", [Reason]),
            init:stop(1)
    end.

-spec apply_testcase_opts(string(), map()) -> map().
apply_testcase_opts("retry", Opts) ->
    Opts#{retry => true};
apply_testcase_opts("chacha20", Opts) ->
    Tls = maps:get(tls, Opts),
    Opts#{tls => Tls#{cipher_suites => [chacha20_poly1305]}};
apply_testcase_opts("zerortt", Opts) ->
    interop_replay:ensure_table(),
    Opts#{replay_protection => interop_replay};
apply_testcase_opts(_Other, Opts) ->
    Opts.

-spec find_certs() -> {string(), string()}.
find_certs() ->
    CertsDir = "/certs",
    CertFile = filename:join(CertsDir, "cert.pem"),
    KeyFile = filename:join(CertsDir, "priv.key"),

    case filelib:is_file(CertFile) of
        true ->
            {CertFile, KeyFile};
        false ->
            io:format("Warning: /certs not found, using test/conf certs~n"),
            {ok, Cwd} = file:get_cwd(),
            {
                filename:join([Cwd, "test", "conf", "server.pem"]),
                filename:join([Cwd, "test", "conf", "server.key"])
            }
    end.

-spec default_www_dir() -> string().
default_www_dir() ->
    case filelib:is_dir("/www") of
        true ->
            "/www";
        false ->
            {ok, Cwd} = file:get_cwd(),
            filename:join([Cwd, "test", "interop", "www"])
    end.

%% Standard acceptor-handoff: a fresh process blocks in the driver's
%% `accept/2' (which runs the production ctx + `nquic_lib'
%% owner loop) and signals the loop only once it owns a connection, so
%% the `#quic_ctx{}' owner is the per-connection process, never the
%% accept loop.
-spec accept_loop(nquic:listener(), string()) -> no_return().
accept_loop(Listener, WwwDir) ->
    Parent = self(),
    Ref = make_ref(),
    _ = spawn(fun() -> accept_one(Parent, Ref, Listener, WwwDir) end),
    receive
        {accepted, Ref} ->
            accept_loop(Listener, WwwDir);
        {accept_failed, Ref, closed} ->
            ok;
        {accept_failed, Ref, Reason} ->
            io:format("Accept error: ~p~n", [Reason]),
            accept_loop(Listener, WwwDir)
    end.

-spec accept_one(pid(), reference(), nquic:listener(), string()) -> ok.
accept_one(Parent, Ref, Listener, WwwDir) ->
    case nquic_ctx_driver:accept(Listener, #{}) of
        {ok, Drv} ->
            Parent ! {accepted, Ref},
            io:format("Accepted connection: ~p~n", [Drv]),
            handle_connection(Drv, WwwDir);
        {error, Reason} ->
            Parent ! {accept_failed, Ref, Reason},
            ok
    end.

-spec handle_connection(nquic_ctx_driver:driver(), string()) -> ok.
handle_connection(Drv, WwwDir) ->
    stream_accept_loop(Drv, WwwDir).

-spec stream_accept_loop(nquic_ctx_driver:driver(), string()) -> ok.
stream_accept_loop(Drv, WwwDir) ->
    case nquic_ctx_driver:accept_stream(Drv, 30000) of
        {ok, StreamId} ->
            spawn(fun() -> handle_stream(Drv, StreamId, WwwDir) end),
            stream_accept_loop(Drv, WwwDir);
        {error, timeout} ->
            io:format("No streams for 30s, closing connection~n"),
            nquic_ctx_driver:close(Drv),
            ok;
        {error, closed} ->
            ok;
        {error, draining} ->
            ok;
        {error, Reason} ->
            io:format("accept_stream error: ~p~n", [Reason]),
            ok
    end.

-spec handle_stream(nquic_ctx_driver:driver(), non_neg_integer(), string()) -> ok.
handle_stream(Drv, StreamId, WwwDir) ->
    io:format("Stream ~p: handler started, reading request...~n", [StreamId]),
    case recv_request(Drv, StreamId, <<>>, 5000) of
        {ok, Path} ->
            io:format("Stream ~p: GET ~s~n", [StreamId, Path]),
            serve_file(Drv, StreamId, WwwDir, Path);
        {error, Reason} ->
            io:format("Stream ~p: request error: ~p~n", [StreamId, Reason]),
            ok
    end.

-spec recv_request(nquic_ctx_driver:driver(), non_neg_integer(), binary(), timeout()) ->
    {ok, string()} | {error, term()}.
recv_request(Drv, StreamId, Acc, Timeout) ->
    case nquic_ctx_driver:recv(Drv, StreamId, Timeout) of
        {ok, Data, _Fin} ->
            Combined = <<Acc/binary, Data/binary>>,
            case binary:match(Combined, <<"\r\n">>) of
                {Pos, _} ->
                    Line = binary:part(Combined, 0, Pos),
                    parse_get_line(Line);
                nomatch ->
                    recv_request(Drv, StreamId, Combined, Timeout)
            end;
        {error, _} = Err ->
            case Acc of
                <<>> ->
                    Err;
                _ ->
                    parse_get_line(Acc)
            end
    end.

-spec parse_get_line(binary()) -> {ok, string()} | {error, bad_request}.
parse_get_line(<<"GET ", Rest/binary>>) ->
    Path = string:trim(binary_to_list(Rest)),
    {ok, Path};
parse_get_line(_) ->
    {error, bad_request}.

-spec serve_file(nquic_ctx_driver:driver(), non_neg_integer(), string(), string()) -> ok.
serve_file(Drv, StreamId, WwwDir, Path0) ->
    Path1 =
        case Path0 of
            "/" ++ Rest -> Rest;
            Other -> Other
        end,
    Path = lists:takewhile(fun(C) -> C =/= $? end, Path1),
    FullPath = filename:join(WwwDir, Path),

    case file:read_file(FullPath) of
        {ok, Contents} ->
            case nquic_ctx_driver:send_fin(Drv, StreamId, Contents) of
                ok ->
                    io:format(
                        "Stream ~p: served ~s (~p bytes)~n",
                        [StreamId, Path, byte_size(Contents)]
                    );
                {error, Reason} ->
                    io:format("Stream ~p: send error: ~p~n", [StreamId, Reason])
            end;
        {error, enoent} ->
            io:format("Stream ~p: file not found: ~s~n", [StreamId, FullPath]),
            case nquic_ctx_driver:send_fin(Drv, StreamId, <<"404 Not Found\r\n">>) of
                ok -> ok;
                {error, _} -> ok
            end;
        {error, Reason} ->
            io:format("Stream ~p: file read error: ~p~n", [StreamId, Reason]),
            ok
    end.
