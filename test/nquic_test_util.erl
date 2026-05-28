-module(nquic_test_util).

-export([
    ensure_test_certs/1,
    ensure_test_fixture/2
]).

-spec ensure_test_certs(file:filename()) -> ok.
ensure_test_certs(ConfDir) ->
    Cert = filename:join(ConfDir, "server.pem"),
    Key = filename:join(ConfDir, "server.key"),
    case {filelib:is_regular(Cert), filelib:is_regular(Key)} of
        {true, true} ->
            ok;
        _ ->
            Script = filename:join(ConfDir, "generate_certs.sh"),
            case filelib:is_regular(Script) of
                true ->
                    Cmd = io_lib:format("bash ~ts ~ts", [Script, ConfDir]),
                    _ = os:cmd(lists:flatten(Cmd)),
                    true = filelib:is_regular(Cert),
                    true = filelib:is_regular(Key),
                    ok;
                false ->
                    erlang:error({missing_generate_certs, Script})
            end
    end.

-spec ensure_test_fixture(file:filename(), non_neg_integer()) -> ok.
ensure_test_fixture(Path, Size) when is_integer(Size), Size >= 0 ->
    case filelib:is_regular(Path) of
        true ->
            case filelib:file_size(Path) of
                Size -> ok;
                _ -> write_fixture(Path, Size)
            end;
        false ->
            ok = filelib:ensure_dir(Path),
            write_fixture(Path, Size)
    end.

write_fixture(Path, Size) ->
    {ok, Fd} = file:open(Path, [write, binary, raw]),
    try
        write_chunks(Fd, Size)
    after
        _ = file:close(Fd)
    end.

write_chunks(_Fd, 0) ->
    ok;
write_chunks(Fd, Remaining) ->
    Chunk = min(Remaining, 65_536),
    ok = file:write(Fd, <<0:(Chunk * 8)>>),
    write_chunks(Fd, Remaining - Chunk).
