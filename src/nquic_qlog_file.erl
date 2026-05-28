-module(nquic_qlog_file).

-moduledoc """
File backend for `nquic_qlog`. Writes draft-ietf-quic-qlog NDJSON
to a per-connection file.

First line is a JSON object describing the trace
(`qlog_format = "JSON-SEQ"`, schema version, connection ID, vantage
point). Each subsequent line is a single JSON event.

Path conventions: callers either pass an absolute path (file is
truncated and reopened) or a directory (a unique file is created
named after the connection's hex-encoded DCID).

This module deliberately uses raw, delayed-write `file` ports for
the steady-state event stream. Each event is one `io_lib` call and
one `file:write` (delayed by 256 KiB or 100 ms). Closing the file
flushes the buffer. The format is line-oriented so an interrupted
trace still loads in qvis.
""".

-behaviour(nquic_qlog).

-export([event/2, init/2, terminate/2]).

-define(SCHEMA_VERSION, <<"draft-12">>).

-record(state, {
    fd :: file:io_device(),
    path :: file:filename_all(),
    cid_hex :: binary(),
    start_us :: integer()
}).

%%%-----------------------------------------------------------------------------
%% NQUIC_QLOG CALLBACKS
%%%-----------------------------------------------------------------------------
-spec event(#state{}, {nquic_qlog:event_name(), nquic_qlog:event_data()}) -> {ok, #state{}}.
event(#state{fd = Fd, start_us = Start} = State, {Name, Data}) ->
    Now = erlang:system_time(microsecond),
    Time = Now - Start,
    _ = file:write(Fd, encode_event(Time, Name, Data)),
    {ok, State}.

-spec init(nquic:connection_id(), map()) -> {ok, #state{}} | {error, term()}.
init(CID, #{path := Path0}) ->
    CidHex = hex(CID),
    Path = resolve_path(Path0, CidHex),
    case file:open(Path, [write, raw, binary, delayed_write]) of
        {ok, Fd} ->
            StartUs = erlang:system_time(microsecond),
            _ = file:write(Fd, header(CidHex, StartUs)),
            {ok, #state{fd = Fd, path = Path, cid_hex = CidHex, start_us = StartUs}};
        {error, _} = Err ->
            Err
    end.

-spec terminate(#state{}, term()) -> ok.
terminate(#state{fd = Fd}, _Reason) ->
    _ = file:close(Fd),
    ok.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec encode_event(integer(), atom(), map()) -> iolist().
encode_event(Time, Name, Data) ->
    [
        <<"{\"time\":">>,
        integer_to_binary(Time),
        <<",\"name\":\"">>,
        atom_to_binary(Name, utf8),
        <<"\",\"data\":">>,
        render_map(Data),
        <<"}\n">>
    ].

-spec escape(binary()) -> binary().
escape(B) ->
    binary:replace(
        binary:replace(B, <<$\\>>, <<"\\\\">>, [global]),
        <<$">>,
        <<"\\\"">>,
        [global]
    ).

-spec header(binary(), integer()) -> iolist().
header(CidHex, StartUs) ->
    StartBin = integer_to_binary(StartUs),
    [
        <<"{\"qlog_format\":\"JSON-SEQ\",\"qlog_version\":\"">>,
        ?SCHEMA_VERSION,
        <<"\",\"trace\":{\"vantage_point\":{\"name\":\"nquic\"},">>,
        <<"\"common_fields\":{\"reference_time\":">>,
        StartBin,
        <<",\"time_units\":\"us\",\"ODCID\":\"">>,
        CidHex,
        <<"\"}}}\n">>
    ].

-spec hex(binary()) -> binary().
hex(B) ->
    binary:encode_hex(B, lowercase).

-spec render_map(map()) -> iolist() | binary().
render_map(M) when map_size(M) =:= 0 ->
    <<"{}">>;
render_map(M) ->
    Pairs = [render_pair(K, V) || {K, V} <- maps:to_list(M)],
    [<<"{">>, lists:join(<<",">>, Pairs), <<"}">>].

-spec render_pair(atom() | binary(), term()) -> iolist().
render_pair(K, V) when is_atom(K) ->
    render_pair(atom_to_binary(K, utf8), V);
render_pair(K, V) ->
    [<<$">>, K, <<"\":">>, render_value(V)].

-spec render_value(term()) -> iolist() | binary().
render_value(V) when is_atom(V) ->
    [<<$">>, atom_to_binary(V, utf8), <<$">>];
render_value(V) when is_integer(V) ->
    integer_to_binary(V);
render_value(V) when is_binary(V) ->
    [<<$">>, escape(V), <<$">>].

-spec resolve_path(file:filename_all(), binary()) -> file:filename_all() | atom().
resolve_path(Path, CidHex) ->
    case filelib:is_dir(Path) of
        true -> filename:join(Path, <<CidHex/binary, ".qlog">>);
        false -> Path
    end.
