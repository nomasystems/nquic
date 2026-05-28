-module(nquic_conn).
-moduledoc """
QUIC Connection Management API.

This module provides functions to query connection state, statistics,
and to close connections. Use `nquic` for establishing connections
and stream operations.

## Connection Information

The `info/1` function returns a map containing:

- `state` - Connection state (initial, handshake, established)
- `role` - client or server
- `scid` - Source connection ID
- `dcid` - Destination connection ID
- `rtt` - RTT statistics (smoothed, variance, min, latest)
- `cwnd` - Congestion window size in bytes
- `bytes_in_flight` - Unacknowledged bytes
- `streams_open` - Number of active streams
""".

-include("nquic_transport.hrl").
-export([
    close/1,
    close/3,
    info/1,
    path_stats/1,
    peercert/1,
    peername/1,
    sockname/1,
    streams/1
]).
-export([migrate/2]).

-export_type([conn_info/0]).

-type conn_info() :: #{
    state := atom(),
    role := client | server,
    scid := nquic:connection_id(),
    dcid := nquic:connection_id(),
    rtt := #{
        smoothed := non_neg_integer(),
        variance := non_neg_integer(),
        min := non_neg_integer(),
        latest := non_neg_integer()
    },
    cwnd := non_neg_integer(),
    bytes_in_flight := non_neg_integer(),
    streams_open := non_neg_integer(),
    local_params := #transport_params{},
    remote_params := #transport_params{} | undefined
}.

-doc "Close the connection gracefully with no error.".
-spec close(pid()) -> ok.
close(Conn) ->
    close(Conn, 0, <<>>).

-doc """
Close the connection with an error code and reason.
Sends a CONNECTION_CLOSE frame with the specified error code and
reason phrase, then terminates the connection.
Common error codes (RFC 9000 Section 20):
- `0` - NO_ERROR (graceful close)
- `1` - INTERNAL_ERROR
- `2` - CONNECTION_REFUSED
- `3` - FLOW_CONTROL_ERROR
- `10` - APPLICATION_ERROR (generic application error)
""".
-spec close(pid(), non_neg_integer(), binary()) -> ok.
close(Conn, ErrorCode, ReasonPhrase) ->
    case nquic_conn_statem:close(Conn, ErrorCode, ReasonPhrase) of
        ok -> ok;
        {error, closed} -> ok;
        {error, {opts, draining}} -> ok;
        {error, {timeout, _}} -> ok
    end.

-doc """
Get connection information and statistics.
Returns detailed information about the connection including RTT
measurements, congestion control state, and transport parameters.
""".
-spec info(pid()) -> {ok, conn_info()} | {error, nquic_error:any_reason()}.
info(Conn) ->
    nquic_conn_statem:info(Conn).

-doc """
Migrate the connection to a new local address (RFC 9000 Section 9).
Initiates active connection migration by rebinding the client socket to the
new local address and sending a PATH_CHALLENGE to validate the new path.
Returns `{error, migration_disabled}` if the peer set `disable_active_migration`.
Only works in the established state.
""".
-spec migrate(pid(), nquic_socket:sockaddr()) -> ok | {error, nquic_error:any_reason()}.
migrate(Conn, NewLocalAddr) ->
    nquic_conn_statem:migrate(Conn, NewLocalAddr).

-doc """
Get path-level statistics for the connection.
Returns a flat map suitable for routing decisions (`srtt_us`, `cwnd`,
`bytes_in_flight`, `ssthresh`, ...) and for operational dashboards
(lifetime `packets_sent`, `packets_lost`, `packets_acked`, ECN
counters, `pto_count`).
Reads cached state inside the gen_statem; no protocol I/O.
""".
-spec path_stats(pid()) -> {ok, nquic_loss:path_stats()} | {error, nquic_error:any_reason()}.
path_stats(Conn) ->
    nquic_conn_statem:path_stats(Conn).

-doc "Get the peer's TLS certificate in DER format.".
-spec peercert(pid()) -> {ok, binary()} | {error, no_peercert | closed | timeout}.
peercert(Conn) ->
    nquic_conn_statem:peercert(Conn).

-doc "Get the peer's address and port.".
-spec peername(pid()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, nquic_error:any_reason()}.
peername(Conn) ->
    nquic_conn_statem:peername(Conn).

-doc "Get the local address and port.".
-spec sockname(pid()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, nquic_error:any_reason()}.
sockname(Conn) ->
    nquic_conn_statem:sockname(Conn).

-doc "List active stream IDs on the connection.".
-spec streams(pid()) -> {ok, [nquic:stream_id()]} | {error, nquic_error:any_reason()}.
streams(Conn) ->
    nquic_conn_statem:streams(Conn).
