-module(nquic_recv).
-moduledoc """
Optimized UDP receive handling for QUIC.

This module provides utilities for configuring socket buffers.
""".

-export([socket_options/0, socket_options/1]).

-define(DEFAULT_RECBUF, 2 * 1024 * 1024).
-define(DEFAULT_SNDBUF, 2 * 1024 * 1024).

-doc "Get default socket options for nquic_socket.".
-spec socket_options() -> nquic_socket:open_opts().
socket_options() ->
    socket_options(#{}).

-doc """
Get socket options for nquic_socket with custom configuration.
Options:
- recbuf: Receive buffer size (default: 2MB)
- sndbuf: Send buffer size (default: 2MB)
- reuseaddr: Reuse address (default: true)
Returns a map suitable for `nquic_socket:open/2`.
""".
-spec socket_options(map()) -> nquic_socket:open_opts().
socket_options(Opts) ->
    Base = #{
        recbuf => maps:get(recbuf, Opts, ?DEFAULT_RECBUF),
        sndbuf => maps:get(sndbuf, Opts, ?DEFAULT_SNDBUF),
        reuseaddr => maps:get(reuseaddr, Opts, true)
    },
    M1 =
        case maps:get(reuseport, Opts, false) of
            true -> Base#{reuseport => true};
            false -> Base
        end,
    M2 =
        case maps:get(ecn, Opts, false) of
            true -> M1#{ecn => true};
            false -> M1
        end,
    M3 =
        case maps:get(gso, Opts, false) of
            false -> M2;
            GSO -> M2#{gso => GSO}
        end,
    case maps:get(gro, Opts, false) of
        true -> M3#{gro => true};
        false -> M3
    end.
