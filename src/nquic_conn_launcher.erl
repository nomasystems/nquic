-module(nquic_conn_launcher).
-moduledoc """
Per-connection child launcher for the partition supervisor.

`nquic_server_sup` (the `simple_one_for_one` partition supervisor) has a
single, fixed child MFA. This launcher is that child: given the
per-connection option map it starts the right owner.

- Default (no `conn_handler`): `nquic_conn_statem`, the handshake
  `gen_statem` that exports the connection to a `nquic:accept/2` caller.
- With `conn_handler => Module`: `Module`, which owns the connection
  from the first packet and drives the handshake itself via
  `nquic_lib:server_accept_init/1` (owner-from-first-packet, no export,
  accept queue, or takeover). `Module` must export `start_link/1`
  taking the option map and returning `{ok, pid()}`; the returned pid is
  the connection owner the partition supervisor links to.

The launcher returns the started owner's pid directly, so the partition
supervisor links/monitors the owner, not the launcher. Children are
`temporary`, so the recorded launcher MFA is never re-invoked.
""".

-export([start_link/1]).

-spec start_link(map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Opts) ->
    case maps:get(conn_handler, Opts, undefined) of
        undefined ->
            nquic_conn_statem:start_link(Opts);
        Module when is_atom(Module) ->
            Module:start_link(Opts)
    end.
