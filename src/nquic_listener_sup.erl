-module(nquic_listener_sup).
-moduledoc """
Top-level listener supervisor.

`rest_for_one` over three children:

  1. `nquic_listener_mgr`: gen_server with the accept queue, parked
     acceptors, resolved port, static key, and a published reference to
     the listener's dispatch table.
  2. `nquic_partitions_sup`: `one_for_one` container holding the per-
     scheduler `nquic_server_sup` partitions. Each partition publishes
     its pid into the dispatch table on init.
  3. `nquic_receiver_sup`: `one_for_one` container of N
     `nquic_receiver` workers (sharing the listen port via SO_REUSEPORT
     when N > 1).

The dispatch ETS table is created here, owned by this supervisor process,
and lives for the lifetime of the listener. Children publish their own
pids into it on init; nothing else has to coordinate restart fan-out.

On `rest_for_one` the cascade is:

  - mgr crash -> mgr + partitions + receivers all restart;
    fresh dispatch slots are populated by each new child's init.
  - partitions crash -> partitions + receivers restart.
  - receiver_sup crash -> only receivers restart.

A single partition crashing is contained inside `nquic_partitions_sup`
(`one_for_one` there) and re-publishes its slot on its own restart.
""".
-behaviour(supervisor).

-export([preload_certs/1, start_link/1]).
-export([init/1]).

-spec init(map()) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}} | {stop, term()}.
init(Opts) ->
    case preload_certs(Opts) of
        {error, CertErr} ->
            {stop, {cert_error, CertErr}};
        {ok, CertOpts} ->
            Dispatch = nquic_dispatch:new(),
            FullOpts = maps:merge(Opts, CertOpts),
            SupFlags = #{
                strategy => rest_for_one,
                intensity => 5,
                period => 60
            },
            ChildSpecs = [
                #{
                    id => nquic_listener_mgr,
                    start =>
                        {nquic_listener_mgr, start_link, [
                            #{dispatch => Dispatch, opts => FullOpts}
                        ]},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [nquic_listener_mgr]
                },
                #{
                    id => nquic_partitions_sup,
                    start => {nquic_partitions_sup, start_link, [Dispatch]},
                    restart => permanent,
                    shutdown => infinity,
                    type => supervisor,
                    modules => [nquic_partitions_sup]
                },
                #{
                    id => nquic_receiver_sup,
                    start =>
                        {nquic_receiver_sup, start_link, [
                            #{dispatch => Dispatch, opts => FullOpts}
                        ]},
                    restart => permanent,
                    shutdown => infinity,
                    type => supervisor,
                    modules => [nquic_receiver_sup]
                }
            ],
            {ok, {SupFlags, ChildSpecs}}
    end.

-doc """
Read certificate / key / CA material from disk so the listener fails
fast on bad paths instead of crashing every connection at handshake
time. Exposed for the legacy `nquic_listener` shim and tests.
""".
-spec preload_certs(map()) -> {ok, map()} | {error, nquic_error:any_reason()}.
preload_certs(Opts) ->
    CertFile = maps:get(certfile, Opts, undefined),
    KeyFile = maps:get(keyfile, Opts, undefined),
    case CertFile of
        undefined ->
            {ok, #{}};
        _ ->
            maybe
                {ok, CBin} ?= read_file(certfile, CertFile),
                {ok, KBin} ?= read_file(keyfile, KeyFile),
                Entries = public_key:pem_decode(CBin),
                CertDERs = [DER || {_, DER, not_encrypted} <- Entries],
                true ?=
                    case CertDERs of
                        [] -> {error, {certfile, no_certificates}};
                        _ -> true
                    end,
                [KEntry | _] = public_key:pem_decode(KBin),
                PrivKey = public_key:pem_entry_decode(KEntry),
                [LeafDER | ChainDERs] = CertDERs,
                CACerts = load_ca_certs(Opts),
                {ok, #{
                    cert_der => LeafDER,
                    cert_chain => ChainDERs,
                    key_decoded => PrivKey,
                    cacerts => CACerts
                }}
            else
                {error, _} = Err -> Err
            end
    end.

-doc """
Start a listener supervision tree. The returned supervisor pid is the
public listener handle: `nquic_listener:accept/2`, `nquic:get_port/1`,
`nquic:metrics/1`, etc. all forward through to the manager child via
`supervisor:which_children/1`.
""".
-spec start_link(map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Opts) when is_map(Opts) ->
    supervisor:start_link(?MODULE, Opts).

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec load_ca_certs(map()) -> [binary()].
load_ca_certs(Opts) ->
    case maps:get(cacerts, Opts, undefined) of
        DERs when is_list(DERs) ->
            DERs;
        undefined ->
            case maps:get(cacertfile, Opts, undefined) of
                undefined ->
                    [];
                CAFile ->
                    case file:read_file(CAFile) of
                        {ok, Bin} ->
                            [DER || {_, DER, not_encrypted} <- public_key:pem_decode(Bin)];
                        {error, _} ->
                            []
                    end
            end
    end.

-spec read_file(atom(), file:filename() | undefined) ->
    {ok, binary()} | {error, nquic_error:any_reason()}.
read_file(Label, undefined) ->
    {error, {Label, missing}};
read_file(Label, Path) ->
    case file:read_file(Path) of
        {ok, _} = Ok -> Ok;
        {error, Reason} -> {error, {Label, Reason}}
    end.
