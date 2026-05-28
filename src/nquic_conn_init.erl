-module(nquic_conn_init).
-moduledoc """
Init-time option parsing and state seeding for the QUIC connection
state machine.

Pure helpers called once from `nquic_conn_statem:init/1` to derive
loss state, GSO size, qlog attachment, the active-connection-id-limit
bump, and the pacer option map from the user-supplied options map.
""".

-include("nquic_conn.hrl").
-include("nquic_transport.hrl").
-export([
    bump_acid_limit/2,
    gso_size/1,
    loss_state/1,
    new_conn_state/1,
    pacer_opts/1,
    qlog/2
]).

-spec bump_acid_limit(non_neg_integer(), boolean()) -> non_neg_integer().
bump_acid_limit(Limit, true) when
    Limit =:= (#transport_params{})#transport_params.active_connection_id_limit
->
    3;
bump_acid_limit(Limit, _) ->
    Limit.

-spec gso_size(map()) -> undefined | pos_integer().
gso_size(Opts) ->
    case maps:get(gso, Opts, false) of
        false -> undefined;
        true -> 1200;
        N when is_integer(N), N > 0 -> N;
        _ -> undefined
    end.

-spec loss_state(map()) -> nquic_loss:loss_state().
loss_state(Opts) ->
    LS0 = nquic_loss:init(
        maps:get(congestion_control, Opts, cubic),
        pacer_opts(Opts)
    ),
    case maps:get(max_payload_size, Opts, 1200) of
        N when is_integer(N), N > 1200 ->
            nquic_loss:set_max_datagram_size(LS0, N);
        _ ->
            LS0
    end.

-doc """
Build the initial `#conn_state{}` from a connection options map.
Role-generic (client or server). Pure: performs no side effects (no
dispatch registration, no metrics, no monitors beyond the owner monitor
the caller asks for via the `owner` opt). Shared by
`nquic_conn_statem:init/1` and the library-mode server handshake entry
`nquic_lib:server_accept_init/1`, so both seed identical state.
Generates a fresh SCID when one is not supplied; the caller registers
`SCID -> owning pid` in the dispatch table.
""".
-spec new_conn_state(map()) -> #conn_state{}.
new_conn_state(Opts) ->
    Role = maps:get(role, Opts),
    SCID = maps:get(scid, Opts, nquic_keys:generate_connection_id(8)),
    DCID = maps:get(dcid, Opts, <<>>),
    ODCID = maps:get(odcid, Opts, undefined),
    Socket = maps:get(socket, Opts, undefined),
    Peer = maps:get(peer, Opts, undefined),
    DispatchTable = maps:get(dispatch_table, Opts, undefined),
    Listener = maps:get(listener, Opts, undefined),
    ALPN = maps:get(alpn, Opts, undefined),
    Hostname = maps:get(hostname, Opts, undefined),
    StaticKey = maps:get(static_key, Opts, undefined),
    Version = maps:get(version, Opts, 1),

    {CertDER, CertChain, PrivKey} =
        case maps:get(cert_der, Opts, undefined) of
            undefined ->
                CertFile = maps:get(certfile, Opts, undefined),
                KeyFile = maps:get(keyfile, Opts, undefined),
                {Cert0, Key0} = nquic_protocol_handshake:load_certs(CertFile, KeyFile),
                {Cert0, [], Key0};
            PreloadedCert ->
                {PreloadedCert, maps:get(cert_chain, Opts, []), maps:get(key_decoded, Opts)}
        end,
    Verify = maps:get(verify, Opts, verify_none),
    CACerts = maps:get(cacerts, Opts, []),
    SessionTicket = maps:get(session_ticket, Opts, undefined),

    BaseParams = maps:get(transport_params, Opts, #transport_params{}),
    VersionInfo = #{
        chosen_version => Version,
        other_versions => nquic_packet:supported_versions()
    },
    MaxIdleTimeout = nquic_conn_timers:idle_timeout_to_param(
        maps:get(idle_timeout, Opts, BaseParams#transport_params.max_idle_timeout)
    ),
    AcidLimit = bump_acid_limit(
        BaseParams#transport_params.active_connection_id_limit,
        maps:get(server_per_conn_fd, Opts, false)
    ),
    LocalParams = BaseParams#transport_params{
        original_destination_connection_id = ODCID,
        initial_source_connection_id = SCID,
        version_information = VersionInfo,
        max_idle_timeout = MaxIdleTimeout,
        active_connection_id_limit = AcidLimit
    },

    LocalCids = #{0 => SCID},
    PeerCids =
        case DCID of
            <<>> -> #{};
            _ -> #{0 => #{cid => DCID, token => <<>>}}
        end,

    NextBidi =
        case Role of
            client -> 0;
            server -> 1
        end,
    NextUni =
        case Role of
            client -> 2;
            server -> 3
        end,
    Crypto = #conn_crypto{
        tls_state = undefined,
        alpn = ALPN,
        hostname = Hostname,
        cert = CertDER,
        cert_chain = CertChain,
        key = PrivKey,
        verify = Verify,
        cacerts = CACerts,
        static_key = StaticKey,
        session_ticket = SessionTicket,
        session_cache = maps:get(session_cache, Opts, false),
        token_cache = maps:get(token_cache, Opts, false),
        cipher_suites = maps:get(cipher_suites, Opts, undefined),
        replay_protection = maps:get(replay_protection, Opts, undefined)
    },
    Streams = #conn_streams{
        next_bidi_stream = NextBidi,
        next_uni_stream = NextUni,
        local_max_streams_bidi = LocalParams#transport_params.initial_max_streams_bidi,
        local_max_streams_uni = LocalParams#transport_params.initial_max_streams_uni,
        last_sent_max_streams_bidi = LocalParams#transport_params.initial_max_streams_bidi,
        last_sent_max_streams_uni = LocalParams#transport_params.initial_max_streams_uni,
        send_buffer_high_water = maps:get(send_buffer, Opts, 1048576),
        send_timeout = maps:get(send_timeout, Opts, infinity)
    },
    PathMgmt = #conn_path_mgmt{
        peer_cids = PeerCids,
        local_cids = LocalCids,
        local_cid_seq = 1,
        address_validated = (Role =:= client),
        path_state = nquic_path:new(Peer)
    },
    {InitOwner, InitOwnerMon} =
        case maps:get(owner, Opts, undefined) of
            undefined -> {undefined, undefined};
            Pid when is_pid(Pid) -> {Pid, monitor(process, Pid)}
        end,
    #conn_state{
        role = Role,
        scid = SCID,
        dcid = DCID,
        odcid = ODCID,
        retry_token = maps:get(client_token, Opts, <<>>),
        socket = Socket,
        peer = Peer,
        dispatch_table = DispatchTable,
        listener = Listener,
        loss_state = loss_state(Opts),
        gso_size = gso_size(Opts),
        max_payload_size = maps:get(max_payload_size, Opts, 1200),
        local_params = LocalParams,
        version = Version,
        version_preference = maps:get(version_preference, Opts, [1]),
        crypto = Crypto,
        streams_state = Streams,
        path = PathMgmt,
        owner = InitOwner,
        owner_mon = InitOwnerMon,
        server_per_conn_fd = maps:get(server_per_conn_fd, Opts, false),
        proactive_cids = maps:get(proactive_cids, Opts, false),
        spin_enabled = maps:get(spin_bit, Opts, false),
        new_token_enabled = maps:get(new_token, Opts, true),
        new_token_lifetime = maps:get(new_token_lifetime, Opts, 86400),
        qlog = qlog(DCID, Opts)
    }.

-spec pacer_opts(map()) -> map().
pacer_opts(Opts) ->
    M0 =
        case maps:get(pacing, Opts, undefined) of
            undefined -> #{};
            Bool when is_boolean(Bool) -> #{enabled => Bool}
        end,
    M1 =
        case maps:get(pacing_factor, Opts, undefined) of
            undefined -> M0;
            F when is_number(F), F > 0 -> M0#{factor => F}
        end,
    M2 =
        case maps:get(pacing_burst, Opts, undefined) of
            undefined -> M1;
            B when is_integer(B), B > 0 -> M1#{burst_packets => B}
        end,
    case maps:get(slow_start, Opts, undefined) of
        undefined -> M2;
        standard -> M2#{slow_start => standard};
        hystart_plus_plus -> M2#{slow_start => hystart_plus_plus}
    end.

-spec qlog(nquic:connection_id(), map()) -> undefined | nquic_qlog:qlog_state().
qlog(CID, Opts) ->
    case maps:get(qlog, Opts, undefined) of
        undefined ->
            undefined;
        Backend ->
            case nquic_qlog:attach(CID, Backend) of
                {ok, State} -> State;
                {error, _} -> undefined
            end
    end.
