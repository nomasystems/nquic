%%%-------------------------------------------------------------------
%%% End-to-end EUnit tests for {@link nquic_protocol_handshake}.
%%%
%%% Drives a full TLS 1.3 handshake between two `#conn_state{}` records
%%% by pumping CRYPTO bytes through the protocol-handshake API directly,
%%% with no `gen_statem`, no socket, and no packet/header protection.
%%% This is the unit-level safety net referenced by `LIBRARY_MODE_PLAN.md`
%%% §4.4 step 4 and the Stage 6 inline-handshake driver.
%%%-------------------------------------------------------------------
-module(nquic_protocol_handshake_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
basic_handshake_test_() ->
    {setup, fun setup_apps/0, fun cleanup_apps/1, fun(_) ->
        {Client, Server} = build_pair(verify_none),
        {ok, ClientEnd, ServerEnd, ClientEvents, ServerEvents} = run_handshake(
            Client, Server
        ),
        [
            ?_assertEqual([], pending_initial(ClientEnd)),
            ?_assertEqual([], pending_initial(ServerEnd)),
            ?_assert(lists:member(connected, ClientEvents)),
            ?_assert(lists:member({state_transition, established}, ClientEvents)),
            ?_assert(lists:member(connected, ServerEvents)),
            ?_assert(lists:member(listener_established, ServerEvents)),
            ?_assert(lists:member({state_transition, established}, ServerEvents)),
            ?_assertMatch(#conn_crypto{tls_state = undefined}, crypto_state(ClientEnd)),
            ?_assertMatch(#conn_crypto{tls_state = undefined}, crypto_state(ServerEnd)),
            ?_assert(address_validated(ClientEnd)),
            ?_assert(address_validated(ServerEnd))
        ]
    end}.

handshake_keys_match_test_() ->
    {setup, fun setup_apps/0, fun cleanup_apps/1, fun(_) ->
        {Client, Server} = build_pair(verify_none),
        {ok, ClientEnd, ServerEnd, _, _} = run_handshake(Client, Server),
        ClientKeys = (crypto_state(ClientEnd))#conn_crypto.keys,
        ServerKeys = (crypto_state(ServerEnd))#conn_crypto.keys,
        [
            ?_assert(maps:is_key(handshake, ClientKeys)),
            ?_assert(maps:is_key(handshake, ServerKeys)),
            ?_assert(maps:is_key(application, ClientKeys)),
            ?_assert(maps:is_key(application, ServerKeys)),
            ?_assert(maps:is_key(initial, ClientEnd#conn_state.pn_spaces)),
            ?_assert(maps:is_key(handshake, ClientEnd#conn_state.pn_spaces)),
            ?_assert(maps:is_key(application, ClientEnd#conn_state.pn_spaces)),
            ?_assert(maps:is_key(handshake, ServerEnd#conn_state.pn_spaces)),
            ?_assert(maps:is_key(application, ServerEnd#conn_state.pn_spaces))
        ]
    end}.

server_alpn_mismatch_returns_protocol_error_test_() ->
    {setup, fun setup_apps/0, fun cleanup_apps/1, fun(_) ->
        Client = build_client_with(<<"localhost">>, [<<"h3">>], verify_none),
        Server = build_server_with([<<"hq-interop">>]),
        {ok, Client1} = nquic_protocol_handshake:start_client_handshake(Client),
        ClientHello = drain_initial_data(Client1),
        Result = nquic_protocol_handshake:process_initial_crypto_server(ClientHello, Server),
        [
            ?_assertMatch({error, {transport_error, _}, _}, Result)
        ]
    end}.

idempotent_initial_crypto_client_test_() ->
    {setup, fun setup_apps/0, fun cleanup_apps/1, fun(_) ->
        {Client, Server} = build_pair(verify_none),
        {ok, Client1} = nquic_protocol_handshake:start_client_handshake(Client),
        ClientHello = drain_initial_data(Client1),
        {ok, _, Server1} = nquic_protocol_handshake:process_initial_crypto_server(
            ClientHello, Server
        ),
        ServerHello = drain_initial_data(Server1),
        {ok, _, Client2} = nquic_protocol_handshake:process_initial_crypto_client(
            ServerHello, Client1
        ),
        Crypto2 = crypto_state(Client2),
        {ok, EventsDup, Client3} = nquic_protocol_handshake:process_initial_crypto_client(
            ServerHello, Client2
        ),
        Crypto3 = crypto_state(Client3),
        [
            ?_assertEqual([], EventsDup),
            ?_assertEqual(Crypto2#conn_crypto.keys, Crypto3#conn_crypto.keys)
        ]
    end}.

run_handshake(Client0, Server0) ->
    {ok, Client1} = nquic_protocol_handshake:start_client_handshake(Client0),
    ClientHello = drain_initial_data(Client1),

    {ok, ServerEvents1, Server1} =
        nquic_protocol_handshake:process_initial_crypto_server(ClientHello, Server0),
    ServerHello = drain_initial_data(Server1),
    Flight = drain_handshake_data(Server1),
    Server2 = clear_pending_all(Server1),

    {ok, _ClientEv1, Client2} =
        nquic_protocol_handshake:process_initial_crypto_client(ServerHello, Client1),
    Client2a = clear_pending_initial(Client2),

    {ok, ClientEvents2, Client3} =
        nquic_protocol_handshake:process_handshake_crypto_client(Flight, Client2a),
    Finished = drain_handshake_data(Client3),
    Client4 = clear_pending_all(Client3),

    {ok, ServerEvents2, Server3} =
        nquic_protocol_handshake:process_handshake_crypto_server(Finished, Server2),

    {ok, Client4, Server3, ClientEvents2, ServerEvents1 ++ ServerEvents2}.

setup_apps() ->
    {ok, Started} = application:ensure_all_started([crypto, asn1, public_key, ssl]),
    ConfDir = test_conf_dir(),
    nquic_test_util:ensure_test_certs(ConfDir),
    #{started => Started, conf_dir => ConfDir}.

cleanup_apps(_) ->
    ok.

test_conf_dir() ->
    case filelib:is_dir("test/conf") of
        true ->
            "test/conf";
        false ->
            filename:join(code:lib_dir(nquic), "test/conf")
    end.

build_pair(Verify) ->
    {build_client_with(<<"localhost">>, [<<"h3">>], Verify), build_server_with([<<"h3">>])}.

build_client_with(Hostname, ALPN, Verify) ->
    DCID = nquic_keys:generate_connection_id(8),
    SCID = nquic_keys:generate_connection_id(8),
    LocalParams = #transport_params{
        original_destination_connection_id = undefined,
        initial_source_connection_id = SCID,
        version_information = #{
            chosen_version => 1,
            other_versions => nquic_packet:supported_versions()
        },
        max_idle_timeout = 30000,
        initial_max_data = 1_000_000,
        initial_max_stream_data_bidi_local = 65536,
        initial_max_stream_data_bidi_remote = 65536,
        initial_max_stream_data_uni = 65536,
        initial_max_streams_bidi = 100,
        initial_max_streams_uni = 100
    },
    Crypto = #conn_crypto{
        alpn = ALPN,
        hostname = Hostname,
        verify = Verify,
        cacerts = []
    },
    PathMgmt = #conn_path_mgmt{
        peer_cids = #{0 => #{cid => DCID, token => <<>>}},
        local_cids = #{0 => SCID},
        local_cid_seq = 1,
        address_validated = true,
        path_state = nquic_path:new(undefined)
    },
    #conn_state{
        role = client,
        scid = SCID,
        dcid = DCID,
        odcid = undefined,
        version = 1,
        loss_state = nquic_loss:init(cubic),
        local_params = LocalParams,
        crypto = Crypto,
        path = PathMgmt
    }.

build_server_with(ALPN) ->
    ConfDir = test_conf_dir(),
    CertFile = filename:join(ConfDir, "server.pem"),
    KeyFile = filename:join(ConfDir, "server.key"),
    {CertDER, PrivKey} = nquic_protocol_handshake:load_certs(CertFile, KeyFile),
    SCID = nquic_keys:generate_connection_id(8),
    LocalParams = #transport_params{
        original_destination_connection_id = <<>>,
        initial_source_connection_id = SCID,
        version_information = #{
            chosen_version => 1,
            other_versions => nquic_packet:supported_versions()
        },
        max_idle_timeout = 30000,
        initial_max_data = 1_000_000,
        initial_max_stream_data_bidi_local = 65536,
        initial_max_stream_data_bidi_remote = 65536,
        initial_max_stream_data_uni = 65536,
        initial_max_streams_bidi = 100,
        initial_max_streams_uni = 100
    },
    Crypto = #conn_crypto{
        alpn = ALPN,
        cert = CertDER,
        cert_chain = [],
        key = PrivKey,
        verify = verify_none,
        cacerts = []
    },
    PathMgmt = #conn_path_mgmt{
        local_cids = #{0 => SCID},
        local_cid_seq = 1,
        path_state = nquic_path:new(undefined)
    },
    #conn_state{
        role = server,
        scid = SCID,
        dcid = <<>>,
        odcid = <<>>,
        version = 1,
        loss_state = nquic_loss:init(cubic),
        local_params = LocalParams,
        crypto = Crypto,
        path = PathMgmt
    }.

drain_initial_data(State) ->
    iolist_to_binary([
        D
     || #crypto{data = D} <- pending_initial(State)
    ]).

drain_handshake_data(State) ->
    iolist_to_binary([
        D
     || #crypto{data = D} <- pending_handshake(State)
    ]).

pending_initial(#conn_state{flow = #conn_flow{pending_initial_frames = F}}) ->
    lists:reverse(F).

pending_handshake(#conn_state{flow = #conn_flow{pending_handshake_frames = F}}) ->
    lists:reverse(F).

clear_pending_initial(#conn_state{flow = Flow} = State) ->
    State#conn_state{flow = Flow#conn_flow{pending_initial_frames = []}}.

clear_pending_all(#conn_state{flow = Flow} = State) ->
    State#conn_state{
        flow = Flow#conn_flow{
            pending_initial_frames = [],
            pending_handshake_frames = [],
            pending_app_frames = []
        }
    }.

crypto_state(#conn_state{crypto = C}) -> C.

address_validated(#conn_state{path = #conn_path_mgmt{address_validated = V}}) -> V.
