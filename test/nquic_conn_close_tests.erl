%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_conn_close} edge paths not exercised
%%% by the integration / state-machine suites.
%%%-------------------------------------------------------------------
-module(nquic_conn_close_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
cleanup_dispatch_no_table_test() ->
    Data = #conn_state{dispatch_table = undefined},
    ?assertEqual(ok, nquic_conn_close:cleanup_dispatch(Data)).

cleanup_dispatch_odcid_undefined_test() ->
    Dispatch = nquic_dispatch:new(2),
    Data = #conn_state{
        dispatch_table = Dispatch,
        path = #conn_path_mgmt{local_cids = #{}},
        odcid = undefined
    },
    ?assertEqual(ok, nquic_conn_close:cleanup_dispatch(Data)).

cleanup_dispatch_odcid_empty_test() ->
    Dispatch = nquic_dispatch:new(2),
    Data = #conn_state{
        dispatch_table = Dispatch,
        path = #conn_path_mgmt{local_cids = #{}},
        odcid = <<>>
    },
    ?assertEqual(ok, nquic_conn_close:cleanup_dispatch(Data)).

cleanup_dispatch_odcid_registered_test() ->
    Dispatch = nquic_dispatch:new(2),
    ODCID = <<1, 2, 3, 4>>,
    true = nquic_listener:dispatch_register(Dispatch, ODCID, self()),
    Data = #conn_state{
        dispatch_table = Dispatch,
        path = #conn_path_mgmt{local_cids = #{}},
        odcid = ODCID
    },
    ?assertEqual(ok, nquic_conn_close:cleanup_dispatch(Data)).

close_owned_socket_client_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Data = #conn_state{role = client, socket = Socket},
    ?assertEqual(ok, nquic_conn_close:close_owned_socket(Data)).

close_owned_socket_server_connected_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Data = #conn_state{role = server, socket = Socket, socket_connected = true},
    ?assertEqual(ok, nquic_conn_close:close_owned_socket(Data)).

close_owned_socket_server_shared_test() ->
    {ok, Socket} = nquic_socket:open(0, #{}),
    Data = #conn_state{role = server, socket = Socket, socket_connected = false},
    ?assertEqual(ok, nquic_conn_close:close_owned_socket(Data)),
    ok = nquic_socket:close(Socket).

send_connection_close_no_socket_test() ->
    Data = #conn_state{
        socket = undefined,
        crypto = #conn_crypto{keys = #{}},
        loss_state = nquic_loss:init()
    },
    ?assertEqual(
        ok,
        nquic_conn_close:send_connection_close(
            Data, {transport_error, internal_error}, initial
        )
    ).

enter_draining_idle_timeout_test() ->
    Data = base_draining_data(),
    {next_state, draining, _Data1, _Actions} =
        nquic_conn_close:enter_draining(
            handshake, {transport_error, idle_timeout}, Data
        ).

enter_draining_other_error_test() ->
    Data = base_draining_data(),
    {next_state, draining, _Data1, _Actions} =
        nquic_conn_close:enter_draining(
            handshake, {transport_error, frame_encoding_error}, Data
        ).

send_close_frame_established_test() ->
    Frame = #connection_close{error_code = 0, frame_type = 0, reason_phrase = <<>>},
    Data = (base_draining_data())#conn_state{
        crypto = #conn_crypto{keys = #{}, cipher = aes_128_gcm}
    },
    ?assertEqual(
        ok, nquic_conn_close:send_close_frame(Frame, Data, established)
    ).

send_close_frame_draining_test() ->
    Frame = #connection_close{error_code = 0, frame_type = 0, reason_phrase = <<>>},
    Data = base_draining_data(),
    ?assertEqual(
        ok, nquic_conn_close:send_close_frame(Frame, Data, draining)
    ).

send_close_frame_handshake_no_handshake_keys_test() ->
    Frame = #connection_close{error_code = 0, frame_type = 0, reason_phrase = <<>>},
    Data = (base_draining_data())#conn_state{
        crypto = #conn_crypto{keys = #{}, cipher = aes_128_gcm}
    },
    ?assertEqual(
        ok, nquic_conn_close:send_close_frame(Frame, Data, handshake)
    ).

send_close_frame_handshake_with_handshake_keys_test() ->
    Frame = #connection_close{error_code = 0, frame_type = 0, reason_phrase = <<>>},
    Data = (base_draining_data())#conn_state{
        crypto = #conn_crypto{
            keys = #{handshake => fake_keys()}, cipher = aes_128_gcm
        }
    },
    ?assertEqual(
        ok, nquic_conn_close:send_close_frame(Frame, Data, handshake)
    ).

send_close_frame_initial_test() ->
    Frame = #connection_close{error_code = 0, frame_type = 0, reason_phrase = <<>>},
    Data = (base_draining_data())#conn_state{
        crypto = #conn_crypto{keys = #{}, cipher = aes_128_gcm}
    },
    ?assertEqual(
        ok, nquic_conn_close:send_close_frame(Frame, Data, initial)
    ).

send_close_frame_unknown_state_test() ->
    Frame = #connection_close{error_code = 0, frame_type = 0, reason_phrase = <<>>},
    Data = (base_draining_data())#conn_state{
        crypto = #conn_crypto{keys = #{}, cipher = aes_128_gcm}
    },
    ?assertEqual(
        ok, nquic_conn_close:send_close_frame(Frame, Data, mystery_state)
    ).

base_draining_data() ->
    #conn_state{
        role = client,
        socket = undefined,
        peer = undefined,
        crypto = #conn_crypto{keys = #{}, cipher = aes_128_gcm},
        loss_state = nquic_loss:init(),
        streams_state = #conn_streams{},
        path = #conn_path_mgmt{path_state = nquic_path:new(undefined)},
        flow = #conn_flow{},
        local_params = #transport_params{},
        pn_spaces = #{},
        app_next_pn = 0,
        version = 1
    }.

fake_keys() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    HP = crypto:strong_rand_bytes(16),
    Role = nquic_keys:make_role_keys(aes_128_gcm, Key, IV, HP),
    #{client => Role, server => Role}.
