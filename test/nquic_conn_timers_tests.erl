%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_conn_timers}.
%%%-------------------------------------------------------------------
-module(nquic_conn_timers_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
idle_timeout_to_param_infinity_test() ->
    ?assertEqual(0, nquic_conn_timers:idle_timeout_to_param(infinity)).

idle_timeout_to_param_integer_test() ->
    ?assertEqual(30000, nquic_conn_timers:idle_timeout_to_param(30000)).

idle_timeout_to_param_zero_test() ->
    ?assertEqual(0, nquic_conn_timers:idle_timeout_to_param(0)).

set_idle_timer_no_remote_disabled_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 0},
        remote_params = undefined
    },
    ?assertEqual([], nquic_conn_timers:set_idle_timer(Data)).

set_idle_timer_local_only_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 30000},
        remote_params = undefined
    },
    [{{timeout, idle_timeout}, Timeout, idle_fire}] =
        nquic_conn_timers:set_idle_timer(Data),
    ?assertEqual(30000, Timeout).

set_idle_timer_min_of_local_remote_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 30000},
        remote_params = #transport_params{max_idle_timeout = 10000}
    },
    [{{timeout, idle_timeout}, 10000, idle_fire}] =
        nquic_conn_timers:set_idle_timer(Data).

set_pto_timer_no_ack_eliciting_in_flight_test() ->
    Data = #conn_state{loss_state = nquic_loss:init(), remote_params = undefined},
    ?assertEqual(
        [{{timeout, pto_timeout}, infinity, undefined}],
        nquic_conn_timers:set_pto_timer(Data)
    ).

set_pto_timer_with_remote_max_ack_delay_test() ->
    LossState0 = nquic_loss:init(),
    PingFrame = #ping{},
    LossState1 = nquic_loss:on_packet_sent(
        LossState0, application, 0, [PingFrame], 0, 100
    ),
    Data = #conn_state{
        loss_state = LossState1,
        remote_params = #transport_params{max_ack_delay = 25}
    },
    [{{timeout, pto_timeout}, PtoMs, pto_fire}] =
        nquic_conn_timers:set_pto_timer(Data),
    ?assert(PtoMs >= 1).

timer_actions_to_statem_empty_test() ->
    ?assertEqual([], nquic_conn_timers:timer_actions_to_statem([])).

timer_actions_to_statem_set_idle_test() ->
    [{{timeout, idle_timeout}, 100, idle_fire}] =
        nquic_conn_timers:timer_actions_to_statem([{set_timer, idle, 100}]).

timer_actions_to_statem_set_pto_test() ->
    [{{timeout, pto_timeout}, 50, pto_fire}] =
        nquic_conn_timers:timer_actions_to_statem([{set_timer, pto, 50}]).

timer_actions_to_statem_set_path_validation_test() ->
    [{{timeout, path_validation}, 200, path_validation_fire}] =
        nquic_conn_timers:timer_actions_to_statem([{set_timer, path_validation, 200}]).

timer_actions_to_statem_set_ack_delay_test() ->
    [{{timeout, ack_delay}, 25, ack_delay_fire}] =
        nquic_conn_timers:timer_actions_to_statem([{set_timer, ack_delay, 25}]).

timer_actions_to_statem_cancel_pto_test() ->
    [{{timeout, pto_timeout}, infinity, undefined}] =
        nquic_conn_timers:timer_actions_to_statem([{cancel_timer, pto}]).

timer_actions_to_statem_multiple_test() ->
    Actions = nquic_conn_timers:timer_actions_to_statem([
        {set_timer, idle, 1},
        {set_timer, pto, 2}
    ]),
    ?assertEqual(2, length(Actions)).

ensure_handshake_timers_keep_state_no_actions_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 0},
        remote_params = undefined,
        loss_state = nquic_loss:init()
    },
    Result = nquic_conn_timers:ensure_handshake_timers({keep_state, Data}),
    ?assertMatch({keep_state, Data, _}, Result),
    {keep_state, _, Actions} = Result,
    ?assert(is_list(Actions)),
    ?assert(length(Actions) >= 1).

ensure_handshake_timers_keep_state_with_actions_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 0},
        remote_params = undefined,
        loss_state = nquic_loss:init()
    },
    Pre = [{some, action}],
    {keep_state, _, Actions} =
        nquic_conn_timers:ensure_handshake_timers({keep_state, Data, Pre}),
    ?assertEqual({some, action}, hd(Actions)).

ensure_handshake_timers_next_state_test() ->
    Data = #conn_state{
        local_params = #transport_params{max_idle_timeout = 0},
        remote_params = undefined,
        loss_state = nquic_loss:init()
    },
    Result = nquic_conn_timers:ensure_handshake_timers(
        {next_state, handshake, Data, [{some, action}]}
    ),
    ?assertMatch({next_state, handshake, Data, _}, Result).

ensure_handshake_timers_stop_passes_through_test() ->
    Stop = {stop, normal, #conn_state{}},
    ?assertEqual(Stop, nquic_conn_timers:ensure_handshake_timers(Stop)).

handle_pto_initial_no_keys_test() ->
    Data = make_handshake_data(server, #{}),
    Result = nquic_conn_timers:handle_pto(initial, Data),
    ?assertMatch({keep_state, _Data1, _Actions}, Result),
    {keep_state, Data1, Actions} = Result,
    ?assertEqual(
        [], (Data1#conn_state.flow)#conn_flow.pending_initial_frames
    ),
    ?assert(is_list(Actions)).

handle_pto_initial_with_keys_test() ->
    InitialKeys = derive_initial_keys(),
    Data = make_handshake_data(server, #{initial => InitialKeys}),
    Result = nquic_conn_timers:handle_pto(initial, Data),
    ?assertMatch({keep_state, _Data1, _Actions}, Result),
    {keep_state, Data1, _Actions} = Result,
    ?assertEqual(
        [], (Data1#conn_state.flow)#conn_flow.pending_initial_frames
    ).

handle_pto_handshake_test() ->
    Data = make_handshake_data(server, #{}),
    Result = nquic_conn_timers:handle_pto(handshake, Data),
    ?assertMatch({keep_state, _Data1, _Actions}, Result),
    {keep_state, Data1, _Actions} = Result,
    ?assertEqual(
        [], (Data1#conn_state.flow)#conn_flow.pending_handshake_frames
    ).

derive_initial_keys() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DCID, 1),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientSecret, aes_128_gcm, 1),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerSecret, aes_128_gcm, 1),
    #{
        client => nquic_keys:make_role_keys(aes_128_gcm, CKey, CIV, CHP),
        server => nquic_keys:make_role_keys(aes_128_gcm, SKey, SIV, SHP)
    }.

make_handshake_data(Role, Keys) ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<9, 10, 11, 12, 13, 14, 15, 16>>,
    Crypto = #conn_crypto{keys = Keys, cipher = aes_128_gcm},
    #conn_state{
        role = Role,
        scid = SCID,
        dcid = DCID,
        crypto = Crypto,
        pn_spaces = #{
            initial => #{next_pn => 0},
            handshake => #{next_pn => 0},
            application => #{next_pn => 0}
        },
        loss_state = nquic_loss:init(),
        local_params = #transport_params{max_idle_timeout = 0},
        remote_params = undefined,
        flow = #conn_flow{},
        path = #conn_path_mgmt{
            path_state = nquic_path:new(undefined),
            address_validated = false,
            anti_amp_bytes_sent = 0,
            anti_amp_bytes_received = 0
        }
    }.
