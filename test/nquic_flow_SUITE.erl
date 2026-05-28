%%%-------------------------------------------------------------------
%%% @doc Flow Control and Data Transfer Verification
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_flow_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("nquic_conn.hrl").
-include("nquic_transport.hrl").
-compile([export_all, nowarn_export_all]).

all() ->
    [
        flow_control_test
    ].

init_per_suite(Config) ->
    application:ensure_all_started(nquic),
    Config.

end_per_suite(_Config) ->
    ok.

flow_control_test(_Config) ->
    LocalParams = #transport_params{
        initial_max_data = 1000,
        initial_max_stream_data_bidi_remote = 500,
        initial_max_stream_data_uni = 500
    },
    RemoteParams = #transport_params{
        initial_max_data = 1000,
        initial_max_stream_data_bidi_remote = 500,
        initial_max_stream_data_bidi_local = 500,
        initial_max_stream_data_uni = 500
    },

    ConnState0 = #conn_state{
        role = client,
        scid = <<1>>,
        dcid = <<2>>,
        local_params = LocalParams,
        remote_params = RemoteParams,
        streams_state = #conn_streams{streams = #{}}
    },

    ConnState = nquic_flow:init_conn_limits(ConnState0),

    {ok, StreamState0, _} = nquic_stream_manager:get_or_create(0, #{}, client),
    StreamState = nquic_flow:init_stream_limits(StreamState0, ConnState, bidi),

    ?assertEqual(ok, nquic_flow:check_conn_send(ConnState, 400)),
    ?assertEqual(ok, nquic_flow:check_stream_send(StreamState, 400)),

    ConnState1 = nquic_flow:on_stream_data_sent(ConnState, 0, 400),
    StreamState1 = StreamState#stream_state{send_offset = 400},

    ?assertEqual(ok, nquic_flow:check_conn_send(ConnState1, 200)),
    ?assertMatch({blocked, 500}, nquic_flow:check_stream_send(StreamState1, 200)),

    StreamState2 = StreamState1#stream_state{send_max_data = 1000},

    ?assertEqual(ok, nquic_flow:check_stream_send(StreamState2, 200)),

    ConnState2 = nquic_flow:on_stream_data_sent(ConnState1, 0, 200),
    _StreamState3 = StreamState2#stream_state{send_offset = 600},

    ?assertMatch({blocked, 1000}, nquic_flow:check_conn_send(ConnState2, 500)),

    Flow2 = ConnState2#conn_state.flow,
    ConnState3 = ConnState2#conn_state{flow = Flow2#conn_flow{remote_max_data = 2000}},

    ?assertEqual(ok, nquic_flow:check_conn_send(ConnState3, 500)),

    ok.
