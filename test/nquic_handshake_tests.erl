%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_handshake}.
%%%-------------------------------------------------------------------
-module(nquic_handshake_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_frame.hrl").
derive_initial_keys_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Keys = nquic_handshake:derive_initial_keys(DCID),
    ?assert(is_map(Keys)),
    ?assert(maps:is_key(client, Keys)),
    ?assert(maps:is_key(server, Keys)),
    #{client := ClientKeys} = Keys,
    ?assert(maps:is_key(key, ClientKeys)),
    ?assert(maps:is_key(iv, ClientKeys)),
    ?assert(maps:is_key(hp, ClientKeys)).

format_keys_test() ->
    Input = #{
        client_key => <<"ck">>,
        client_iv => <<"ci">>,
        client_hp => <<"ch">>,
        server_key => <<"sk">>,
        server_iv => <<"si">>,
        server_hp => <<"sh">>
    },
    Result = nquic_handshake:format_keys(Input),
    ?assertEqual(#{key => <<"ck">>, iv => <<"ci">>, hp => <<"ch">>}, maps:get(client, Result)),
    ?assertEqual(#{key => <<"sk">>, iv => <<"si">>, hp => <<"sh">>}, maps:get(server, Result)).

install_handshake_keys_test() ->
    Keys = #{
        client_key => <<"ck">>,
        client_iv => <<"ci">>,
        client_hp => <<"ch">>,
        server_key => <<"sk">>,
        server_iv => <<"si">>,
        server_hp => <<"sh">>
    },
    Existing = #{initial => #{}},
    Result = nquic_handshake:install_handshake_keys(Keys, Existing),
    ?assert(maps:is_key(handshake, Result)),
    ?assert(maps:is_key(initial, Result)).

build_initial_frames_test() ->
    Frames = nquic_handshake:build_initial_frames(<<"hello">>),
    ?assertMatch([#crypto{offset = 0, data = <<"hello">>}], Frames).
