%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_zero_rtt}.
%%%
%%% Drives both arms of `check/3': the safe-default `undefined' arm
%%% (no replay-protection module configured) and the callback-dispatch
%%% arm. The dispatch arm uses this module itself as the callback
%%% target; it implements the `nquic_zero_rtt' behaviour and routes
%%% acceptance through the process dictionary so individual cases can
%%% control the outcome without spinning up a full fixture module.
%%%-------------------------------------------------------------------
-module(nquic_zero_rtt_tests).

-behaviour(nquic_zero_rtt).

-include_lib("eunit/include/eunit.hrl").

-export([check/2]).

-define(PEER, #{family => inet, addr => {127, 0, 0, 1}, port => 4433}).

check_with_undefined_module_returns_reject_test() ->
    ?assertEqual(reject, nquic_zero_rtt:check(undefined, <<"id">>, ?PEER)),
    ?assertEqual(reject, nquic_zero_rtt:check(undefined, <<>>, ?PEER)).

check_dispatches_to_module_accept_test() ->
    set_decision(accept),
    try
        ?assertEqual(accept, nquic_zero_rtt:check(?MODULE, <<"id-1">>, ?PEER))
    after
        clear_decision()
    end.

check_dispatches_to_module_reject_test() ->
    set_decision(reject),
    try
        ?assertEqual(reject, nquic_zero_rtt:check(?MODULE, <<"id-2">>, ?PEER))
    after
        clear_decision()
    end.

check_forwards_identity_and_peer_test() ->
    set_decision(record),
    try
        Identity = <<"forwarded-identity">>,
        Peer = #{family => inet6, addr => {0, 0, 0, 0, 0, 0, 0, 1}, port => 9999},
        accept = nquic_zero_rtt:check(?MODULE, Identity, Peer),
        ?assertEqual({Identity, Peer}, get(?MODULE))
    after
        clear_decision()
    end.

check(Identity, Peer) ->
    case get(?MODULE) of
        record ->
            put(?MODULE, {Identity, Peer}),
            accept;
        Decision when Decision =:= accept; Decision =:= reject ->
            Decision
    end.

set_decision(Decision) ->
    put(?MODULE, Decision).

clear_decision() ->
    erase(?MODULE).
