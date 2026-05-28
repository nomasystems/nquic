%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_path}.
%%%-------------------------------------------------------------------
-module(nquic_path_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_frame.hrl").
-include("nquic_path.hrl").
new_creates_path_state_test() ->
    Peer = #{family => inet, addr => {127, 0, 0, 1}, port => 4433},
    PS = nquic_path:new(Peer),
    ?assertEqual(Peer, PS#path_state.peer),
    ?assertEqual(undefined, PS#path_state.previous_peer),
    ?assertEqual(undefined, PS#path_state.pending_challenge),
    ?assert(PS#path_state.path_validated).

new_undefined_peer_test() ->
    PS = nquic_path:new(undefined),
    ?assertEqual(undefined, PS#path_state.peer),
    ?assert(PS#path_state.path_validated).

detect_peer_change_same_address_test() ->
    Peer = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    PS = nquic_path:new(Peer),
    ?assertEqual(unchanged, nquic_path:detect_peer_change(PS, Peer)).

detect_peer_change_new_address_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS = nquic_path:new(Old),
    {changed, PS1} = nquic_path:detect_peer_change(PS, New),
    ?assertEqual(New, PS1#path_state.peer),
    ?assertEqual(Old, PS1#path_state.previous_peer),
    ?assertNot(PS1#path_state.path_validated),
    ?assertEqual(0, PS1#path_state.new_path_bytes_sent),
    ?assertEqual(0, PS1#path_state.new_path_bytes_received).

detect_peer_change_same_ip_different_port_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 1}, port => 6000},
    PS = nquic_path:new(Old),
    {changed, PS1} = nquic_path:detect_peer_change(PS, New),
    ?assertEqual(New, PS1#path_state.peer),
    ?assertEqual(Old, PS1#path_state.previous_peer),
    ?assertNot(PS1#path_state.path_validated).

detect_peer_change_undefined_peer_test() ->
    PS = nquic_path:new(undefined),
    Source = #{family => inet, addr => {192, 168, 1, 1}, port => 4433},
    {changed, PS1} = nquic_path:detect_peer_change(PS, Source),
    ?assertEqual(Source, PS1#path_state.peer),
    ?assertEqual(undefined, PS1#path_state.previous_peer),
    ?assert(PS1#path_state.path_validated).

detect_peer_change_ipv6_test() ->
    Old = #{family => inet6, addr => {0, 0, 0, 0, 0, 0, 0, 1}, port => 4433},
    New = #{family => inet6, addr => {0, 0, 0, 0, 0, 0, 0, 2}, port => 4433},
    PS = nquic_path:new(Old),
    {changed, PS1} = nquic_path:detect_peer_change(PS, New),
    ?assertEqual(New, PS1#path_state.peer),
    ?assertEqual(Old, PS1#path_state.previous_peer).

initiate_validation_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS = nquic_path:new(Old),
    {PS1, #path_challenge{data = Challenge}} = nquic_path:initiate_validation(PS, New),
    ?assertEqual(8, byte_size(Challenge)),
    ?assertEqual(New, PS1#path_state.peer),
    ?assertEqual(Old, PS1#path_state.previous_peer),
    ?assertEqual(Challenge, PS1#path_state.pending_challenge),
    ?assertNot(PS1#path_state.path_validated),
    ?assertEqual(0, PS1#path_state.challenge_retries),
    ?assertNotEqual(0, PS1#path_state.challenge_sent_time).

on_response_match_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS = nquic_path:new(Old),
    {PS1, #path_challenge{data = Challenge}} = nquic_path:initiate_validation(PS, New),
    {validated, PS2} = nquic_path:on_response(PS1, Challenge),
    ?assert(PS2#path_state.path_validated),
    ?assertEqual(undefined, PS2#path_state.pending_challenge),
    ?assertEqual(undefined, PS2#path_state.previous_peer),
    ?assertEqual(New, PS2#path_state.peer).

on_response_mismatch_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS = nquic_path:new(Old),
    {PS1, _} = nquic_path:initiate_validation(PS, New),
    {mismatch, PS2} = nquic_path:on_response(PS1, <<0, 0, 0, 0, 0, 0, 0, 0>>),
    ?assertNot(PS2#path_state.path_validated),
    ?assertNotEqual(undefined, PS2#path_state.pending_challenge).

on_response_no_pending_test() ->
    PS = nquic_path:new(#{family => inet, addr => {10, 0, 0, 1}, port => 5000}),
    {mismatch, _} = nquic_path:on_response(PS, <<1, 2, 3, 4, 5, 6, 7, 8>>).

on_timeout_retry_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS = nquic_path:new(Old),
    {PS1, #path_challenge{data = C1}} = nquic_path:initiate_validation(PS, New),
    {retry, PS2, #path_challenge{data = C2}} = nquic_path:on_timeout(PS1),
    ?assertNotEqual(C1, C2),
    ?assertEqual(1, PS2#path_state.challenge_retries),
    ?assertEqual(New, PS2#path_state.peer),
    ?assertNot(PS2#path_state.path_validated).

on_timeout_exhausted_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, _} = nquic_path:initiate_validation(PS0, New),
    {retry, PS2, _} = nquic_path:on_timeout(PS1),
    {retry, PS3, _} = nquic_path:on_timeout(PS2),
    {retry, PS4, _} = nquic_path:on_timeout(PS3),
    {failed, PS5} = nquic_path:on_timeout(PS4),
    ?assert(PS5#path_state.path_validated),
    ?assertEqual(Old, PS5#path_state.peer),
    ?assertEqual(undefined, PS5#path_state.previous_peer),
    ?assertEqual(undefined, PS5#path_state.pending_challenge).

is_validating_test() ->
    PS = nquic_path:new(#{family => inet, addr => {10, 0, 0, 1}, port => 5000}),
    ?assertNot(nquic_path:is_validating(PS)),
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    {PS1, _} = nquic_path:initiate_validation(PS, New),
    ?assert(nquic_path:is_validating(PS1)),
    {validated, PS2} = nquic_path:on_response(PS1, PS1#path_state.pending_challenge),
    ?assertNot(nquic_path:is_validating(PS2)).

is_validated_test() ->
    PS = nquic_path:new(#{family => inet, addr => {10, 0, 0, 1}, port => 5000}),
    ?assert(nquic_path:is_validated(PS)),
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    {PS1, _} = nquic_path:initiate_validation(PS, New),
    ?assertNot(nquic_path:is_validated(PS1)),
    {validated, PS2} = nquic_path:on_response(PS1, PS1#path_state.pending_challenge),
    ?assert(nquic_path:is_validated(PS2)).

validation_clears_pending_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS0 = nquic_path:new(Old),
    {PS1, #path_challenge{data = C}} = nquic_path:initiate_validation(PS0, New),
    ?assertNotEqual(undefined, PS1#path_state.pending_challenge),
    {validated, PS2} = nquic_path:on_response(PS1, C),
    ?assertEqual(undefined, PS2#path_state.pending_challenge).

get_previous_peer_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS = nquic_path:new(Old),
    ?assertEqual(undefined, nquic_path:get_previous_peer(PS)),
    {PS1, _} = nquic_path:initiate_validation(PS, New),
    ?assertEqual(Old, nquic_path:get_previous_peer(PS1)),
    {validated, PS2} = nquic_path:on_response(PS1, PS1#path_state.pending_challenge),
    ?assertEqual(undefined, nquic_path:get_previous_peer(PS2)).

is_nat_rebinding_same_ip_different_port_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 1}, port => 6000},
    PS = nquic_path:new(Old),
    {PS1, _} = nquic_path:initiate_validation(PS, New),
    ?assert(nquic_path:is_nat_rebinding(PS1)).

is_nat_rebinding_different_ip_test() ->
    Old = #{family => inet, addr => {10, 0, 0, 1}, port => 5000},
    New = #{family => inet, addr => {10, 0, 0, 2}, port => 6000},
    PS = nquic_path:new(Old),
    {PS1, _} = nquic_path:initiate_validation(PS, New),
    ?assertNot(nquic_path:is_nat_rebinding(PS1)).

is_nat_rebinding_no_previous_test() ->
    PS = nquic_path:new(#{family => inet, addr => {10, 0, 0, 1}, port => 5000}),
    ?assertNot(nquic_path:is_nat_rebinding(PS)).

is_nat_rebinding_undefined_peer_test() ->
    PS = nquic_path:new(undefined),
    ?assertNot(nquic_path:is_nat_rebinding(PS)).

is_nat_rebinding_ipv6_test() ->
    Old = #{family => inet6, addr => {0, 0, 0, 0, 0, 0, 0, 1}, port => 4433},
    New = #{family => inet6, addr => {0, 0, 0, 0, 0, 0, 0, 1}, port => 5000},
    PS = nquic_path:new(Old),
    {PS1, _} = nquic_path:initiate_validation(PS, New),
    ?assert(nquic_path:is_nat_rebinding(PS1)).
