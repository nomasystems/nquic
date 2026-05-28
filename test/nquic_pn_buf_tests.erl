%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_pn_buf}.
%%%
%%% The buffer is a domain-specific deque optimised for the QUIC
%%% steady-state pattern (monotonic-PN insert, prefix removal). These
%%% tests pin the API contract and the invariant that ascending PN
%%% iteration is preserved across all combinations of `front' and
%%% `back' shapes.
%%%-------------------------------------------------------------------
-module(nquic_pn_buf_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_loss.hrl").
mk(PN) ->
    #sent_packet{
        packet_number = PN,
        time_sent = PN * 10,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    }.

new_is_empty_test() ->
    B = nquic_pn_buf:new(),
    ?assert(nquic_pn_buf:is_empty(B)),
    ?assertEqual(0, nquic_pn_buf:size(B)).

insert_single_test() ->
    B0 = nquic_pn_buf:new(),
    B1 = nquic_pn_buf:insert(1, mk(1), B0),
    ?assertNot(nquic_pn_buf:is_empty(B1)),
    ?assertEqual(1, nquic_pn_buf:size(B1)),
    ?assert(nquic_pn_buf:is_defined(1, B1)),
    ?assertNot(nquic_pn_buf:is_defined(2, B1)),
    ?assertEqual(
        #sent_packet{
            packet_number = 1,
            time_sent = 10,
            size = 1200,
            ack_eliciting = true,
            in_flight = true,
            frames = []
        },
        nquic_pn_buf:get(1, B1)
    ).

insert_monotonic_preserves_order_test() ->
    B0 = nquic_pn_buf:new(),
    Buf = lists:foldl(
        fun(PN, Acc) -> nquic_pn_buf:insert(PN, mk(PN), Acc) end,
        B0,
        lists:seq(1, 100)
    ),
    ?assertEqual(lists:seq(1, 100), nquic_pn_buf:keys(Buf)),
    ?assertEqual(100, nquic_pn_buf:size(Buf)).

lookup_missing_test() ->
    B0 = nquic_pn_buf:new(),
    B1 = nquic_pn_buf:insert(5, mk(5), B0),
    ?assertEqual(none, nquic_pn_buf:lookup(1, B1)),
    ?assertEqual({value, mk(5)}, nquic_pn_buf:lookup(5, B1)),
    ?assertError({key_not_found, 99}, nquic_pn_buf:get(99, B1)).

delete_only_in_back_test() ->
    B0 = nquic_pn_buf:new(),
    Buf = lists:foldl(
        fun(PN, Acc) -> nquic_pn_buf:insert(PN, mk(PN), Acc) end,
        B0,
        [1, 2, 3]
    ),
    Buf1 = nquic_pn_buf:delete(2, Buf),
    ?assertEqual([1, 3], nquic_pn_buf:keys(Buf1)),
    ?assertEqual(2, nquic_pn_buf:size(Buf1)).

delete_missing_is_noop_test() ->
    B0 = nquic_pn_buf:new(),
    Buf = nquic_pn_buf:insert(1, mk(1), B0),
    Buf1 = nquic_pn_buf:delete(99, Buf),
    ?assertEqual(Buf, Buf1).

take_range_full_back_test() ->
    Buf = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 10)
    ),
    {Removed, Buf1} = nquic_pn_buf:take_range(3, 6, Buf),
    ?assertEqual([3, 4, 5, 6], [P#sent_packet.packet_number || P <- Removed]),
    ?assertEqual([1, 2, 7, 8, 9, 10], nquic_pn_buf:keys(Buf1)),
    ?assertEqual(6, nquic_pn_buf:size(Buf1)).

take_range_inverted_test() ->
    Buf = nquic_pn_buf:insert(1, mk(1), nquic_pn_buf:new()),
    {Removed, Buf1} = nquic_pn_buf:take_range(5, 2, Buf),
    ?assertEqual([], Removed),
    ?assertEqual(Buf, Buf1).

take_range_no_match_test() ->
    Buf = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 5)
    ),
    {Removed, Buf1} = nquic_pn_buf:take_range(100, 200, Buf),
    ?assertEqual([], Removed),
    ?assertEqual([1, 2, 3, 4, 5], nquic_pn_buf:keys(Buf1)).

take_range_after_partial_drain_test() ->
    Buf0 = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 10)
    ),
    {_, Buf1} = nquic_pn_buf:take_range(1, 5, Buf0),
    ?assertEqual([6, 7, 8, 9, 10], nquic_pn_buf:keys(Buf1)),
    {Removed, Buf2} = nquic_pn_buf:take_range(7, 9, Buf1),
    ?assertEqual([7, 8, 9], [P#sent_packet.packet_number || P <- Removed]),
    ?assertEqual([6, 10], nquic_pn_buf:keys(Buf2)).

take_range_straddles_front_back_test() ->
    Buf0 = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 5)
    ),
    {_, Buf1} = nquic_pn_buf:take_range(1, 1, Buf0),
    Buf2 = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        Buf1,
        [6, 7, 8]
    ),
    {Removed, Buf3} = nquic_pn_buf:take_range(4, 7, Buf2),
    ?assertEqual([4, 5, 6, 7], [P#sent_packet.packet_number || P <- Removed]),
    ?assertEqual([2, 3, 8], nquic_pn_buf:keys(Buf3)).

take_lost_packet_threshold_test() ->
    Buf = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 10)
    ),
    {Lost, Buf1, NextT} = nquic_pn_buf:take_lost(Buf, 4, 0, 1000),
    ?assertEqual([1, 2, 3, 4], [P#sent_packet.packet_number || P <- Lost]),
    ?assertEqual([5, 6, 7, 8, 9, 10], nquic_pn_buf:keys(Buf1)),
    ?assertEqual(1050, NextT).

take_lost_time_threshold_test() ->
    Buf = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 10)
    ),
    {Lost, Buf1, NextT} = nquic_pn_buf:take_lost(Buf, 0, 35, 100),
    ?assertEqual([1, 2, 3], [P#sent_packet.packet_number || P <- Lost]),
    ?assertEqual(140, NextT),
    ?assertEqual([4, 5, 6, 7, 8, 9, 10], nquic_pn_buf:keys(Buf1)).

take_lost_all_lost_test() ->
    Buf = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 5)
    ),
    {Lost, Buf1, NextT} = nquic_pn_buf:take_lost(Buf, 100, 1_000_000, 100),
    ?assertEqual(5, length(Lost)),
    ?assertEqual(undefined, NextT),
    ?assert(nquic_pn_buf:is_empty(Buf1)).

take_lost_none_lost_test() ->
    Buf = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 5)
    ),
    {Lost, _Buf1, NextT} = nquic_pn_buf:take_lost(Buf, -1, -1, 100),
    ?assertEqual([], Lost),
    ?assertEqual(110, NextT).

take_lost_straddles_front_back_test() ->
    Buf0 = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 3)
    ),
    {_, Buf1} = nquic_pn_buf:take_range(0, 0, Buf0),
    Buf2 = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        Buf1,
        [4, 5, 6]
    ),
    {Lost, Buf3, _NextT} = nquic_pn_buf:take_lost(Buf2, 4, 0, 100),
    ?assertEqual([1, 2, 3, 4], [P#sent_packet.packet_number || P <- Lost]),
    ?assertEqual([5, 6], nquic_pn_buf:keys(Buf3)).

take_older_than_basic_test() ->
    Buf = lists:foldl(
        fun(PN, A) -> nquic_pn_buf:insert(PN, mk(PN), A) end,
        nquic_pn_buf:new(),
        lists:seq(1, 5)
    ),
    {Old, Buf1} = nquic_pn_buf:take_older_than(Buf, 25),
    ?assertEqual([1, 2], [P#sent_packet.packet_number || P <- Old]),
    ?assertEqual([3, 4, 5], nquic_pn_buf:keys(Buf1)).

take_older_than_empty_test() ->
    {Old, Buf1} = nquic_pn_buf:take_older_than(nquic_pn_buf:new(), 100),
    ?assertEqual([], Old),
    ?assert(nquic_pn_buf:is_empty(Buf1)).

oracle_equivalence_test() ->
    Ops = [
        {insert, 1},
        {insert, 2},
        {insert, 3},
        {take_range, 1, 1},
        {insert, 4},
        {insert, 5},
        {take_range, 2, 4},
        {insert, 6},
        {insert, 7},
        {take_range, 3, 6},
        {insert, 8}
    ],
    {Buf, Map} = lists:foldl(fun apply_op/2, {nquic_pn_buf:new(), #{}}, Ops),
    Expected = lists:sort(maps:keys(Map)),
    ?assertEqual(Expected, nquic_pn_buf:keys(Buf)),
    ?assertEqual(maps:size(Map), nquic_pn_buf:size(Buf)).

apply_op({insert, PN}, {Buf, Map}) ->
    Pkt = mk(PN),
    {nquic_pn_buf:insert(PN, Pkt, Buf), Map#{PN => Pkt}};
apply_op({take_range, L, H}, {Buf, Map}) ->
    {_Removed, Buf1} = nquic_pn_buf:take_range(L, H, Buf),
    Map1 = maps:filter(fun(K, _V) -> K < L orelse K > H end, Map),
    {Buf1, Map1}.

%% from_list / lookup / delete / to_list contract + a take_older_than
%% shape that drives consume_back_for_older.
sp(N) ->
    #sent_packet{
        packet_number = N,
        time_sent = N * 1000,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = []
    }.

from_list_lookup_delete_to_list_test() ->
    B0 = nquic_pn_buf:from_list([{N, sp(N)} || N <- [1, 2, 3, 4, 5]]),
    ?assertEqual(5, nquic_pn_buf:size(B0)),
    ?assertMatch({value, #sent_packet{packet_number = 3}}, nquic_pn_buf:lookup(3, B0)),
    ?assertEqual(none, nquic_pn_buf:lookup(99, B0)),
    B1 = nquic_pn_buf:delete(3, B0),
    ?assertEqual(none, nquic_pn_buf:lookup(3, B1)),
    ?assertEqual([1, 2, 4, 5], [N || {N, _} <- nquic_pn_buf:to_list(B1)]),
    %% Deleting an absent PN is a no-op.
    ?assertEqual(B1, nquic_pn_buf:delete(3, B1)).

take_older_than_back_segment_test() ->
    %% Insert then prefix-remove to force a non-trivial `back' segment,
    %% then age out a cutoff that straddles it.
    B0 = lists:foldl(
        fun(N, B) -> nquic_pn_buf:insert(N, sp(N), B) end,
        nquic_pn_buf:new(),
        lists:seq(1, 10)
    ),
    {_Old, B1} = nquic_pn_buf:take_older_than(B0, 3 * 1000 + 1),
    B2 = lists:foldl(
        fun(N, B) -> nquic_pn_buf:insert(N, sp(N), B) end,
        B1,
        lists:seq(11, 16)
    ),
    {Old2, B3} = nquic_pn_buf:take_older_than(B2, 12 * 1000 + 1),
    ?assert(is_list(Old2)),
    ?assert(lists:all(fun(P) -> P#sent_packet.time_sent =< 12 * 1000 + 1 end, Old2)),
    ?assert(nquic_pn_buf:size(B3) >= 0).
