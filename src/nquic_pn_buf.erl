-module(nquic_pn_buf).

-moduledoc """
Sent-packet buffer for `nquic_loss`.

QUIC's send pattern is monotonic-PN insert at the tail (RFC 9000
§12.3, packet numbers strictly increase within a packet number
space) followed by ACK arrivals that typically remove a prefix of
the oldest unacked entries. The previous implementation backed
this by `gb_trees`, which fires periodic O(N) rebalances under
monotonic-key insertion that show up as hot frames in profiling
(`gb_trees:to_list`, `gb_trees:balance_list_1`, `gb_trees:count`).

Internal representation is a two-list deque. `front` holds older
entries in ascending PN order; `back` holds newer entries in
descending PN order with the head being the newest. The invariant
`max(PN in front) < min(PN in back)` is preserved by every
operation.

Insert at the tail is `O(1)`. Ascending walk with early stop is
`O(K)` where `K` is the number of entries scanned. The common
case for ACK and loss-detection sweeps is "scan a prefix of the
front", which never touches `back`. Operations that consume the
entire front then peek into the back reverse `back` once, paid
amortised across the full traversal.
""".

-include("nquic_loss.hrl").
-export([
    delete/2,
    from_list/1,
    get/2,
    insert/3,
    is_defined/2,
    is_empty/1,
    keys/1,
    lookup/2,
    new/0,
    size/1,
    take_lost/4,
    take_older_than/2,
    take_range/3,
    to_list/1,
    values/1
]).

-export_type([buf/0]).

-record(buf, {
    front = [] :: [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    back = [] :: [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    size = 0 :: non_neg_integer()
}).

-opaque buf() :: #buf{}.

-spec build_residual(
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}] | exhausted
) -> [{nquic_packet_number:t(), nquic_loss:sent_packet()}].
build_residual(KeptF, KeptB, exhausted) ->
    lists:reverse(KeptF) ++ lists:reverse(KeptB);
build_residual(KeptF, KeptB, RestB) ->
    lists:reverse(KeptF) ++ lists:reverse(KeptB, RestB).

-spec consume_back_for_lost(
    [nquic_loss:sent_packet()],
    non_neg_integer(),
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    non_neg_integer(),
    integer(),
    integer(),
    pos_integer(),
    buf()
) -> {[nquic_loss:sent_packet()], buf(), non_neg_integer() | undefined}.
consume_back_for_lost(LostF, MCF, [], N, _PThresh, _TCutoff, _LossDelay, Buf) ->
    {lists:reverse(LostF), Buf#buf{front = [], size = N - MCF}, undefined};
consume_back_for_lost(LostF, MCF, B, N, PThresh, TCutoff, LossDelay, Buf) ->
    BackAsc = lists:reverse(B),
    {LostB, RestB, NextLossTime, MCB} = scan_lost(BackAsc, PThresh, TCutoff, LossDelay, [], 0),
    Lost = lists:reverse(LostF, lists:reverse(LostB)),
    NewFront =
        case RestB of
            exhausted -> [];
            _ -> RestB
        end,
    {Lost, Buf#buf{front = NewFront, back = [], size = N - MCF - MCB}, NextLossTime}.

-spec consume_back_for_older(
    [nquic_loss:sent_packet()],
    non_neg_integer(),
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    non_neg_integer(),
    integer(),
    buf()
) -> {[nquic_loss:sent_packet()], buf()}.
consume_back_for_older(OldF, MCF, [], N, _Cutoff, Buf) ->
    {lists:reverse(OldF), Buf#buf{front = [], size = N - MCF}};
consume_back_for_older(OldF, MCF, B, N, Cutoff, Buf) ->
    BackAsc = lists:reverse(B),
    {OldB, RestB, MCB} = scan_older(BackAsc, Cutoff, [], 0),
    Old = lists:reverse(OldF, lists:reverse(OldB)),
    NewFront =
        case RestB of
            exhausted -> [];
            _ -> RestB
        end,
    {Old, Buf#buf{front = NewFront, back = [], size = N - MCF - MCB}}.

-spec consume_back_for_range(
    nquic_packet_number:t(),
    nquic_packet_number:t(),
    [nquic_loss:sent_packet()],
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    non_neg_integer(),
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    non_neg_integer(),
    buf()
) -> {[nquic_loss:sent_packet()], buf()}.
consume_back_for_range(_Low, _High, MatchedF, KeptF, MCF, [], N, Buf) ->
    NewFront = lists:reverse(KeptF),
    {lists:reverse(MatchedF), Buf#buf{front = NewFront, size = N - MCF}};
consume_back_for_range(Low, High, MatchedF, KeptF, MCF, B, N, Buf) ->
    BackAsc = lists:reverse(B),
    {MatchedB, KeptB, RestB, MCB} = scan_asc_part(Low, High, BackAsc, [], [], 0),
    AllMatched = lists:reverse(MatchedF, lists:reverse(MatchedB)),
    NewFront = build_residual(KeptF, KeptB, RestB),
    {AllMatched, Buf#buf{front = NewFront, back = [], size = N - MCF - MCB}}.

-doc """
Remove the entry at `PN`. Worst-case `O(N)` linear scan. Used by
spurious-loss bookkeeping where an ACK arrives for a previously
declared-lost packet and the entry must be cleared from the
`recently_lost` index.
""".
-spec delete(nquic_packet_number:t(), buf()) -> buf().
delete(PN, #buf{front = F, back = B, size = N} = Buf) ->
    case lists:keytake(PN, 1, F) of
        {value, _, F1} ->
            Buf#buf{front = F1, size = N - 1};
        false ->
            case lists:keytake(PN, 1, B) of
                {value, _, B1} -> Buf#buf{back = B1, size = N - 1};
                false -> Buf
            end
    end.

-doc """
Build a buffer from a list of `{PN, Pkt}` pairs. Sorts ascending and
seeds `front` with the result. Intended for tests and migration
helpers; production code should grow the buffer via `insert/3`.
""".
-spec from_list([{nquic_packet_number:t(), nquic_loss:sent_packet()}]) -> buf().
from_list(List) ->
    Sorted = lists:sort(fun({A, _}, {B, _}) -> A =< B end, List),
    #buf{front = Sorted, back = [], size = length(Sorted)}.

-doc """
Get the packet at `PN` or raise. Mirrors `gb_trees:get/2` for tests
that depended on the exception shape; production code should prefer
`lookup/2`.
""".
-spec get(nquic_packet_number:t(), buf()) -> nquic_loss:sent_packet().
get(PN, Buf) ->
    case lookup(PN, Buf) of
        {value, V} -> V;
        none -> error({key_not_found, PN})
    end.

-doc """
Insert `Pkt` at packet number `PN`. The caller must guarantee `PN` is
strictly greater than every existing PN in the buffer (the natural
monotonic-PN-per-space invariant from RFC 9000 §12.3). The function
does not validate this; violating the invariant only matters for
later iteration / range operations, which assume PN-ascending order.
""".
-spec insert(nquic_packet_number:t(), nquic_loss:sent_packet(), buf()) -> buf().
insert(PN, Pkt, #buf{back = B, size = N} = Buf) ->
    Buf#buf{back = [{PN, Pkt} | B], size = N + 1}.

-doc "Existence predicate. Same complexity as `lookup/2`.".
-spec is_defined(nquic_packet_number:t(), buf()) -> boolean().
is_defined(PN, Buf) ->
    case lookup(PN, Buf) of
        none -> false;
        {value, _} -> true
    end.

-doc "Return whether the buffer holds no entries.".
-spec is_empty(buf()) -> boolean().
is_empty(#buf{size = 0}) -> true;
is_empty(#buf{}) -> false.

-doc "Packet numbers in ascending order. Materialises the full list.".
-spec keys(buf()) -> [nquic_packet_number:t()].
keys(#buf{front = F, back = B}) ->
    [PN || {PN, _} <- F] ++ [PN || {PN, _} <- lists:reverse(B)].

-doc """
Look up the packet at `PN`. Worst-case `O(N)` linear scan; the buffer
is not designed for random access, so callers should reserve this
for tests or rare paths (e.g. computing an RTT sample from the
largest acked PN, which is at most one call per ACK).
""".
-spec lookup(nquic_packet_number:t(), buf()) -> none | {value, nquic_loss:sent_packet()}.
lookup(PN, #buf{front = F, back = B}) ->
    case lists:keyfind(PN, 1, F) of
        false ->
            case lists:keyfind(PN, 1, B) of
                false -> none;
                {_, V} -> {value, V}
            end;
        {_, V} ->
            {value, V}
    end.

-doc "Construct an empty buffer.".
-spec new() -> buf().
new() -> #buf{}.

-spec scan_asc_part(
    nquic_packet_number:t(),
    nquic_packet_number:t(),
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    [nquic_loss:sent_packet()],
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    non_neg_integer()
) ->
    {
        [nquic_loss:sent_packet()],
        [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
        [{nquic_packet_number:t(), nquic_loss:sent_packet()}] | exhausted,
        non_neg_integer()
    }.
scan_asc_part(_Low, _High, [], MatchedRev, KeptRev, MC) ->
    {MatchedRev, KeptRev, exhausted, MC};
scan_asc_part(_Low, High, [{PN, _V} | _Rest] = All, MatchedRev, KeptRev, MC) when PN > High ->
    {MatchedRev, KeptRev, All, MC};
scan_asc_part(Low, High, [{PN, V} | Rest], MatchedRev, KeptRev, MC) when PN < Low ->
    scan_asc_part(Low, High, Rest, MatchedRev, [{PN, V} | KeptRev], MC);
scan_asc_part(Low, High, [{_PN, V} | Rest], MatchedRev, KeptRev, MC) ->
    scan_asc_part(Low, High, Rest, [V | MatchedRev], KeptRev, MC + 1).

-spec scan_back_desc(
    nquic_packet_number:t(),
    nquic_packet_number:t(),
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    [nquic_loss:sent_packet()],
    non_neg_integer()
) ->
    {
        [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
        [nquic_loss:sent_packet()],
        [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
        non_neg_integer()
    }.
scan_back_desc(_Low, _High, [], NewerAsc, MatchedAsc, MC) ->
    {NewerAsc, MatchedAsc, [], MC};
scan_back_desc(Low, High, [{PN, V} | Rest], NewerAsc, MatchedAsc, MC) when PN > High ->
    scan_back_desc(Low, High, Rest, [{PN, V} | NewerAsc], MatchedAsc, MC);
scan_back_desc(Low, _High, [{PN, _V} | _] = All, NewerAsc, MatchedAsc, MC) when PN < Low ->
    {NewerAsc, MatchedAsc, All, MC};
scan_back_desc(Low, High, [{_PN, V} | Rest], NewerAsc, MatchedAsc, MC) ->
    scan_back_desc(Low, High, Rest, NewerAsc, [V | MatchedAsc], MC + 1).

-spec scan_lost(
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    integer(),
    integer(),
    pos_integer(),
    [nquic_loss:sent_packet()],
    non_neg_integer()
) ->
    {
        [nquic_loss:sent_packet()],
        [{nquic_packet_number:t(), nquic_loss:sent_packet()}] | exhausted,
        non_neg_integer() | undefined,
        non_neg_integer()
    }.
scan_lost([], _PThresh, _TCutoff, _LossDelay, LostRev, MC) ->
    {LostRev, exhausted, undefined, MC};
scan_lost(
    [{PN, #sent_packet{time_sent = TS} = Pkt} | Rest], PThresh, TCutoff, LossDelay, LostRev, MC
) when
    PN =< PThresh; TS =< TCutoff
->
    scan_lost(Rest, PThresh, TCutoff, LossDelay, [Pkt | LostRev], MC + 1);
scan_lost(
    [{_PN, #sent_packet{time_sent = TS}} | _] = All, _PThresh, _TCutoff, LossDelay, LostRev, MC
) ->
    {LostRev, All, TS + LossDelay, MC}.

-spec scan_older(
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    integer(),
    [nquic_loss:sent_packet()],
    non_neg_integer()
) ->
    {
        [nquic_loss:sent_packet()],
        [{nquic_packet_number:t(), nquic_loss:sent_packet()}] | exhausted,
        non_neg_integer()
    }.
scan_older([], _Cutoff, OldRev, MC) ->
    {OldRev, exhausted, MC};
scan_older([{_PN, #sent_packet{time_sent = TS} = Pkt} | Rest], Cutoff, OldRev, MC) when
    TS =< Cutoff
->
    scan_older(Rest, Cutoff, [Pkt | OldRev], MC + 1);
scan_older(All, _Cutoff, OldRev, MC) ->
    {OldRev, All, MC}.

-doc "Number of entries currently held.".
-spec size(buf()) -> non_neg_integer().
size(#buf{size = N}) -> N.

-doc """
Take all entries that satisfy the RFC 9002 §6.1 loss conditions
(`PN =< PThresh` OR `time_sent =< TCutoff`). Returns the lost
packets in PN-ascending order, the residual buffer, and the
NextLossTime hint (the first not-lost packet's
`time_sent + LossDelay`, or `undefined` if every packet was lost).
Stops at the first packet that fails both conditions. PN order
equals time-sent order on monotonic clock + monotonic PN, so all
suffix entries are also not lost; early-stop is safe.
""".
-spec take_lost(buf(), integer(), integer(), pos_integer()) ->
    {[nquic_loss:sent_packet()], buf(), non_neg_integer() | undefined}.
take_lost(#buf{front = F, back = B, size = N} = Buf, PThresh, TCutoff, LossDelay) ->
    case scan_lost(F, PThresh, TCutoff, LossDelay, [], 0) of
        {LostF, exhausted, _, MC} ->
            consume_back_for_lost(LostF, MC, B, N, PThresh, TCutoff, LossDelay, Buf);
        {LostF, RestF, NextLossTime, MC} ->
            {lists:reverse(LostF), Buf#buf{front = RestF, size = N - MC}, NextLossTime}
    end.

-doc """
Take all entries with `time_sent =< Cutoff`. Walks ascending and
stops at the first entry newer than `Cutoff`. Used to prune the
recently-lost index past the spurious-loss reorder window.
""".
-spec take_older_than(buf(), integer()) -> {[nquic_loss:sent_packet()], buf()}.
take_older_than(#buf{front = F, back = B, size = N} = Buf, Cutoff) ->
    case scan_older(F, Cutoff, [], 0) of
        {OldF, exhausted, MC} ->
            consume_back_for_older(OldF, MC, B, N, Cutoff, Buf);
        {OldF, RestF, MC} ->
            {lists:reverse(OldF), Buf#buf{front = RestF, size = N - MC}}
    end.

-doc """
Take all entries with `Low =< PN =< High`. Returns the matched
packets in PN-ascending order plus the residual buffer. The common
case (range covers a prefix of `front`) touches only `front` and
runs in `O(K)` where `K` is the partition position. When the range
straddles into `back`, `back` is reversed once into `front` and the
scan continues; paid as a single linear pass amortised across the
caller.
""".
-spec take_range(nquic_packet_number:t(), nquic_packet_number:t(), buf()) ->
    {[nquic_loss:sent_packet()], buf()}.
take_range(Low, High, Buf) when Low > High ->
    {[], Buf};
take_range(Low, High, #buf{front = [], back = B, size = N} = Buf) ->
    take_range_back_only(Low, High, B, N, Buf);
take_range(Low, High, #buf{front = F, back = B, size = N} = Buf) ->
    case scan_asc_part(Low, High, F, [], [], 0) of
        {Matched, Kept, exhausted, MC} ->
            consume_back_for_range(Low, High, Matched, Kept, MC, B, N, Buf);
        {Matched, Kept, RestF, MC} ->
            NewFront = lists:reverse(Kept, RestF),
            {lists:reverse(Matched), Buf#buf{front = NewFront, size = N - MC}}
    end.

-spec take_range_back_only(
    nquic_packet_number:t(),
    nquic_packet_number:t(),
    [{nquic_packet_number:t(), nquic_loss:sent_packet()}],
    non_neg_integer(),
    buf()
) -> {[nquic_loss:sent_packet()], buf()}.
take_range_back_only(Low, High, B, N, Buf) ->
    {NewerAsc, MatchedAsc, OlderTail, MC} =
        scan_back_desc(Low, High, B, [], [], 0),
    NewFront = lists:reverse(OlderTail),
    NewBack = lists:reverse(NewerAsc),
    {MatchedAsc, Buf#buf{front = NewFront, back = NewBack, size = N - MC}}.

-doc "All `{PN, Pkt}` entries in PN-ascending order.".
-spec to_list(buf()) -> [{nquic_packet_number:t(), nquic_loss:sent_packet()}].
to_list(#buf{front = F, back = B}) ->
    F ++ lists:reverse(B).

-doc "Packet records in PN-ascending order. Materialises the full list.".
-spec values(buf()) -> [nquic_loss:sent_packet()].
values(#buf{front = F, back = B}) ->
    [V || {_, V} <- F] ++ [V || {_, V} <- lists:reverse(B)].
