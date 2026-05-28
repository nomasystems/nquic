-module(nquic_packet_number).

-moduledoc """
Packet number encoding and decoding per RFC 9000 Appendix A.

Packet numbers are truncated to 1-4 bytes based on the distance from the
largest acknowledged packet number. The receiver reconstructs the full
packet number using the closest value to the largest acknowledged.
""".

-export([decode/3, encode/2]).

-export_type([t/0]).

-type t() :: non_neg_integer().

-doc "Reconstruct a full packet number from a truncated value.".
-spec decode(LargestAcked :: non_neg_integer(), TruncatedPN :: non_neg_integer(), PnLen :: 1..4) ->
    FullPN :: non_neg_integer().
decode(LargestAcked, TruncatedPN, PnLen) ->
    PnWindow = 1 bsl (PnLen * 8),
    HalfWindow = PnWindow div 2,
    PnCandidate = (LargestAcked band (bnot (PnWindow - 1))) bor TruncatedPN,
    if
        PnCandidate =< LargestAcked - HalfWindow ->
            PnCandidate + PnWindow;
        PnCandidate > LargestAcked + HalfWindow, PnCandidate >= PnWindow ->
            PnCandidate - PnWindow;
        true ->
            PnCandidate
    end.

-doc "Truncate a full packet number for wire encoding based on largest acknowledged.".
-spec encode(FullPN :: non_neg_integer(), LargestAcked :: non_neg_integer()) ->
    {PnLen :: 1..4, TruncatedPN :: non_neg_integer()}.
encode(FullPN, LargestAcked) ->
    Delta = FullPN - LargestAcked,
    if
        Delta < 128 -> {1, FullPN band 16#FF};
        Delta < 32768 -> {2, FullPN band 16#FFFF};
        Delta < 8388608 -> {3, FullPN band 16#FFFFFF};
        true -> {4, FullPN band 16#FFFFFFFF}
    end.
