-module(nquic_varint).

-moduledoc """
Variable-length integer encoding per RFC 9000 Section 16.

QUIC uses a variable-length encoding for integers up to 2^62 - 1.
The two most significant bits indicate the encoding length: 1, 2, 4, or 8 bytes.
""".

-compile({inline, [decode/1, encode/1, safe_encode/1, size/1]}).

-export([decode/1, encode/1, safe_encode/1, size/1]).

-export_type([t/0]).

-type t() :: 0..16#3fffffffffffffff.

-doc "Decode a variable-length integer from the head of a binary.".
-spec decode(binary()) -> {ok, t(), binary()} | {error, incomplete_binary}.
decode(<<0:2, I:6, Rest/binary>>) ->
    {ok, I, Rest};
decode(<<1:2, I:14, Rest/binary>>) ->
    {ok, I, Rest};
decode(<<2:2, I:30, Rest/binary>>) ->
    {ok, I, Rest};
decode(<<3:2, I:62, Rest/binary>>) ->
    {ok, I, Rest};
decode(Bin) when is_binary(Bin) ->
    {error, incomplete_binary}.

-doc "Encode an integer as a QUIC variable-length integer.".
-spec encode(t()) -> binary().
encode(I) when I >= 0, I =< 63 ->
    <<0:2, I:6>>;
encode(I) when I =< 16383 ->
    <<1:2, I:14>>;
encode(I) when I =< 1073741823 ->
    <<2:2, I:30>>;
encode(I) when I =< 4611686018427387903 ->
    <<3:2, I:62>>.

-doc "Encode with overflow checking. Returns `{error, overflow}` for values >= 2^62.".
-spec safe_encode(integer()) -> {ok, binary()} | {error, overflow}.
safe_encode(I) when is_integer(I), I >= 0, I =< 4611686018427387903 ->
    {ok, encode(I)};
safe_encode(_) ->
    {error, overflow}.

-doc "Return the encoded byte size of a variable-length integer (1, 2, 4, or 8).".
-spec size(t()) -> 1 | 2 | 4 | 8.
size(I) when I >= 0, I =< 63 -> 1;
size(I) when I =< 16383 -> 2;
size(I) when I =< 1073741823 -> 4;
size(I) when I =< 4611686018427387903 -> 8.
