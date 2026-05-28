-module(nquic_stateless_reset).

-moduledoc """
Stateless reset token generation and detection per RFC 9000 Section 10.3.

Stateless reset allows an endpoint to terminate a connection when it has lost
state. The token is an HMAC-SHA256 of the connection ID, truncated to 16 bytes.
Reset packets look like short header packets to avoid identification.
""".

-export([build_packet/1, detect/2, generate_token/2]).

-doc "Build a stateless reset packet that looks like a short header packet.".
-spec build_packet(binary()) -> binary().
build_packet(Token) when byte_size(Token) =:= 16 ->
    PrefixLen = 5 + rand:uniform(21) - 1,
    Prefix = crypto:strong_rand_bytes(PrefixLen),
    <<_:1, _:1, Rest:6>> = <<(binary:first(Prefix))>>,
    <<0:1, 1:1, Rest:6, (binary:part(Prefix, 1, PrefixLen - 1))/binary, Token/binary>>.

-doc """
Check whether a packet is a stateless reset by comparing the last 16 bytes.
Comparison is constant-time (RFC 9000 Section 10.3.1: "An endpoint MUST
use a comparison that is constant-time with respect to the contents of
the token") to avoid timing side channels.
""".
-spec detect(binary(), binary()) -> boolean().
detect(Packet, Token) when byte_size(Packet) >= 21, byte_size(Token) =:= 16 ->
    PacketLen = byte_size(Packet),
    nquic_crypto:constant_time_equal(binary:part(Packet, PacketLen - 16, 16), Token);
detect(_, _) ->
    false.

-doc "Generate a stateless reset token from a static key and connection ID.".
-spec generate_token(binary(), binary()) -> binary().
generate_token(StaticKey, CID) ->
    <<Token:16/binary, _/binary>> = crypto:mac(hmac, sha256, StaticKey, CID),
    Token.
