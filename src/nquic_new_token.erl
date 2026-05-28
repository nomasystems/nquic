-module(nquic_new_token).

-moduledoc """
Server-side NEW_TOKEN issuance and validation per RFC 9000 §8.1.3.

The server hands out an opaque token via the NEW_TOKEN frame after
the handshake completes. A returning client echoes the token on its
next Initial; if the token validates, the server skips the Retry
round-trip and proceeds with handshake immediately.

The token binds the client's IP+port to a freshness timestamp,
authenticated by HMAC-SHA256 with the same static key Retry uses,
**domain-separated** by the leading `"new_token"` tag in the HMAC
input so a Retry token cannot be replayed as a NEW_TOKEN token (and
vice versa).

Token format: `<<HMAC:32/binary, IssuedAt:64, AddrBin/binary>>`
HMAC input: `<<"new_token", Lifetime:32, IssuedAt:64, AddrBin/binary>>`
""".

-export([
    generate/3,
    generate/4,
    validate/3,
    validate/4
]).

-define(DOMAIN_TAG, <<"new_token">>).
-define(DEFAULT_LIFETIME_S, 86400).

-doc "Generate a NEW_TOKEN token bound to `PeerAddr`, valid for 24 hours.".
-spec generate(binary(), nquic_socket:sockaddr(), pos_integer()) -> binary().
generate(StaticKey, PeerAddr, Lifetime) ->
    generate(StaticKey, PeerAddr, Lifetime, erlang:system_time(second)).

-doc "Like `generate/3` but with an explicit issue time (for testing).".
-spec generate(binary(), nquic_socket:sockaddr(), pos_integer(), non_neg_integer()) -> binary().
generate(StaticKey, PeerAddr, Lifetime, IssuedAt) ->
    AddrBin = nquic_retry:encode_addr(PeerAddr),
    HmacInput = <<?DOMAIN_TAG/binary, Lifetime:32, IssuedAt:64, AddrBin/binary>>,
    HMAC = crypto:mac(hmac, sha256, StaticKey, HmacInput),
    <<HMAC/binary, IssuedAt:64, AddrBin/binary>>.

-doc "Validate a NEW_TOKEN token against the current peer address.".
-spec validate(binary(), binary(), nquic_socket:sockaddr()) ->
    ok | {error, invalid_new_token}.
validate(Token, StaticKey, PeerAddr) ->
    validate(Token, StaticKey, PeerAddr, ?DEFAULT_LIFETIME_S).

-spec validate(binary(), binary(), nquic_socket:sockaddr(), pos_integer()) ->
    ok | {error, invalid_new_token}.
validate(<<HMAC:32/binary, IssuedAt:64, AddrBin/binary>>, StaticKey, PeerAddr, Lifetime) ->
    HmacInput = <<?DOMAIN_TAG/binary, Lifetime:32, IssuedAt:64, AddrBin/binary>>,
    Expected = crypto:mac(hmac, sha256, StaticKey, HmacInput),
    Now = erlang:system_time(second),
    Expired = (Now - IssuedAt) > Lifetime,
    AddrMatch = (AddrBin =:= nquic_retry:encode_addr(PeerAddr)),
    maybe
        true ?= nquic_retry:hmac_equal(HMAC, Expected),
        true ?= not Expired,
        true ?= AddrMatch,
        ok
    else
        false -> {error, invalid_new_token}
    end;
validate(_, _, _, _) ->
    {error, invalid_new_token}.
