-module(nquic_keys).

-moduledoc """
QUIC key derivation per RFC 9001 Section 5.

Derives initial, handshake, and application traffic secrets using HKDF.
Supports key update (RFC 9001 Section 6), 0-RTT early secrets, and
connection ID generation.
""".

-include("nquic_conn.hrl").
-export([
    cipher_to_hash/1,
    derive_packet_protection/3,
    early_secrets/2,
    early_secrets/3,
    generate_connection_id/0,
    generate_connection_id/1,
    handshake_secrets/2,
    handshake_secrets/3,
    handshake_secrets/4,
    initial_salt/1,
    initial_secrets/1,
    initial_secrets/2,
    local_keys/2,
    make_role_keys/4,
    master_secrets/2,
    master_secrets/3,
    peer_keys/2,

    qhkdf_expand/4,
    qhkdf_expand/5,
    resolve_role_keys/2,

    update_traffic_secret/3
]).

-export_type([role/0, role_keys/0]).

-type role() :: client | server.
-type role_keys() :: #{client := map(), server := map()}.

-define(INITIAL_SALT_V1,
    <<16#38, 16#76, 16#2c, 16#f7, 16#f5, 16#59, 16#34, 16#b3, 16#4d, 16#17, 16#9a, 16#e6, 16#a4,
        16#c8, 16#0c, 16#ad, 16#cc, 16#bb, 16#7f, 16#0a>>
).

-define(INITIAL_SALT_V2,
    <<16#0d, 16#ed, 16#e3, 16#de, 16#f7, 16#00, 16#a6, 16#db, 16#81, 16#93, 16#81, 16#be, 16#6e,
        16#26, 16#9d, 16#cb, 16#f9, 16#bd, 16#2e, 16#d9>>
).

-doc """
Derive key, IV, and header protection key from a traffic secret for a
QUIC version. RFC 9001 uses the `"quic key/iv/hp"` HKDF labels; RFC 9369
substitutes `"quicv2 key/iv/hp"` for QUIC v2 (0x6b3343cf).
""".
-spec derive_packet_protection(
    binary(), aes_128_gcm | aes_256_gcm | chacha20_poly1305, non_neg_integer()
) -> {Key :: binary(), IV :: binary(), HP :: binary()}.
derive_packet_protection(Secret, Cipher, Version) ->
    {KeyLen, IVLen, HPLen} =
        case Cipher of
            aes_128_gcm -> {16, 12, 16};
            aes_256_gcm -> {32, 12, 32};
            chacha20_poly1305 -> {32, 12, 32}
        end,
    Key = qhkdf_expand(Secret, quic_label(Version, <<" key">>), <<>>, KeyLen),
    IV = qhkdf_expand(Secret, quic_label(Version, <<" iv">>), <<>>, IVLen),
    HP = qhkdf_expand(Secret, quic_label(Version, <<" hp">>), <<>>, HPLen),
    {Key, IV, HP}.

-doc "Derive 0-RTT client secret without PSK.".
-spec early_secrets(binary(), sha256 | sha384) -> binary().
early_secrets(ClientHelloHash, Hash) ->
    early_secrets(undefined, ClientHelloHash, Hash).

-doc "Derive 0-RTT client secret with optional PSK for session resumption.".
-spec early_secrets(binary() | undefined, binary(), sha256 | sha384) -> binary().
early_secrets(PSK, ClientHelloHash, Hash) ->
    HashLen = hash_len(Hash),
    Zero = <<0:(HashLen * 8)>>,
    IKM =
        case PSK of
            undefined -> Zero;
            _ -> PSK
        end,
    EarlySecret = hkdf_extract(Hash, Zero, IKM),
    qhkdf_expand(EarlySecret, <<"c e traffic">>, ClientHelloHash, HashLen, Hash).

-doc "Derive handshake traffic secrets from shared secret and transcript hash.".
-spec handshake_secrets(binary(), binary()) ->
    {ClientSecret :: binary(), ServerSecret :: binary(), HandshakeSecret :: binary()}.
handshake_secrets(SharedSecret, TranscriptHash) ->
    handshake_secrets(SharedSecret, TranscriptHash, sha256).

-doc "Derive handshake traffic secrets with explicit hash algorithm.".
-spec handshake_secrets(binary(), binary(), sha256 | sha384) ->
    {ClientSecret :: binary(), ServerSecret :: binary(), HandshakeSecret :: binary()}.
handshake_secrets(SharedSecret, TranscriptHash, Hash) ->
    handshake_secrets(SharedSecret, TranscriptHash, Hash, undefined).

-doc """
Derive handshake traffic secrets with optional PSK (RFC 8446 Section 7.1).
When PSK is provided (session resumption), it is used as the IKM for
EarlySecret. Without PSK, zeros are used (standard non-resumption path).
""".
-spec handshake_secrets(
    binary(), binary(), sha256 | sha384, binary() | undefined
) ->
    {ClientSecret :: binary(), ServerSecret :: binary(), HandshakeSecret :: binary()}.
handshake_secrets(SharedSecret, TranscriptHash, Hash, PSK) ->
    HashLen = hash_len(Hash),
    Zero = <<0:(HashLen * 8)>>,
    IKM =
        case PSK of
            undefined -> Zero;
            _ -> PSK
        end,
    EmptyHash = crypto:hash(Hash, <<>>),
    EarlySecret = hkdf_extract(Hash, Zero, IKM),
    DerivedSecret = qhkdf_expand(EarlySecret, <<"derived">>, EmptyHash, HashLen),
    HandshakeSecret = hkdf_extract(Hash, DerivedSecret, SharedSecret),

    ClientSecret = qhkdf_expand(HandshakeSecret, <<"c hs traffic">>, TranscriptHash, HashLen),
    ServerSecret = qhkdf_expand(HandshakeSecret, <<"s hs traffic">>, TranscriptHash, HashLen),
    {ClientSecret, ServerSecret, HandshakeSecret}.

-doc "Return the initial salt for the given QUIC version.".
-spec initial_salt(non_neg_integer()) -> binary().
initial_salt(16#6b3343cf) -> ?INITIAL_SALT_V2;
initial_salt(_) -> ?INITIAL_SALT_V1.

-doc "Derive client and server initial secrets from the destination connection ID.".
-spec initial_secrets(nquic:connection_id()) ->
    {ClientSecret :: binary(), ServerSecret :: binary()}.
initial_secrets(DestCID) ->
    initial_secrets(DestCID, 1).

-doc "Derive initial secrets for the given QUIC version.".
-spec initial_secrets(nquic:connection_id(), non_neg_integer()) ->
    {ClientSecret :: binary(), ServerSecret :: binary()}.
initial_secrets(DestCID, Version) ->
    InitialSecret = hkdf_extract(sha256, initial_salt(Version), DestCID),
    ClientSecret = derive_secret(InitialSecret, <<"client in">>),
    ServerSecret = derive_secret(InitialSecret, <<"server in">>),
    {ClientSecret, ServerSecret}.

-doc """
Build a role key map from derive_packet_protection output.
For AES ciphers, includes a cached HP cipher context (`hp_ctx`) that
avoids per-packet EVP_CIPHER_CTX creation in the mask/unmask hot path.
ChaCha20 omits hp_ctx since its IV changes per packet.
""".
-spec make_role_keys(
    aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    binary(),
    binary(),
    binary()
) -> #{key := binary(), iv := binary(), hp := binary()}.
make_role_keys(chacha20_poly1305, Key, IV, HP) ->
    #{key => Key, iv => IV, hp => HP};
make_role_keys(Cipher, Key, IV, HP) ->
    #{key => Key, iv => IV, hp => HP, hp_ctx => nquic_hp:init_hp_ctx(Cipher, HP)}.

%%%-----------------------------------------------------------------------------
%% CONNECTION ID GENERATION
%%%-----------------------------------------------------------------------------
-define(DEFAULT_CID_LEN, 8).
-doc "Map a TLS cipher suite to its HKDF hash algorithm.".
-spec cipher_to_hash(aes_128_gcm | aes_256_gcm | chacha20_poly1305) -> sha256 | sha384.
cipher_to_hash(aes_128_gcm) -> sha256;
cipher_to_hash(aes_256_gcm) -> sha384;
cipher_to_hash(chacha20_poly1305) -> sha256.

-spec derive_secret(binary(), binary()) -> binary().
derive_secret(PRK, Label) ->
    qhkdf_expand(PRK, Label, <<>>, 32).

-doc "Generate a random 8-byte connection ID.".
-spec generate_connection_id() -> nquic:connection_id().
generate_connection_id() ->
    generate_connection_id(?DEFAULT_CID_LEN).

-doc "Generate a random connection ID of the given length (1-20 bytes).".
-spec generate_connection_id(pos_integer()) -> nquic:connection_id().
generate_connection_id(Len) when Len > 0, Len =< 20 ->
    crypto:strong_rand_bytes(Len).

-spec hash_len(sha256 | sha384) -> pos_integer().
hash_len(sha256) -> 32;
hash_len(sha384) -> 48.

-spec hkdf_expand(sha256 | sha384, binary(), binary(), pos_integer()) -> binary().
hkdf_expand(Hash, PRK, Info, Length) ->
    HashLen = hash_len(Hash),
    if
        Length =:= HashLen ->
            crypto:mac(hmac, Hash, PRK, <<Info/binary, 1>>);
        Length < HashLen ->
            T1 = crypto:mac(hmac, Hash, PRK, <<Info/binary, 1>>),
            binary:part(T1, 0, Length);
        true ->
            N = (Length + HashLen - 1) div HashLen,
            hkdf_expand(Hash, PRK, Info, Length, N, 1, <<>>, <<>>)
    end.

-spec hkdf_expand(
    sha256 | sha384,
    binary(),
    binary(),
    pos_integer(),
    non_neg_integer(),
    pos_integer(),
    binary(),
    binary()
) -> binary().
hkdf_expand(_Hash, _PRK, _Info, Length, _N, _I, _T, Acc) when byte_size(Acc) >= Length ->
    <<Result:Length/binary, _/binary>> = Acc,
    Result;
hkdf_expand(Hash, PRK, Info, Length, N, I, T, Acc) ->
    NI = crypto:mac(hmac, Hash, PRK, <<T/binary, Info/binary, I:8>>),
    hkdf_expand(Hash, PRK, Info, Length, N, I + 1, NI, <<Acc/binary, NI/binary>>).

-spec hkdf_extract(sha256 | sha384, binary(), binary()) -> binary().
hkdf_extract(Hash, Salt, IKM) ->
    crypto:mac(hmac, Hash, Salt, IKM).

-doc """
Return the local role's packet protection keys from a `#{client => _, server => _}`
map. The local side uses these to encrypt outbound packets.
""".
-spec local_keys(role(), role_keys()) -> map().
local_keys(client, #{client := Keys}) -> Keys;
local_keys(server, #{server := Keys}) -> Keys.

-doc "Derive application traffic secrets from handshake secret and transcript hash.".
-spec master_secrets(binary(), binary()) -> {ClientSecret :: binary(), ServerSecret :: binary()}.
master_secrets(HandshakeSecret, TranscriptHash) ->
    master_secrets(HandshakeSecret, TranscriptHash, sha256).

-doc "Derive application traffic secrets with explicit hash algorithm.".
-spec master_secrets(binary(), binary(), sha256 | sha384) ->
    {ClientSecret :: binary(), ServerSecret :: binary()}.
master_secrets(HandshakeSecret, TranscriptHash, Hash) ->
    HashLen = hash_len(Hash),
    Zero = <<0:(HashLen * 8)>>,
    EmptyHash = crypto:hash(Hash, <<>>),
    DerivedSecret = qhkdf_expand(HandshakeSecret, <<"derived">>, EmptyHash, HashLen),
    MasterSecret = hkdf_extract(Hash, DerivedSecret, Zero),

    ClientSecret = qhkdf_expand(MasterSecret, <<"c ap traffic">>, TranscriptHash, HashLen),
    ServerSecret = qhkdf_expand(MasterSecret, <<"s ap traffic">>, TranscriptHash, HashLen),
    {ClientSecret, ServerSecret}.

-doc """
Return the peer role's packet protection keys from a `#{client => _, server => _}`
map. The local side uses these to decrypt inbound packets.
""".
-spec peer_keys(role(), role_keys()) -> map().
peer_keys(client, #{server := Keys}) -> Keys;
peer_keys(server, #{client := Keys}) -> Keys.

-doc "QUIC HKDF-Expand-Label with sha256 default.".
-spec qhkdf_expand(binary(), binary(), binary(), pos_integer()) -> binary().
qhkdf_expand(PRK, Label, Context, Length) ->
    qhkdf_expand(PRK, Label, Context, Length, sha256).

-doc "QUIC HKDF-Expand-Label with explicit hash algorithm.".
-spec qhkdf_expand(binary(), binary(), binary(), pos_integer(), sha256 | sha384) -> binary().
qhkdf_expand(PRK, Label, Context, Length, Hash) ->
    FullLabel = <<"tls13 ", Label/binary>>,
    CtxLen = byte_size(Context),
    Info = <<Length:16, (byte_size(FullLabel)):8, FullLabel/binary, CtxLen:8, Context/binary>>,
    hkdf_expand(Hash, PRK, Info, Length).

-spec quic_label(non_neg_integer(), binary()) -> binary().
quic_label(16#6b3343cf, Suffix) -> <<"quicv2", Suffix/binary>>;
quic_label(_Version, Suffix) -> <<"quic", Suffix/binary>>.

-doc """
Resolve a `role_keys()` map into `{LocalKeys, PeerKeys}` for the given
role. Convenience used at app-keys install time to populate the
per-role caches on `#conn_crypto{}` (`app_send_keys` / `app_recv_keys`)
in one map walk instead of separate `local_keys/2` + `peer_keys/2`
calls.
""".
-spec resolve_role_keys(role(), role_keys()) -> {Local :: map(), Peer :: map()}.
resolve_role_keys(client, #{client := C, server := S}) -> {C, S};
resolve_role_keys(server, #{client := C, server := S}) -> {S, C}.

-doc """
Derive next traffic secret, key, and IV for key update.
RFC 9001 uses the `"quic ku"` label; RFC 9369 substitutes `"quicv2 ku"`
for QUIC v2.
""".
-spec update_traffic_secret(
    binary(), aes_128_gcm | aes_256_gcm | chacha20_poly1305, non_neg_integer()
) -> {NewSecret :: binary(), Key :: binary(), IV :: binary()}.
update_traffic_secret(CurrentSecret, Cipher, Version) ->
    Hash = cipher_to_hash(Cipher),
    HashLen = hash_len(Hash),
    NewSecret = qhkdf_expand(CurrentSecret, quic_label(Version, <<" ku">>), <<>>, HashLen, Hash),
    {Key, IV, _HP} = derive_packet_protection(NewSecret, Cipher, Version),
    {NewSecret, Key, IV}.
