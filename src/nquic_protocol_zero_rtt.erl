-module(nquic_protocol_zero_rtt).
-moduledoc """
0-RTT (early data) packet-protection key installation.

Derives and installs the client 0-RTT keys into `#conn_state{}` for
both the resumption-less path (keyed off the ClientHello hash) and the
PSK resumption path (keyed off the pre-shared key). RFC 9001 §4.3 /
RFC 8446 §7.1 early secret derivation. Behaviour is identical for both
entry points except the early-secret input.
""".

-include("nquic_conn.hrl").
-export([
    install_zero_rtt_keys/3,
    install_zero_rtt_keys_psk/4
]).

-type cipher() :: aes_128_gcm | aes_256_gcm | chacha20_poly1305.

-spec install(binary(), cipher(), nquic_protocol:state()) -> nquic_protocol:state().
install(EarlySecret, Cipher, State) ->
    Version = State#conn_state.version,
    {Key, IV, HP} = nquic_keys:derive_packet_protection(EarlySecret, Cipher, Version),
    ZeroRTTKeys = #{client => nquic_keys:make_role_keys(Cipher, Key, IV, HP)},
    Crypto0 = State#conn_state.crypto,
    NewKeys = (Crypto0#conn_crypto.keys)#{rtt0 => ZeroRTTKeys},
    State#conn_state{crypto = Crypto0#conn_crypto{keys = NewKeys}}.

-doc "Install 0-RTT keys derived from the ClientHello hash and cipher.".
-spec install_zero_rtt_keys(binary(), cipher(), nquic_protocol:state()) ->
    nquic_protocol:state().
install_zero_rtt_keys(ClientHelloHash, Cipher, State) ->
    Hash = nquic_keys:cipher_to_hash(Cipher),
    EarlySecret = nquic_keys:early_secrets(ClientHelloHash, Hash),
    install(EarlySecret, Cipher, State).

-doc "Install 0-RTT keys with a pre-shared key from session resumption.".
-spec install_zero_rtt_keys_psk(binary(), binary(), cipher(), nquic_protocol:state()) ->
    nquic_protocol:state().
install_zero_rtt_keys_psk(PSK, ClientHelloHash, Cipher, State) ->
    Hash = nquic_keys:cipher_to_hash(Cipher),
    EarlySecret = nquic_keys:early_secrets(PSK, ClientHelloHash, Hash),
    install(EarlySecret, Cipher, State).
