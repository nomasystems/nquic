-module(nquic_handshake).
-moduledoc """
QUIC handshake management.

This module handles TLS 1.3 handshake integration, key derivation,
and handshake packet construction for QUIC connections.
""".

-include("nquic_frame.hrl").
-export([derive_initial_keys/1, derive_initial_keys/2]).
-export([install_app_keys/2, install_handshake_keys/2]).
-export([format_keys/1, format_keys/2]).
-export([build_handshake_frames/1, build_initial_frames/1]).

-doc "Build frames for a Handshake packet with CRYPTO data.".
-spec build_handshake_frames(binary()) -> [nquic_frame:t()].
build_handshake_frames(CryptoData) ->
    [#crypto{offset = 0, data = CryptoData}].

-doc "Build frames for an Initial packet with CRYPTO data.".
-spec build_initial_frames(binary()) -> [nquic_frame:t()].
build_initial_frames(CryptoData) ->
    [#crypto{offset = 0, data = CryptoData}].

-doc "Derive initial encryption keys from DCID per RFC 9001.".
-spec derive_initial_keys(nquic:connection_id()) ->
    #{
        client := #{key := binary(), iv := binary(), hp := binary()},
        server := #{key := binary(), iv := binary(), hp := binary()}
    }.
derive_initial_keys(DCID) ->
    derive_initial_keys(DCID, 1).

-doc "Derive initial encryption keys from DCID for a specific QUIC version.".
-spec derive_initial_keys(nquic:connection_id(), non_neg_integer()) ->
    #{
        client := #{key := binary(), iv := binary(), hp := binary()},
        server := #{key := binary(), iv := binary(), hp := binary()}
    }.
derive_initial_keys(DCID, Version) ->
    {ClientSecret, ServerSecret} = nquic_keys:initial_secrets(DCID, Version),
    {CKey, CIV, CHP} = nquic_keys:derive_packet_protection(ClientSecret, aes_128_gcm, Version),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(ServerSecret, aes_128_gcm, Version),

    #{
        client => nquic_keys:make_role_keys(aes_128_gcm, CKey, CIV, CHP),
        server => nquic_keys:make_role_keys(aes_128_gcm, SKey, SIV, SHP)
    }.

-doc "Convert TLS key material to packet protection format.".
-spec format_keys(map()) ->
    #{
        client := #{key := binary(), iv := binary(), hp := binary()},
        server := #{key := binary(), iv := binary(), hp := binary()}
    }.
format_keys(Keys) ->
    #{
        client => #{
            key => maps:get(client_key, Keys),
            iv => maps:get(client_iv, Keys),
            hp => maps:get(client_hp, Keys)
        },
        server => #{
            key => maps:get(server_key, Keys),
            iv => maps:get(server_iv, Keys),
            hp => maps:get(server_hp, Keys)
        }
    }.

-doc "Convert TLS key material to packet protection format with cached HP context.".
-spec format_keys(map(), aes_128_gcm | aes_256_gcm | chacha20_poly1305) ->
    #{
        client := #{key := binary(), iv := binary(), hp := binary()},
        server := #{key := binary(), iv := binary(), hp := binary()}
    }.
format_keys(Keys, Cipher) ->
    CK = maps:get(client_key, Keys),
    CIV = maps:get(client_iv, Keys),
    CHP = maps:get(client_hp, Keys),
    SK = maps:get(server_key, Keys),
    SIV = maps:get(server_iv, Keys),
    SHP = maps:get(server_hp, Keys),
    #{
        client => nquic_keys:make_role_keys(Cipher, CK, CIV, CHP),
        server => nquic_keys:make_role_keys(Cipher, SK, SIV, SHP)
    }.

-doc "Format and install application keys from TLS-derived secrets.".
-spec install_app_keys(map(), map()) ->
    #{
        application := #{
            client := #{key := binary(), iv := binary(), hp := binary()},
            server := #{key := binary(), iv := binary(), hp := binary()}
        }
    }.
install_app_keys(Keys, ExistingKeys) ->
    FormattedKeys = format_keys(Keys),
    ExistingKeys#{application => FormattedKeys}.

-doc "Format and install handshake keys from TLS-derived secrets.".
-spec install_handshake_keys(map(), map()) ->
    #{
        handshake := #{
            client := #{key := binary(), iv := binary(), hp := binary()},
            server := #{key := binary(), iv := binary(), hp := binary()}
        }
    }.
install_handshake_keys(Keys, ExistingKeys) ->
    FormattedKeys = format_keys(Keys),
    ExistingKeys#{handshake => FormattedKeys}.
