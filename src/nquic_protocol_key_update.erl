-module(nquic_protocol_key_update).
-moduledoc """
QUIC key update (RFC 9001 Section 6).

Pure functions over `#conn_state{}` implementing 1-RTT key rotation:
deriving the next application traffic secrets, flipping the key phase,
and tracking the previous read keys so packets sent with the old phase
can still be decrypted during the transition. External side effects
are limited to `nquic_keys`.
""".

-include("nquic_conn.hrl").
-include("nquic_packet.hrl").
-export([
    initiate_key_update/1,
    maybe_handle_key_update/2,
    perform_key_update/1
]).

-spec initiate_key_update(nquic_protocol:state()) ->
    {ok, nquic_protocol:state()} | {error, key_update_pending}.
initiate_key_update(#conn_state{crypto = #conn_crypto{key_update_pending = true}}) ->
    {error, key_update_pending};
initiate_key_update(State) ->
    NewState = perform_key_update(State),
    Crypto1 = NewState#conn_state.crypto,
    {ok, NewState#conn_state{crypto = Crypto1#conn_crypto{key_update_pending = true}}}.

-spec maybe_handle_key_update(nquic_packet:header(), nquic_protocol:state()) ->
    nquic_protocol:state().
maybe_handle_key_update(#short_header{key_phase = RecvKP}, State) ->
    Crypto0 = State#conn_state.crypto,
    #conn_crypto{key_phase = CurrentKP, key_update_pending = Pending} = Crypto0,
    case RecvKP =:= CurrentKP andalso Pending of
        true ->
            State#conn_state{crypto = Crypto0#conn_crypto{key_update_pending = false}};
        false ->
            State
    end;
maybe_handle_key_update(_LongHeader, State) ->
    State.

-spec perform_key_update(nquic_protocol:state()) -> nquic_protocol:state().
perform_key_update(State) ->
    #conn_state{role = Role, version = Version, crypto = Crypto0} = State,
    #conn_crypto{
        cipher = Cipher,
        keys = Keys,
        key_phase = CurrentKP,
        app_recv_keys = OldPeerKeys,
        client_app_secret = ClientSecret,
        server_app_secret = ServerSecret
    } = Crypto0,
    #{application := AppKeys} = Keys,
    #{client := CKeys, server := SKeys} = AppKeys,
    #{key := OldKey, iv := OldIV} = OldPeerKeys,
    OldReadKeys = #{key => OldKey, iv => OldIV},
    {NewClientSecret, NewCKey, NewCIV} = nquic_keys:update_traffic_secret(
        ClientSecret, Cipher, Version
    ),
    {NewServerSecret, NewSKey, NewSIV} = nquic_keys:update_traffic_secret(
        ServerSecret, Cipher, Version
    ),
    NewAppKeys = #{
        client => CKeys#{key => NewCKey, iv => NewCIV},
        server => SKeys#{key => NewSKey, iv => NewSIV}
    },
    {NewSendKeys, NewRecvKeys} = nquic_keys:resolve_role_keys(Role, NewAppKeys),
    NewCrypto = Crypto0#conn_crypto{
        keys = Keys#{application => NewAppKeys},
        app_send_keys = NewSendKeys,
        app_recv_keys = NewRecvKeys,
        key_phase = not CurrentKP,
        client_app_secret = NewClientSecret,
        server_app_secret = NewServerSecret,
        old_read_keys = OldReadKeys
    },
    State#conn_state{crypto = NewCrypto}.
