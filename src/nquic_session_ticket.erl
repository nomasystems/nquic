-module(nquic_session_ticket).
-moduledoc """
Client-side NewSessionTicket processing (RFC 8446 §4.6.1, RFC 9000 §7.4.1).

Decodes a post-handshake CRYPTO `NewSessionTicket`, derives the PSK
from the resumption secret + ticket nonce, attaches the server's
transport parameters (so a later 0-RTT connect can seed
`remote_params`), persists the ticket via the configured session
cache, and notifies the connection owner.
""".

-include("nquic_conn.hrl").
-export([process_new_session_ticket/2]).

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc """
Process a received NewSessionTicket from post-handshake CRYPTO.

`Bin` is the raw TLS handshake message (msg_type=4); anything else is
returned untouched. Updates the connection state with the cached
ticket map, persists to the configured session cache (if any), and
sends `{quic_session_ticket, _, _}` to the owner.
""".
-spec process_new_session_ticket(binary(), #conn_state{}) -> #conn_state{}.
process_new_session_ticket(<<4:8, _/binary>> = Bin, Data) ->
    case nquic_tls:decode_new_session_ticket(Bin) of
        {ok, Ticket0} ->
            Ticket1 = enrich_with_psk(Ticket0, Data),
            Ticket = enrich_with_remote_params(Ticket1, Data),
            Crypto0 = Data#conn_state.crypto,
            Data1 = Data#conn_state{
                crypto = Crypto0#conn_crypto{session_ticket = Ticket}
            },
            cache(Data1, Ticket),
            notify_owner(Data1, Ticket),
            Data1;
        {error, _} ->
            Data
    end;
process_new_session_ticket(_, Data) ->
    Data.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec cache(#conn_state{}, map()) -> ok.
cache(
    #conn_state{
        crypto = #conn_crypto{hostname = Host, session_cache = Cache},
        peer = Peer
    },
    Ticket
) when Host =/= undefined, Peer =/= undefined ->
    Port = maps:get(port, Peer, 0),
    store(Cache, Host, Port, Ticket);
cache(_, _) ->
    ok.

-spec enrich_with_psk(map(), #conn_state{}) -> map().
enrich_with_psk(
    Ticket,
    #conn_state{crypto = #conn_crypto{resumption_secret = ResSecret, cipher = Cipher}}
) when
    is_binary(ResSecret)
->
    Nonce = maps:get(nonce, Ticket, <<>>),
    Hash = nquic_keys:cipher_to_hash(Cipher),
    HashLen =
        case Hash of
            sha256 -> 32;
            sha384 -> 48
        end,
    PSK = nquic_keys:qhkdf_expand(ResSecret, <<"resumption">>, Nonce, HashLen, Hash),
    Ticket#{psk => PSK, cipher => Cipher};
enrich_with_psk(Ticket, _Data) ->
    Ticket.

-spec enrich_with_remote_params(map(), #conn_state{}) -> map().
enrich_with_remote_params(Ticket, #conn_state{remote_params = RP}) when
    RP =/= undefined
->
    Ticket#{remote_params => RP};
enrich_with_remote_params(Ticket, _Data) ->
    Ticket.

-spec notify_owner(#conn_state{}, map()) -> ok.
notify_owner(#conn_state{owner = Owner}, Ticket) when is_pid(Owner) ->
    Owner ! {quic_session_ticket, self(), Ticket},
    ok;
notify_owner(_, _) ->
    ok.

-spec store(
    atom() | false | {module, module()} | undefined,
    inet:hostname() | inet:ip_address(),
    inet:port_number(),
    map()
) -> ok.
store(false, _Host, _Port, _Ticket) ->
    ok;
store(undefined, _Host, _Port, _Ticket) ->
    ok;
store({module, Mod}, Host, Port, Ticket) ->
    Mod:store(Host, Port, Ticket);
store(Name, Host, Port, Ticket) when is_atom(Name) ->
    nquic_session_cache:store(Name, Host, Port, Ticket).
