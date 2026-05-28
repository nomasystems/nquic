%%%-------------------------------------------------------------------
%%% @doc TLS 1.3 handshake records shared between nquic_tls_client and
%%% nquic_tls_server.
%%%
%%% Only the records used by *both* the client and server modules live
%%% here. Records specific to one side are defined in that module.
%%% Field shapes mirror the records OTP's `tls_handshake' module uses
%%% for `encode_handshake/2'.
%%%-------------------------------------------------------------------

-ifndef(NQUIC_TLS_HRL).
-define(NQUIC_TLS_HRL, true).

-record(key_share_entry, {
    group,
    key_exchange
}).

-record(server_hello_versions, {
    versions
}).

-endif.
