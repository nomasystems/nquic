-module(nquic_error).

-moduledoc """
Canonical error taxonomy for `nquic`.

Every error that crosses the public surface of `nquic` or `nquic_lib`
is shaped by this module so callers can pattern-match exhaustively on
`nquic:error_reason()/0`.

Two responsibilities:

* Constructors: `closed/0`, `timeout/1`, `transport/1`, `tls/1`,
  `application/2`, `protocol/1`, `flow_control/1`, `opts/1`,
  `connect/1`, `listen/1` return canonical `{error, error_reason()}`
  tuples. Use them at sites that already know which bucket the term
  belongs to.
* Mappers: `from_socket/2`, `from_tls_alert/1`, `from_handshake/1`,
  `from_connection_close/1`, `wrap/1`, `wrap_result/1` translate raw
  upstream shapes (POSIX atoms, TLS alerts, `#connection_close{}`
  records, internal atoms) into the canonical sum.

`wrap/1` is the single funnel for unknown error terms at the public
boundary; already-canonical values pass through unchanged.

## Error-handling convention contract

`t:nquic:error_reason/0` is a **closed**, `{error, _}`-wrapped,
category-classified tagged union. The *supported* way to interrogate
a value is the trio:

* `category/1`: one atom from the small closed set
  `closed | timeout | transport | tls | application | protocol |
  flow_control | opts | connect | listen` (never crashes on a
  canonical value).
* `is_retryable/1`: `boolean()`.
* `format/1`: human-readable `iodata()`.

Callers should classify and branch via these functions, **not** by
pattern-matching the inner shape (which may gain arms within a
category without a major version bump; the category set will not).

This is the same convention `nhttp_error` follows
(`{error, {category(), reason()}}` plus its own
`category/1` / `is_retryable/1` / `format/1`). The two taxonomies are
therefore *structurally parallel by convention*, not coupled: nquic
ships **no** adapter and depends on no HTTP library. A consumer that
needs to project nquic failures into its own error vocabulary writes
a small total adapter over `category/1` **at its own boundary**. nquic
deliberately does not know nhttp exists, so it stays reusable by any
non-HTTP QUIC consumer and independently releasable.
""".

-include("nquic_frame.hrl").
%%%-----------------------------------------------------------------------------
%% EXPORTS - CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-export([
    application/2,
    closed/0,
    connect/1,
    flow_control/1,
    listen/1,
    opts/1,
    protocol/1,
    timeout/1,
    tls/1,
    transport/1
]).

%%%-----------------------------------------------------------------------------
%% EXPORTS - MAPPERS
%%%-----------------------------------------------------------------------------
-export([
    from_connection_close/1,
    from_handshake/1,
    from_socket/2,
    from_tls_alert/1,
    wrap/1,
    wrap_reason/1,
    wrap_result/1
]).

%%%-----------------------------------------------------------------------------
%% EXPORTS - HELPERS
%%%-----------------------------------------------------------------------------
-export([
    category/1,
    format/1,
    is_retryable/1
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-export_type([
    any_reason/0,
    application_reason/0,
    category/0,
    error_reason/0,
    flow_control_reason/0,
    opts_reason/0,
    protocol_reason/0,
    timeout_phase/0,
    tls_reason/0,
    transport_reason/0
]).

-doc "Phase tag for `{timeout, Phase}` outcomes.".
-type timeout_phase() :: handshake | idle | recv | send | accept.

-doc "Transport-domain error reasons (peer CONNECTION_CLOSE 0x1c or local I/O).".
-type transport_reason() ::
    no_error
    | internal_error
    | connection_refused
    | flow_control_error
    | stream_limit_error
    | stream_state_error
    | final_size_error
    | frame_encoding_error
    | transport_parameter_error
    | connection_id_limit_error
    | protocol_violation
    | invalid_token
    | application_error
    | crypto_buffer_exceeded
    | key_update_error
    | aead_limit_reached
    | no_viable_path
    | crypto_error
    | idle_timeout
    | stateless_reset
    | version_negotiation
    | closed_by_peer
    | {posix, inet:posix()}
    | {peer_close, non_neg_integer(), binary()}.

-doc "TLS-layer error reasons (peer alerts or local handshake validation).".
-type tls_reason() ::
    unexpected_message
    | handshake_failure
    | bad_certificate
    | unsupported_certificate
    | certificate_revoked
    | certificate_expired
    | certificate_unknown
    | illegal_parameter
    | unknown_ca
    | access_denied
    | decode_error
    | decrypt_error
    | protocol_version
    | insufficient_security
    | internal_error
    | inappropriate_fallback
    | user_canceled
    | missing_extension
    | unsupported_extension
    | unrecognized_name
    | bad_certificate_status_response
    | unknown_psk_identity
    | certificate_required
    | no_application_protocol
    | no_psk
    | no_matching_psk
    | no_static_key
    | no_peercert
    | binder_mismatch
    | binder_verification_failed
    | psk_identity_binder_mismatch
    | client_finished_verification_failed
    | malformed_finished
    | malformed_new_session_ticket
    | not_new_session_ticket
    | invalid_ticket_cipher
    | invalid_ticket_format
    | ticket_decrypt_failed
    | ticket_too_short
    | {bad_cert, dynamic()}
    | {hostname_mismatch, binary()}
    | {alert, atom()}.

-doc "Protocol-level errors: wire format, parser, RFC 9000 violations.".
-type protocol_reason() ::
    protocol_violation
    | frame_encoding_error
    | packet_too_short
    | integrity_check_failed
    | final_size_error
    | migration_disabled
    | duplicate_parameter
    | truncated_param_value
    | transport_parameter_error
    | no_available_cids
    | retry_token_too_short
    | invalid_retry_token
    | datagrams_not_negotiated
    | datagram_too_large
    | invalid_packet
    | incomplete_binary
    | key_update_pending
    | no_initial_keys
    | no_zero_rtt_keys
    | no_probe_needed
    | overflow
    | stream_state_error
    | decrypt_failed
    | {transport_parameter_error, atom()}
    | {processing_failed, dynamic()}
    | {encoding_failed, dynamic()}
    | {flight_generation_failed, dynamic()}
    | {decrypt_failed, dynamic()}.

-doc "Flow control or congestion-control blocking outcomes.".
-type flow_control_reason() ::
    flow_control_error
    | stream_limit_error
    | congestion_control_blocked
    | eagain
    | partial_send
    | stream_blocked.

-doc "Options / configuration / API-misuse errors.".
-type opts_reason() ::
    not_owner
    | not_found
    | not_connected
    | not_established
    | not_writable
    | unknown_request
    | unknown_stream
    | invalid_stream
    | invalid_stream_id
    | stream_not_found
    | stream_closed
    | stream_reset
    | empty
    | no_data
    | sups_not_ready
    | draining
    | ctx_requires_wait
    | not_supported_in_mode
    | {missing_option, atom()}
    | {misplaced_option, atom()}
    | {certfile, atom()}
    | {unsupported_cipher_suite, binary() | atom()}
    | {already_started, pid()}.

-doc "Application-domain close reason carrying peer error code and phrase.".
-type application_reason() :: {non_neg_integer(), binary()}.

-doc """
Closed error taxonomy returned by every public function. The outer arm
classifies the failure; the inner value carries detail without growing
the union.
""".
-type error_reason() ::
    closed
    | fin
    | {timeout, timeout_phase()}
    | {transport, transport_reason()}
    | {tls, tls_reason()}
    | {application, non_neg_integer(), binary()}
    | {protocol, protocol_reason()}
    | {flow_control, flow_control_reason()}
    | {opts, opts_reason()}
    | {connect, inet:posix() | atom()}
    | {listen, inet:posix() | atom()}.

-doc """
Wide internal error type carried by modules that have not yet been
funnelled through a constructor. Callers at the public boundary must
pass these through `wrap/1` before returning to the user.
""".
-type any_reason() ::
    error_reason()
    | atom()
    | tuple()
    | binary()
    | map()
    | list()
    | integer().

-doc "Category tag returned by `category/1`, useful for telemetry.".
-type category() ::
    closed
    | timeout
    | transport
    | tls
    | application
    | protocol
    | flow_control
    | opts
    | connect
    | listen.

%%%-----------------------------------------------------------------------------
%% CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc "Application-domain CONNECTION_CLOSE from the peer.".
-spec application(non_neg_integer(), binary()) -> {error, error_reason()}.
application(Code, Reason) when is_integer(Code), Code >= 0, is_binary(Reason) ->
    {error, {application, Code, Reason}}.

-doc "Terminal connection state.".
-spec closed() -> {error, error_reason()}.
closed() ->
    {error, closed}.

-doc "Client-side DNS / socket open / connect failure (POSIX atom).".
-spec connect(inet:posix() | atom()) -> {error, error_reason()}.
connect(Reason) when is_atom(Reason) ->
    {error, {connect, Reason}}.

-doc "Local flow control / congestion blocking.".
-spec flow_control(flow_control_reason()) -> {error, error_reason()}.
flow_control(Reason) ->
    {error, {flow_control, Reason}}.

-doc "Server-side socket bind / listen failure (POSIX atom).".
-spec listen(inet:posix() | atom()) -> {error, error_reason()}.
listen(Reason) when is_atom(Reason) ->
    {error, {listen, Reason}}.

-doc "Options / configuration / API-misuse error.".
-spec opts(opts_reason()) -> {error, error_reason()}.
opts(Reason) ->
    {error, {opts, Reason}}.

-doc "Wire-format / protocol violation detected locally.".
-spec protocol(protocol_reason()) -> {error, error_reason()}.
protocol(Reason) ->
    {error, {protocol, Reason}}.

-doc "Timeout in a named phase.".
-spec timeout(timeout_phase()) -> {error, error_reason()}.
timeout(Phase) when
    Phase =:= handshake;
    Phase =:= idle;
    Phase =:= recv;
    Phase =:= send;
    Phase =:= accept
->
    {error, {timeout, Phase}}.

-doc "TLS-layer error: peer alert or local handshake validation.".
-spec tls(tls_reason()) -> {error, error_reason()}.
tls(Reason) ->
    {error, {tls, Reason}}.

-doc "Transport-layer error: peer CONNECTION_CLOSE (0x1c) or local I/O.".
-spec transport(transport_reason()) -> {error, error_reason()}.
transport(Reason) ->
    {error, {transport, Reason}}.

%%%-----------------------------------------------------------------------------
%% MAPPERS
%%%-----------------------------------------------------------------------------
-doc """
Map a peer-sent `#connection_close{}` record to a canonical
`{transport, _}` or `{application, Code, Reason}` error.
""".
-spec from_connection_close(#connection_close{}) -> {error, error_reason()}.
from_connection_close(#connection_close{is_application = true, error_code = Code, reason_phrase = R}) ->
    {error, {application, Code, R}};
from_connection_close(#connection_close{error_code = Code, reason_phrase = R}) ->
    {error, {transport, {peer_close, Code, R}}}.

-doc """
Map a TLS-handshake-side internal failure (no-PSK, binder mismatch,
malformed finished, ...) to a canonical `{tls, _}` error.
""".
-spec from_handshake(atom() | tuple()) -> {error, error_reason()}.
from_handshake({bad_cert, _} = Reason) ->
    {error, {tls, Reason}};
from_handshake({hostname_mismatch, _} = Reason) ->
    {error, {tls, Reason}};
from_handshake({Tag, _} = Reason) when is_atom(Tag) ->
    {error, {tls, Reason}};
from_handshake(Reason) when is_atom(Reason) ->
    {error, {tls, Reason}}.

-doc """
Map a raw POSIX atom from a `socket` / `inet` call to the matching
canonical bucket according to which operation produced it.
`Origin` is one of `connect`, `listen`, `transport`.
""".
-spec from_socket(connect | listen | transport, inet:posix() | atom()) ->
    {error, error_reason()}.
from_socket(connect, Reason) when is_atom(Reason) ->
    {error, {connect, Reason}};
from_socket(listen, Reason) when is_atom(Reason) ->
    {error, {listen, Reason}};
from_socket(transport, Reason) when is_atom(Reason) ->
    {error, {transport, {posix, Reason}}}.

-doc """
Map a TLS alert atom or `{tls_alert, _}` record to a canonical
`{tls, _}` error.
""".
-spec from_tls_alert(atom() | tuple()) -> {error, error_reason()}.
from_tls_alert({tls_alert, Alert}) when is_atom(Alert) ->
    {error, {tls, Alert}};
from_tls_alert({tls_alert, Alert, _Reason}) when is_atom(Alert) ->
    {error, {tls, Alert}};
from_tls_alert(Alert) when is_atom(Alert) ->
    {error, {tls, Alert}}.

-doc """
Normalise any term into the canonical taxonomy. Already-canonical values
pass through unchanged.
""".
-spec wrap(term()) -> {error, error_reason()}.
wrap({error, Reason}) ->
    wrap_reason(Reason);
wrap(Reason) ->
    wrap_reason(Reason).

-doc """
Wrap an `{ok, _} | {error, _}` result so the error arm is canonical.
The `ok` and `{ok, _}` arms pass through unchanged.
""".
-spec wrap_result(ok | {ok, T} | {error, term()}) ->
    ok | {ok, T} | {error, error_reason()}.
wrap_result(ok) ->
    ok;
wrap_result({ok, _} = Ok) ->
    Ok;
wrap_result({error, _} = Error) ->
    wrap(Error).

%%%-----------------------------------------------------------------------------
%% HELPERS
%%%-----------------------------------------------------------------------------
-doc "Category tag for telemetry / log fields.".
-spec category(error_reason()) -> category().
category(closed) -> closed;
category(fin) -> closed;
category({timeout, _}) -> timeout;
category({transport, _}) -> transport;
category({tls, _}) -> tls;
category({application, _, _}) -> application;
category({protocol, _}) -> protocol;
category({flow_control, _}) -> flow_control;
category({opts, _}) -> opts;
category({connect, _}) -> connect;
category({listen, _}) -> listen.

-doc "Human-readable rendering for log lines.".
-spec format(error_reason()) -> iolist().
format(closed) ->
    "connection closed";
format(fin) ->
    "stream FIN received; end of stream";
format({timeout, Phase}) ->
    io_lib:format("timeout in ~p phase", [Phase]);
format({transport, {peer_close, Code, <<>>}}) ->
    io_lib:format("peer closed: transport error code ~b", [Code]);
format({transport, {peer_close, Code, Reason}}) ->
    io_lib:format("peer closed: transport error code ~b (~s)", [Code, Reason]);
format({transport, {posix, P}}) ->
    io_lib:format("transport I/O error: ~p", [P]);
format({transport, R}) ->
    io_lib:format("transport error: ~p", [R]);
format({tls, R}) ->
    io_lib:format("TLS error: ~p", [R]);
format({application, Code, <<>>}) ->
    io_lib:format("application close: code ~b", [Code]);
format({application, Code, Reason}) ->
    io_lib:format("application close: code ~b (~s)", [Code, Reason]);
format({protocol, R}) ->
    io_lib:format("protocol error: ~p", [R]);
format({flow_control, R}) ->
    io_lib:format("flow control: ~p", [R]);
format({opts, R}) ->
    io_lib:format("options error: ~p", [R]);
format({connect, R}) ->
    io_lib:format("connect failed: ~p", [R]);
format({listen, R}) ->
    io_lib:format("listen failed: ~p", [R]).

-doc "Whether the caller may sensibly retry after this error.".
-spec is_retryable(error_reason()) -> boolean().
is_retryable(closed) -> false;
is_retryable(fin) -> false;
is_retryable({timeout, idle}) -> true;
is_retryable({timeout, recv}) -> true;
is_retryable({timeout, _}) -> false;
is_retryable({transport, no_error}) -> true;
is_retryable({transport, version_negotiation}) -> true;
is_retryable({transport, stateless_reset}) -> true;
is_retryable({transport, idle_timeout}) -> true;
is_retryable({transport, {posix, etimedout}}) -> true;
is_retryable({transport, _}) -> false;
is_retryable({tls, _}) -> false;
is_retryable({application, _, _}) -> false;
is_retryable({protocol, _}) -> false;
is_retryable({flow_control, eagain}) -> true;
is_retryable({flow_control, congestion_control_blocked}) -> true;
is_retryable({flow_control, stream_blocked}) -> true;
is_retryable({flow_control, _}) -> false;
is_retryable({opts, _}) -> false;
is_retryable({connect, econnrefused}) -> true;
is_retryable({connect, etimedout}) -> true;
is_retryable({connect, ehostunreach}) -> true;
is_retryable({connect, enetunreach}) -> true;
is_retryable({connect, _}) -> false;
is_retryable({listen, _}) -> false.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec bucket_for_atom(atom()) ->
    closed
    | {timeout, timeout_phase()}
    | flow_control
    | protocol
    | tls
    | transport
    | opts
    | connect
    | listen
    | unknown.
%% closed bucket
bucket_for_atom(closed) -> closed;
bucket_for_atom(closed_by_peer) -> closed;
%% timeout bucket
bucket_for_atom(timeout) -> {timeout, recv};
bucket_for_atom(send_timeout) -> {timeout, send};
%% transport bucket
bucket_for_atom(no_error) -> transport;
bucket_for_atom(internal_error) -> transport;
bucket_for_atom(connection_refused) -> transport;
bucket_for_atom(connection_id_limit_error) -> transport;
bucket_for_atom(invalid_token) -> transport;
bucket_for_atom(application_error) -> transport;
bucket_for_atom(crypto_buffer_exceeded) -> transport;
bucket_for_atom(key_update_error) -> transport;
bucket_for_atom(aead_limit_reached) -> transport;
bucket_for_atom(no_viable_path) -> transport;
bucket_for_atom(crypto_error) -> transport;
bucket_for_atom(idle_timeout) -> transport;
bucket_for_atom(stateless_reset) -> transport;
bucket_for_atom(version_negotiation) -> transport;
%% flow control bucket
bucket_for_atom(flow_control_error) -> flow_control;
bucket_for_atom(stream_limit_error) -> flow_control;
bucket_for_atom(congestion_control_blocked) -> flow_control;
bucket_for_atom(eagain) -> flow_control;
bucket_for_atom(partial_send) -> flow_control;
bucket_for_atom(stream_blocked) -> flow_control;
%% protocol bucket
bucket_for_atom(protocol_violation) -> protocol;
bucket_for_atom(frame_encoding_error) -> protocol;
bucket_for_atom(packet_too_short) -> protocol;
bucket_for_atom(integrity_check_failed) -> protocol;
bucket_for_atom(final_size_error) -> protocol;
bucket_for_atom(migration_disabled) -> protocol;
bucket_for_atom(duplicate_parameter) -> protocol;
bucket_for_atom(truncated_param_value) -> protocol;
bucket_for_atom(transport_parameter_error) -> protocol;
bucket_for_atom(no_available_cids) -> protocol;
bucket_for_atom(retry_token_too_short) -> protocol;
bucket_for_atom(invalid_retry_token) -> protocol;
bucket_for_atom(datagrams_not_negotiated) -> protocol;
bucket_for_atom(datagram_too_large) -> protocol;
bucket_for_atom(invalid_packet) -> protocol;
bucket_for_atom(incomplete_binary) -> protocol;
bucket_for_atom(key_update_pending) -> protocol;
bucket_for_atom(no_initial_keys) -> protocol;
bucket_for_atom(no_zero_rtt_keys) -> protocol;
bucket_for_atom(no_probe_needed) -> protocol;
bucket_for_atom(overflow) -> protocol;
bucket_for_atom(stream_state_error) -> protocol;
bucket_for_atom(decrypt_failed) -> protocol;
%% tls bucket
bucket_for_atom(no_psk) -> tls;
bucket_for_atom(no_matching_psk) -> tls;
bucket_for_atom(no_static_key) -> tls;
bucket_for_atom(no_peercert) -> tls;
bucket_for_atom(binder_mismatch) -> tls;
bucket_for_atom(binder_verification_failed) -> tls;
bucket_for_atom(psk_identity_binder_mismatch) -> tls;
bucket_for_atom(client_finished_verification_failed) -> tls;
bucket_for_atom(malformed_finished) -> tls;
bucket_for_atom(malformed_new_session_ticket) -> tls;
bucket_for_atom(not_new_session_ticket) -> tls;
bucket_for_atom(invalid_ticket_cipher) -> tls;
bucket_for_atom(invalid_ticket_format) -> tls;
bucket_for_atom(ticket_decrypt_failed) -> tls;
bucket_for_atom(ticket_too_short) -> tls;
bucket_for_atom(unexpected_message) -> tls;
bucket_for_atom(handshake_failure) -> tls;
bucket_for_atom(bad_certificate) -> tls;
bucket_for_atom(unsupported_certificate) -> tls;
bucket_for_atom(certificate_revoked) -> tls;
bucket_for_atom(certificate_expired) -> tls;
bucket_for_atom(certificate_unknown) -> tls;
bucket_for_atom(illegal_parameter) -> tls;
bucket_for_atom(unknown_ca) -> tls;
bucket_for_atom(access_denied) -> tls;
bucket_for_atom(decode_error) -> tls;
bucket_for_atom(decrypt_error) -> tls;
bucket_for_atom(protocol_version) -> tls;
bucket_for_atom(insufficient_security) -> tls;
bucket_for_atom(inappropriate_fallback) -> tls;
bucket_for_atom(user_canceled) -> tls;
bucket_for_atom(missing_extension) -> tls;
bucket_for_atom(unsupported_extension) -> tls;
bucket_for_atom(unrecognized_name) -> tls;
bucket_for_atom(bad_certificate_status_response) -> tls;
bucket_for_atom(unknown_psk_identity) -> tls;
bucket_for_atom(certificate_required) -> tls;
bucket_for_atom(no_application_protocol) -> tls;
%% opts bucket
bucket_for_atom(not_owner) -> opts;
bucket_for_atom(not_found) -> opts;
bucket_for_atom(not_connected) -> opts;
bucket_for_atom(not_established) -> opts;
bucket_for_atom(not_writable) -> opts;
bucket_for_atom(unknown_request) -> opts;
bucket_for_atom(unknown_stream) -> opts;
bucket_for_atom(invalid_stream) -> opts;
bucket_for_atom(invalid_stream_id) -> opts;
bucket_for_atom(stream_not_found) -> opts;
bucket_for_atom(stream_closed) -> opts;
bucket_for_atom(stream_reset) -> opts;
bucket_for_atom(empty) -> opts;
bucket_for_atom(no_data) -> opts;
bucket_for_atom(sups_not_ready) -> opts;
bucket_for_atom(draining) -> opts;
%% connect bucket (POSIX atoms returned from getaddr/connect/open)
bucket_for_atom(econnrefused) -> connect;
bucket_for_atom(etimedout) -> connect;
bucket_for_atom(ehostunreach) -> connect;
bucket_for_atom(enetunreach) -> connect;
bucket_for_atom(econnreset) -> connect;
bucket_for_atom(ehostdown) -> connect;
bucket_for_atom(enetdown) -> connect;
bucket_for_atom(nxdomain) -> connect;
%% listen bucket (POSIX atoms returned from bind)
bucket_for_atom(eaddrinuse) -> listen;
bucket_for_atom(eaddrnotavail) -> listen;
bucket_for_atom(eacces) -> listen;
bucket_for_atom(_) -> unknown.

-spec classify_atom(atom()) -> {error, error_reason()}.
classify_atom(Atom) ->
    case bucket_for_atom(Atom) of
        closed -> {error, closed};
        {timeout, P} -> {error, {timeout, P}};
        flow_control -> {error, {flow_control, Atom}};
        protocol -> {error, {protocol, Atom}};
        tls -> {error, {tls, Atom}};
        transport -> {error, {transport, Atom}};
        opts -> {error, {opts, Atom}};
        connect -> {error, {connect, Atom}};
        listen -> {error, {listen, Atom}};
        unknown -> {error, {transport, {posix, Atom}}}
    end.

-spec fold_opaque(term()) -> atom().
fold_opaque(A) when is_atom(A) -> A;
fold_opaque(_) -> internal_error.

-doc """
Generic dispatcher used by `wrap/1`. Exported for the rare site that
already destructured the `{error, _}` tuple and only has the payload.
""".
-spec wrap_reason(term()) -> {error, error_reason()}.
%% Already canonical pass-throughs.
wrap_reason(closed) ->
    {error, closed};
wrap_reason(fin) ->
    {error, fin};
wrap_reason({timeout, Phase} = E) when
    Phase =:= handshake;
    Phase =:= idle;
    Phase =:= recv;
    Phase =:= send;
    Phase =:= accept
->
    {error, E};
wrap_reason({transport, _} = E) ->
    {error, E};
wrap_reason({tls, _} = E) ->
    {error, E};
wrap_reason({application, _, _} = E) ->
    {error, E};
wrap_reason({protocol, _} = E) ->
    {error, E};
wrap_reason({flow_control, _} = E) ->
    {error, E};
wrap_reason({opts, _} = E) ->
    {error, E};
wrap_reason({connect, _} = E) ->
    {error, E};
wrap_reason({listen, _} = E) ->
    {error, E};
%% Connection state aliases that fold into `closed`.
wrap_reason(closed_by_peer) ->
    {error, closed};
wrap_reason(not_connected) ->
    {error, {opts, not_connected}};
wrap_reason(not_established) ->
    {error, {opts, not_established}};
wrap_reason(draining) ->
    {error, {opts, draining}};
%% Bare timeout.
wrap_reason(timeout) ->
    {error, {timeout, recv}};
%% Legacy peer-close wire shapes.
wrap_reason({transport_error, Atom}) when is_atom(Atom) ->
    {error, {transport, Atom}};
wrap_reason({transport_error, Code, Reason}) when is_integer(Code), is_binary(Reason) ->
    {error, {transport, {peer_close, Code, Reason}}};
wrap_reason({application_error, Code, Reason}) when is_integer(Code), is_binary(Reason) ->
    {error, {application, Code, Reason}};
%% TLS shapes.
wrap_reason({tls_alert, Alert}) when is_atom(Alert) ->
    {error, {tls, Alert}};
wrap_reason({tls_alert, Alert, _}) when is_atom(Alert) ->
    {error, {tls, Alert}};
wrap_reason({bad_cert, _} = R) ->
    {error, {tls, R}};
wrap_reason({hostname_mismatch, _} = R) ->
    {error, {tls, R}};
wrap_reason({unsupported_cipher_suite, _} = R) ->
    {error, {opts, R}};
wrap_reason({certfile, _} = R) ->
    {error, {opts, R}};
wrap_reason({missing_option, _} = R) ->
    {error, {opts, R}};
wrap_reason({already_started, _} = R) ->
    {error, {opts, R}};
%% Transport-parameter shapes.
wrap_reason(transport_parameter_error) ->
    {error, {protocol, transport_parameter_error}};
wrap_reason({transport_parameter_error, _} = R) ->
    {error, {protocol, R}};
wrap_reason({version_negotiation_error, _Atom}) ->
    {error, {transport, version_negotiation}};
wrap_reason(version_negotiation) ->
    {error, {transport, version_negotiation}};
wrap_reason(stateless_reset) ->
    {error, {transport, stateless_reset}};
wrap_reason(idle_timeout) ->
    {error, {transport, idle_timeout}};
%% Bare atoms classified by membership.
wrap_reason(Atom) when is_atom(Atom) ->
    classify_atom(Atom);
%% Anything else falls into transport as opaque payload.
wrap_reason(Other) ->
    {error, {transport, {posix, fold_opaque(Other)}}}.
