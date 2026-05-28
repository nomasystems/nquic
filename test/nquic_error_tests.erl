-module(nquic_error_tests).

-include_lib("eunit/include/eunit.hrl").
-include("nquic_frame.hrl").
%%%-----------------------------------------------------------------------------
%%% Constructors
%%%-----------------------------------------------------------------------------

closed_test() ->
    ?assertEqual({error, closed}, nquic_error:closed()).

timeout_phases_test_() ->
    Phases = [handshake, idle, recv, send, accept],
    [
        ?_assertEqual({error, {timeout, P}}, nquic_error:timeout(P))
     || P <- Phases
    ].

timeout_rejects_unknown_phase_test() ->
    ?assertError(function_clause, nquic_error:timeout(connect)).

transport_test() ->
    ?assertEqual({error, {transport, no_error}}, nquic_error:transport(no_error)),
    ?assertEqual(
        {error, {transport, {posix, etimedout}}},
        nquic_error:transport({posix, etimedout})
    ).

tls_test() ->
    ?assertEqual({error, {tls, unknown_ca}}, nquic_error:tls(unknown_ca)),
    ?assertEqual({error, {tls, {bad_cert, expired}}}, nquic_error:tls({bad_cert, expired})).

application_test() ->
    ?assertEqual(
        {error, {application, 256, <<"too big">>}},
        nquic_error:application(256, <<"too big">>)
    ).

application_rejects_non_binary_phrase_test() ->
    ?assertError(function_clause, nquic_error:application(0, "string")).

protocol_test() ->
    ?assertEqual(
        {error, {protocol, frame_encoding_error}},
        nquic_error:protocol(frame_encoding_error)
    ).

flow_control_test() ->
    ?assertEqual({error, {flow_control, eagain}}, nquic_error:flow_control(eagain)).

opts_test() ->
    ?assertEqual({error, {opts, not_owner}}, nquic_error:opts(not_owner)),
    ?assertEqual(
        {error, {opts, {missing_option, certfile}}},
        nquic_error:opts({missing_option, certfile})
    ).

connect_test() ->
    ?assertEqual({error, {connect, nxdomain}}, nquic_error:connect(nxdomain)).

listen_test() ->
    ?assertEqual({error, {listen, eaddrinuse}}, nquic_error:listen(eaddrinuse)).

%%%-----------------------------------------------------------------------------
%%% Mappers
%%%-----------------------------------------------------------------------------

from_socket_test_() ->
    [
        ?_assertEqual(
            {error, {connect, econnrefused}}, nquic_error:from_socket(connect, econnrefused)
        ),
        ?_assertEqual({error, {listen, eaddrinuse}}, nquic_error:from_socket(listen, eaddrinuse)),
        ?_assertEqual(
            {error, {transport, {posix, epipe}}},
            nquic_error:from_socket(transport, epipe)
        )
    ].

from_tls_alert_test_() ->
    [
        ?_assertEqual(
            {error, {tls, unknown_ca}}, nquic_error:from_tls_alert({tls_alert, unknown_ca})
        ),
        ?_assertEqual(
            {error, {tls, bad_certificate}},
            nquic_error:from_tls_alert({tls_alert, bad_certificate, ignored})
        ),
        ?_assertEqual(
            {error, {tls, decrypt_error}},
            nquic_error:from_tls_alert(decrypt_error)
        )
    ].

from_handshake_test_() ->
    [
        ?_assertEqual({error, {tls, no_psk}}, nquic_error:from_handshake(no_psk)),
        ?_assertEqual(
            {error, {tls, {bad_cert, expired}}},
            nquic_error:from_handshake({bad_cert, expired})
        ),
        ?_assertEqual(
            {error, {tls, {hostname_mismatch, <<"x">>}}},
            nquic_error:from_handshake({hostname_mismatch, <<"x">>})
        )
    ].

from_connection_close_transport_test() ->
    Frame = #connection_close{
        error_code = 16#0a,
        reason_phrase = <<"violation">>,
        is_application = false
    },
    ?assertEqual(
        {error, {transport, {peer_close, 16#0a, <<"violation">>}}},
        nquic_error:from_connection_close(Frame)
    ).

from_connection_close_application_test() ->
    Frame = #connection_close{
        error_code = 16#0102,
        reason_phrase = <<"app bye">>,
        is_application = true
    },
    ?assertEqual(
        {error, {application, 16#0102, <<"app bye">>}},
        nquic_error:from_connection_close(Frame)
    ).

%%%-----------------------------------------------------------------------------
%%% wrap/1: pass-through and folding
%%%-----------------------------------------------------------------------------

wrap_fin_eof_test_() ->
    [
        ?_assertEqual({error, fin}, nquic_error:wrap(fin)),
        ?_assertEqual({error, fin}, nquic_error:wrap({error, fin})),
        ?_assertEqual(closed, nquic_error:category(fin)),
        ?_assertNot(nquic_error:is_retryable(fin)),
        ?_assert(is_list(lists:flatten(nquic_error:format(fin))))
    ].

wrap_passes_canonical_through_test_() ->
    [
        ?_assertEqual({error, closed}, nquic_error:wrap({error, closed})),
        ?_assertEqual({error, {timeout, recv}}, nquic_error:wrap({error, {timeout, recv}})),
        ?_assertEqual({error, {tls, unknown_ca}}, nquic_error:wrap({error, {tls, unknown_ca}})),
        ?_assertEqual(
            {error, {application, 1, <<>>}},
            nquic_error:wrap({error, {application, 1, <<>>}})
        )
    ].

wrap_folds_legacy_atoms_test_() ->
    [
        ?_assertEqual({error, closed}, nquic_error:wrap(closed_by_peer)),
        ?_assertEqual({error, {opts, not_connected}}, nquic_error:wrap(not_connected)),
        ?_assertEqual({error, {opts, not_established}}, nquic_error:wrap(not_established)),
        ?_assertEqual({error, {opts, draining}}, nquic_error:wrap(draining)),
        ?_assertEqual({error, {timeout, recv}}, nquic_error:wrap(timeout)),
        ?_assertEqual({error, {transport, idle_timeout}}, nquic_error:wrap(idle_timeout)),
        ?_assertEqual({error, {transport, stateless_reset}}, nquic_error:wrap(stateless_reset)),
        ?_assertEqual(
            {error, {transport, version_negotiation}},
            nquic_error:wrap(version_negotiation)
        ),
        ?_assertEqual({error, {flow_control, eagain}}, nquic_error:wrap(eagain)),
        ?_assertEqual(
            {error, {flow_control, partial_send}},
            nquic_error:wrap(partial_send)
        ),
        ?_assertEqual(
            {error, {protocol, frame_encoding_error}},
            nquic_error:wrap(frame_encoding_error)
        ),
        ?_assertEqual(
            {error, {protocol, protocol_violation}},
            nquic_error:wrap(protocol_violation)
        ),
        ?_assertEqual({error, {tls, no_psk}}, nquic_error:wrap(no_psk)),
        ?_assertEqual({error, {opts, not_owner}}, nquic_error:wrap(not_owner)),
        ?_assertEqual({error, {connect, econnrefused}}, nquic_error:wrap(econnrefused)),
        ?_assertEqual({error, {listen, eaddrinuse}}, nquic_error:wrap(eaddrinuse))
    ].

wrap_folds_legacy_tuples_test_() ->
    [
        ?_assertEqual(
            {error, {transport, protocol_violation}},
            nquic_error:wrap({transport_error, protocol_violation})
        ),
        ?_assertEqual(
            {error, {transport, {peer_close, 5, <<"x">>}}},
            nquic_error:wrap({transport_error, 5, <<"x">>})
        ),
        ?_assertEqual(
            {error, {application, 42, <<"app">>}},
            nquic_error:wrap({application_error, 42, <<"app">>})
        ),
        ?_assertEqual({error, {tls, decrypt_error}}, nquic_error:wrap({tls_alert, decrypt_error})),
        ?_assertEqual(
            {error, {tls, {bad_cert, expired}}},
            nquic_error:wrap({bad_cert, expired})
        ),
        ?_assertEqual(
            {error, {opts, {missing_option, certfile}}},
            nquic_error:wrap({missing_option, certfile})
        ),
        ?_assertEqual(
            {error, {opts, {certfile, no_certificates}}},
            nquic_error:wrap({certfile, no_certificates})
        ),
        ?_assertEqual(
            {error, {opts, {unsupported_cipher_suite, <<"x">>}}},
            nquic_error:wrap({unsupported_cipher_suite, <<"x">>})
        ),
        ?_assertEqual(
            {error, {protocol, {transport_parameter_error, foo}}},
            nquic_error:wrap({transport_parameter_error, foo})
        ),
        ?_assertEqual(
            {error, {protocol, transport_parameter_error}},
            nquic_error:wrap(transport_parameter_error)
        )
    ].

wrap_result_test_() ->
    [
        ?_assertEqual(ok, nquic_error:wrap_result(ok)),
        ?_assertEqual({ok, 1}, nquic_error:wrap_result({ok, 1})),
        ?_assertEqual({error, closed}, nquic_error:wrap_result({error, closed_by_peer})),
        ?_assertEqual(
            {error, {flow_control, eagain}},
            nquic_error:wrap_result({error, eagain})
        )
    ].

wrap_unknown_atom_falls_into_transport_test() ->
    ?assertEqual(
        {error, {transport, {posix, ezzz}}},
        nquic_error:wrap(ezzz)
    ).

%% Table-driven coverage for bucket_for_atom dispatch.

closed_bucket_atoms_test_() ->
    [
        ?_assertEqual({error, closed}, nquic_error:wrap(A))
     || A <- [closed, closed_by_peer]
    ].

transport_bucket_atoms_test_() ->
    Atoms = [
        no_error,
        internal_error,
        connection_refused,
        connection_id_limit_error,
        invalid_token,
        application_error,
        crypto_buffer_exceeded,
        key_update_error,
        aead_limit_reached,
        no_viable_path,
        crypto_error,
        idle_timeout,
        stateless_reset,
        version_negotiation
    ],
    [
        ?_assertEqual({error, {transport, A}}, nquic_error:wrap(A))
     || A <- Atoms
    ].

flow_control_bucket_atoms_test_() ->
    Atoms = [
        flow_control_error,
        stream_limit_error,
        congestion_control_blocked,
        eagain,
        partial_send,
        stream_blocked
    ],
    [
        ?_assertEqual({error, {flow_control, A}}, nquic_error:wrap(A))
     || A <- Atoms
    ].

protocol_bucket_atoms_test_() ->
    Atoms = [
        protocol_violation,
        frame_encoding_error,
        packet_too_short,
        integrity_check_failed,
        final_size_error,
        migration_disabled,
        duplicate_parameter,
        truncated_param_value,
        transport_parameter_error,
        no_available_cids,
        retry_token_too_short,
        invalid_retry_token,
        datagrams_not_negotiated,
        datagram_too_large,
        invalid_packet,
        incomplete_binary,
        key_update_pending,
        no_initial_keys,
        no_zero_rtt_keys,
        no_probe_needed,
        overflow,
        stream_state_error,
        decrypt_failed
    ],
    [
        ?_assertEqual({error, {protocol, A}}, nquic_error:wrap(A))
     || A <- Atoms
    ].

tls_bucket_atoms_test_() ->
    Atoms = [
        no_psk,
        no_matching_psk,
        no_static_key,
        no_peercert,
        binder_mismatch,
        binder_verification_failed,
        psk_identity_binder_mismatch,
        client_finished_verification_failed,
        malformed_finished,
        malformed_new_session_ticket,
        not_new_session_ticket,
        invalid_ticket_cipher,
        invalid_ticket_format,
        ticket_decrypt_failed,
        ticket_too_short,
        unexpected_message,
        handshake_failure,
        bad_certificate,
        unsupported_certificate,
        certificate_revoked,
        certificate_expired,
        certificate_unknown,
        illegal_parameter,
        unknown_ca,
        access_denied,
        decode_error,
        decrypt_error,
        protocol_version,
        insufficient_security,
        inappropriate_fallback,
        user_canceled,
        missing_extension,
        unsupported_extension,
        unrecognized_name,
        bad_certificate_status_response,
        unknown_psk_identity,
        certificate_required,
        no_application_protocol
    ],
    [
        ?_assertEqual({error, {tls, A}}, nquic_error:wrap(A))
     || A <- Atoms
    ].

opts_bucket_atoms_test_() ->
    Atoms = [
        not_owner,
        not_found,
        not_connected,
        not_established,
        not_writable,
        unknown_request,
        unknown_stream,
        invalid_stream,
        invalid_stream_id,
        stream_not_found,
        stream_closed,
        stream_reset,
        empty,
        no_data,
        sups_not_ready,
        draining
    ],
    [
        ?_assertEqual({error, {opts, A}}, nquic_error:wrap(A))
     || A <- Atoms
    ].

connect_bucket_atoms_test_() ->
    Atoms = [
        econnrefused,
        etimedout,
        ehostunreach,
        enetunreach,
        econnreset,
        ehostdown,
        enetdown,
        nxdomain
    ],
    [
        ?_assertEqual({error, {connect, A}}, nquic_error:wrap(A))
     || A <- Atoms
    ].

listen_bucket_atoms_test_() ->
    Atoms = [eaddrinuse, eaddrnotavail, eacces],
    [
        ?_assertEqual({error, {listen, A}}, nquic_error:wrap(A))
     || A <- Atoms
    ].

%% Non-atom and tuple fallthroughs

wrap_non_atom_term_test_() ->
    [
        ?_assertEqual({error, {transport, {posix, internal_error}}}, nquic_error:wrap(<<"bin">>)),
        ?_assertEqual({error, {transport, {posix, internal_error}}}, nquic_error:wrap(42))
    ].

wrap_already_started_test() ->
    Pid = self(),
    ?assertEqual(
        {error, {opts, {already_started, Pid}}},
        nquic_error:wrap({already_started, Pid})
    ).

wrap_version_negotiation_tuple_test() ->
    ?assertEqual(
        {error, {transport, version_negotiation}},
        nquic_error:wrap({version_negotiation_error, foo})
    ).

wrap_timeout_phases_passthrough_test_() ->
    [
        ?_assertEqual({error, {timeout, P}}, nquic_error:wrap({timeout, P}))
     || P <- [handshake, idle, recv, send, accept]
    ].

is_retryable_extra_test_() ->
    [
        ?_assert(nquic_error:is_retryable({flow_control, stream_blocked})),
        ?_assert(nquic_error:is_retryable({connect, ehostunreach})),
        ?_assert(nquic_error:is_retryable({connect, enetunreach}))
    ].

from_handshake_unknown_tag_tuple_test() ->
    ?assertEqual(
        {error, {tls, {handshake_failed, {foo, 1}}}},
        nquic_error:from_handshake({handshake_failed, {foo, 1}})
    ).

from_tls_alert_record_three_arg_test() ->
    ?assertEqual(
        {error, {tls, unknown_ca}},
        nquic_error:from_tls_alert({tls_alert, unknown_ca, <<"why">>})
    ).

%%%-----------------------------------------------------------------------------
%%% Helpers
%%%-----------------------------------------------------------------------------

category_test_() ->
    [
        ?_assertEqual(closed, nquic_error:category(closed)),
        ?_assertEqual(timeout, nquic_error:category({timeout, idle})),
        ?_assertEqual(transport, nquic_error:category({transport, no_error})),
        ?_assertEqual(tls, nquic_error:category({tls, unknown_ca})),
        ?_assertEqual(application, nquic_error:category({application, 1, <<>>})),
        ?_assertEqual(protocol, nquic_error:category({protocol, protocol_violation})),
        ?_assertEqual(flow_control, nquic_error:category({flow_control, eagain})),
        ?_assertEqual(opts, nquic_error:category({opts, not_owner})),
        ?_assertEqual(connect, nquic_error:category({connect, econnrefused})),
        ?_assertEqual(listen, nquic_error:category({listen, eaddrinuse}))
    ].

is_retryable_test_() ->
    [
        ?_assertNot(nquic_error:is_retryable(closed)),
        ?_assert(nquic_error:is_retryable({timeout, idle})),
        ?_assert(nquic_error:is_retryable({timeout, recv})),
        ?_assertNot(nquic_error:is_retryable({timeout, handshake})),
        ?_assert(nquic_error:is_retryable({transport, no_error})),
        ?_assert(nquic_error:is_retryable({transport, version_negotiation})),
        ?_assert(nquic_error:is_retryable({transport, stateless_reset})),
        ?_assert(nquic_error:is_retryable({transport, idle_timeout})),
        ?_assert(nquic_error:is_retryable({transport, {posix, etimedout}})),
        ?_assertNot(nquic_error:is_retryable({transport, protocol_violation})),
        ?_assertNot(nquic_error:is_retryable({tls, unknown_ca})),
        ?_assertNot(nquic_error:is_retryable({application, 1, <<>>})),
        ?_assertNot(nquic_error:is_retryable({protocol, protocol_violation})),
        ?_assert(nquic_error:is_retryable({flow_control, eagain})),
        ?_assert(nquic_error:is_retryable({flow_control, congestion_control_blocked})),
        ?_assertNot(nquic_error:is_retryable({flow_control, flow_control_error})),
        ?_assertNot(nquic_error:is_retryable({opts, not_owner})),
        ?_assert(nquic_error:is_retryable({connect, econnrefused})),
        ?_assert(nquic_error:is_retryable({connect, etimedout})),
        ?_assertNot(nquic_error:is_retryable({connect, nxdomain})),
        ?_assertNot(nquic_error:is_retryable({listen, eaddrinuse}))
    ].

format_test_() ->
    [
        ?_assert(is_list(lists:flatten(nquic_error:format(closed)))),
        ?_assert(is_list(lists:flatten(nquic_error:format({timeout, idle})))),
        ?_assert(
            is_list(lists:flatten(nquic_error:format({transport, {peer_close, 5, <<>>}})))
        ),
        ?_assert(
            is_list(
                lists:flatten(nquic_error:format({transport, {peer_close, 5, <<"why">>}}))
            )
        ),
        ?_assert(is_list(lists:flatten(nquic_error:format({transport, {posix, epipe}})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({transport, idle_timeout})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({tls, unknown_ca})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({application, 1, <<>>})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({application, 1, <<"app">>})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({protocol, protocol_violation})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({flow_control, eagain})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({opts, not_owner})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({connect, econnrefused})))),
        ?_assert(is_list(lists:flatten(nquic_error:format({listen, eaddrinuse}))))
    ].

%% Regression: the convention-contract trio (category/1, is_retryable/1,
%% format/1) must be total over every outer arm of error_reason/0,
%% including the opts reasons added by plans 8 and 19. A consumer
%% adapts via these interrogators, so a crash here breaks the
%% cross-lib coherence contract documented in nquic_error's moduledoc.
convention_contract_totality_test_() ->
    Categories = [
        closed,
        timeout,
        transport,
        tls,
        application,
        protocol,
        flow_control,
        opts,
        connect,
        listen
    ],
    Samples = [
        closed,
        fin,
        {timeout, handshake},
        {timeout, idle},
        {transport, idle_timeout},
        {transport, {posix, epipe}},
        {tls, unknown_ca},
        {application, 16#101, <<"app">>},
        {protocol, protocol_violation},
        {flow_control, eagain},
        {opts, not_owner},
        {opts, ctx_requires_wait},
        {opts, not_supported_in_mode},
        {opts, {missing_option, tls}},
        {opts, {misplaced_option, certfile}},
        {connect, econnrefused},
        {listen, eaddrinuse}
    ],
    [
        {lists:flatten(io_lib:format("~p", [R])), fun() ->
            Cat = nquic_error:category(R),
            ?assert(lists:member(Cat, Categories)),
            ?assert(is_boolean(nquic_error:is_retryable(R))),
            ?assert(is_list(lists:flatten(nquic_error:format(R))))
        end}
     || R <- Samples
    ].

%% Exhaustive `wrap/1' bucket/shape contract: one representative per
%% otherwise-unexercised `wrap_reason' shape clause, `classify_atom'
%% bucket, and `bucket_for_atom' arm. Pure and deterministic.
wrap_shape_passthrough_test_() ->
    Cases = [
        {{timeout, handshake}, {error, {timeout, handshake}}},
        {{timeout, idle}, {error, {timeout, idle}}},
        {{timeout, send}, {error, {timeout, send}}},
        {{timeout, accept}, {error, {timeout, accept}}},
        {{transport, flow_control_error}, {error, {transport, flow_control_error}}},
        {{tls, bad_record_mac}, {error, {tls, bad_record_mac}}},
        {{application, 7, <<"x">>}, {error, {application, 7, <<"x">>}}},
        {{protocol, frame_encoding_error}, {error, {protocol, frame_encoding_error}}},
        {{flow_control, eagain}, {error, {flow_control, eagain}}},
        {{opts, not_owner}, {error, {opts, not_owner}}},
        {{connect, econnrefused}, {error, {connect, econnrefused}}},
        {{listen, eaddrinuse}, {error, {listen, eaddrinuse}}},
        {{tls_alert, handshake_failure}, {error, {tls, handshake_failure}}},
        {{tls_alert, handshake_failure, extra}, {error, {tls, handshake_failure}}},
        {{bad_cert, expired}, {error, {tls, {bad_cert, expired}}}},
        {{hostname_mismatch, "h"}, {error, {tls, {hostname_mismatch, "h"}}}},
        {{unsupported_cipher_suite, x}, {error, {opts, {unsupported_cipher_suite, x}}}},
        {{certfile, "c.pem"}, {error, {opts, {certfile, "c.pem"}}}},
        {{missing_option, tls}, {error, {opts, {missing_option, tls}}}}
    ],
    [
        {lists:flatten(io_lib:format("~p", [In])), fun() ->
            ?assertEqual(Out, nquic_error:wrap(In)),
            ?assertEqual(Out, nquic_error:wrap({error, In}))
        end}
     || {In, Out} <- Cases
    ].

wrap_bucket_for_atom_test_() ->
    Cases = [
        {closed, {error, closed}},
        {closed_by_peer, {error, closed}},
        {timeout, {error, {timeout, recv}}},
        {send_timeout, {error, {timeout, send}}},
        {idle_timeout, {error, {transport, idle_timeout}}},
        {stateless_reset, {error, {transport, stateless_reset}}},
        {version_negotiation, {error, {transport, version_negotiation}}},
        {transport_parameter_error, {error, {protocol, transport_parameter_error}}},
        {certificate_required, {error, {tls, certificate_required}}},
        {no_application_protocol, {error, {tls, no_application_protocol}}},
        {not_connected, {error, {opts, not_connected}}},
        {not_established, {error, {opts, not_established}}},
        {stream_not_found, {error, {opts, stream_not_found}}},
        {draining, {error, {opts, draining}}},
        {econnrefused, {error, {connect, econnrefused}}},
        {nxdomain, {error, {connect, nxdomain}}},
        {eaddrinuse, {error, {listen, eaddrinuse}}},
        {eacces, {error, {listen, eacces}}},
        {zzz_unknown_atom, {error, {transport, {posix, zzz_unknown_atom}}}}
    ],
    [
        {atom_to_list(In), fun() -> ?assertEqual(Out, nquic_error:wrap(In)) end}
     || {In, Out} <- Cases
    ].

wrap_opaque_non_atom_test() ->
    ?assertEqual(
        {error, {transport, {posix, internal_error}}},
        nquic_error:wrap({a, tuple, 3})
    ).
