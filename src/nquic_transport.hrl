-ifndef(NQUIC_TRANSPORT_HRL).
-define(NQUIC_TRANSPORT_HRL, true).

-record(transport_params, {
    original_destination_connection_id :: nquic:connection_id() | undefined,
    max_idle_timeout = 0 :: non_neg_integer(),
    stateless_reset_token :: binary() | undefined,
    max_udp_payload_size = 65527 :: pos_integer(),
    initial_max_data = 16777216 :: non_neg_integer(),
    initial_max_stream_data_bidi_local = 1048576 :: non_neg_integer(),
    initial_max_stream_data_bidi_remote = 1048576 :: non_neg_integer(),
    initial_max_stream_data_uni = 1048576 :: non_neg_integer(),
    initial_max_streams_bidi = 1024 :: non_neg_integer(),
    initial_max_streams_uni = 1024 :: non_neg_integer(),
    ack_delay_exponent = 3 :: 0..20,
    max_ack_delay = 25 :: non_neg_integer(),
    disable_active_migration = false :: boolean(),
    preferred_address :: nquic_transport:preferred_address() | undefined,
    active_connection_id_limit = 2 :: non_neg_integer(),
    initial_source_connection_id :: nquic:connection_id() | undefined,
    retry_source_connection_id :: nquic:connection_id() | undefined,
    version_information :: nquic_transport:version_information() | undefined,
    max_datagram_frame_size :: non_neg_integer() | undefined
}).

-endif.
