-ifndef(NQUIC_FRAME_HRL).
-define(NQUIC_FRAME_HRL, true).

-define(NQUIC_MAX_DATAGRAM, 65535).

-record(padding, {}).

-record(ping, {}).

-record(ack_range, {
    gap = 0 :: non_neg_integer(),
    length = 0 :: non_neg_integer()
}).

-record(ack, {
    largest_acknowledged :: nquic_packet_number:t(),
    delay :: non_neg_integer(),
    first_ack_range :: non_neg_integer(),
    ack_ranges = [] :: [#ack_range{}],
    ecn_counts :: term() | undefined
}).

-record(reset_stream, {
    stream_id :: nquic:stream_id(),
    app_error_code :: nquic:error_code(),
    final_size :: non_neg_integer()
}).

-record(stop_sending, {
    stream_id :: nquic:stream_id(),
    app_error_code :: nquic:error_code()
}).

-record(crypto, {
    offset :: non_neg_integer(),
    data :: binary()
}).

-record(new_token, {
    token :: binary()
}).

-record(stream, {
    stream_id :: nquic:stream_id(),
    offset :: non_neg_integer(),
    length :: non_neg_integer(),
    fin = false :: boolean(),
    data :: iodata()
}).

-record(max_data, {
    max_data :: non_neg_integer()
}).

-record(max_stream_data, {
    stream_id :: nquic:stream_id(),
    max_stream_data :: non_neg_integer()
}).

-record(max_streams, {
    max_streams :: non_neg_integer(),
    is_uni = false :: boolean()
}).

-record(data_blocked, {
    limit :: non_neg_integer()
}).

-record(stream_data_blocked, {
    stream_id :: nquic:stream_id(),
    limit :: non_neg_integer()
}).

-record(streams_blocked, {
    limit :: non_neg_integer(),
    is_uni = false :: boolean()
}).

-record(new_connection_id, {
    seq_num :: non_neg_integer(),
    retire_prior_to :: non_neg_integer(),
    cid :: nquic:connection_id(),
    stateless_reset_token :: binary()
}).

-record(retire_connection_id, {
    seq_num :: non_neg_integer()
}).

-record(path_challenge, {
    data :: binary()
}).

-record(path_response, {
    data :: binary()
}).

-record(connection_close, {
    error_code :: non_neg_integer(),
    frame_type = 0 :: non_neg_integer(),
    reason_phrase = <<>> :: binary(),
    is_application = false :: boolean()
}).

-record(handshake_done, {}).

-record(datagram, {
    data :: binary()
}).

-endif.
