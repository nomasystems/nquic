-ifndef(NQUIC_PATH_HRL).
-define(NQUIC_PATH_HRL, true).

-record(path_state, {
    peer :: nquic_socket:sockaddr() | undefined,
    previous_peer :: nquic_socket:sockaddr() | undefined,
    pending_challenge :: binary() | undefined,
    challenge_sent_time = 0 :: non_neg_integer(),
    challenge_retries = 0 :: non_neg_integer(),
    path_validated = true :: boolean(),
    new_path_bytes_sent = 0 :: non_neg_integer(),
    new_path_bytes_received = 0 :: non_neg_integer()
}).

-endif.
