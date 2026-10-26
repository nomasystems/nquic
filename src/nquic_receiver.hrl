-ifndef(NQUIC_RECEIVER_HRL).
-define(NQUIC_RECEIVER_HRL, true).

-record(state, {
    socket :: nquic_socket:t(),
    select_info :: nquic_socket:select_info() | undefined,
    dispatch_table :: nquic_dispatch:t(),
    listener :: pid(),
    opts :: map(),
    static_key :: binary(),
    max_new_conns_per_sec = 0 :: non_neg_integer(),
    rate_count = 0 :: non_neg_integer(),
    rate_window_start = 0 :: integer(),
    retry = false :: boolean(),
    retry_token_lifetime = 30 :: pos_integer(),
    ecn = false :: boolean(),
    gro = false :: boolean()
}).

-endif.
