-ifndef(NQUIC_CC_CUBIC_HRL).
-define(NQUIC_CC_CUBIC_HRL, true).

-include("nquic_transport.hrl").

-type snapshot() :: {
    non_neg_integer(),
    non_neg_integer(),
    integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    undefined | float(),
    boolean()
}.

-define(INFINITY_SSTHRESH, 16#FFFFFFFFFFFFFFFF).
-define(NO_RECOVERY, -576460752303423488).

-record(state, {
    cwnd :: non_neg_integer(),
    ssthresh = ?INFINITY_SSTHRESH :: non_neg_integer(),
    max_datagram_size = ?MIN_UDP_PAYLOAD_SIZE :: pos_integer(),
    recovery_start_time = ?NO_RECOVERY :: integer(),
    w_max = 0 :: non_neg_integer(),
    w_last_max = 0 :: non_neg_integer(),
    epoch_start = 0 :: non_neg_integer(),
    origin_point = 0 :: non_neg_integer(),
    tcp_cwnd = 0 :: non_neg_integer(),
    cubic_k = undefined :: undefined | float(),
    congestion_occurred = false :: boolean(),
    prev_state :: undefined | snapshot(),
    hystart_phase = standard ::
        standard | slow_start | css | done,
    last_round_min_rtt = ?INFINITY_SSTHRESH :: non_neg_integer(),
    current_round_min_rtt = ?INFINITY_SSTHRESH :: non_neg_integer(),
    rtt_sample_count = 0 :: non_neg_integer(),
    last_round_largest_pn = 0 :: non_neg_integer(),
    css_baseline_min_rtt = ?INFINITY_SSTHRESH :: non_neg_integer(),
    css_round_count = 0 :: non_neg_integer(),
    undo_bytes = 0 :: non_neg_integer(),
    app_limited_since :: integer() | undefined,
    sent_in_flight = 0 :: non_neg_integer()
}).

-endif.
