-ifndef(NQUIC_LOSS_HRL).
-define(NQUIC_LOSS_HRL, true).

-record(sent_packet, {
    packet_number :: nquic_packet_number:t(),
    time_sent :: non_neg_integer(),
    size :: non_neg_integer(),
    ack_eliciting :: boolean(),
    in_flight :: boolean(),
    frames :: [nquic_frame:t()]
}).

-define(K_PACING_FACTOR, 1.25).
-define(K_PACING_BURST_PACKETS, 10).

-record(pacer_state, {
    enabled = false :: boolean(),
    factor = ?K_PACING_FACTOR :: number(),
    burst_packets = ?K_PACING_BURST_PACKETS :: pos_integer(),
    next_send_time :: undefined | integer()
}).

-record(loss_state, {
    sent_packets = #{
        initial => nquic_pn_buf:new(),
        handshake => nquic_pn_buf:new(),
        application => nquic_pn_buf:new()
    } :: #{nquic_packet:space() => nquic_pn_buf:buf()},

    largest_acked_packet = #{} :: #{nquic_packet:space() => nquic_packet_number:t()},

    loss_time = #{} :: #{nquic_packet:space() => non_neg_integer()},

    rtt_state :: nquic_rtt:rtt_state(),

    cc_state :: dynamic(),

    bytes_in_flight = 0 :: non_neg_integer(),

    pto_count = 0 :: non_neg_integer(),

    ack_eliciting_in_flight = 0 :: non_neg_integer(),

    first_rtt_sample :: non_neg_integer() | undefined,

    last_send_time :: non_neg_integer() | undefined,

    recently_lost = #{
        initial => nquic_pn_buf:new(),
        handshake => nquic_pn_buf:new(),
        application => nquic_pn_buf:new()
    } :: #{nquic_packet:space() => nquic_pn_buf:buf()},

    peer_ecn_ce = #{} :: #{nquic_packet:space() => non_neg_integer()},
    peer_ecn_total = #{} :: #{nquic_packet:space() => non_neg_integer()},
    ecn_enabled = true :: boolean(),
    ecn_socket_dirty = false :: boolean(),
    pacer = #pacer_state{} :: #pacer_state{}
}).

-endif.
