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

-endif.
