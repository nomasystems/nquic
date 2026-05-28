-ifndef(NQUIC_PACKET_HRL).
-define(NQUIC_PACKET_HRL, true).

-record(long_header, {
    type :: initial | handshake | rtt0 | retry | version_negotiation,

    version :: 0..16#FFFFFFFF,

    dcid :: nquic:connection_id(),

    scid :: nquic:connection_id(),

    token :: binary() | undefined,

    payload_len :: non_neg_integer() | undefined,

    packet_number :: nquic_packet_number:t() | undefined,

    pn_len :: 1..4 | undefined
}).

-record(short_header, {
    dcid :: nquic:connection_id(),

    packet_number :: nquic_packet_number:t() | undefined,

    key_phase = false :: boolean(),

    spin = 0 :: 0..1,

    pn_len :: 1..4 | undefined
}).

-endif.
