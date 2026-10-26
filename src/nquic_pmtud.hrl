-ifndef(NQUIC_PMTUD_HRL).
-define(NQUIC_PMTUD_HRL, true).

-include("nquic_transport.hrl").

-define(BASE_PLPMTU, ?MIN_UDP_PAYLOAD_SIZE).
-define(MAX_PLPMTU, 1452).

-record(pmtud, {
    state = disabled :: disabled | base | searching | search_complete | error,
    current_mtu = ?BASE_PLPMTU :: pos_integer(),
    probe_size = 0 :: non_neg_integer(),
    probe_count = 0 :: non_neg_integer(),
    search_low = ?BASE_PLPMTU :: pos_integer(),
    search_high = ?MAX_PLPMTU :: pos_integer(),
    probe_pending = false :: boolean(),
    last_probe_time = 0 :: non_neg_integer()
}).

-endif.
