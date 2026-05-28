-ifndef(NQUIC_CONN_HRL).
-define(NQUIC_CONN_HRL, true).

-include("nquic_transport.hrl").

-record(stream_state, {
    stream_id :: nquic:stream_id(),
    type :: bidi | uni,

    send_state = ready :: ready | send | data_sent | data_recvd | reset_sent | reset_recvd,
    send_offset = 0 :: non_neg_integer(),
    send_max_data = 0 :: non_neg_integer(),
    last_stream_data_blocked = 0 :: non_neg_integer(),
    pending_send_data = [] :: [binary()],
    pending_send_size = 0 :: non_neg_integer(),
    pending_send_fin = false :: boolean(),

    recv_state = recv :: recv | size_known | data_recvd | reset_recvd | data_read | reset_read,
    recv_offset = 0 :: non_neg_integer(),
    recv_max_offset = 0 :: non_neg_integer(),
    recv_window = 0 :: non_neg_integer(),

    recv_buffer = gb_trees:empty() ::
        gb_trees:tree(non_neg_integer(), {binary(), boolean()}),

    app_buffer = [] :: iodata(),
    app_buffer_size = 0 :: non_neg_integer()
}).

-record(conn_crypto, {
    tls_state :: term(),
    keys = #{} :: #{nquic_packet:space() | rtt0 => map()},
    app_send_keys :: map() | undefined,
    app_recv_keys :: map() | undefined,
    crypto_buffer = #{} :: #{nquic_packet:space() => {non_neg_integer(), binary(), list()}},
    cipher = aes_128_gcm :: aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    cipher_suites :: [aes_128_gcm | aes_256_gcm | chacha20_poly1305] | undefined,
    key_phase = false :: boolean(),
    key_update_pending = false :: boolean(),
    client_app_secret :: binary() | undefined,
    server_app_secret :: binary() | undefined,
    old_read_keys :: #{key := binary(), iv := binary()} | undefined,
    zero_rtt_accepted = false :: boolean(),
    replay_protection :: module() | undefined,
    session_ticket :: map() | undefined,
    resumption_secret :: binary() | undefined,
    session_cache :: atom() | false | {module, module()} | undefined,
    token_cache = false :: atom() | false | {module, module()},
    alpn :: [binary()] | undefined,
    hostname :: string() | binary() | undefined,
    cert :: binary() | undefined,
    cert_chain = [] :: [binary()],
    key :: any() | undefined,
    verify = verify_none :: verify_none | verify_peer,
    cacerts = [] :: [binary()],
    peer_cert :: binary() | undefined,
    static_key :: binary() | undefined
}).

-record(conn_streams, {
    streams = #{} :: #{nquic:stream_id() => #stream_state{}},
    next_bidi_stream :: nquic:stream_id() | undefined,
    next_uni_stream :: nquic:stream_id() | undefined,
    peer_max_streams_bidi = 0 :: non_neg_integer(),
    peer_max_streams_uni = 0 :: non_neg_integer(),
    local_max_streams_bidi = 0 :: non_neg_integer(),
    local_max_streams_uni = 0 :: non_neg_integer(),
    last_sent_max_streams_bidi = 0 :: non_neg_integer(),
    last_sent_max_streams_uni = 0 :: non_neg_integer(),
    max_peer_bidi_stream_id :: non_neg_integer() | undefined,
    max_peer_uni_stream_id :: non_neg_integer() | undefined,
    opened_peer_bidi_count = 0 :: non_neg_integer(),
    opened_peer_uni_count = 0 :: non_neg_integer(),
    closed_peer_bidi_wm = -1 :: integer(),
    closed_peer_uni_wm = -1 :: integer(),
    closed_peer_streams = #{} :: #{nquic:stream_id() => true},
    recv_waiters = #{} :: #{nquic:stream_id() => gen_statem:from()},
    accept_stream_waiters = queue:new() :: queue:queue(gen_statem:from()),
    pending_streams = queue:new() :: queue:queue(nquic:stream_id()),
    blocked_streams = #{} :: #{nquic:stream_id() => true},
    pending_send_streams = #{} :: #{nquic:stream_id() => true},
    send_buffer_high_water = 1048576 :: pos_integer(),
    send_timeout = infinity :: timeout(),
    send_waiters = queue:new() :: queue:queue(nquic_conn_send_waiters:t())
}).

-record(conn_flow, {
    local_max_data = 0 :: non_neg_integer(),
    remote_max_data = 0 :: non_neg_integer(),
    data_sent = 0 :: non_neg_integer(),
    data_received = 0 :: non_neg_integer(),
    last_data_blocked = 0 :: non_neg_integer(),
    pending_initial_frames = [] :: [nquic_frame:t()],
    pending_handshake_frames = [] :: [nquic_frame:t()],
    pending_app_frames = [] :: [nquic_frame:t()],
    pending_app_pre_encoded = [] :: [{non_neg_integer(), iodata(), nquic_frame:t()}],
    queued_app_send_bytes = 0 :: non_neg_integer()
}).

-record(conn_path_mgmt, {
    path_state :: nquic_path:state() | undefined,
    peer_cids = #{} :: #{non_neg_integer() => #{cid := nquic:connection_id(), token := binary()}},
    local_cids = #{} :: #{non_neg_integer() => nquic:connection_id()},
    local_cid_seq = 1 :: non_neg_integer(),
    peer_retire_prior_to = 0 :: non_neg_integer(),
    anti_amp_bytes_received = 0 :: non_neg_integer(),
    anti_amp_bytes_sent = 0 :: non_neg_integer(),
    address_validated = false :: boolean()
}).

-record(conn_state, {
    role :: client | server,
    scid :: nquic:connection_id(),
    dcid :: nquic:connection_id(),
    odcid :: nquic:connection_id() | undefined,
    retry_scid :: nquic:connection_id() | undefined,
    retry_token = <<>> :: binary(),

    version = 1 :: non_neg_integer(),
    version_preference = [1] :: [non_neg_integer()],

    socket :: nquic_socket:t() | undefined,
    peer :: nquic_socket:sockaddr() | undefined,
    select_info :: nquic_socket:select_info() | undefined,

    pn_spaces = #{} :: #{nquic_packet:space() => map()},
    app_next_pn = 0 :: non_neg_integer(),
    app_largest_received = -1 :: integer(),

    loss_state :: nquic_loss:loss_state() | undefined,

    dispatch_table :: nquic_dispatch:t() | undefined,
    listener :: pid() | undefined,

    connect_waiters = [] :: [gen_server:from()],

    local_params = #transport_params{} :: #transport_params{},
    remote_params :: #transport_params{} | undefined,

    server_packet_processed = false :: boolean(),

    owner :: pid() | undefined,
    owner_mon :: reference() | undefined,

    deferred_flush_pending = false :: boolean(),

    pending_ack_count = 0 :: non_neg_integer(),

    last_idle_ms :: non_neg_integer() | infinity | undefined,
    last_pto_ms :: non_neg_integer() | cancel | undefined,

    recv_ecn = not_ect :: nquic_socket:ecn_mark(),

    pmtud :: nquic_pmtud:pmtud_state() | undefined,

    gso_size :: undefined | pos_integer(),

    max_payload_size = 1200 :: pos_integer(),

    server_per_conn_fd = false :: boolean(),

    proactive_cids = false :: boolean(),

    socket_connected = false :: boolean(),

    self_migration_pending = false :: boolean(),

    metrics_counters :: nquic_metrics:conn_counters() | undefined,

    spin_enabled = false :: boolean(),
    peer_spin = 0 :: 0..1,

    new_token_enabled = true :: boolean(),
    new_token_lifetime = 86400 :: pos_integer(),

    qlog = undefined :: undefined | nquic_qlog:qlog_state(),

    close_kind :: undefined | local | peer | idle_timeout | protocol_error,

    crypto = #conn_crypto{} :: #conn_crypto{},
    streams_state = #conn_streams{} :: #conn_streams{},
    flow = #conn_flow{} :: #conn_flow{},
    path = #conn_path_mgmt{} :: #conn_path_mgmt{}
}).

-endif.
