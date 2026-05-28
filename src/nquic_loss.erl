-module(nquic_loss).

-moduledoc """
Loss detection per RFC 9002.

Tracks sent packets per packet number space with shared RTT estimation and
congestion control. Uses both packet threshold (3 packets) and time threshold
(9/8 of max(smoothed_rtt, latest_rtt)) for loss detection. PTO with exponential
backoff triggers probes when no ACKs arrive.

Persistent congestion (RFC 9002 Section 7.6) is declared when a contiguous
run of ack-eliciting packets is lost spanning at least
`(SRTT + max(4 * RTTvar, kGranularity) + max_ack_delay) * 3` and both
endpoints were sent after the first RTT sample. On detection the congestion
controller's window collapses to `2 * max_datagram_size`.
""".

-include("nquic_frame.hrl").
-include("nquic_loss.hrl").
-export([
    detect_loss/3,

    get_ack_eliciting_in_flight/1,
    get_bytes_in_flight/1,
    get_cc_algorithm/1,
    get_cwnd/1,
    get_largest_acked/2,
    get_loss_timer/1,
    get_pto_count/1,
    get_pto_timeout/2,
    get_rtt_stats/1,
    get_sent_packet_numbers/1,
    get_sent_packets/1,

    has_ack_eliciting_in_flight/1,
    init/0,
    init/1,
    on_ack_received/6,
    on_packet_sent/6,
    on_pto/1,
    reset_pto_count/1
]).
-export([set_max_datagram_size/2]).
-export([clear_handshake_spaces/1, clear_initial_space/1]).
-export([is_ecn_enabled/1, process_ecn_counts/3, set_ecn_enabled/2]).
-export([clear_ecn_socket_dirty/1, is_ecn_socket_dirty/1]).
-export([path_stats/1]).
-export([
    init/2,
    pacer_check/2,
    pacer_config/1,
    pacer_disable/1,
    pacer_is_enabled/1,
    pacer_next_send_time/1
]).

-export_type([cc_opts/0, loss_state/0, pacer_opts/0, path_stats/0, sent_packet/0]).

-type sent_packet() :: #sent_packet{}.

-type pacer_opts() :: #{
    enabled => boolean(),
    factor => number(),
    burst_packets => pos_integer()
}.

-type cc_opts() :: #{
    slow_start => standard | hystart_plus_plus,
    _ => _
}.

-type path_stats() :: #{
    srtt_us := non_neg_integer(),
    rttvar_us := non_neg_integer(),
    min_rtt_us := non_neg_integer(),
    latest_rtt_us := non_neg_integer(),
    cwnd := non_neg_integer(),
    bytes_in_flight := non_neg_integer(),
    ssthresh := non_neg_integer() | undefined,
    mss := pos_integer(),
    ecn_enabled := boolean(),
    peer_ecn_ce := non_neg_integer(),
    peer_ecn_total := non_neg_integer(),
    pto_count := non_neg_integer()
}.

-define(K_PACKET_THRESHOLD, 3).
-define(K_GRANULARITY_US, 1_000).
-define(K_PERSISTENT_CONGESTION_THRESHOLD, 3).
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
    pacer = #pacer_state{} :: pacer_state()
}).
-type pacer_state() :: #pacer_state{}.

-type loss_state() :: #loss_state{}.

-spec add_recently_lost(nquic_pn_buf:buf(), [sent_packet()]) -> nquic_pn_buf:buf().
add_recently_lost(RecentlyLost, Packets) ->
    lists:foldl(
        fun(P, Acc) -> nquic_pn_buf:insert(P#sent_packet.packet_number, P, Acc) end,
        RecentlyLost,
        Packets
    ).

-spec cc_acked_loop(
    [sent_packet()], dynamic(), non_neg_integer(), map()
) -> {dynamic(), non_neg_integer()}.
cc_acked_loop([], CC, InFlight, _RTTStats) ->
    {CC, InFlight};
cc_acked_loop([#sent_packet{in_flight = true, size = Sz} = P | Rest], CC, InFlight, RTTStats) ->
    CC1 = nquic_cc:on_packet_acked(CC, P, InFlight, RTTStats),
    cc_acked_loop(Rest, CC1, max(0, InFlight - Sz), RTTStats);
cc_acked_loop([P | Rest], CC, InFlight, RTTStats) ->
    CC1 = nquic_cc:on_packet_acked(CC, P, InFlight, RTTStats),
    cc_acked_loop(Rest, CC1, InFlight, RTTStats).

-spec cc_opts_for_new(map()) -> map().
cc_opts_for_new(Opts) ->
    case maps:get(slow_start, Opts, undefined) of
        undefined -> #{};
        Mode -> #{slow_start => Mode}
    end.

-doc "Clear initial and handshake sent-packet maps after handshake is confirmed.".
-spec clear_handshake_spaces(loss_state()) -> loss_state().
clear_handshake_spaces(#loss_state{sent_packets = SP} = State) ->
    State#loss_state{
        sent_packets = SP#{initial => nquic_pn_buf:new(), handshake => nquic_pn_buf:new()}
    }.

-doc "Clear the Initial-space sent-packet buffer after RFC 9001 §4.9.1 key discard.".
-spec clear_initial_space(loss_state()) -> loss_state().
clear_initial_space(#loss_state{sent_packets = SP} = State) ->
    State#loss_state{sent_packets = SP#{initial => nquic_pn_buf:new()}}.

-spec count_ack_eliciting_in_flight([sent_packet()]) -> non_neg_integer().
count_ack_eliciting_in_flight(Packets) -> count_aeif(Packets, 0).

-spec count_aeif([sent_packet()], non_neg_integer()) -> non_neg_integer().
count_aeif([], Acc) ->
    Acc;
count_aeif([#sent_packet{ack_eliciting = true, in_flight = true} | T], Acc) ->
    count_aeif(T, Acc + 1);
count_aeif([_ | T], Acc) ->
    count_aeif(T, Acc).

-doc "Run loss detection for a specific packet number space at the given time.".
-spec detect_loss(loss_state(), nquic_packet:space(), non_neg_integer()) ->
    {ok, loss_state(), [nquic_frame:t()]}.
detect_loss(State, Space, Now) ->
    {State1, LostPackets} = detect_loss_internal(State, Space, Now),
    {ok, State1, extract_frames(LostPackets)}.

-spec detect_loss_internal(loss_state(), nquic_packet:space(), non_neg_integer()) ->
    {loss_state(), [sent_packet()]}.
detect_loss_internal(State, Space, Now) ->
    #loss_state{
        sent_packets = AllSent,
        largest_acked_packet = AllLargest,
        loss_time = AllLossTime,
        rtt_state = RTT,
        recently_lost = AllRecentlyLost
    } = State,

    SpaceSent = maps:get(Space, AllSent),
    LargestAcked = maps:get(Space, AllLargest, undefined),

    case LargestAcked of
        undefined ->
            {State, []};
        _ ->
            Stats = nquic_rtt:get(RTT),
            SmoothedRTT = maps:get(smoothed_rtt, Stats),
            LatestRTT = maps:get(latest_rtt, Stats),
            RTT_Val = max(SmoothedRTT, LatestRTT),
            Delay = (RTT_Val * 9) div 8,
            LossDelay = max(Delay, ?K_GRANULARITY_US),
            LossTimeCutoff = Now - LossDelay,

            PacketThresholdCutoff = LargestAcked - ?K_PACKET_THRESHOLD,

            {LostPackets, NewSpaceSent, NextLossTime} =
                nquic_pn_buf:take_lost(
                    SpaceSent, PacketThresholdCutoff, LossTimeCutoff, LossDelay
                ),

            LostAEIF = count_ack_eliciting_in_flight(LostPackets),
            ReorderWindow = 2 * SmoothedRTT,
            RecentlyLostSpace =
                add_recently_lost(
                    prune_recently_lost(
                        maps:get(Space, AllRecentlyLost),
                        Now - ReorderWindow
                    ),
                    LostPackets
                ),
            {
                State#loss_state{
                    sent_packets = AllSent#{Space := NewSpaceSent},
                    loss_time = AllLossTime#{Space => NextLossTime},
                    ack_eliciting_in_flight =
                        State#loss_state.ack_eliciting_in_flight - LostAEIF,
                    recently_lost = AllRecentlyLost#{Space := RecentlyLostSpace}
                },
                LostPackets
            }
    end.

-spec extract_frames([sent_packet()]) -> [nquic_frame:t()].
extract_frames(Packets) ->
    lists:flatmap(fun(#sent_packet{frames = F}) -> F end, Packets).

-spec find_largest_pkt([sent_packet(), ...]) -> sent_packet().
find_largest_pkt([P | Rest]) ->
    find_largest_pkt(Rest, P, P#sent_packet.packet_number).

-spec find_largest_pkt([sent_packet()], sent_packet(), nquic_packet_number:t()) -> sent_packet().
find_largest_pkt([], Best, _BestPN) ->
    Best;
find_largest_pkt([#sent_packet{packet_number = PN} = P | Rest], _Best, BestPN) when PN > BestPN ->
    find_largest_pkt(Rest, P, PN);
find_largest_pkt([_ | Rest], Best, BestPN) ->
    find_largest_pkt(Rest, Best, BestPN).

-doc "Get the cached count of ack-eliciting packets currently in flight.".
-spec get_ack_eliciting_in_flight(loss_state()) -> non_neg_integer().
get_ack_eliciting_in_flight(#loss_state{ack_eliciting_in_flight = N}) ->
    N.

-doc "Get the total bytes currently in flight across all packet number spaces.".
-spec get_bytes_in_flight(loss_state()) -> non_neg_integer().
get_bytes_in_flight(#loss_state{bytes_in_flight = B}) -> B.

-doc "Get the congestion control algorithm from the current loss state.".
-spec get_cc_algorithm(loss_state()) -> atom().
get_cc_algorithm(#loss_state{cc_state = {Mod, _}}) ->
    case Mod of
        nquic_cc_newreno -> newreno;
        nquic_cc_cubic -> cubic;
        _ -> cubic
    end.

-doc "Get the current congestion window size in bytes.".
-spec get_cwnd(loss_state()) -> non_neg_integer().
get_cwnd(#loss_state{cc_state = CC}) ->
    nquic_cc:get_cwnd(CC).

-doc "Get the largest acknowledged packet number for a given space, or 0 if none.".
-spec get_largest_acked(loss_state(), nquic_packet:space()) -> non_neg_integer().
get_largest_acked(#loss_state{largest_acked_packet = AllLargest}, Space) ->
    maps:get(Space, AllLargest, 0).

-doc "Get the earliest loss detection time across all packet number spaces, or undefined.".
-spec get_loss_timer(loss_state()) -> non_neg_integer() | undefined.
get_loss_timer(#loss_state{loss_time = LossTimes}) ->
    T1 = maps:get(initial, LossTimes, undefined),
    T2 = maps:get(handshake, LossTimes, undefined),
    T3 = maps:get(application, LossTimes, undefined),
    min_time(T1, min_time(T2, T3)).

-doc "Get the current PTO count.".
-spec get_pto_count(loss_state()) -> non_neg_integer().
get_pto_count(#loss_state{pto_count = Count}) -> Count.

-doc """
Calculate the probe timeout (microseconds) with exponential backoff.
`MaxAckDelayUs` must be in microseconds. Callers that hold the peer's
advertised `max_ack_delay` (milliseconds, per RFC 9000 S18.2) must
convert: `MaxAckDelayMs * 1000`.
""".
-spec get_pto_timeout(loss_state(), non_neg_integer()) -> non_neg_integer().
get_pto_timeout(#loss_state{rtt_state = RTT, pto_count = PtoCount}, MaxAckDelayUs) ->
    Stats = nquic_rtt:get(RTT),
    SRTT = maps:get(smoothed_rtt, Stats),
    RTTVar = maps:get(rttvar, Stats),
    Base = SRTT + max(4 * RTTVar, ?K_GRANULARITY_US) + MaxAckDelayUs,
    Base bsl PtoCount.

-doc "Get the current RTT statistics as a map.".
-spec get_rtt_stats(loss_state()) -> map().
get_rtt_stats(#loss_state{rtt_state = RTT}) ->
    nquic_rtt:get(RTT).

-doc "Get all outstanding sent packet numbers across every packet number space.".
-spec get_sent_packet_numbers(loss_state()) -> [nquic_packet_number:t()].
get_sent_packet_numbers(#loss_state{sent_packets = AllSent}) ->
    maps:fold(
        fun(_, SpaceSent, Acc) -> nquic_pn_buf:keys(SpaceSent) ++ Acc end,
        [],
        AllSent
    ).

-doc """
Get all currently tracked `#sent_packet{}` records across every packet
number space. Intended for tests and diagnostics; production code should
prefer the dedicated counters (`get_bytes_in_flight/1`,
`has_ack_eliciting_in_flight/1`).
""".
-spec get_sent_packets(loss_state()) -> [sent_packet()].
get_sent_packets(#loss_state{sent_packets = AllSent}) ->
    maps:fold(
        fun(_, SpaceSent, Acc) -> nquic_pn_buf:values(SpaceSent) ++ Acc end,
        [],
        AllSent
    ).

-doc "Return true if any ack-eliciting packets are currently in flight.".
-spec has_ack_eliciting_in_flight(loss_state()) -> boolean().
has_ack_eliciting_in_flight(#loss_state{ack_eliciting_in_flight = N}) ->
    N > 0.

-doc "Initialize loss detection state with default RTT and NewReno congestion control.".
-spec init() -> loss_state().
init() ->
    Empty = nquic_pn_buf:new(),
    #loss_state{
        sent_packets = #{initial => Empty, handshake => Empty, application => Empty},
        largest_acked_packet = #{},
        loss_time = #{},
        rtt_state = nquic_rtt:new(),
        cc_state = nquic_cc:new(newreno),
        bytes_in_flight = 0
    }.

-doc "Initialize loss detection state with the given congestion control algorithm.".
-spec init(atom()) -> loss_state().
init(Algorithm) ->
    init(Algorithm, #{}).

-doc """
Initialize loss detection state.
`Opts` is a single map carrying both pacer (`enabled`, `factor`,
`burst_packets`) and congestion-control (`slow_start`) knobs. Callers
that only have pacer config can keep passing a `pacer_opts/0` shape;
`init/2` deduplicates the two via the structural key set.
""".
-spec init(atom(), pacer_opts() | cc_opts()) -> loss_state().
init(Algorithm, Opts) ->
    Pacer = #pacer_state{
        enabled = maps:get(enabled, Opts, false),
        factor = maps:get(factor, Opts, ?K_PACING_FACTOR),
        burst_packets = maps:get(burst_packets, Opts, ?K_PACING_BURST_PACKETS)
    },
    Empty = nquic_pn_buf:new(),
    #loss_state{
        sent_packets = #{initial => Empty, handshake => Empty, application => Empty},
        largest_acked_packet = #{},
        loss_time = #{},
        rtt_state = nquic_rtt:new(),
        cc_state = nquic_cc:new(Algorithm, cc_opts_for_new(Opts)),
        bytes_in_flight = 0,
        pacer = Pacer
    }.

-spec is_ack_eliciting([nquic_frame:t()]) -> boolean().
is_ack_eliciting([]) -> false;
is_ack_eliciting([#ack{} | T]) -> is_ack_eliciting(T);
is_ack_eliciting([#padding{} | T]) -> is_ack_eliciting(T);
is_ack_eliciting([#connection_close{} | T]) -> is_ack_eliciting(T);
is_ack_eliciting(_) -> true.

-doc "Check whether ECN is enabled for this connection.".
-spec is_ecn_enabled(loss_state()) -> boolean().
is_ecn_enabled(#loss_state{ecn_enabled = E}) -> E.

-spec is_idle_reset(
    non_neg_integer() | undefined, non_neg_integer(), non_neg_integer(), nquic_rtt:rtt_state()
) -> boolean().
is_idle_reset(undefined, _TimeSent, _InFlight, _RTT) ->
    false;
is_idle_reset(_LastSend, _TimeSent, InFlight, _RTT) when InFlight > 0 ->
    false;
is_idle_reset(LastSend, TimeSent, _InFlight, RTT) ->
    SRTT = nquic_rtt:smoothed_rtt(RTT),
    SRTT > 0 andalso (TimeSent - LastSend) > 3 * SRTT.

-spec is_persistent_congestion(
    [sent_packet()],
    non_neg_integer() | undefined,
    #{smoothed_rtt := non_neg_integer(), rttvar := non_neg_integer(), _ => _},
    non_neg_integer()
) -> boolean().
is_persistent_congestion(_LostPackets, undefined, _RTTStats, _MaxAckDelayUs) ->
    false;
is_persistent_congestion(LostPackets, FirstRttSample, RTTStats, MaxAckDelayUs) ->
    Eligible = [
        P
     || P <- LostPackets,
        P#sent_packet.ack_eliciting,
        P#sent_packet.time_sent > FirstRttSample
    ],
    case Eligible of
        [_, _ | _] ->
            Sorted = lists:sort(
                fun(A, B) -> A#sent_packet.packet_number =< B#sent_packet.packet_number end,
                Eligible
            ),
            PCDuration = pc_duration(RTTStats, MaxAckDelayUs),
            scan_pc_run(Sorted, undefined, PCDuration);
        _ ->
            false
    end.

-spec max_acked_from_ranges([{non_neg_integer(), non_neg_integer()}]) -> non_neg_integer().
max_acked_from_ranges([{_, High}]) ->
    High;
max_acked_from_ranges([{_, High} | Rest]) ->
    max(High, max_acked_from_ranges(Rest)).

-spec min_time(non_neg_integer() | undefined, non_neg_integer() | undefined) ->
    non_neg_integer() | undefined.
min_time(undefined, T) -> T;
min_time(T, undefined) -> T;
min_time(A, B) -> min(A, B).

-doc """
Process an ACK frame, returning updated state plus acked and lost frames.
`MaxAckDelayUs` is the peer's advertised `max_ack_delay` in microseconds.
It is used to compute the persistent congestion window (RFC 9002 Section
7.6.1). Pass `0` if it is not yet known.
""".
-spec on_ack_received(
    loss_state(),
    nquic_packet:space(),
    [{non_neg_integer(), non_neg_integer()}],
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer()
) ->
    {ok, loss_state(), [nquic_frame:t()], [nquic_frame:t()]}.
on_ack_received(State, Space, AckedRanges, AckDelay, Now, MaxAckDelayUs) ->
    #loss_state{
        sent_packets = AllSent,
        largest_acked_packet = AllLargest,
        rtt_state = RTT,
        cc_state = CC,
        bytes_in_flight = InFlight,
        recently_lost = AllRecentlyLost
    } = State,

    SpaceSent = maps:get(Space, AllSent),
    LargestAcked = maps:get(Space, AllLargest, undefined),

    {NewSpaceSent, AckedPackets} = process_acked_ranges(SpaceSent, AckedRanges),

    RecentlyLostSpace = maps:get(Space, AllRecentlyLost),
    {CCAfterSpurious, State0} =
        case nquic_pn_buf:is_empty(RecentlyLostSpace) of
            true ->
                {CC, State};
            false ->
                {NewBuf, Spurious} =
                    process_acked_ranges(RecentlyLostSpace, AckedRanges),
                NewCC =
                    case Spurious of
                        [] -> CC;
                        _ -> nquic_cc:on_spurious_congestion(CC)
                    end,
                {NewCC, State#loss_state{
                    recently_lost = AllRecentlyLost#{Space := NewBuf},
                    cc_state = NewCC
                }}
        end,

    if
        AckedPackets == [] ->
            {ok, State0, [], []};
        true ->
            MaxAcked = max_acked_from_ranges(AckedRanges),
            NewLargestAcked =
                case LargestAcked of
                    undefined -> MaxAcked;
                    _ -> max(LargestAcked, MaxAcked)
                end,

            State1 =
                case find_largest_pkt(AckedPackets) of
                    #sent_packet{
                        packet_number = MaxAcked,
                        time_sent = TimeSent,
                        ack_eliciting = true
                    } ->
                        Sample = Now - TimeSent,
                        NewRTT = nquic_rtt:update(RTT, Sample, AckDelay),
                        FirstSample =
                            case State0#loss_state.first_rtt_sample of
                                undefined -> TimeSent;
                                Existing -> Existing
                            end,
                        State0#loss_state{rtt_state = NewRTT, first_rtt_sample = FirstSample};
                    _ ->
                        State0
                end,

            RTTStats = nquic_rtt:get(State1#loss_state.rtt_state),
            {CC1, InFlight1} =
                cc_acked_loop(AckedPackets, CCAfterSpurious, InFlight, RTTStats),

            AckedAEIF = count_ack_eliciting_in_flight(AckedPackets),
            {State2, LostPackets} = detect_loss_internal(
                State1#loss_state{
                    sent_packets = AllSent#{Space := NewSpaceSent},
                    largest_acked_packet = AllLargest#{Space => NewLargestAcked},
                    cc_state = CC1,
                    bytes_in_flight = InFlight1,
                    ack_eliciting_in_flight =
                        State1#loss_state.ack_eliciting_in_flight - AckedAEIF
                },
                Space,
                Now
            ),

            LostBytes = lists:foldl(fun(P, Acc) -> Acc + P#sent_packet.size end, 0, LostPackets),
            {CC2, InFlight2} =
                if
                    LostBytes > 0 ->
                        LatestSentTime = lists:foldl(
                            fun(P, Acc) -> max(P#sent_packet.time_sent, Acc) end,
                            0,
                            LostPackets
                        ),
                        C_new = nquic_cc:on_congestion_event(
                            State2#loss_state.cc_state,
                            LostBytes,
                            State2#loss_state.bytes_in_flight,
                            LatestSentTime
                        ),
                        I_new = lists:foldl(
                            fun(P, Acc) ->
                                if
                                    P#sent_packet.in_flight -> max(0, Acc - P#sent_packet.size);
                                    true -> Acc
                                end
                            end,
                            State2#loss_state.bytes_in_flight,
                            LostPackets
                        ),
                        {C_new, I_new};
                    true ->
                        {State2#loss_state.cc_state, State2#loss_state.bytes_in_flight}
                end,

            CC3 =
                case
                    is_persistent_congestion(
                        LostPackets,
                        State1#loss_state.first_rtt_sample,
                        nquic_rtt:get(State2#loss_state.rtt_state),
                        MaxAckDelayUs
                    )
                of
                    true -> nquic_cc:on_persistent_congestion(CC2);
                    false -> CC2
                end,

            AckedFrames = extract_frames(AckedPackets),
            LostFrames = extract_frames(LostPackets),

            {ok, State2#loss_state{cc_state = CC3, bytes_in_flight = InFlight2, pto_count = 0},
                AckedFrames, LostFrames}
    end.

-doc "Record a sent packet in the given packet number space.".
-spec on_packet_sent(
    loss_state(),
    nquic_packet:space(),
    nquic_packet_number:t(),
    [nquic_frame:t()],
    non_neg_integer(),
    non_neg_integer()
) -> loss_state().
on_packet_sent(State, Space, PN, Frames, TimeSent, Size) ->
    #loss_state{
        sent_packets = AllSent,
        cc_state = CC,
        bytes_in_flight = InFlight,
        ack_eliciting_in_flight = AEIF,
        last_send_time = LastSend,
        rtt_state = RTT,
        pacer = Pacer
    } = State,

    SpaceSent = maps:get(Space, AllSent),

    IsAckEliciting = is_ack_eliciting(Frames),
    InFlightPkt = IsAckEliciting orelse (Size > 0),

    Packet = #sent_packet{
        packet_number = PN,
        time_sent = TimeSent,
        size = Size,
        ack_eliciting = IsAckEliciting,
        in_flight = InFlightPkt,
        frames = Frames
    },

    CCAfterIdle =
        case is_idle_reset(LastSend, TimeSent, InFlight, RTT) of
            true -> nquic_cc:on_idle_reset(CC);
            false -> CC
        end,

    NewInFlight =
        if
            InFlightPkt -> InFlight + Size;
            true -> InFlight
        end,
    NewCC = nquic_cc:on_packet_sent(CCAfterIdle, Size, NewInFlight),
    NewAEIF =
        if
            IsAckEliciting -> AEIF + 1;
            true -> AEIF
        end,

    NewPacer = pacer_advance(Pacer, NewCC, RTT, TimeSent, Size),

    State#loss_state{
        sent_packets = AllSent#{Space := nquic_pn_buf:insert(PN, Packet, SpaceSent)},
        cc_state = NewCC,
        bytes_in_flight = NewInFlight,
        ack_eliciting_in_flight = NewAEIF,
        last_send_time = TimeSent,
        pacer = NewPacer
    }.

-doc "Increment the PTO count after a probe timeout fires.".
-spec on_pto(loss_state()) -> loss_state().
on_pto(#loss_state{pto_count = Count} = State) ->
    State#loss_state{pto_count = Count + 1}.

-spec pc_duration(
    #{smoothed_rtt := non_neg_integer(), rttvar := non_neg_integer(), _ => _},
    non_neg_integer()
) -> non_neg_integer().
pc_duration(RTTStats, MaxAckDelayUs) when is_integer(MaxAckDelayUs), MaxAckDelayUs >= 0 ->
    SRTT = maps:get(smoothed_rtt, RTTStats),
    RTTVar = maps:get(rttvar, RTTStats),
    Base = SRTT + max(4 * RTTVar, ?K_GRANULARITY_US) + MaxAckDelayUs,
    Base * ?K_PERSISTENT_CONGESTION_THRESHOLD.

-spec process_acked_ranges(
    nquic_pn_buf:buf(),
    [{non_neg_integer(), non_neg_integer()}]
) -> {nquic_pn_buf:buf(), [sent_packet()]}.
process_acked_ranges(Sent, AckedRanges) ->
    process_acked_ranges_loop(AckedRanges, Sent, []).

-spec process_acked_ranges_loop(
    [{non_neg_integer(), non_neg_integer()}],
    nquic_pn_buf:buf(),
    [sent_packet()]
) -> {nquic_pn_buf:buf(), [sent_packet()]}.
process_acked_ranges_loop([], Sent, Acked) ->
    {Sent, Acked};
process_acked_ranges_loop([{Low, High} | Rest], Sent, Acked) ->
    {Removed, Sent1} = nquic_pn_buf:take_range(Low, High, Sent),
    process_acked_ranges_loop(Rest, Sent1, Removed ++ Acked).

-doc """
Process ECN counts from a received ACK frame (RFC 9002 Section 7.1).
Compares the peer's reported CE count against the last known baseline.
If CE count increased, triggers a congestion event on the CC algorithm.
If total ECN marks decreased (validation failure), disables ECN for the path.
Returns `{ok, State}` when no CE increase was detected, or
`{ok, State}` after congestion window reduction when CE increased.
""".
-spec process_ecn_counts(
    loss_state(),
    nquic_packet:space(),
    {non_neg_integer(), non_neg_integer(), non_neg_integer()} | undefined
) -> loss_state().
process_ecn_counts(State, _Space, undefined) ->
    State;
process_ecn_counts(State, Space, {ECT0, ECT1, CE}) ->
    #loss_state{
        peer_ecn_ce = AllCE,
        peer_ecn_total = AllTotal,
        cc_state = CC,
        bytes_in_flight = InFlight
    } = State,
    PrevCE = maps:get(Space, AllCE, 0),
    PrevTotal = maps:get(Space, AllTotal, 0),
    NewTotal = ECT0 + ECT1 + CE,
    case NewTotal < PrevTotal of
        true ->
            State#loss_state{ecn_enabled = false, ecn_socket_dirty = true};
        false ->
            State1 = State#loss_state{
                peer_ecn_ce = AllCE#{Space => CE},
                peer_ecn_total = AllTotal#{Space => NewTotal}
            },
            case CE > PrevCE of
                true ->
                    Now = erlang:monotonic_time(microsecond),
                    NewCC = nquic_cc:on_congestion_event(CC, 0, InFlight, Now),
                    State1#loss_state{cc_state = NewCC};
                false ->
                    State1
            end
    end.

-spec prune_recently_lost(nquic_pn_buf:buf(), integer()) -> nquic_pn_buf:buf().
prune_recently_lost(RecentlyLost, Cutoff) ->
    {_Old, Pruned} = nquic_pn_buf:take_older_than(RecentlyLost, Cutoff),
    Pruned.

-spec scan_pc_run(
    [sent_packet(), ...], sent_packet() | undefined, non_neg_integer()
) -> boolean().
scan_pc_run([_], _RunStart, _PCD) ->
    false;
scan_pc_run([P1, P2 | Rest], RunStart, PCD) ->
    case P2#sent_packet.packet_number == P1#sent_packet.packet_number + 1 of
        true ->
            Start =
                case RunStart of
                    undefined -> P1;
                    _ -> RunStart
                end,
            case P2#sent_packet.time_sent - Start#sent_packet.time_sent >= PCD of
                true -> true;
                false -> scan_pc_run([P2 | Rest], Start, PCD)
            end;
        false ->
            scan_pc_run([P2 | Rest], undefined, PCD)
    end.

%%%-----------------------------------------------------------------------------
%% PACER (RFC 9002 §7.7)
%%%-----------------------------------------------------------------------------
-doc "Clear the `ecn_socket_dirty` flag after the caller has applied the transition.".
-spec clear_ecn_socket_dirty(loss_state()) -> loss_state().
clear_ecn_socket_dirty(S) -> S#loss_state{ecn_socket_dirty = false}.

-spec in_slow_start(nquic_cc:cc_state()) -> boolean().
in_slow_start(CC) ->
    case nquic_cc:get_ssthresh(CC) of
        undefined -> true;
        Ssthresh -> nquic_cc:get_cwnd(CC) =< Ssthresh
    end.

-doc """
Cheap predicate for the `ecn_socket_dirty` flag.
Pure record-field read, no allocation. The flush hot path uses this to
short-circuit out of the rare validation-failure transition without
paying for a tuple return.
""".
-spec is_ecn_socket_dirty(loss_state()) -> boolean().
is_ecn_socket_dirty(#loss_state{ecn_socket_dirty = D}) -> D.

-spec pacer_advance(
    pacer_state(),
    nquic_cc:cc_state(),
    nquic_rtt:rtt_state(),
    integer(),
    non_neg_integer()
) -> pacer_state().
pacer_advance(#pacer_state{enabled = false} = P, _CC, _RTT, _Now, _Size) ->
    P;
pacer_advance(#pacer_state{} = P, CC, RTT, Now, Size) ->
    case in_slow_start(CC) of
        true ->
            P;
        false ->
            SRTT = max(?K_GRANULARITY_US, nquic_rtt:smoothed_rtt(RTT)),
            Cwnd = max(1, nquic_cc:get_cwnd(CC)),
            #pacer_state{factor = N, burst_packets = Burst} = P,
            MSS = nquic_cc:get_max_datagram_size(CC),
            Delta = round(Size * SRTT / (N * Cwnd)),
            BurstCredit = Burst * MSS * SRTT div max(1, Cwnd),
            Floor = Now - BurstCredit,
            Base =
                case P#pacer_state.next_send_time of
                    undefined -> Floor;
                    Prev -> max(Floor, Prev)
                end,
            P#pacer_state{next_send_time = Base + Delta}
    end.

-doc """
Decide whether the pacer admits a send at `Now` (microsecond
monotonic). Returns `pass` to send immediately or `{block, NextUs}`
when the caller must hold off until `NextUs`. Disabled or in-slow-
start pacers always pass.
""".
-spec pacer_check(loss_state() | undefined, integer()) ->
    pass | {block, integer()}.
pacer_check(undefined, _Now) ->
    pass;
pacer_check(#loss_state{pacer = #pacer_state{enabled = false}}, _Now) ->
    pass;
pacer_check(#loss_state{pacer = #pacer_state{next_send_time = undefined}}, _Now) ->
    pass;
pacer_check(#loss_state{cc_state = CC, pacer = #pacer_state{} = P}, Now) ->
    case in_slow_start(CC) of
        true ->
            pass;
        false ->
            #pacer_state{next_send_time = NextUs} = P,
            case Now >= NextUs of
                true -> pass;
                false -> {block, NextUs}
            end
    end.

-doc """
Project the pacer + CC configuration as a map suitable for re-passing
to `init/2`. Used by code paths that re-initialise loss state on path
/ retry transitions and want to preserve pacing and HyStart++ settings.
""".
-spec pacer_config(loss_state()) -> map().
pacer_config(#loss_state{pacer = #pacer_state{} = P, cc_state = CC}) ->
    Base = #{
        enabled => P#pacer_state.enabled,
        factor => P#pacer_state.factor,
        burst_packets => P#pacer_state.burst_packets
    },
    case slow_start_mode(CC) of
        undefined -> Base;
        Mode -> Base#{slow_start => Mode}
    end.

-doc "Disable the pacer. Used by the caller to opt out at runtime.".
-spec pacer_disable(loss_state()) -> loss_state().
pacer_disable(#loss_state{pacer = P} = State) ->
    State#loss_state{pacer = P#pacer_state{enabled = false}}.

-doc """
Whether the pacer is configured on this connection. The pacer may be
present-and-disengaged if `cwnd =< ssthresh` (still in slow start) or
if the pacing budget has not been built up yet.
""".
-spec pacer_is_enabled(loss_state()) -> boolean().
pacer_is_enabled(#loss_state{pacer = #pacer_state{enabled = E}}) -> E.

-doc """
Earliest microsecond (monotonic, may be negative on Erlang's
monotonic clock) at which the pacer permits the next send.
`undefined` if the pacer has never engaged on this connection.
""".
-spec pacer_next_send_time(loss_state()) -> undefined | integer().
pacer_next_send_time(#loss_state{pacer = #pacer_state{next_send_time = T}}) -> T.

-doc """
Project a flat path-stats map for `nquic_conn:path_stats/1`.
Sums per-PN-space ECN counts (peer-reported CE and total) into single
integers so the consumer does not have to know about packet-number
spaces.
""".
-spec path_stats(loss_state()) -> path_stats().
path_stats(#loss_state{} = S) ->
    #loss_state{
        cc_state = CC,
        bytes_in_flight = InFlight,
        pto_count = PtoCount,
        rtt_state = RTT,
        ecn_enabled = ECN,
        peer_ecn_ce = PeerCE,
        peer_ecn_total = PeerTotal
    } = S,
    Stats = nquic_rtt:get(RTT),
    SumValues =
        fun(Map) ->
            maps:fold(fun(_K, V, Acc) -> Acc + V end, 0, Map)
        end,
    #{
        srtt_us => maps:get(smoothed_rtt, Stats, 0),
        rttvar_us => maps:get(rttvar, Stats, 0),
        min_rtt_us => maps:get(min_rtt, Stats, 0),
        latest_rtt_us => maps:get(latest_rtt, Stats, 0),
        cwnd => nquic_cc:get_cwnd(CC),
        bytes_in_flight => InFlight,
        ssthresh => nquic_cc:get_ssthresh(CC),
        mss => nquic_cc:get_max_datagram_size(CC),
        ecn_enabled => ECN,
        peer_ecn_ce => SumValues(PeerCE),
        peer_ecn_total => SumValues(PeerTotal),
        pto_count => PtoCount
    }.

-doc "Reset the PTO count to zero after receiving an ACK.".
-spec reset_pto_count(loss_state()) -> loss_state().
reset_pto_count(State) ->
    State#loss_state{pto_count = 0}.

-doc "Enable or disable ECN for this connection.".
-spec set_ecn_enabled(loss_state(), boolean()) -> loss_state().
set_ecn_enabled(State, E) -> State#loss_state{ecn_enabled = E}.

-doc "Set the maximum datagram size used by the congestion controller.".
-spec set_max_datagram_size(loss_state(), pos_integer()) -> loss_state().
set_max_datagram_size(State, MaxSize) when MaxSize >= 1200 ->
    #loss_state{cc_state = CC} = State,
    NewCC = nquic_cc:set_max_datagram_size(CC, MaxSize),
    State#loss_state{cc_state = NewCC}.

-spec slow_start_mode(nquic_cc:cc_state()) -> standard | hystart_plus_plus | undefined.
slow_start_mode({nquic_cc_cubic, S}) ->
    case nquic_cc_cubic:hystart_phase(S) of
        standard -> standard;
        _ -> hystart_plus_plus
    end;
slow_start_mode(_) ->
    undefined.
