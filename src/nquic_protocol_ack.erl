-module(nquic_protocol_ack).
-moduledoc """
ACK generation and received-packet-number bookkeeping (RFC 9000 §13.2,
§19.3).

Pure functions over `#conn_state{}` covering received-PN range algebra
(insert / merge / prune), per-space `received_ranges` and
`largest_received` tracking, ECN counter accounting, ACK-frame
construction, and the ack-eliciting decision that governs whether an
ACK is queued. Queued ACKs drain into the per-encryption-level frame
queues owned by `nquic_protocol_send`, which this module calls
module-qualified.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-export([
    apply_received_ranges_prune/3,
    build_ack_for_space/2,
    force_queue_ack/2,
    insert_pn_range/2,
    is_ack_eliciting/1,
    maybe_queue_ack/3,
    merge_ranges/1,
    prune_received_ranges/2,
    ranges_to_ack_ranges/2,
    track_ecn_mark/3,
    track_received_pn/3,
    track_received_pn_and_ecn/4
]).

-doc """
Apply RFC 9000 §13.2.4 pruning to `received_ranges` for `Space`.

`AckedFrames` is the flattened frame list returned by
`nquic_loss:on_ack_received/6` for an incoming ACK in `Space`. Any
`#ack{}` frames in that list are ACKs we previously sent that the peer
has now acknowledged; their `largest_acknowledged` value is therefore
known-known on both sides, so the corresponding tracked PNs can be
dropped from our `received_ranges`. Without this prune `received_ranges`
grows monotonically across a connection's lifetime and inflates both
ACK build cost and the work the peer does to process those ACKs.
""".
-spec apply_received_ranges_prune(
    nquic_packet:space(), [nquic_frame:t()], nquic_protocol:state()
) -> nquic_protocol:state().
apply_received_ranges_prune(Space, AckedFrames, State) ->
    case max_largest_acked(AckedFrames, undefined) of
        undefined ->
            State;
        Threshold ->
            #conn_state{pn_spaces = PnSpaces} = State,
            SpaceMap = maps:get(Space, PnSpaces, #{}),
            case maps:get(received_ranges, SpaceMap, []) of
                [] ->
                    State;
                Ranges ->
                    NewRanges = prune_received_ranges(Ranges, Threshold),
                    NewSpaceMap = SpaceMap#{received_ranges => NewRanges},
                    State#conn_state{pn_spaces = PnSpaces#{Space => NewSpaceMap}}
            end
    end.

-spec build_ack_for_space(nquic_packet:space(), nquic_protocol:state()) -> {ok, #ack{}} | none.
build_ack_for_space(Space, #conn_state{pn_spaces = PnSpaces}) ->
    SpaceMap = maps:get(Space, PnSpaces, #{}),
    Ranges = maps:get(received_ranges, SpaceMap, []),
    case Ranges of
        [{Largest, Low} | RestRanges] ->
            FirstAckRange = Largest - Low,
            AckRanges = ranges_to_ack_ranges(Low, RestRanges),
            ECN = ecn_counts_from_space(SpaceMap),
            {ok, #ack{
                largest_acknowledged = Largest,
                delay = 0,
                first_ack_range = FirstAckRange,
                ack_ranges = AckRanges,
                ecn_counts = ECN
            }};
        [] ->
            none
    end.

-spec bump_app_ack(non_neg_integer(), nquic_protocol:state()) -> nquic_protocol:state().
bump_app_ack(Count, State) when Count >= 2 ->
    force_queue_ack(application, State#conn_state{pending_ack_count = 0});
bump_app_ack(Count, State) ->
    State#conn_state{pending_ack_count = Count}.

-spec ecn_counts_from_space(map()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer()} | undefined.
ecn_counts_from_space(SpaceMap) ->
    ECT0 = maps:get(ecn_ect0, SpaceMap, 0),
    ECT1 = maps:get(ecn_ect1, SpaceMap, 0),
    CE = maps:get(ecn_ce, SpaceMap, 0),
    case ECT0 + ECT1 + CE of
        0 -> undefined;
        _ -> {ECT0, ECT1, CE}
    end.

-spec ecn_mark_key(nquic_socket:ecn_mark()) -> ecn_ect0 | ecn_ect1 | ecn_ce.
ecn_mark_key(ect0) -> ecn_ect0;
ecn_mark_key(ect1) -> ecn_ect1;
ecn_mark_key(ce) -> ecn_ce.

-spec force_queue_ack(application, nquic_protocol:state()) -> nquic_protocol:state().
force_queue_ack(application, State) ->
    queue_app_ack(build_ack_for_space(application, State), State).

-spec insert_pn_range(nquic_packet_number:t(), [{nquic_packet_number:t(), nquic_packet_number:t()}]) ->
    [{nquic_packet_number:t(), nquic_packet_number:t()}].
insert_pn_range(PN, []) ->
    [{PN, PN}];
insert_pn_range(PN, [{High, Low} | Rest]) ->
    if
        PN >= Low, PN =< High ->
            [{High, Low} | Rest];
        PN =:= High + 1 ->
            merge_ranges([{PN, Low} | Rest]);
        PN =:= Low - 1 ->
            merge_ranges([{High, PN} | Rest]);
        PN > High + 1 ->
            [{PN, PN}, {High, Low} | Rest];
        true ->
            [{High, Low} | insert_pn_range(PN, Rest)]
    end.

-spec is_ack_eliciting([nquic_frame:t()]) -> boolean().
is_ack_eliciting([]) -> false;
is_ack_eliciting([#ack{} | Rest]) -> is_ack_eliciting(Rest);
is_ack_eliciting([#padding{} | Rest]) -> is_ack_eliciting(Rest);
is_ack_eliciting([#connection_close{} | Rest]) -> is_ack_eliciting(Rest);
is_ack_eliciting([_ | _]) -> true.

-spec max_largest_acked([nquic_frame:t()], nquic_packet_number:t() | undefined) ->
    nquic_packet_number:t() | undefined.
max_largest_acked([], Acc) ->
    Acc;
max_largest_acked([#ack{largest_acknowledged = L} | Rest], undefined) ->
    max_largest_acked(Rest, L);
max_largest_acked([#ack{largest_acknowledged = L} | Rest], Acc) when L > Acc ->
    max_largest_acked(Rest, L);
max_largest_acked([_ | Rest], Acc) ->
    max_largest_acked(Rest, Acc).

-spec maybe_queue_ack(nquic_packet:header(), [nquic_frame:t()], nquic_protocol:state()) ->
    nquic_protocol:state().
maybe_queue_ack(Header, Frames, State) ->
    queue_ack_if_eliciting(is_ack_eliciting(Frames), Header, State).

-spec merge_ranges([{nquic_packet_number:t(), nquic_packet_number:t()}]) ->
    [{nquic_packet_number:t(), nquic_packet_number:t()}].
merge_ranges([{H1, L1}, {H2, L2} | Rest]) when L1 =< H2 + 1 ->
    merge_ranges([{max(H1, H2), min(L1, L2)} | Rest]);
merge_ranges(Ranges) ->
    Ranges.

-doc """
Drop ranges from `received_ranges` (descending list of `{High, Low}`
pairs) whose entire span is at or below `Threshold`. The range that
straddles `Threshold` is truncated; ranges entirely above `Threshold`
are unchanged. Used by `apply_received_ranges_prune/3` to apply RFC
9000 §13.2.4.
""".
-spec prune_received_ranges(
    [{nquic_packet_number:t(), nquic_packet_number:t()}], nquic_packet_number:t()
) -> [{nquic_packet_number:t(), nquic_packet_number:t()}].
prune_received_ranges([], _Threshold) ->
    [];
prune_received_ranges([{_H, L} = R | Rest], Threshold) when L > Threshold ->
    [R | prune_received_ranges(Rest, Threshold)];
prune_received_ranges([{H, _L} | _Rest], Threshold) when H =< Threshold ->
    [];
prune_received_ranges([{H, _L} | _Rest], Threshold) ->
    [{H, Threshold + 1}].

-spec queue_ack_for_space(nquic_packet:space(), nquic_protocol:state()) -> nquic_protocol:state().
queue_ack_for_space(initial, State) ->
    queue_initial_ack(build_ack_for_space(initial, State), State);
queue_ack_for_space(handshake, State) ->
    queue_handshake_ack(build_ack_for_space(handshake, State), State);
queue_ack_for_space(application, #conn_state{pending_ack_count = Count} = State) ->
    bump_app_ack(Count + 1, State).

-spec queue_ack_if_eliciting(boolean(), nquic_packet:header(), nquic_protocol:state()) ->
    nquic_protocol:state().
queue_ack_if_eliciting(false, _Header, State) ->
    State;
queue_ack_if_eliciting(true, Header, State) ->
    queue_ack_for_space(nquic_protocol_send:packet_space_from_header(Header), State).

-spec queue_app_ack({ok, #ack{}} | none, nquic_protocol:state()) -> nquic_protocol:state().
queue_app_ack({ok, AckFrame}, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_app_frame(AckFrame, State),
    State1;
queue_app_ack(none, State) ->
    State.

-spec queue_handshake_ack({ok, #ack{}} | none, nquic_protocol:state()) -> nquic_protocol:state().
queue_handshake_ack({ok, AckFrame}, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_handshake_frame(AckFrame, State),
    State1;
queue_handshake_ack(none, State) ->
    State.

-spec queue_initial_ack({ok, #ack{}} | none, nquic_protocol:state()) -> nquic_protocol:state().
queue_initial_ack({ok, AckFrame}, State) ->
    {ok, State1} = nquic_protocol_send_queues:queue_initial_frame(AckFrame, State),
    State1;
queue_initial_ack(none, State) ->
    State.

-spec ranges_to_ack_ranges(nquic_packet_number:t(), [
    {nquic_packet_number:t(), nquic_packet_number:t()}
]) ->
    [#ack_range{}].
ranges_to_ack_ranges(_PrevLow, []) ->
    [];
ranges_to_ack_ranges(PrevLow, [{High, Low} | Rest]) ->
    Gap = PrevLow - High - 2,
    Length = High - Low,
    [#ack_range{gap = Gap, length = Length} | ranges_to_ack_ranges(Low, Rest)].

-doc "Increment the per-space ECN counter for the given mark.".
-spec track_ecn_mark(nquic_packet:space(), nquic_socket:ecn_mark(), nquic_protocol:state()) ->
    nquic_protocol:state().
track_ecn_mark(_Space, not_ect, State) ->
    State;
track_ecn_mark(Space, Mark, #conn_state{pn_spaces = PnSpaces} = State) ->
    SpaceMap = maps:get(Space, PnSpaces, #{next_pn => 0}),
    Key = ecn_mark_key(Mark),
    Old = maps:get(Key, SpaceMap, 0),
    NewSpaceMap = SpaceMap#{Key => Old + 1},
    State#conn_state{pn_spaces = PnSpaces#{Space => NewSpaceMap}}.

-spec track_received_pn(nquic_packet:space(), nquic_packet_number:t(), nquic_protocol:state()) ->
    nquic_protocol:state().
track_received_pn(application, PN, State) ->
    PnSpaces = State#conn_state.pn_spaces,
    SpaceMap = maps:get(application, PnSpaces, #{next_pn => 0}),
    Ranges = maps:get(received_ranges, SpaceMap, []),
    NewRanges = insert_pn_range(PN, Ranges),
    NewSpaceMap = SpaceMap#{received_ranges => NewRanges},
    State#conn_state{
        app_largest_received = max(PN, State#conn_state.app_largest_received),
        pn_spaces = PnSpaces#{application => NewSpaceMap}
    };
track_received_pn(Space, PN, State) ->
    #conn_state{pn_spaces = PnSpaces} = State,
    SpaceMap = maps:get(Space, PnSpaces, #{next_pn => 0}),
    LargestReceived = maps:get(largest_received, SpaceMap, -1),
    Ranges = maps:get(received_ranges, SpaceMap, []),
    NewRanges = insert_pn_range(PN, Ranges),
    NewSpaceMap = SpaceMap#{
        largest_received => max(PN, LargestReceived),
        received_ranges => NewRanges
    },
    State#conn_state{pn_spaces = PnSpaces#{Space => NewSpaceMap}}.

-doc """
Fused PN tracking + ECN counter update in a single `pn_spaces` rewrite.
Replaces `track_received_pn/3` followed by `track_ecn_mark/3` on the
recv hot path, halving the `#conn_state{}` record copies and the
outer `pn_spaces` map updates. Behaviourally equivalent to calling
both helpers in sequence.
""".
-spec track_received_pn_and_ecn(
    nquic_packet:space(), nquic_packet_number:t(), nquic_socket:ecn_mark(), nquic_protocol:state()
) -> nquic_protocol:state().
track_received_pn_and_ecn(application, PN, ECN, #conn_state{pn_spaces = PnSpaces} = State) ->
    SpaceMap = maps:get(application, PnSpaces, #{next_pn => 0}),
    Ranges = maps:get(received_ranges, SpaceMap, []),
    NewRanges = insert_pn_range(PN, Ranges),
    SpaceMap1 = SpaceMap#{received_ranges => NewRanges},
    NewSpaceMap =
        case ECN of
            not_ect ->
                SpaceMap1;
            _ ->
                Key = ecn_mark_key(ECN),
                Old = maps:get(Key, SpaceMap1, 0),
                SpaceMap1#{Key => Old + 1}
        end,
    State#conn_state{
        app_largest_received = max(PN, State#conn_state.app_largest_received),
        pn_spaces = PnSpaces#{application => NewSpaceMap}
    };
track_received_pn_and_ecn(Space, PN, ECN, #conn_state{pn_spaces = PnSpaces} = State) ->
    SpaceMap = maps:get(Space, PnSpaces, #{next_pn => 0}),
    LargestReceived = maps:get(largest_received, SpaceMap, -1),
    Ranges = maps:get(received_ranges, SpaceMap, []),
    NewRanges = insert_pn_range(PN, Ranges),
    SpaceMap1 = SpaceMap#{
        largest_received => max(PN, LargestReceived),
        received_ranges => NewRanges
    },
    NewSpaceMap =
        case ECN of
            not_ect ->
                SpaceMap1;
            _ ->
                Key = ecn_mark_key(ECN),
                Old = maps:get(Key, SpaceMap1, 0),
                SpaceMap1#{Key => Old + 1}
        end,
    State#conn_state{pn_spaces = PnSpaces#{Space => NewSpaceMap}}.
