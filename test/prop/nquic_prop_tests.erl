%%%-------------------------------------------------------------------
%%% Property-based tests for nquic
%%%-------------------------------------------------------------------
-module(nquic_prop_tests).

-include_lib("triq/include/triq.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("nquic/src/nquic_conn.hrl").
-include_lib("nquic/src/nquic_frame.hrl").
-include_lib("nquic/src/nquic_loss.hrl").
-include_lib("nquic/src/nquic_transport.hrl").

-compile(nowarn_unused_import).


varint_roundtrip_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(1000, prop_varint_roundtrip())))}.

varint_size_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(1000, prop_varint_size())))}.

frame_roundtrip_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(500, prop_frame_roundtrip())))}.

packet_number_roundtrip_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(1000, prop_packet_number_roundtrip())))}.

transport_params_roundtrip_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(200, prop_transport_params_roundtrip())))}.

connection_id_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(1000, prop_connection_id_valid())))}.

stream_recv_buffer_permutation_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(200, prop_stream_recv_buffer_permutation())))}.

ack_ranges_monotonic_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(200, prop_ack_ranges_monotonic())))}.

bytes_in_flight_invariant_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(200, prop_bytes_in_flight_invariant())))}.

ack_eliciting_counter_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(200, prop_ack_eliciting_counter())))}.

bytes_in_flight_invariant_bulk_prop_test_() ->
    {timeout, 120,
        ?_assert(triq:check(triq:numtests(30, prop_bytes_in_flight_invariant_bulk())))}.

ack_eliciting_counter_bulk_prop_test_() ->
    {timeout, 120,
        ?_assert(triq:check(triq:numtests(30, prop_ack_eliciting_counter_bulk())))}.

pto_monotonic_prop_test_() ->
    {timeout, 60, ?_assert(triq:check(triq:numtests(200, prop_pto_monotonic())))}.


varint() ->
    ?LET(Bits, int(0, 62),
         ?LET(Val, int(0, (1 bsl Bits) - 1),
              Val)).

varint_1byte() -> int(0, 63).

stream_id() ->
    ?LET({Base, Type}, {int(0, 16#FFFFFFF), int(0, 3)},
         Base * 4 + Type).

packet_number() -> int(0, 16#FFFFFFFF).

small_binary() ->
    ?LET(Len, int(0, 100),
         binary(Len)).

ping_frame() -> #ping{}.

ack_frame() ->
    ?LET({Largest, Delay, FirstRange}, {packet_number(), varint_1byte(), varint_1byte()},
         #ack{largest_acknowledged = Largest, delay = Delay, first_ack_range = FirstRange, ack_ranges = []}).

crypto_frame() ->
    ?LET({Offset, Data}, {varint(), small_binary()},
         #crypto{offset = Offset, data = Data}).

stream_frame() ->
    ?LET({StreamId, Offset, Fin, Data}, {stream_id(), varint(), bool(), small_binary()},
         #stream{stream_id = StreamId, offset = Offset, length = byte_size(Data),
                 fin = Fin, data = Data}).

max_data_frame() ->
    ?LET(Max, varint(),
         #max_data{max_data = Max}).

max_stream_data_frame() ->
    ?LET({StreamId, Max}, {stream_id(), varint()},
         #max_stream_data{stream_id = StreamId, max_stream_data = Max}).

max_streams_frame() ->
    ?LET({IsUni, Max}, {bool(), int(0, (1 bsl 60) - 1)},
         #max_streams{is_uni = IsUni, max_streams = Max}).

connection_close_frame() ->
    ?LET({Code, FrameType, Reason}, {varint(), varint(), small_binary()},
         #connection_close{error_code = Code, frame_type = FrameType, reason_phrase = Reason}).

handshake_done_frame() -> #handshake_done{}.

any_frame() ->
    oneof([
        ping_frame(),
        ack_frame(),
        crypto_frame(),
        stream_frame(),
        max_data_frame(),
        max_stream_data_frame(),
        max_streams_frame(),
        connection_close_frame(),
        handshake_done_frame()
    ]).

transport_params() ->
    ?LET({MaxIdle, MaxUdp, MaxData, MaxStreamBidiL, MaxStreamBidiR, MaxStreamUni,
          MaxBidi, MaxUni, AckDelay, MaxAckDelay, DisableMigration, ActiveCidLimit,
          InitSCIDLen},
         {int(1, 300000), int(1200, 65527), int(1, 16#FFFFFFFF),
          int(1, 16#FFFFFFFF), int(1, 16#FFFFFFFF), int(1, 16#FFFFFFFF),
          int(1, 16#FFFF), int(1, 16#FFFF), int(1, 20), int(1, 16383),
          bool(), int(2, 8), int(4, 20)},
         #transport_params{
             max_idle_timeout = MaxIdle,
             max_udp_payload_size = MaxUdp,
             initial_max_data = MaxData,
             initial_max_stream_data_bidi_local = MaxStreamBidiL,
             initial_max_stream_data_bidi_remote = MaxStreamBidiR,
             initial_max_stream_data_uni = MaxStreamUni,
             initial_max_streams_bidi = MaxBidi,
             initial_max_streams_uni = MaxUni,
             ack_delay_exponent = AckDelay,
             max_ack_delay = MaxAckDelay,
             disable_active_migration = DisableMigration,
             active_connection_id_limit = ActiveCidLimit,
             initial_source_connection_id = crypto:strong_rand_bytes(InitSCIDLen)
         }).


prop_varint_roundtrip() ->
    ?FORALL(Val, varint(),
            begin
                Encoded = nquic_varint:encode(Val),
                {ok, Decoded, <<>>} = nquic_varint:decode(Encoded),
                Val =:= Decoded
            end).

prop_varint_size() ->
    ?FORALL(Val, varint(),
            begin
                Encoded = nquic_varint:encode(Val),
                Size = byte_size(Encoded),
                ExpectedSize = if
                    Val =< 63 -> 1;
                    Val =< 16383 -> 2;
                    Val =< 1073741823 -> 4;
                    true -> 8
                end,
                Size =:= ExpectedSize
            end).

prop_frame_roundtrip() ->
    ?FORALL(Frame, any_frame(),
            begin
                Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
                {ok, Decoded, <<>>} = nquic_frame:decode(Encoded),
                frames_equal(Frame, Decoded)
            end).

prop_packet_number_roundtrip() ->
    ?FORALL({LargestAcked, Delta}, {int(0, 16#FFFFFFFF), int(0, 16#FFFF)},
            begin
                PN = LargestAcked + Delta,
                {PnLen, TruncatedPN} = nquic_packet_number:encode(PN, LargestAcked),
                Decoded = nquic_packet_number:decode(LargestAcked, TruncatedPN, PnLen),
                PN =:= Decoded
            end).

prop_transport_params_roundtrip() ->
    ?FORALL(Params, transport_params(),
            begin
                Encoded = nquic_transport:encode(Params),
                {ok, Decoded} = nquic_transport:decode(Encoded, client),
                transport_params_equal(Params, Decoded)
            end).

prop_connection_id_valid() ->
    ?FORALL(Len, int(1, 20),
            begin
                CID = nquic_keys:generate_connection_id(Len),
                byte_size(CID) =:= Len
            end).

prop_stream_recv_buffer_permutation() ->
    ?FORALL(
        {N, ChunkSize},
        {int(1, 200), int(1, 16)},
        ?FORALL(
            Perm,
            shuffled_chunks(N, ChunkSize),
            begin
                Final = lists:foldl(
                    fun({Offset, Data}, S) ->
                        Frame = #stream{stream_id = 0, offset = Offset, data = Data, fin = false},
                        {ok, S1} = nquic_stream_statem:handle_recv(S, Frame),
                        S1
                    end,
                    nquic_stream_statem:new(0, bidi),
                    Perm
                ),
                Total = N * ChunkSize,
                Expected = list_to_binary([B band 255 || B <- lists:seq(0, Total - 1)]),
                Final#stream_state.recv_offset =:= Total andalso
                    iolist_to_binary(Final#stream_state.app_buffer) =:= Expected
            end
        )
    ).

shuffled_chunks(N, Size) ->
    Chunks = [
        {I * Size, list_to_binary([(I * Size + J) band 255 || J <- lists:seq(0, Size - 1)])}
        || I <- lists:seq(0, N - 1)
    ],
    ?LET(
        Tagged,
        [{int(0, 1 bsl 30), C} || C <- Chunks],
        [C || {_, C} <- lists:keysort(1, Tagged)]
    ).


frames_equal(#ping{}, #ping{}) -> true;
frames_equal(#handshake_done{}, #handshake_done{}) -> true;
frames_equal(#ack{largest_acknowledged = L1, delay = D1, first_ack_range = F1, ack_ranges = R1},
             #ack{largest_acknowledged = L2, delay = D2, first_ack_range = F2, ack_ranges = R2}) ->
    L1 =:= L2 andalso D1 =:= D2 andalso F1 =:= F2 andalso R1 =:= R2;
frames_equal(#crypto{offset = O1, data = D1}, #crypto{offset = O2, data = D2}) ->
    O1 =:= O2 andalso D1 =:= D2;
frames_equal(#stream{stream_id = S1, offset = O1, fin = F1, data = D1},
             #stream{stream_id = S2, offset = O2, fin = F2, data = D2}) ->
    S1 =:= S2 andalso O1 =:= O2 andalso F1 =:= F2 andalso D1 =:= D2;
frames_equal(#max_data{max_data = M1}, #max_data{max_data = M2}) ->
    M1 =:= M2;
frames_equal(#max_stream_data{stream_id = S1, max_stream_data = M1},
             #max_stream_data{stream_id = S2, max_stream_data = M2}) ->
    S1 =:= S2 andalso M1 =:= M2;
frames_equal(#max_streams{is_uni = U1, max_streams = M1},
             #max_streams{is_uni = U2, max_streams = M2}) ->
    U1 =:= U2 andalso M1 =:= M2;
frames_equal(#connection_close{error_code = E1, frame_type = F1, reason_phrase = R1},
             #connection_close{error_code = E2, frame_type = F2, reason_phrase = R2}) ->
    E1 =:= E2 andalso F1 =:= F2 andalso R1 =:= R2;
frames_equal(_, _) -> false.



loss_op_seq() ->
    ?LET(N, int(1, 30), gen_loss_ops(N)).

gen_loss_ops(N) ->
    gen_loss_ops(N, 0, [], []).

gen_loss_ops(0, _NextPN, _InFlight, Acc) ->
    lists:reverse(Acc);
gen_loss_ops(N, NextPN, InFlight, Acc) ->
    ?LET(
        OpKind,
        weighted_op_kind(InFlight),
        case OpKind of
            send ->
                ?LET(
                    {Sz, AE},
                    {int(100, 1500), bool()},
                    gen_loss_ops(
                        N - 1,
                        NextPN + 1,
                        [{NextPN, Sz, AE} | InFlight],
                        [{send, NextPN, Sz, AE} | Acc]
                    )
                );
            ack when InFlight =/= [] ->
                ?LET(
                    Ranges,
                    pick_ranges([PN || {PN, _, _} <- InFlight]),
                    begin
                        Acked = [
                            PN
                         || PN <- [P || {P, _, _} <- InFlight],
                            in_any_range(PN, Ranges)
                        ],
                        gen_loss_ops(
                            N - 1,
                            NextPN,
                            [E || {PN, _, _} = E <- InFlight, not lists:member(PN, Acked)],
                            [{ack, Ranges, NextPN * 100 + 1} | Acc]
                        )
                    end
                );
            ack ->
                gen_loss_ops(N, NextPN, InFlight, Acc)
        end
    ).

weighted_op_kind([]) -> send;
weighted_op_kind(_) -> oneof([send, send, ack]).

in_any_range(_PN, []) -> false;
in_any_range(PN, [{Lo, Hi} | _]) when PN >= Lo, PN =< Hi -> true;
in_any_range(PN, [_ | Rest]) -> in_any_range(PN, Rest).

pick_ranges(PNs) when PNs =/= [] ->
    ?LET(
        Subset,
        non_empty_subset(PNs),
        collapse_ranges(lists:reverse(lists:usort(Subset)))
    ).

non_empty_subset([X]) ->
    [X];
non_empty_subset(PNs) ->
    ?LET(Mask, vector(length(PNs), bool()), begin
        Picked = [PN || {PN, true} <- lists:zip(PNs, Mask)],
        case Picked of
            [] -> [hd(PNs)];
            _ -> Picked
        end
    end).

collapse_ranges([]) ->
    [];
collapse_ranges([P | Rest]) ->
    collapse_ranges(Rest, P, P, []).

collapse_ranges([], Hi, Lo, Acc) ->
    lists:reverse([{Lo, Hi} | Acc]);
collapse_ranges([P | Rest], Hi, Lo, Acc) when P =:= Lo - 1 ->
    collapse_ranges(Rest, Hi, P, Acc);
collapse_ranges([P | Rest], Hi, Lo, Acc) ->
    collapse_ranges(Rest, P, P, [{Lo, Hi} | Acc]).

apply_op({send, PN, Size, AE}, State, Now) ->
    Frames =
        case AE of
            true -> [#stream{stream_id = PN, offset = 0, length = 0, data = <<>>}];
            false -> [#padding{}]
        end,
    nquic_loss:on_packet_sent(State, application, PN, Frames, Now, Size);
apply_op({ack, Ranges, _}, State, Now) ->
    {ok, State1, _, _} = nquic_loss:on_ack_received(
        State, application, Ranges, 0, Now, 25_000
    ),
    State1.

apply_ops(Ops, State0) ->
    {Final, _} = lists:foldl(
        fun(Op, {S, T}) ->
            S1 = apply_op(Op, S, T),
            {S1, T + 1000}
        end,
        {State0, 1000},
        Ops
    ),
    Final.

prop_ack_ranges_monotonic() ->
    ?FORALL(Ops, loss_op_seq(),
        begin
            {Largests, _} = lists:foldl(
                fun(Op, {Acc, S}) ->
                    S1 = apply_op(Op, S, 1000 + length(Acc) * 1000),
                    L = nquic_loss:get_largest_acked(S1, application),
                    {[L | Acc], S1}
                end,
                {[], nquic_loss:init()},
                Ops
            ),
            non_decreasing(lists:reverse(Largests))
        end).

non_decreasing([]) -> true;
non_decreasing([_]) -> true;
non_decreasing([A, B | Rest]) when A =< B -> non_decreasing([B | Rest]);
non_decreasing(_) -> false.

prop_bytes_in_flight_invariant() ->
    ?FORALL(Ops, loss_op_seq(),
        begin
            Final = apply_ops(Ops, nquic_loss:init()),
            Sent = nquic_loss:get_sent_packets(Final),
            ExpectedInFlight = lists:sum(
                [P#sent_packet.size || P <- Sent, P#sent_packet.in_flight]
            ),
            nquic_loss:get_bytes_in_flight(Final) =:= ExpectedInFlight
        end).

prop_ack_eliciting_counter() ->
    ?FORALL(Ops, loss_op_seq(),
        begin
            Final = apply_ops(Ops, nquic_loss:init()),
            Sent = nquic_loss:get_sent_packets(Final),
            Recount = length(
                [P || P <- Sent, P#sent_packet.ack_eliciting, P#sent_packet.in_flight]
            ),
            nquic_loss:get_ack_eliciting_in_flight(Final) =:= Recount
        end).

loss_op_seq_bulk() ->
    ?LET(N, int(150, 800), gen_loss_ops(N)).

prop_bytes_in_flight_invariant_bulk() ->
    ?FORALL(Ops, loss_op_seq_bulk(),
        begin
            Final = apply_ops(Ops, nquic_loss:init()),
            Sent = nquic_loss:get_sent_packets(Final),
            ExpectedInFlight = lists:sum(
                [P#sent_packet.size || P <- Sent, P#sent_packet.in_flight]
            ),
            nquic_loss:get_bytes_in_flight(Final) =:= ExpectedInFlight
        end).

prop_ack_eliciting_counter_bulk() ->
    ?FORALL(Ops, loss_op_seq_bulk(),
        begin
            Final = apply_ops(Ops, nquic_loss:init()),
            Sent = nquic_loss:get_sent_packets(Final),
            Recount = length(
                [P || P <- Sent, P#sent_packet.ack_eliciting, P#sent_packet.in_flight]
            ),
            nquic_loss:get_ack_eliciting_in_flight(Final) =:= Recount
        end).

prop_pto_monotonic() ->
    ?FORALL({Initial, K}, {nquic_loss_init_state(), int(0, 6)},
        begin
            States = lists:foldl(
                fun(_, [S | _] = Acc) -> [nquic_loss:on_pto(S) | Acc] end,
                [Initial],
                lists:seq(1, K)
            ),
            PTOs = [nquic_loss:get_pto_timeout(S, 25_000) || S <- lists:reverse(States)],
            non_decreasing(PTOs)
        end).

nquic_loss_init_state() ->
    ?LET(Sample, int(1_000, 200_000),
        begin
            S0 = nquic_loss:init(),
            S1 = nquic_loss:on_packet_sent(S0, application, 0, [#ping{}], 0, 100),
            {ok, S2, _, _} = nquic_loss:on_ack_received(
                S1, application, [{0, 0}], 0, Sample, 25_000
            ),
            S2
        end).

transport_params_equal(P1, P2) ->
    P1#transport_params.max_idle_timeout =:= P2#transport_params.max_idle_timeout andalso
    P1#transport_params.max_udp_payload_size =:= P2#transport_params.max_udp_payload_size andalso
    P1#transport_params.initial_max_data =:= P2#transport_params.initial_max_data andalso
    P1#transport_params.initial_max_stream_data_bidi_local =:= P2#transport_params.initial_max_stream_data_bidi_local andalso
    P1#transport_params.initial_max_stream_data_bidi_remote =:= P2#transport_params.initial_max_stream_data_bidi_remote andalso
    P1#transport_params.initial_max_stream_data_uni =:= P2#transport_params.initial_max_stream_data_uni andalso
    P1#transport_params.initial_max_streams_bidi =:= P2#transport_params.initial_max_streams_bidi andalso
    P1#transport_params.initial_max_streams_uni =:= P2#transport_params.initial_max_streams_uni andalso
    P1#transport_params.ack_delay_exponent =:= P2#transport_params.ack_delay_exponent andalso
    P1#transport_params.max_ack_delay =:= P2#transport_params.max_ack_delay andalso
    P1#transport_params.disable_active_migration =:= P2#transport_params.disable_active_migration andalso
    P1#transport_params.active_connection_id_limit =:= P2#transport_params.active_connection_id_limit.
