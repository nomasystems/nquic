%%%-------------------------------------------------------------------
%%% EUnit tests for {@link nquic_frame}.
%%%-------------------------------------------------------------------
-module(nquic_frame_tests).

-include_lib("eunit/include/eunit.hrl").

-include("nquic_frame.hrl").
padding_test() ->
    ?assertMatch({ok, #padding{}, <<>>}, nquic_frame:decode(nquic_frame:encode(#padding{}))).

ping_test() ->
    ?assertMatch({ok, #ping{}, <<>>}, nquic_frame:decode(nquic_frame:encode(#ping{}))).

crypto_test() ->
    Frame = #crypto{offset = 0, data = <<1, 2, 3>>},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    ?assertMatch({ok, Frame, <<>>}, nquic_frame:decode(Encoded)).

ack_test() ->
    Frame = #ack{
        largest_acknowledged = 100,
        delay = 10,
        first_ack_range = 5,
        ack_ranges = [#ack_range{gap = 1, length = 2}],
        ecn_counts = {1, 2, 3}
    },
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    ?assertMatch({ok, Frame, <<>>}, nquic_frame:decode(Encoded)).

stream_test() ->
    Frame = #stream{stream_id = 4, offset = 10, length = 3, data = <<7, 8, 9>>, fin = true},
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    ?assertMatch({ok, Frame, <<>>}, nquic_frame:decode(Encoded)).

connection_close_test() ->
    Frame = #connection_close{
        error_code = 123,
        frame_type = 1,
        reason_phrase = <<"oops">>,
        is_application = false
    },
    Encoded = iolist_to_binary(nquic_frame:encode(Frame)),
    ?assertMatch({ok, Frame, <<>>}, nquic_frame:decode(Encoded)).

handshake_done_test() ->
    ?assertMatch(
        {ok, #handshake_done{}, <<>>},
        nquic_frame:decode(nquic_frame:encode(#handshake_done{}))
    ).

%% STREAM frame type-byte variants without an explicit length (data
%% runs to end of packet) + NEW_CONNECTION_ID truncation.
decode_stream_no_len_variants_test_() ->
    [
        ?_assertEqual(
            {ok,
                #stream{
                    stream_id = 5,
                    offset = 0,
                    fin = false,
                    data = <<"hello">>,
                    length = 5
                },
                <<>>},
            nquic_frame:decode(<<8, 5, "hello">>)
        ),
        ?_assertEqual(
            {ok,
                #stream{
                    stream_id = 5,
                    offset = 0,
                    fin = true,
                    data = <<"hello">>,
                    length = 5
                },
                <<>>},
            nquic_frame:decode(<<9, 5, "hello">>)
        ),
        ?_assertEqual(
            {ok,
                #stream{
                    stream_id = 5,
                    offset = 10,
                    fin = false,
                    data = <<"hi">>,
                    length = 2
                },
                <<>>},
            nquic_frame:decode(<<12, 5, 10, "hi">>)
        ),
        ?_assertEqual(
            {ok,
                #stream{
                    stream_id = 5,
                    offset = 10,
                    fin = true,
                    data = <<"hi">>,
                    length = 2
                },
                <<>>},
            nquic_frame:decode(<<13, 5, 10, "hi">>)
        )
    ].

decode_new_connection_id_truncated_test() ->
    ?assertEqual(
        {error, incomplete_binary},
        nquic_frame:decode(<<24, 1, 0, 99, 1, 2, 3>>)
    ).
