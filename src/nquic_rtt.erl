-module(nquic_rtt).

-moduledoc """
RTT estimation per RFC 9002 Section 5.

Maintains smoothed RTT, RTT variance, minimum RTT, and latest RTT.

All values are kept in **microseconds** to match the rest of the loss /
congestion-control plumbing (which measures elapsed time with
`erlang:monotonic_time(microsecond)`). Initial values are 333 ms
(smoothed) and 166 ms (variance) per RFC 9002 5.3, expressed in
microseconds.
""".

-export([get/1, new/0, smoothed_rtt/1, update/3]).

-export_type([rtt_state/0]).

-define(INITIAL_RTT_US, 333_000).

-record(rtt_state, {
    latest_rtt = 0 :: non_neg_integer(),
    min_rtt = 0 :: non_neg_integer(),
    smoothed_rtt = 0 :: non_neg_integer(),
    rttvar = 0 :: non_neg_integer(),
    first_sample_time = 0 :: non_neg_integer()
}).

-type rtt_state() :: #rtt_state{}.

-doc "Return a map of current RTT statistics: latest, min, smoothed, and variance.".
-spec get(rtt_state()) ->
    #{
        latest_rtt := non_neg_integer(),
        min_rtt := non_neg_integer(),
        smoothed_rtt := non_neg_integer(),
        rttvar := non_neg_integer()
    }.
get(State) ->
    #{
        latest_rtt => State#rtt_state.latest_rtt,
        min_rtt => State#rtt_state.min_rtt,
        smoothed_rtt => State#rtt_state.smoothed_rtt,
        rttvar => State#rtt_state.rttvar
    }.

-doc """
Initialize RTT state with a 333 ms smoothed RTT and 166 ms variance,
in microseconds.
""".
-spec new() -> rtt_state().
new() ->
    #rtt_state{
        latest_rtt = 0,
        min_rtt = 0,
        smoothed_rtt = ?INITIAL_RTT_US,
        rttvar = ?INITIAL_RTT_US div 2,
        first_sample_time = 0
    }.

-spec smoothed_rtt(rtt_state()) -> non_neg_integer().
smoothed_rtt(State) ->
    State#rtt_state.smoothed_rtt.

-doc "Update RTT with a new sample and the peer-reported ACK delay.".
-spec update(rtt_state(), non_neg_integer(), non_neg_integer()) -> rtt_state().
update(State, Sample, AckDelay) ->
    #rtt_state{
        min_rtt = MinRTT,
        smoothed_rtt = SRTT,
        rttvar = RTTVar
    } = State,

    if
        MinRTT =:= 0 ->
            State#rtt_state{
                latest_rtt = Sample,
                min_rtt = Sample,
                smoothed_rtt = Sample,
                rttvar = Sample div 2
            };
        true ->
            NewMinRTT = min(MinRTT, Sample),

            AdjustedRTT = max(NewMinRTT, Sample - AckDelay),

            RTTVarSample = abs(SRTT - AdjustedRTT),
            NewRTTVar = (3 * RTTVar + RTTVarSample) div 4,

            NewSRTT = (7 * SRTT + AdjustedRTT) div 8,

            State#rtt_state{
                latest_rtt = Sample,
                min_rtt = NewMinRTT,
                smoothed_rtt = NewSRTT,
                rttvar = NewRTTVar
            }
    end.
