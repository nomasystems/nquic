-module(nquic_cc).

-moduledoc """
Congestion control behaviour and dispatch per RFC 9002 Section 7.

Defines the `nquic_cc` behaviour that congestion control algorithms must implement.
Provides a dispatch layer that wraps the algorithm module and its opaque state.
Currently ships with `nquic_cc_newreno`.
""".

-include("nquic_loss.hrl").
-callback init() -> dynamic().
-callback on_packet_sent(dynamic(), non_neg_integer(), non_neg_integer()) -> dynamic().
-callback on_packet_acked(dynamic(), #sent_packet{}, non_neg_integer(), map()) -> dynamic().
-callback on_congestion_event(
    dynamic(), non_neg_integer(), non_neg_integer(), non_neg_integer()
) ->
    dynamic().
-callback on_persistent_congestion(dynamic()) -> dynamic().
-callback on_spurious_congestion(dynamic()) -> dynamic().
-callback on_idle_reset(dynamic()) -> dynamic().
-callback get_cwnd(dynamic()) -> non_neg_integer().
-callback get_ssthresh(dynamic()) -> non_neg_integer() | undefined.

-export([
    get_cwnd/1,
    get_ssthresh/1,
    new/1,
    new/2,
    on_congestion_event/4,
    on_packet_acked/4,
    on_packet_sent/3,
    on_persistent_congestion/1,
    on_spurious_congestion/1,
    on_idle_reset/1
]).
-export([get_max_datagram_size/1, set_max_datagram_size/2]).

-export_type([algorithm/0, cc_state/0]).

-type cc_state() :: {module(), dynamic()}.
-type algorithm() :: newreno | cubic.

-doc "Get the current congestion window size in bytes.".
-spec get_cwnd(cc_state()) -> non_neg_integer().
get_cwnd({Mod, State}) ->
    Mod:get_cwnd(State).

-doc "Get the current maximum datagram size.".
-spec get_max_datagram_size({module(), dynamic()}) -> pos_integer().
get_max_datagram_size({Mod, State}) ->
    case erlang:function_exported(Mod, get_max_datagram_size, 1) of
        true -> Mod:get_max_datagram_size(State);
        false -> 1200
    end.

-doc "Get the current slow start threshold.".
-spec get_ssthresh(cc_state()) -> non_neg_integer() | undefined.
get_ssthresh({Mod, State}) ->
    Mod:get_ssthresh(State).

-doc "Create a new congestion control state for the given algorithm.".
-spec new(algorithm() | dynamic()) -> cc_state().
new(Algorithm) ->
    new(Algorithm, #{}).

-doc """
Create a new congestion control state with options.
CUBIC understands `slow_start => standard | hystart_plus_plus`
(RFC 9406). Other algorithms ignore unknown keys.
""".
-spec new(algorithm() | dynamic(), map()) -> cc_state().
new(Algorithm, Opts) ->
    Module =
        case Algorithm of
            newreno -> nquic_cc_newreno;
            cubic -> nquic_cc_cubic;
            _ -> nquic_cc_cubic
        end,
    State =
        case erlang:function_exported(Module, init, 1) of
            true -> Module:init(Opts);
            false -> Module:init()
        end,
    {Module, State}.

-doc "Notify the congestion controller of a loss event.".
-spec on_congestion_event(cc_state(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    cc_state().
on_congestion_event({Mod, State}, LostBytes, BytesInFlight, SentTime) ->
    {Mod, Mod:on_congestion_event(State, LostBytes, BytesInFlight, SentTime)}.

-doc """
Reset the congestion controller after an idle period (RFC 9002 Section
7.8). The window collapses to the initial window so the sender does not
burst beyond the path's available capacity after a long pause.
""".
-spec on_idle_reset(cc_state()) -> cc_state().
on_idle_reset({Mod, State}) ->
    {Mod, Mod:on_idle_reset(State)}.

-doc "Notify the congestion controller that a packet was acknowledged.".
-spec on_packet_acked(cc_state(), #sent_packet{}, non_neg_integer(), map()) -> cc_state().
on_packet_acked({Mod, State}, Packet, BytesInFlight, RTTStats) ->
    {Mod, Mod:on_packet_acked(State, Packet, BytesInFlight, RTTStats)}.

-doc "Notify the congestion controller that a packet was sent.".
-spec on_packet_sent(cc_state(), non_neg_integer(), non_neg_integer()) -> cc_state().
on_packet_sent({Mod, State}, BytesSent, BytesInFlight) ->
    {Mod, Mod:on_packet_sent(State, BytesSent, BytesInFlight)}.

-doc """
Notify the congestion controller that persistent congestion has been
detected (RFC 9002 Section 7.6). The congestion window must collapse to
the minimum window (`2 * max_datagram_size`).
""".
-spec on_persistent_congestion(cc_state()) -> cc_state().
on_persistent_congestion({Mod, State}) ->
    {Mod, Mod:on_persistent_congestion(State)}.

-doc """
Notify the congestion controller that the most recent congestion-event
reduction was triggered by a spurious loss (RFC 9002 Appendix A.10).
Implementations should restore the pre-reduction snapshot of the window
state. If no snapshot is available (no rollback pending), this is a
no-op.
""".
-spec on_spurious_congestion(cc_state()) -> cc_state().
on_spurious_congestion({Mod, State}) ->
    {Mod, Mod:on_spurious_congestion(State)}.

-doc "Set the maximum datagram size for congestion window calculations.".
-spec set_max_datagram_size({module(), dynamic()}, pos_integer()) -> {module(), dynamic()}.
set_max_datagram_size({Mod, State}, Size) ->
    case erlang:function_exported(Mod, set_max_datagram_size, 2) of
        true -> {Mod, Mod:set_max_datagram_size(State, Size)};
        false -> {Mod, State}
    end.
