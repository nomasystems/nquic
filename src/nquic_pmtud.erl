-module(nquic_pmtud).

-moduledoc """
Datagram Packetization Layer PMTU Discovery (DPLPMTUD) per RFC 8899.

Pure functional state machine for path MTU discovery. The caller
(nquic_protocol or nquic_conn_statem) drives transitions by calling
`on_probe_acked/1`, `on_probe_lost/1`, `on_timeout/1`, etc.

States: disabled, base, searching, search_complete, error.
""".

-include("nquic_frame.hrl").
-export([
    disable/1,
    enable/1,
    generate_probe/1,
    get_current_mtu/1,
    get_probe_size/1,
    get_state/1,
    get_timer_ms/1,
    needs_probe/1,
    new/0,
    new/1,
    on_black_hole/1,
    on_probe_acked/1,
    on_probe_lost/1,
    on_timeout/1
]).

-export_type([pmtud_state/0]).

-define(BASE_PLPMTU, 1200).
-define(MAX_PLPMTU, 1452).
-define(MIN_PROBE_STEP, 20).
-define(MAX_PROBE_RETRIES, 3).
-define(REPROBE_INTERVAL_MS, 600000).

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

-type pmtud_state() :: #pmtud{}.

-doc "Disable PMTUD. Resets to BASE_PLPMTU.".
-spec disable(pmtud_state()) -> pmtud_state().
disable(S) ->
    S#pmtud{
        state = disabled,
        current_mtu = ?BASE_PLPMTU,
        probe_size = 0,
        probe_count = 0,
        probe_pending = false
    }.

-doc "Enable PMTUD. Transitions from disabled to searching.".
-spec enable(pmtud_state()) -> pmtud_state().
enable(#pmtud{state = disabled} = S) ->
    ProbeSize = next_probe_size(?BASE_PLPMTU, ?MAX_PLPMTU),
    S#pmtud{
        state = searching,
        probe_size = ProbeSize,
        probe_count = 0,
        probe_pending = true,
        search_low = ?BASE_PLPMTU,
        search_high = S#pmtud.search_high
    };
enable(S) ->
    S.

-doc """
Generate a probe frame list (PING + PADDING to target size).
Returns `{ok, Frames, Size, State}` where Size is the target probe size
and State has probe_pending cleared, or `{error, no_probe_needed}`.
""".
-spec generate_probe(pmtud_state()) ->
    {ok, [nquic_frame:t()], pos_integer(), pmtud_state()} | {error, no_probe_needed}.
generate_probe(#pmtud{state = searching, probe_pending = true, probe_size = Size} = S) ->
    Frames = [#ping{}, #padding{}],
    {ok, Frames, Size, S#pmtud{probe_pending = false}};
generate_probe(_) ->
    {error, no_probe_needed}.

-doc "Get the current effective MTU.".
-spec get_current_mtu(pmtud_state()) -> pos_integer().
get_current_mtu(#pmtud{current_mtu = MTU}) -> MTU.

-doc "Get the size of the next probe packet.".
-spec get_probe_size(pmtud_state()) -> non_neg_integer().
get_probe_size(#pmtud{probe_size = Size}) -> Size.

-doc "Get the current DPLPMTUD state.".
-spec get_state(pmtud_state()) -> disabled | base | searching | search_complete | error.
get_state(#pmtud{state = State}) -> State.

-doc """
Get the timer interval in milliseconds, or `infinity` if no timer needed.
""".
-spec get_timer_ms(pmtud_state()) -> pos_integer() | infinity.
get_timer_ms(#pmtud{state = search_complete}) ->
    ?REPROBE_INTERVAL_MS;
get_timer_ms(_) ->
    infinity.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-doc "Whether a probe packet should be sent now.".
-spec needs_probe(pmtud_state()) -> boolean().
needs_probe(#pmtud{state = searching, probe_pending = true}) -> true;
needs_probe(_) -> false.

-doc "Create a new PMTUD state (disabled).".
-spec new() -> pmtud_state().
new() ->
    #pmtud{}.

-doc "Create a new PMTUD state with a custom max MTU.".
-spec new(pos_integer()) -> pmtud_state().
new(MaxMTU) when MaxMTU >= ?BASE_PLPMTU ->
    #pmtud{search_high = MaxMTU}.

-spec next_probe_size(pos_integer(), pos_integer()) -> pos_integer().
next_probe_size(Low, High) ->
    (Low + High) div 2.

-doc "Called when black hole is detected (sustained loss after MTU increase).".
-spec on_black_hole(pmtud_state()) -> pmtud_state().
on_black_hole(S) ->
    S#pmtud{
        state = error,
        current_mtu = ?BASE_PLPMTU,
        probe_size = 0,
        probe_count = 0,
        probe_pending = false
    }.

-doc "Called when a probe packet was acknowledged.".
-spec on_probe_acked(pmtud_state()) -> pmtud_state().
on_probe_acked(#pmtud{state = searching, probe_size = ProbeSize} = S) ->
    Now = erlang:monotonic_time(microsecond),
    NewLow = ProbeSize,
    NewHigh = S#pmtud.search_high,
    case NewHigh - NewLow < ?MIN_PROBE_STEP of
        true ->
            S#pmtud{
                state = search_complete,
                current_mtu = ProbeSize,
                probe_size = 0,
                probe_count = 0,
                probe_pending = false,
                search_low = NewLow,
                last_probe_time = Now
            };
        false ->
            NextProbe = next_probe_size(NewLow, NewHigh),
            S#pmtud{
                current_mtu = ProbeSize,
                probe_size = NextProbe,
                probe_count = 0,
                probe_pending = true,
                search_low = NewLow,
                last_probe_time = Now
            }
    end;
on_probe_acked(S) ->
    S.

-doc "Called when a probe packet was lost (not acked within timeout).".
-spec on_probe_lost(pmtud_state()) -> pmtud_state().
on_probe_lost(#pmtud{state = searching, probe_count = Count} = S) ->
    NewCount = Count + 1,
    case NewCount >= ?MAX_PROBE_RETRIES of
        true ->
            NewHigh = S#pmtud.probe_size,
            NewLow = S#pmtud.search_low,
            case NewHigh - NewLow < ?MIN_PROBE_STEP of
                true ->
                    S#pmtud{
                        state = search_complete,
                        probe_size = 0,
                        probe_count = 0,
                        probe_pending = false
                    };
                false ->
                    NextProbe = next_probe_size(NewLow, NewHigh),
                    S#pmtud{
                        probe_size = NextProbe,
                        probe_count = 0,
                        probe_pending = true,
                        search_high = NewHigh
                    }
            end;
        false ->
            S#pmtud{probe_count = NewCount, probe_pending = true}
    end;
on_probe_lost(S) ->
    S.

-doc """
Called on reprobe timer expiry. Triggers a new search from current MTU.
""".
-spec on_timeout(pmtud_state()) -> pmtud_state().
on_timeout(#pmtud{state = search_complete, current_mtu = CurrentMTU} = S) ->
    ProbeSize = next_probe_size(CurrentMTU, S#pmtud.search_high),
    case ProbeSize =:= CurrentMTU of
        true ->
            S;
        false ->
            S#pmtud{
                state = searching,
                probe_size = ProbeSize,
                probe_count = 0,
                probe_pending = true,
                search_low = CurrentMTU
            }
    end;
on_timeout(S) ->
    S.
