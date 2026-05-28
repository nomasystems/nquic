-module(nquic_path).

-moduledoc """
Path validation for QUIC connection migration (RFC 9000 Section 9).

Pure-functional module operating on `#path_state{}`. Handles peer address
change detection, PATH_CHALLENGE/PATH_RESPONSE tracking, and anti-amplification
limits on new paths. All state lives in the connection's `#conn_state{}` record;
this module provides the logic without owning any processes.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_path.hrl").
-export([
    detect_peer_change/2,
    get_previous_peer/1,
    initiate_validation/2,
    is_nat_rebinding/1,
    is_validated/1,
    is_validating/1,
    new/1,
    on_response/2,
    on_timeout/1
]).

-export_type([state/0]).

-type state() :: #path_state{}.

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc """
Detect if the source address of a received packet differs from the current peer.

Returns `unchanged` when the addresses match or `{changed, UpdatedPathState}`
when the source differs. A previously-undefined peer is treated as a first-time
set rather than a change.
""".
-spec detect_peer_change(state(), nquic_socket:sockaddr()) ->
    unchanged | {changed, state()}.
detect_peer_change(#path_state{peer = undefined} = PS, Source) ->
    {changed, PS#path_state{peer = Source, path_validated = true}};
detect_peer_change(#path_state{peer = Current} = PS, Source) ->
    case same_address(Current, Source) of
        true ->
            unchanged;
        false ->
            {changed, PS#path_state{
                previous_peer = Current,
                peer = Source,
                path_validated = false,
                new_path_bytes_sent = 0,
                new_path_bytes_received = 0
            }}
    end.

-doc "Return the previous peer address (for fallback on validation failure).".
-spec get_previous_peer(state()) -> nquic_socket:sockaddr() | undefined.
get_previous_peer(#path_state{previous_peer = P}) -> P.

-doc """
Initiate path validation by generating an 8-byte challenge.
Stores the challenge data and candidate address. Returns the updated path state
and a PATH_CHALLENGE frame to send to the new address.
""".
-spec initiate_validation(state(), nquic_socket:sockaddr()) ->
    {state(), #path_challenge{}}.
initiate_validation(PS, NewPeer) ->
    ChallengeData = crypto:strong_rand_bytes(8),
    Now = erlang:monotonic_time(microsecond),
    NewPS = PS#path_state{
        previous_peer = PS#path_state.peer,
        peer = NewPeer,
        pending_challenge = ChallengeData,
        challenge_sent_time = Now,
        challenge_retries = 0,
        path_validated = false,
        new_path_bytes_sent = 0,
        new_path_bytes_received = 0
    },
    Frame = #path_challenge{data = ChallengeData},
    {NewPS, Frame}.

-doc """
True if the migration is a likely NAT rebinding: same IP, different port.
When true, callers should skip CC/RTT reset since the underlying network path
has not changed (RFC 9000 Section 9.3.1).
""".
-spec is_nat_rebinding(state()) -> boolean().
is_nat_rebinding(#path_state{peer = undefined}) -> false;
is_nat_rebinding(#path_state{previous_peer = undefined}) -> false;
is_nat_rebinding(#path_state{peer = #{addr := Addr}, previous_peer = #{addr := Addr}}) -> true;
is_nat_rebinding(#path_state{}) -> false.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-doc "True if the current path has been validated.".
-spec is_validated(state()) -> boolean().
is_validated(#path_state{path_validated = V}) -> V.

-doc "True if a path validation is currently in progress.".
-spec is_validating(state()) -> boolean().
is_validating(#path_state{pending_challenge = undefined}) -> false;
is_validating(#path_state{}) -> true.

-doc "Create a new path state with the given initial peer address.".
-spec new(nquic_socket:sockaddr() | undefined) -> state().
new(Peer) ->
    #path_state{
        peer = Peer,
        previous_peer = undefined,
        pending_challenge = undefined,
        challenge_sent_time = 0,
        challenge_retries = 0,
        path_validated = true,
        new_path_bytes_sent = 0,
        new_path_bytes_received = 0
    }.

-doc """
Process a PATH_RESPONSE. If the response data matches the pending challenge,
the path is validated. Otherwise the state is unchanged.
""".
-spec on_response(state(), binary()) ->
    {validated, state()} | {mismatch, state()}.
on_response(#path_state{pending_challenge = undefined} = PS, _ResponseData) ->
    {mismatch, PS};
on_response(#path_state{pending_challenge = Expected} = PS, ResponseData) ->
    case ResponseData of
        Expected ->
            {validated, PS#path_state{
                pending_challenge = undefined,
                path_validated = true,
                previous_peer = undefined
            }};
        _ ->
            {mismatch, PS}
    end.

-doc """
Handle path validation timeout. Retries up to 3 times with a fresh challenge.
After 3 retries, returns `failed` so the caller can revert to the previous peer.
""".
-spec on_timeout(state()) ->
    {retry, state(), #path_challenge{}} | {failed, state()}.
on_timeout(#path_state{challenge_retries = Retries} = PS) when Retries >= 3 ->
    FailedPS = PS#path_state{
        peer = PS#path_state.previous_peer,
        previous_peer = undefined,
        pending_challenge = undefined,
        path_validated = true,
        new_path_bytes_sent = 0,
        new_path_bytes_received = 0
    },
    {failed, FailedPS};
on_timeout(PS) ->
    NewChallenge = crypto:strong_rand_bytes(8),
    Now = erlang:monotonic_time(microsecond),
    NewPS = PS#path_state{
        pending_challenge = NewChallenge,
        challenge_sent_time = Now,
        challenge_retries = PS#path_state.challenge_retries + 1
    },
    Frame = #path_challenge{data = NewChallenge},
    {retry, NewPS, Frame}.

-spec same_address(nquic_socket:sockaddr(), nquic_socket:sockaddr()) -> boolean().
same_address(#{addr := Addr, port := Port}, #{addr := Addr, port := Port}) ->
    true;
same_address(_, _) ->
    false.
