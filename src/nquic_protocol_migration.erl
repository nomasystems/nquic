-module(nquic_protocol_migration).
-moduledoc """
Connection migration and PMTUD for the QUIC protocol state.

Pure functions over `#conn_state{}` covering RFC 9000 Section 9
(connection migration: peer-address update, path validation outcome,
preferred-address handoff) and RFC 8899 (Packetisation Layer Path MTU
Discovery: probe acknowledgement, loss, and black-hole reaction).
Extracted from `nquic_protocol` as part of REVIEW_PLAN.md Phase 4.4.

External side effects are limited to delegating into `nquic_path`,
`nquic_pmtud`, `nquic_loss`, `nquic_socket`, and `nquic_protocol_cid`.
PATH_CHALLENGE frames produced during preferred-address migration are
queued through `nquic_protocol_send_queues:queue_app_frame/2`.
""".

-include("nquic_conn.hrl").
-include("nquic_path.hrl").
-include("nquic_transport.hrl").
-export([
    apply_peer_update/2,
    check_migration_allowed/1,
    complete_migration/1,
    handle_preferred_address/2,
    revert_migration/1,
    select_preferred_peer/2
]).
-export([
    enable_pmtud/1,
    maybe_detect_black_hole/1,
    pmtud_on_black_hole/1,
    pmtud_on_probe_acked/1,
    pmtud_on_probe_lost/1
]).

-define(BLACK_HOLE_PTO_THRESHOLD, 3).

%%%-----------------------------------------------------------------------------
%% PATH VALIDATION / CONNECTION MIGRATION (RFC 9000 SECTION 9)
%%%-----------------------------------------------------------------------------
-spec apply_peer_update(nquic_socket:sockaddr(), nquic_protocol:state()) -> nquic_protocol:state().
apply_peer_update(Source, #conn_state{path = Path0} = State) ->
    PS = Path0#conn_path_mgmt.path_state,
    case nquic_path:detect_peer_change(PS, Source) of
        unchanged ->
            State;
        {changed, NewPS} ->
            State#conn_state{
                peer = NewPS#path_state.peer,
                path = Path0#conn_path_mgmt{path_state = NewPS}
            }
    end.

-spec check_migration_allowed(nquic_protocol:state()) -> ok | {error, nquic_error:any_reason()}.
check_migration_allowed(#conn_state{
    remote_params = RemoteParams,
    path = #conn_path_mgmt{peer_cids = PeerCids},
    dcid = DCID
}) ->
    DisableFlag =
        case RemoteParams of
            undefined -> false;
            #transport_params{disable_active_migration = V} -> V
        end,
    Available = maps:filter(
        fun(_Seq, #{cid := CID}) -> CID =/= DCID end,
        PeerCids
    ),
    maybe
        false ?= DisableFlag,
        true ?= map_size(Available) > 0,
        ok
    else
        true -> {error, migration_disabled};
        false -> {error, no_available_cids}
    end.

-spec complete_migration(nquic_protocol:state()) ->
    {ok, nquic_protocol:state()} | {error, no_available_cids}.
complete_migration(#conn_state{path = Path0, loss_state = LossState} = State) ->
    PS = Path0#conn_path_mgmt.path_state,
    case nquic_protocol_cid:rotate_dcid(State) of
        {error, no_available_cids} ->
            {error, no_available_cids};
        {ok, State0} ->
            State1 =
                case nquic_path:is_nat_rebinding(PS) of
                    true ->
                        State0;
                    false ->
                        Algorithm = nquic_loss:get_cc_algorithm(LossState),
                        PacerCfg = nquic_loss:pacer_config(LossState),
                        State0#conn_state{
                            loss_state = nquic_loss:init(Algorithm, PacerCfg)
                        }
                end,
            Path1 = State1#conn_state.path,
            NewPath = Path1#conn_path_mgmt{
                address_validated = true,
                anti_amp_bytes_sent = 0,
                anti_amp_bytes_received = 0
            },
            {ok, State1#conn_state{path = NewPath}}
    end.

-doc """
Handle preferred address migration (RFC 9000 Section 9.6).
Installs the CID from the preferred_address transport parameter at
sequence 1, selects the matching address family, and initiates path
validation by queuing a PATH_CHALLENGE frame.
Returns the updated state and a path validation timeout action.
""".
-spec handle_preferred_address(nquic_transport:preferred_address(), nquic_protocol:state()) ->
    {ok, nquic_protocol:state(), [nquic_protocol:timeout_action()]}.
handle_preferred_address(PA, #conn_state{path = Path0, peer = Peer} = State) ->
    PS = Path0#conn_path_mgmt.path_state,
    PeerCids = Path0#conn_path_mgmt.peer_cids,
    #{cid := NewCID, stateless_reset_token := Token} = PA,
    TargetPeer = select_preferred_peer(PA, Peer),
    PeerCids1 = PeerCids#{1 => #{cid => NewCID, token => Token}},
    {NewPS, ChallengeFrame} = nquic_path:initiate_validation(PS, TargetPeer),
    NewPath = Path0#conn_path_mgmt{peer_cids = PeerCids1, path_state = NewPS},
    State2 = State#conn_state{peer = TargetPeer, path = NewPath},
    {ok, State3} = nquic_protocol_send_queues:queue_app_frame(ChallengeFrame, State2),
    PVTimeout = nquic_protocol_timer:compute_path_validation_timeout(State3),
    {ok, State3, [{set_timer, path_validation, PVTimeout}]}.

%%%-----------------------------------------------------------------------------
%% PMTUD (RFC 8899)
%%%-----------------------------------------------------------------------------
-doc "Enable PMTUD on the connection. Starts probe search.".
-spec enable_pmtud(nquic_protocol:state()) -> nquic_protocol:state().
enable_pmtud(#conn_state{pmtud = undefined} = State) ->
    PS = nquic_pmtud:enable(nquic_pmtud:new()),
    State#conn_state{pmtud = PS};
enable_pmtud(#conn_state{pmtud = PS} = State) ->
    State#conn_state{pmtud = nquic_pmtud:enable(PS)}.

-spec maybe_detect_black_hole(nquic_protocol:state()) -> nquic_protocol:state().
maybe_detect_black_hole(#conn_state{pmtud = undefined} = State) ->
    State;
maybe_detect_black_hole(#conn_state{pmtud = PS, loss_state = LS} = State) ->
    PtoCount = nquic_loss:get_pto_count(LS),
    CurrentMTU = nquic_pmtud:get_current_mtu(PS),
    case PtoCount >= ?BLACK_HOLE_PTO_THRESHOLD andalso CurrentMTU > 1200 of
        true -> pmtud_on_black_hole(State);
        false -> State
    end.

-doc "Called on black hole detection. Reverts to BASE_PLPMTU.".
-spec pmtud_on_black_hole(nquic_protocol:state()) -> nquic_protocol:state().
pmtud_on_black_hole(#conn_state{pmtud = undefined} = State) ->
    State;
pmtud_on_black_hole(#conn_state{pmtud = PS, loss_state = LS} = State) ->
    PS1 = nquic_pmtud:on_black_hole(PS),
    LS1 = nquic_loss:set_max_datagram_size(LS, 1200),
    State#conn_state{pmtud = PS1, loss_state = LS1}.

-doc "Called when a PMTUD probe was acknowledged. Updates MTU if search progresses.".
-spec pmtud_on_probe_acked(nquic_protocol:state()) -> nquic_protocol:state().
pmtud_on_probe_acked(#conn_state{pmtud = undefined} = State) ->
    State;
pmtud_on_probe_acked(#conn_state{pmtud = PS, loss_state = LS} = State) ->
    PS1 = nquic_pmtud:on_probe_acked(PS),
    NewMTU = nquic_pmtud:get_current_mtu(PS1),
    OldMTU = nquic_pmtud:get_current_mtu(PS),
    LS1 =
        case NewMTU > OldMTU of
            true -> nquic_loss:set_max_datagram_size(LS, NewMTU);
            false -> LS
        end,
    State#conn_state{pmtud = PS1, loss_state = LS1}.

-doc "Called when a PMTUD probe was lost.".
-spec pmtud_on_probe_lost(nquic_protocol:state()) -> nquic_protocol:state().
pmtud_on_probe_lost(#conn_state{pmtud = undefined} = State) ->
    State;
pmtud_on_probe_lost(#conn_state{pmtud = PS} = State) ->
    State#conn_state{pmtud = nquic_pmtud:on_probe_lost(PS)}.

-spec revert_migration(nquic_protocol:state()) -> nquic_protocol:state().
revert_migration(#conn_state{path = #conn_path_mgmt{path_state = PS}} = State) ->
    State#conn_state{peer = PS#path_state.peer}.

-spec select_preferred_peer(nquic_transport:preferred_address(), nquic_socket:sockaddr()) ->
    nquic_socket:sockaddr().
select_preferred_peer(#{ipv4 := {IPv4, V4Port}, ipv6 := {IPv6, V6Port}}, CurrentPeer) ->
    case maps:get(family, CurrentPeer, inet) of
        inet -> nquic_socket:make_sockaddr(IPv4, V4Port);
        inet6 -> nquic_socket:make_sockaddr(IPv6, V6Port)
    end.
