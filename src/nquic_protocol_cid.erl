-module(nquic_protocol_cid).
-moduledoc """
Connection ID management for the QUIC protocol state.

Pure functions over `#conn_state{}` that handle peer CID issuance
(NEW_CONNECTION_ID), retirement (RETIRE_CONNECTION_ID), local CID
rotation, and DCID switching for path migration. Extracted from
`nquic_protocol` as part of REVIEW_PLAN.md Phase 4.4.

Side effects are limited to `nquic_listener:dispatch_register/3` and
`nquic_listener:dispatch_unregister/2` for keeping the dispatch table
in sync when the connection has one set; everything else is functional
state manipulation.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_transport.hrl").
-export([
    find_cid_seq/2,
    handle_new_connection_id/5,
    handle_retire_connection_id/2,
    issue_new_connection_id/1,
    issue_spare_cids/1,
    retire_peer_cids/2,
    rotate_dcid/1
]).

%%%-----------------------------------------------------------------------------
%% PUBLIC API
%%%-----------------------------------------------------------------------------
-spec find_cid_seq(nquic:connection_id(), #{non_neg_integer() => map()}) ->
    non_neg_integer() | undefined.
find_cid_seq(CID, PeerCids) ->
    maps:fold(
        fun(Seq, #{cid := C}, Acc) ->
            case C of
                CID -> Seq;
                _ -> Acc
            end
        end,
        undefined,
        PeerCids
    ).

-spec handle_new_connection_id(
    non_neg_integer(), non_neg_integer(), nquic:connection_id(), binary(), nquic_protocol:state()
) ->
    {ok, nquic_protocol:state()}.
handle_new_connection_id(SeqNum, RetirePriorTo, CID, Token, State) ->
    #conn_state{path = Path0} = State,
    #conn_path_mgmt{
        peer_cids = PeerCids,
        peer_retire_prior_to = CurrentRetirePrior
    } = Path0,
    NewRetirePrior = max(CurrentRetirePrior, RetirePriorTo),
    PeerCids1 =
        case SeqNum >= NewRetirePrior of
            true -> PeerCids#{SeqNum => #{cid => CID, token => Token}};
            false -> PeerCids
        end,
    {ToRetire, PeerCids2} = retire_peer_cids(NewRetirePrior, PeerCids1),
    NewPath = Path0#conn_path_mgmt{
        peer_cids = PeerCids2,
        peer_retire_prior_to = NewRetirePrior
    },
    State1 = State#conn_state{path = NewPath},
    State2 = send_retire_frames(ToRetire, State1),
    {ok, State2}.

-spec handle_retire_connection_id(non_neg_integer(), nquic_protocol:state()) ->
    {ok, nquic_protocol:state()}.
handle_retire_connection_id(SeqNum, State) ->
    #conn_state{path = Path0, dispatch_table = Table} = State,
    LocalCids = Path0#conn_path_mgmt.local_cids,
    case maps:get(SeqNum, LocalCids, undefined) of
        undefined ->
            {ok, State};
        CID ->
            case Table of
                undefined -> ok;
                _ -> nquic_listener:dispatch_unregister(Table, CID)
            end,
            NewLocalCids = maps:remove(SeqNum, LocalCids),
            NewPath = Path0#conn_path_mgmt{local_cids = NewLocalCids},
            State1 = State#conn_state{path = NewPath},
            issue_new_connection_id(State1)
    end.

-spec retire_peer_cids(non_neg_integer(), #{non_neg_integer() => map()}) ->
    {[non_neg_integer()], #{non_neg_integer() => map()}}.
retire_peer_cids(RetirePriorTo, PeerCids) ->
    maps:fold(
        fun(Seq, _Entry, {Retired, Remaining}) ->
            case Seq < RetirePriorTo of
                true -> {[Seq | Retired], maps:remove(Seq, Remaining)};
                false -> {Retired, Remaining}
            end
        end,
        {[], PeerCids},
        PeerCids
    ).

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec issue_n_cids(non_neg_integer(), nquic_protocol:state()) -> {ok, nquic_protocol:state()}.
issue_n_cids(0, State) ->
    {ok, State};
issue_n_cids(N, State) ->
    case issue_new_connection_id(State) of
        {ok, State1} -> issue_n_cids(N - 1, State1)
    end.

-spec issue_new_connection_id(nquic_protocol:state()) -> {ok, nquic_protocol:state()}.
issue_new_connection_id(State) ->
    #conn_state{path = Path0, dispatch_table = Table, crypto = Crypto} = State,
    #conn_path_mgmt{local_cids = LocalCids, local_cid_seq = NextSeq} = Path0,
    NewCID = nquic_keys:generate_connection_id(8),
    ResetToken =
        case Crypto#conn_crypto.static_key of
            undefined -> crypto:strong_rand_bytes(16);
            SK -> nquic_stateless_reset:generate_token(SK, NewCID)
        end,
    case Table of
        undefined -> ok;
        _ -> nquic_listener:dispatch_register(Table, NewCID, self())
    end,
    Frame = #new_connection_id{
        seq_num = NextSeq,
        retire_prior_to = 0,
        cid = NewCID,
        stateless_reset_token = ResetToken
    },
    NewLocalCids = LocalCids#{NextSeq => NewCID},
    NewPath = Path0#conn_path_mgmt{
        local_cids = NewLocalCids,
        local_cid_seq = NextSeq + 1
    },
    State1 = State#conn_state{path = NewPath},
    nquic_protocol_send_queues:queue_app_frame(Frame, State1).

-doc """
Issue spare NEW_CONNECTION_ID frames up to the peer's
`active_connection_id_limit`.
Both endpoints account the SCID delivered in transport parameters as a
single local CID (sequence 0); peers tolerate up to `limit` concurrent
CIDs (RFC 9000 §5.1.1). We top up the gap so a future migration has
spare CIDs on both sides; without this, server-initiated migration
(per-conn FDs) cannot rotate DCID and the path validation refuses to
flip.
No-op when remote transport parameters have not been processed yet:
the limit is unknown, and the existing reactive `issue_new_connection_id`
path picks up the slack on demand.
""".
-spec issue_spare_cids(nquic_protocol:state()) -> {ok, nquic_protocol:state()}.
issue_spare_cids(#conn_state{remote_params = undefined} = State) ->
    {ok, State};
issue_spare_cids(#conn_state{remote_params = RP, path = Path} = State) ->
    Limit = RP#transport_params.active_connection_id_limit,
    Current = map_size(Path#conn_path_mgmt.local_cids),
    issue_n_cids(max(0, Limit - Current), State).

-spec rotate_dcid(nquic_protocol:state()) ->
    {ok, nquic_protocol:state()} | {error, no_available_cids}.
rotate_dcid(#conn_state{path = Path0, dcid = CurrentDCID} = State) ->
    PeerCids = Path0#conn_path_mgmt.peer_cids,
    Available = maps:filter(
        fun(_Seq, #{cid := CID}) -> CID =/= CurrentDCID end,
        PeerCids
    ),
    case map_size(Available) of
        0 ->
            {error, no_available_cids};
        _ ->
            MinSeq = lists:min(maps:keys(Available)),
            #{cid := NewDCID} = maps:get(MinSeq, Available),
            OldSeq = find_cid_seq(CurrentDCID, PeerCids),
            State1 = State#conn_state{dcid = NewDCID},
            State2 =
                case OldSeq of
                    undefined -> State1;
                    Seq -> send_retire_frames([Seq], State1)
                end,
            {ok, State2}
    end.

-spec send_retire_frames([non_neg_integer()], nquic_protocol:state()) -> nquic_protocol:state().
send_retire_frames([], State) ->
    State;
send_retire_frames([Seq | Rest], State) ->
    Frame = #retire_connection_id{seq_num = Seq},
    {ok, State1} = nquic_protocol_send_queues:queue_app_frame(Frame, State),
    send_retire_frames(Rest, State1).
