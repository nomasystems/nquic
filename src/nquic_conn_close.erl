-module(nquic_conn_close).
-moduledoc """
Connection close and draining state transitions (RFC 9000 §10.2).

Owns the CONNECTION_CLOSE emit path and the bookkeeping that moves a
connection into the `draining` gen_statem state: cancelling the other
timers, replying to parked waiters, notifying the owner, and arming
the draining-period timeout. Also handles the dispatch / socket
cleanup that runs from `terminate/3`.
""".

-include("nquic_conn.hrl").
-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-export([
    cleanup_dispatch/1,
    close_owned_socket/1,
    draining_cancellations/0,
    enter_close_draining/2,
    enter_draining/3,
    enter_draining_common/1,
    enter_draining_silent/1,
    maybe_drain/2,
    send_close_frame/3,
    send_connection_close/3
]).

-export_type([state_name/0]).

-type state_name() :: nquic_conn_statem:state_name().

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc "Unregister all CIDs (and the original DCID for servers) from dispatch.".
-spec cleanup_dispatch(#conn_state{}) -> ok.
cleanup_dispatch(#conn_state{dispatch_table = undefined}) ->
    ok;
cleanup_dispatch(#conn_state{
    dispatch_table = Table,
    path = #conn_path_mgmt{local_cids = LocalCids},
    odcid = ODCID
}) ->
    ok = maps:foreach(
        fun(_Seq, CID) ->
            nquic_listener:dispatch_unregister(Table, CID)
        end,
        LocalCids
    ),
    case ODCID of
        undefined ->
            ok;
        <<>> ->
            ok;
        _ ->
            true = nquic_listener:dispatch_unregister(Table, ODCID),
            ok
    end.

-doc """
Close the UDP socket if this gen_statem owns it.
Clients own the socket (the UDP FD is handed off via
`nquic_socket:controlling_process/2` in `nquic:connect/3`); server
connections borrow the receiver's shared
socket and must not close it. Server connections that have completed
the server-initiated migration (RFC 9000 §9, `server_per_conn_fd`)
own a dedicated `connect(2)`-bound ephemeral FD and must close it.
The exported library-mode path is short-circuited at the
`terminate/3` entry.
""".
-spec close_owned_socket(#conn_state{}) -> ok.
close_owned_socket(#conn_state{role = client, socket = Socket}) when Socket =/= undefined ->
    _ = nquic_socket:close(Socket),
    ok;
close_owned_socket(#conn_state{socket_connected = true, socket = Socket}) when
    Socket =/= undefined
->
    _ = nquic_socket:close(Socket),
    ok;
close_owned_socket(_Data) ->
    ok.

-doc """
Cancel every non-draining gen_statem timer.
The draining state must not be woken by spurious idle / PTO /
ack_delay / path_validation fires while it waits for
`draining_timeout`. RFC 9000 §10.2.2: the only event that drives
the connection during draining is the timeout itself.
""".
-spec draining_cancellations() -> [gen_statem:action()].
draining_cancellations() ->
    [
        {{timeout, idle_timeout}, infinity, undefined},
        {{timeout, pto_timeout}, infinity, undefined},
        {{timeout, ack_delay}, infinity, undefined},
        {{timeout, path_validation}, infinity, undefined}
    ].

-doc """
Enter draining state after an explicit `nquic:close/1,2` call.
CONNECTION_CLOSE has already been flushed via
`nquic_protocol` + the gen_statem's send path before we get here.
""".
-spec enter_close_draining(gen_statem:from(), #conn_state{}) ->
    gen_statem:event_handler_result(term()).
enter_close_draining(From, Data) ->
    Data1 = nquic_conn_metrics:mark_close(Data, local),
    enter_draining_with_replies([{reply, From, ok}], Data1).

-doc """
Enter draining state after sending a locally-generated CONNECTION_CLOSE.
Used for transport errors detected by the local stack. `StateName` is
the gen_statem state that was active when the violation was detected,
so the close frame is emitted at an encryption level the peer can
actually decrypt (RFC 9000 §10.2.3).
""".
-spec enter_draining(state_name(), {transport_error, atom()}, #conn_state{}) ->
    gen_statem:event_handler_result(term()).
enter_draining(StateName, {transport_error, Error}, Data) ->
    Kind =
        case Error of
            idle_timeout -> idle_timeout;
            _ -> protocol_error
        end,
    Data1 = nquic_conn_metrics:mark_close(Data, Kind),
    _ = send_connection_close(Data1, Error, StateName),
    enter_draining_common(Data1).

-doc """
Common draining-state entry: notify the owner, fail parked waiters,
arm the `draining_timeout`, and cancel the other timers.
""".
-spec enter_draining_common(#conn_state{}) ->
    gen_statem:event_handler_result(term()).
enter_draining_common(Data) ->
    enter_draining_with_replies([], Data).

-doc """
Enter draining without sending CONNECTION_CLOSE.
Used when the peer initiated the close (we must not respond, RFC 9000
§10.2.2).
""".
-spec enter_draining_silent(#conn_state{}) ->
    gen_statem:event_handler_result(term()).
enter_draining_silent(Data) ->
    Data1 = nquic_conn_metrics:mark_close(Data, peer),
    enter_draining_common(Data1).

-doc """
Convert a transport-error `stop` into a draining transition.
If no keys exist yet (very early failure, peer can't decrypt anything)
we just stop. Otherwise we transition to draining so the close frame
the local stack just emitted reaches the peer.
""".
-spec maybe_drain(state_name(), gen_statem:event_handler_result(dynamic())) ->
    gen_statem:event_handler_result(dynamic()).
maybe_drain(
    StateName,
    {stop, {transport_error, _} = Reason, #conn_state{crypto = #conn_crypto{keys = Keys}} = Data}
) ->
    case map_size(Keys) of
        0 -> {stop, Reason, Data};
        _ -> enter_draining(StateName, Reason, Data)
    end;
maybe_drain(_StateName, Other) ->
    Other.

-doc """
Emit `Frame` at every encryption level the peer can decrypt for `StateName`.
RFC 9000 §10.2.3: during the handshake the peer may not yet have
derived Handshake or Application keys, so a CONNECTION_CLOSE must be
sent at a level the peer can decrypt. Until the handshake is confirmed
(gen_statem state = `established`) the server SHOULD send the close in
both Handshake (when keys exist) and Initial packets so at least one
is processable. Once established, only the 1-RTT copy is needed.
""".
-spec send_close_frame(#connection_close{}, #conn_state{}, state_name()) -> ok.
send_close_frame(Frame, Data, StateName) ->
    Keys = (Data#conn_state.crypto)#conn_crypto.keys,
    Levels = close_frame_levels(StateName, Keys),
    lists:foreach(fun(L) -> send_close_frame_at_level(Frame, Data, L) end, Levels).

-doc """
Build a transport-level CONNECTION_CLOSE for `Error` and send it at the
appropriate encryption levels.
""".
-spec send_connection_close(#conn_state{}, nquic_error:any_reason(), state_name()) -> ok.
send_connection_close(Data, Error, StateName) ->
    #conn_state{socket = Socket} = Data,
    case Socket of
        undefined ->
            ok;
        _ ->
            Code = nquic_protocol:error_code(Error),
            Frame = #connection_close{
                error_code = Code,
                frame_type = 0,
                reason_phrase = nquic_protocol:error_to_reason_phrase(Error)
            },
            send_close_frame(Frame, Data, StateName)
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec close_frame_levels(atom(), #{atom() => dynamic()}) ->
    [initial | handshake | application].
close_frame_levels(established, _Keys) ->
    [application];
close_frame_levels(draining, _Keys) ->
    [];
close_frame_levels(handshake, Keys) ->
    case maps:is_key(handshake, Keys) of
        true -> [initial, handshake];
        false -> [initial]
    end;
close_frame_levels(initial, _Keys) ->
    [initial];
close_frame_levels(_Other, _Keys) ->
    [initial].

-spec enter_draining_with_replies([gen_statem:action()], #conn_state{}) ->
    gen_statem:event_handler_result(term()).
enter_draining_with_replies(LeadingReplies, Data) ->
    Timeout = nquic_protocol:get_draining_timeout(Data),
    WaiterReplies = [{reply, From, {error, closed}} || From <- Data#conn_state.connect_waiters],
    RecvReplies = [
        {reply, From, {error, closed}}
     || From <- maps:values((Data#conn_state.streams_state)#conn_streams.recv_waiters)
    ],
    AcceptReplies = [
        {reply, From, {error, closed}}
     || From <- queue:to_list((Data#conn_state.streams_state)#conn_streams.accept_stream_waiters)
    ],
    SS0 = Data#conn_state.streams_state,
    NewSS = SS0#conn_streams{
        recv_waiters = #{},
        accept_stream_waiters = queue:new()
    },
    Data1 = Data#conn_state{
        connect_waiters = [],
        streams_state = NewSS
    },
    AllReplies = LeadingReplies ++ WaiterReplies ++ RecvReplies ++ AcceptReplies,
    {next_state, draining, Data1,
        AllReplies ++
            draining_cancellations() ++
            [{{timeout, draining_timeout}, Timeout, drain_expire}]}.

-spec send_close_frame_at_level(
    #connection_close{}, #conn_state{}, initial | handshake | application
) -> ok | {error, term()}.
send_close_frame_at_level(Frame, Data, Level) ->
    try
        #conn_state{
            scid = SCID,
            dcid = DCID,
            socket = Socket,
            peer = Peer,
            crypto = #conn_crypto{keys = Keys, cipher = NegotiatedCipher}
        } = Data,

        Cipher =
            case Level of
                initial -> aes_128_gcm;
                _ -> NegotiatedCipher
            end,

        Role = Data#conn_state.role,
        KeysMap = maps:get(Level, Keys),
        RoleKeys = maps:get(Role, KeysMap),

        #{key := Key, iv := IV, hp := _} = RoleKeys,

        Payload0 = nquic_frame:encode(Frame),

        LossState = Data#conn_state.loss_state,
        {PnLen, TruncPN, PN} =
            case Level of
                application ->
                    PN0 = Data#conn_state.app_next_pn,
                    LA = nquic_loss:get_largest_acked(LossState, application),
                    {PL0, TPN0} = nquic_packet_number:encode(PN0, LA),
                    {PL0, TPN0, PN0};
                _ ->
                    SpaceMap = maps:get(Level, Data#conn_state.pn_spaces, #{next_pn => 0}),
                    #{next_pn := PN0} = SpaceMap,
                    LA = nquic_loss:get_largest_acked(LossState, Level),
                    {PL0, TPN0} = nquic_packet_number:encode(PN0, LA),
                    {PL0, TPN0, PN0}
            end,

        Payload = nquic_protocol_send:ensure_sample_size(Payload0, PnLen),

        {HeaderBin, PnOffset} =
            case Level of
                application ->
                    H = #short_header{
                        dcid = DCID,
                        packet_number = TruncPN,
                        key_phase = (Data#conn_state.crypto)#conn_crypto.key_phase,
                        spin = nquic_protocol_send:outgoing_spin(Data),
                        pn_len = PnLen
                    },
                    HB = nquic_packet:encode_header(H),
                    PO = byte_size(HB) - PnLen,
                    {HB, PO};
                _ ->
                    H = #long_header{
                        type = Level,
                        version = Data#conn_state.version,
                        dcid = DCID,
                        scid = SCID,
                        payload_len = iolist_size(Payload) + 16,
                        packet_number = TruncPN,
                        pn_len = PnLen
                    },
                    HB = nquic_packet:encode_header(H),
                    PO = byte_size(HB) - PnLen,
                    {HB, PO}
            end,

        {Ciphertext, Tag} = nquic_crypto:encrypt(Cipher, Key, IV, PN, HeaderBin, Payload),
        SampleOff = 4 - PnLen,
        Sample = nquic_protocol_send:hp_sample(Ciphertext, Tag, SampleOff),
        Mask = nquic_hp:generate_mask_from_keys(RoleKeys, Cipher, Sample),
        IsLong = Level =/= application,
        {MaskedHeader, _} = nquic_hp:mask_header(Mask, HeaderBin, PnOffset, IsLong),
        MaskedPacket = [MaskedHeader, Ciphertext, Tag],

        nquic_socket:send(Socket, Peer, MaskedPacket)
    catch
        error:_:_ ->
            ok
    end.
