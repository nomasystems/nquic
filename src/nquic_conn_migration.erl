-module(nquic_conn_migration).
-moduledoc """
Connection-migration glue for the handshake state machine.

The pure migration core lives in `m:nquic_protocol_migration`; this
module is the handshake-statem-side glue that opens/rebinds sockets,
rotates connection IDs, queues `PATH_CHALLENGE`, and tears down
listener dispatch routing. Functions take and return `#conn_state{}`
(or a classified result) and never produce gen_statem transitions or
action lists; `nquic_conn_statem` owns the FSM. `flush_and_send/1`
stays in the statem: callers here queue frames and the statem-side
adapter flushes.
""".

-include("nquic_conn.hrl").
-include("nquic_path.hrl").
-export([
    arm_recv_after_migration/1,
    attempt_server_migration/1,
    awaiting_per_conn_fd_cid/1,
    finalize_server_migration/1,
    initiate_client_migration/2,
    maybe_initiate_server_migration/1,
    rotate_or_close/2
]).

-export_type([server_migration_result/0]).

-type server_migration_result() :: #conn_state{}.

-spec arm_recv_after_migration(#conn_state{}) -> #conn_state{}.
arm_recv_after_migration(#conn_state{socket = Socket} = Data) ->
    case nquic_socket:recv_now(Socket) of
        {ok, _} ->
            Data;
        {select, SelectInfo} ->
            Data#conn_state{select_info = SelectInfo};
        {error, _} ->
            Data
    end.

-spec attempt_server_migration(#conn_state{}) -> {ok, #conn_state{}} | {error, term()}.
attempt_server_migration(#conn_state{peer = Peer, path = Path0, gso_size = GsoSize} = Data) ->
    OpenOpts =
        case GsoSize of
            undefined -> #{};
            Size when is_integer(Size) -> #{gso => Size}
        end,
    maybe
        {ok, NewSocket} ?= nquic_socket:open_ephemeral(Peer, OpenOpts),
        {ok, Data1} ?= rotate_or_close(NewSocket, Data),
        PS0 = (Path0)#conn_path_mgmt.path_state,
        {NewPS, Challenge} = nquic_path:initiate_validation(PS0, PS0#path_state.peer),
        NewPath = Path0#conn_path_mgmt{path_state = NewPS},
        Data2 = Data1#conn_state{path = NewPath},
        {ok, Data3} ?= nquic_protocol_send_queues:queue_app_frame(Challenge, Data2),
        Data4 = Data3#conn_state{
            socket = NewSocket,
            socket_connected = true,
            self_migration_pending = true,
            select_info = undefined
        },
        {ok, arm_recv_after_migration(Data4)}
    else
        {error, _} = Err -> Err
    end.

-spec awaiting_per_conn_fd_cid(#conn_state{}) -> boolean().
awaiting_per_conn_fd_cid(#conn_state{
    role = server,
    server_per_conn_fd = true,
    socket_connected = false
}) ->
    true;
awaiting_per_conn_fd_cid(_Data) ->
    false.

-spec finalize_server_migration(#conn_state{}) -> #conn_state{}.
finalize_server_migration(#conn_state{dispatch_table = undefined} = Data) ->
    Data;
finalize_server_migration(
    #conn_state{
        dispatch_table = Table,
        path = #conn_path_mgmt{local_cids = LocalCids},
        odcid = ODCID
    } = Data
) ->
    ok = maps:foreach(
        fun(_Seq, CID) ->
            _ = nquic_listener:dispatch_unregister(Table, CID),
            ok
        end,
        LocalCids
    ),
    case ODCID of
        undefined ->
            ok;
        <<>> ->
            ok;
        _ ->
            _ = nquic_listener:dispatch_unregister(Table, ODCID),
            ok
    end,
    Data#conn_state{dispatch_table = undefined}.

-doc """
Rebind the client socket and queue a `PATH_CHALLENGE` for the new
path. The challenge is left queued; the statem caller flushes.
""".
-spec initiate_client_migration(nquic_socket:sockaddr(), #conn_state{}) ->
    {ok, #conn_state{}} | {error, term()}.
initiate_client_migration(
    NewLocalAddr, #conn_state{socket = OldSocket, path = Path0} = Data
) ->
    PS = Path0#conn_path_mgmt.path_state,
    case nquic_socket:rebind(OldSocket, NewLocalAddr) of
        {ok, NewSocket} ->
            {NewPS, ChallengeFrame} = nquic_path:initiate_validation(PS, PS#path_state.peer),
            NewPath = Path0#conn_path_mgmt{path_state = NewPS},
            Data1 = Data#conn_state{socket = NewSocket, path = NewPath},
            nquic_protocol_send_queues:queue_app_frame(ChallengeFrame, Data1);
        {error, _} = Err ->
            Err
    end.

-doc """
Attempt the `server_per_conn_fd` self-migration, returning a
classified result. Logging is the statem's responsibility;
`noop` means the connection was not eligible.
""".
-spec maybe_initiate_server_migration(#conn_state{}) -> server_migration_result().
maybe_initiate_server_migration(
    #conn_state{
        role = server,
        server_per_conn_fd = true,
        socket_connected = false,
        self_migration_pending = false,
        peer = Peer
    } = Data
) when Peer =/= undefined ->
    case attempt_server_migration(Data) of
        {ok, Data1} ->
            Data1;
        {error, no_available_cids} ->
            Data;
        {error, Reason} ->
            logger:warning(
                "nquic: server_per_conn_fd migration aborted: ~p", [Reason]
            ),
            Data
    end;
maybe_initiate_server_migration(Data) ->
    Data.

-spec rotate_or_close(nquic_socket:t(), #conn_state{}) ->
    {ok, #conn_state{}} | {error, no_available_cids}.
rotate_or_close(NewSocket, Data) ->
    case nquic_protocol_cid:rotate_dcid(Data) of
        {ok, _} = Ok ->
            Ok;
        {error, no_available_cids} = Err ->
            _ = nquic_socket:close(NewSocket),
            Err
    end.
