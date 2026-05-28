-module(nquic_conn_events).
-moduledoc """
Protocol-event delivery for the handshake state machine.

Folds `nquic_protocol` events into `#conn_state{}`: waking parked
waiters, queueing peer-opened streams, caching tokens, finalising
server migration. This is the event-to-state logic only; deciding the
gen_statem transition for `state_transition` / `migrate_to_preferred`
events stays in `nquic_conn_statem`
(`translate_protocol_events/2`).
""".

-include("nquic_conn.hrl").
-export([
    deliver_protocol_event/2,
    deliver_protocol_events/2,
    notify_owner_new_token/2
]).

-spec deliver_protocol_event(nquic_protocol:event(), #conn_state{}) -> #conn_state{}.
deliver_protocol_event({stream_data, StreamID}, Data) ->
    nquic_conn_streams:maybe_notify_recv_waiter(StreamID, Data);
deliver_protocol_event({stream_opened, StreamID}, Data) ->
    nquic_conn_streams:notify_or_queue_stream(StreamID, Data);
deliver_protocol_event({stream_reset, StreamID, _ErrorCode}, Data) ->
    nquic_conn_streams:maybe_notify_recv_waiter(StreamID, Data);
deliver_protocol_event({stop_sending, _StreamID, _ErrorCode}, Data) ->
    Data;
deliver_protocol_event({stream_writable, _StreamID}, Data) ->
    Data;
deliver_protocol_event({datagram_received, _DgramData}, Data) ->
    Data;
deliver_protocol_event({new_session_ticket, CryptoData}, Data) ->
    nquic_session_ticket:process_new_session_ticket(CryptoData, Data);
deliver_protocol_event({new_token_received, Token}, Data) ->
    nquic_conn_streams:cache_new_token(Token, Data),
    notify_owner_new_token(Token, Data),
    Data;
deliver_protocol_event(connection_closed, Data) ->
    Data;
deliver_protocol_event(connected, Data) ->
    Data#conn_state{connect_waiters = []};
deliver_protocol_event(listener_established, Data) ->
    nquic_conn_metrics:listener_established(Data);
deliver_protocol_event(local_migration_validated, Data) ->
    nquic_conn_migration:finalize_server_migration(Data);
deliver_protocol_event({state_transition, _}, Data) ->
    Data;
deliver_protocol_event({migrate_to_preferred, _}, Data) ->
    Data.

-spec deliver_protocol_events([nquic_protocol:event()], #conn_state{}) -> #conn_state{}.
deliver_protocol_events([], Data) ->
    Data;
deliver_protocol_events([Event | Rest], Data) ->
    Data1 = deliver_protocol_event(Event, Data),
    deliver_protocol_events(Rest, Data1).

-spec notify_owner_new_token(binary(), #conn_state{}) -> ok.
notify_owner_new_token(Token, #conn_state{owner = Owner}) when is_pid(Owner) ->
    Owner ! {quic_new_token, self(), Token},
    ok;
notify_owner_new_token(_Token, _Data) ->
    ok.
