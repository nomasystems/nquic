-module(nquic_zero_rtt).

-moduledoc """
Behaviour for 0-RTT anti-replay protection (RFC 9001 Section 9.2).

A QUIC server that accepts 0-RTT application data MUST implement a
single-use / time-bounded replay cache for PSK identities (session
tickets). nquic refuses 0-RTT entirely unless the listener opts supply
`{replay_protection, Module}` and `Module` implements this behaviour.

### Minimum security requirements

Per RFC 9001 Section 9.2 and RFC 8446 Appendix E.5 the implementation
MUST, for each PSK identity, ensure:

* the identity is only ever accepted at most once, or
* the combination of identity and the server-authenticated
  `early_data_context` is only ever accepted at most once.

Identities outside the ticket lifetime MUST be rejected. A replay
cache whose window is shorter than the ticket lifetime is acceptable
and SHOULD be preferred.

### Callback contract

`check/2` receives the opaque PSK identity bytes and the peer
address. Returning `accept` installs 0-RTT keys and signals
`early_data` back to the client. Returning `reject` makes the server
ignore the early-data indication and behave as a normal handshake
(the client will queue the 0-RTT data and retransmit after
handshake completes).

Implementations SHOULD be non-blocking and constant-time.
""".

-export([check/3]).

-callback check(Identity :: binary(), Peer :: nquic_socket:sockaddr()) ->
    accept | reject.

-doc """
Invoke a replay-protection module, if configured.

`Module` can be `undefined` (the listener did not opt-in); in that
case this function returns `reject` unconditionally, which is the
safe default. Non-`undefined` modules are required to implement the
`check/2` callback.
""".
-spec check(module() | undefined, binary(), nquic_socket:sockaddr()) -> accept | reject.
check(undefined, _Identity, _Peer) ->
    reject;
check(Module, Identity, Peer) ->
    Module:check(Identity, Peer).
