# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-10-27

### Added

- `ip` and `ipv6_v6only` listen options: the local address of every receiver socket. An IPv6 address such as `{0,0,0,0,0,0,0,0}` with `ipv6_v6only => false` serves IPv6 and IPv4 peers on one port

### Changed

- The response packet carries the ACK of a single request packet. A flush with no other frame holds the ACK of one ack-eliciting packet while the endpoint has nothing in flight, until the next frame or the 1 ms `ack_delay` timer (RFC 9000 §13.2.1). Request/response traffic sends one datagram per request in each direction instead of two

### Fixed

- Complete the handshake after the loss of the server Initial or the client Finished. The PTO probes every space with packets in flight, and a lost HANDSHAKE_DONE is sent again (RFC 9001 §4.9.2, RFC 9002 §6.2.4)
- Restart the PTO only when an ack-eliciting packet is sent, and keep the client PTO armed until the handshake is confirmed. A 1-RTT probe carries data when data is available (RFC 9002 §6.2)
- Remove the packets of a discarded Initial or Handshake space from the in-flight counters, and discard 1-RTT packets on the server until the client Finished (RFC 9001 §5.7, RFC 9002 §6.4)
- Declare loss only at or below the largest acknowledged packet, run the time threshold loss timer, and take an RTT sample when the largest acknowledged packet is ACK-only (RFC 9002 §5.1, §6.1)
- Send one ACK frame per flush with the measured ACK Delay, and advertise a `max_ack_delay` of 10 ms (RFC 9000 §13.2, §18.2)
- Size the congestion window by the datagrams that the sender sends, and start an ECN-CE congestion event at the send time of the largest acknowledged packet (RFC 9002 §7.2, Appendix B.7)
- Conform CUBIC to RFC 9438 §4. The window does not grow while the sender is application limited, the target is at most 1.5 times the window, K comes from the window at the start of congestion avoidance, and a rollback needs all lost bytes acknowledged. A datagram size change no longer crashes the owner with `badarith`

## [1.1.0] - 2026-09-30

### Fixed

- Return `{error, finished_not_found}` for an empty TLS handshake flight instead of a crash reason
- Ignore a `path_validation` timeout when the connection has no path state, instead of crashing the owner
- Drop Retry packets explicitly after the handshake
- Include `flowinfo` and `scope_id` in IPv6 sockaddr maps, as `socket:sockaddr_in6()` requires
- Correct type specs flagged by set-theoretic type checking, including the missing `aes_256_gcm` in `nquic_crypto`

## [1.0.3] - 2026-08-12

### Added

- Support for OTP 29 by removing deprecated `catch` expressions.

## [1.0.2] - 2026-06-08

### Fixed

- Budget CRYPTO handshake fragmentation off the peer's advertised `max_udp_payload_size` rather than the local 1200-byte floor, so the handshake flight fits the peer's datagram limit (#5)

## [1.0.1] - 2026-06-03

### Fixed

- Fragment the CRYPTO handshake flight to honor the peer's `max_udp_payload_size`, avoiding oversized datagrams during the handshake (#2, #3)

## [1.0.0] - 2026-05-28

Initial public release candidate.

### Added

- QUIC v1 transport (RFC 9000) and QUIC v2 (RFC 9369)
- TLS 1.3 handshake via OTP `ssl` and `crypto` (RFC 9001)
- Loss detection and congestion control (RFC 9002): CUBIC (default) and NewReno
- Bidirectional and unidirectional streams with connection- and stream-level flow control
- Unreliable datagrams (RFC 9221)
- 0-RTT early data with pluggable anti-replay callback (RFC 9001 §9.2)
- Key update (RFC 9001 §6)
- Connection migration with path validation (RFC 9000 §9)
- Server preferred-address migration (RFC 9000 §9.6)
- Stateless reset with constant-time token compare (RFC 9000 §10.3)
- Retry with HMAC-signed source-address tokens (RFC 9000 §8.1.4)
- Anti-amplification limit, 3x per RFC 9000 §8.1
- ECN with per-path validation (RFC 9000 §13.4, RFC 9002 §B.4)
- DPLPMTUD search and black-hole detection (RFC 8899)
- Library-mode API (`nquic_lib`): protocol exposed as pure functions over an opaque `nquic:ctx()`
- Connected UDP sockets for server connections, kernel-routed
- SO_REUSEPORT with multiple receiver processes for kernel-level load distribution
- Striped ETS dispatch tables with atomics-based counters
- Partitioned connection supervisors, one per scheduler
- Session resumption with pluggable session cache backend
- Property-based test suites backed by triq
- Self-interop compliance suite and Docker-based interop runner against aioquic, ngtcp2, picoquic
