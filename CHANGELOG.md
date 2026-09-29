# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Return `{error, finished_not_found}` for an empty TLS handshake flight instead of a crash reason
- Ignore a `path_validation` timeout when the connection has no path state, instead of crashing the owner
- Drop Retry packets explicitly after the handshake
- Include `flowinfo` and `scope_id` in IPv6 sockaddr maps, as `socket:sockaddr_in6()` requires
- Correct type specs flagged by set-theoretic type checking, including the missing `aes_256_gcm` in `nquic_crypto`

## [1.0.2] - 2026-08-12

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
