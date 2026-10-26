# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ip` and `ipv6_v6only` listen options: the local address of every receiver socket. An IPv6 address such as `{0,0,0,0,0,0,0,0}` with `ipv6_v6only => false` serves IPv6 and IPv4 peers on one port

### Fixed

- Complete the handshake after the loss of the server Initial. The handshake PTO probes every packet number space with packets in flight and resends their CRYPTO data, on the `nquic:accept` and the `conn_handler` server paths (RFC 9002 §6.2.4)
- Keep the client PTO armed until a Handshake packet is acknowledged or the handshake is confirmed, and keep the client PTO backoff on Initial ACKs (RFC 9002 §6.2.1, §6.2.2.1)
- Restart the PTO only when an ack-eliciting packet is sent. Received datagrams and ACK-only flushes no longer push the PTO out (RFC 9002 §6.2, Appendix A.8)
- Keep the CUBIC state consistent when the maximum datagram size changes. An ACK in congestion avoidance after a size change no longer crashes the owner with `badarith`
- Use `min(max_payload_size, peer max_udp_payload_size)` as the datagram size of the congestion controller, not the peer limit alone. The initial window and the window growth follow the datagrams that the sender sends (RFC 9002 §7.2)
- Remove the packets of a discarded Initial or Handshake space from the bytes in flight and the ack-eliciting count, and reset the PTO backoff. An idle server no longer sends a PING at each PTO (RFC 9002 §6.4, Appendix A.10)
- Discard 1-RTT packets on the server until it processes the client Finished (RFC 9001 §5.7)
- Complete the handshake after the loss of the client Finished. The client keeps the Handshake space until HANDSHAKE_DONE, and the PTO after connect probes the Handshake space while it has packets in flight (RFC 9001 §4.9.2, RFC 9002 Appendix A.8)
- Send HANDSHAKE_DONE again when it is declared lost (RFC 9000 §13.3)
- Declare a packet lost only when its packet number is at or below the largest acknowledged packet (RFC 9002 §6.1)
- Take an RTT sample when the largest acknowledged packet is newly acknowledged and one of the newly acknowledged packets is ack-eliciting. An ACK-only largest packet no longer drops the sample (RFC 9002 §5.1)
- Run the time threshold loss timer. The `pto` timer runs to the earliest loss time of an in-flight packet when one is set, and the packets lost at that time are sent again before the PTO (RFC 9002 §6.1.2, Appendix A.8, A.10)
- Put queued new data or the oldest unacknowledged data in a 1-RTT PTO probe, and send a PING only when no data is available. The probe leaves when the pacer blocks (RFC 9002 §6.2.4)
- Start the congestion event of an ECN-CE increase at the send time of the largest acknowledged packet. CE marks for packets sent before the current recovery period no longer reduce the window again (RFC 9002 Appendix B.7)
- Send one ACK frame per flush in 1-RTT packets, built at the send. A batch of received packets no longer queues one ACK frame for each two packets (RFC 9000 §13.2.1)
- Report the ACK Delay of 1-RTT ACK frames: the time from the receipt of the largest acknowledged packet to the send, scaled by the local `ack_delay_exponent`. Initial and Handshake ACK frames carry 0 (RFC 9000 §13.2.5, §19.3)
- Advertise a `max_ack_delay` of 10 ms, which covers the measured ACK delay and the 1 ms ACK timer. The PTO of the peer no longer adds 25 ms. A peer that omits `max_ack_delay` has the default of 25 ms (RFC 9000 §18.2)
- Stop CUBIC window growth while the sender is application limited. An ACK grows the window only when the bytes in flight, before the ACK or after the last send, are within three segments of the window, or above half the window in slow start. The elapsed time of the cubic curve excludes application-limited periods (RFC 9438 §4.2, §5.8, RFC 9002 §7.8)
- Limit the CUBIC target window to 1.5 times the current window (RFC 9438 §4.2)
- Compute the CUBIC K from `W_max` and the window at the start of congestion avoidance. K is 0 when `W_max` is not known or is at or below that window, and the curve then starts at that window (RFC 9438 §4.2, §4.10)
- Roll back a CUBIC window reduction only when all bytes declared lost since the reduction are acknowledged later. One late ACK no longer undoes a reduction that other losses justify (RFC 9438 §4.9.2)

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
