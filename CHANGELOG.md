<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions move in
`0.0.1` steps, in lockstep with the Crypto Service SDKs.

## [0.0.41] - Unreleased

## [0.0.40] - 2026-11-16

The first release: a typed client for crypto-server's v2 API at commit
`3e8ecfd` (`ci/server.ref`).

### Added

- `Client`, async on Tokio, with one method per v2 operation (59) and the
  probes `root`, `health`, `live` and `ready`; `blocking::Client` behind
  the `blocking` feature with the same methods.
- Request and answer types with the encodings the OpenAPI document
  states: `Hex`, `Base64`, and `SecretBytes` / `SecretString` for key
  material, passwords and plaintexts (zeroised on drop, redacted in
  `Debug`). `HpkeData` and `KmsEncryptRequest::bytes` never leave an
  encoding to the server's guess.
- The resilience contract shared by the SDKs: per-attempt `timeout`
  (30 s), overall `deadline`, `RetryPolicy` (off by default; full jitter;
  `Retry-After` honoured up to the maximum delay; stateful routes retried
  only after `429` or `503`), `traceparent` (fixed or per call), and a
  replaceable `Transport`.
- `Error::Api` with the RFC 9457 `Problem` (an `about:blank` stand-in for
  a body that is not one), `Error::Transport` with `timed_out`,
  `Error::Decode` naming only a position, `Error::Config`.
- `send_raw` for the v1 routes, `/metrics` and anything newer.
- The conformance kit vendored from crypto-service with its checksums,
  run through the typed methods against a live server (119 vectors),
  seven examples, criterion benches, two cargo-fuzz targets, and CI with
  coverage, complexity, cargo-deny, CodeQL, Scorecard and a release
  workflow publishing to crates.io.
