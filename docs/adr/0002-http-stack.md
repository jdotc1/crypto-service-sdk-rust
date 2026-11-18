<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 2. The HTTP stack: reqwest with rustls

- Status: accepted
- Date: 2026-11-15

## Context

The client needs pooled keep-alive connections, HTTP/2 where the server
offers it, gzip, TLS with verification always on, refused redirects and
cancellation by dropping a future. It should not link OpenSSL.

## Decision

`reqwest` 0.13 without default features, with `rustls` (aws-lc-rs and the
platform verifier, so the system trust store applies), `http2` and
`gzip`. Redirects are disabled with `Policy::none()`. There is no option
to accept invalid certificates. The runtime dependencies are `reqwest`,
`tokio` (time), `http`, `serde`, `serde_json`, `base64`, `zeroize` and
`thiserror`. A `Transport` trait sits in front of `reqwest`, so tests and
callers can supply another stack; the client's timeout, deadline and
retries wrap any transport.

## Consequences

- One pool per client, shared by its clones.
- aws-lc-rs needs a C toolchain to build; `cargo deny` bans `native-tls`
  and `openssl-sys`.
- The licence allow-list includes the permissive licences of the TLS
  stack (ISC, BSD-3-Clause, MIT-0, CDLA-Permissive-2.0, Unicode-3.0).
