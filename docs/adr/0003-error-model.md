<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 3. The error model

- Status: accepted
- Date: 2026-11-15

## Context

crypto-server answers every error with an RFC 9457 problem
(`application/problem+json`) carrying a stable `type`, a `code` from the
library or key store, and `errors[]` for validation failures. Proxies
may answer with HTML. The SDKs share one error model: an API error with
the problem, a transport error with a `timedOut` flag, and a shared base.

## Decision

One `Error` enum is the shared base: `Api(ApiError)` holds the status and
the `Problem` (an `about:blank` problem stands in for a body that is not
one, exactly as the TypeScript SDK's `readProblem`), `Transport` holds
`timed_out` and the cause, `Decode` a 2xx body of the wrong shape, and
`Config` options that cannot work.

No message carries a secret: `ApiError` shows the status, title and type
(written by the server for the client), `TransportError` a fixed text,
`DecodeError` only a category, line and column; `serde_json`'s own
message, which can quote the offending value, is dropped.

## Consequences

- Callers match on the variant and read `problem.kind` or `code()`.
- Debugging a decode error needs the body, which the caller must capture
  deliberately (`send_raw`), never from the error.
