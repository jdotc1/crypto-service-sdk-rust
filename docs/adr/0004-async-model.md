<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 4. The async model

- Status: accepted
- Date: 2026-11-15

## Context

Rust services calling crypto-server are mostly async on Tokio, but CLIs
and scripts want plain blocking calls. Two independent implementations
would drift; one written over the other must not deadlock or spawn a
runtime per call.

## Decision

The async `Client` is primary: `async fn` methods, `Clone + Send + Sync`,
cancellation by dropping the future, the per-attempt timeout and the
deadline as Tokio timeouts. `blocking::Client` (feature `blocking`) owns
one multi-thread Tokio runtime with one worker and runs each async call
on it with `block_on`; both clients come from one macro table, so their
methods cannot drift. Retries are off by default and follow the
TypeScript SDK's safety table.

## Consequences

- One code path for both clients; the blocking tests check every route.
- A blocking client must be created, used and dropped outside an async
  context, as with `reqwest::blocking`; the docs say so.
- Callers on another async runtime need Tokio's timer, which the async
  client uses for timeouts.
