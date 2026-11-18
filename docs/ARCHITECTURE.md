<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Architecture

```text
caller ── Client::<operation>(&Request) ──► encode (serde_json)
             │                                   │
             │            src/client.rs: deadline ─► retries ─► per-attempt timeout
             │                                   │
             │                         Transport::send (src/transport.rs)
             │                         ReqwestTransport: rustls, HTTP/2, gzip,
             │                         pooled keep-alive, redirects refused
             ▼                                   │
        Result<Answer, Error> ◄── decode: 2xx ─► `{ "data" }` ─► Answer
                                   other ─► Error::Api(Problem)
```

## Modules

| Module | Role |
| :--- | :--- |
| `operations.rs` | one macro table: each operation's name, method, path, request and answer type; it generates the async methods, the blocking ones and the route list the tests check |
| `builder.rs` | `ClientBuilder`: base URL checks, credentials as sensitive headers, `traceparent` |
| `client.rs` | the pipeline: headers, deadline, retries, per-attempt timeout, decoding; `send_raw` |
| `retry.rs` | `RetryPolicy`, the stateful-route table from the TypeScript SDK's `request.ts`, `Retry-After` parsing |
| `transport.rs` | the `Transport` trait and `ReqwestTransport` |
| `error.rs` | `Error`, `ApiError`, `Problem`, `TransportError`, `DecodeError` |
| `encoding.rs`, `secret.rs` | `Hex`, `Base64`, `SecretBytes`, `SecretString` |
| `types/` | request and answer types, by area |
| `blocking.rs` | `blocking::Client` over a one-worker Tokio runtime |

## Concurrency and sharing

`Client` holds an `Arc` of its options and transport, so a clone is a
pointer copy and every clone shares one `reqwest` connection pool.
`Client` is `Send + Sync`: any number of tasks or threads may call one
instance at once. A call is a future; dropping it cancels the request.
`blocking::Client` shares the same guarantee across threads.

## Generic code stays branch-free

`call<B, T>` only encodes and decodes; the branches (status, retries,
encoding errors) live in non-generic functions. Besides keeping the
binary small, this lets coverage measure each branch once, rather than
once per answer type.
