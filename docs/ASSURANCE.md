<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Assurance case

This is the argument that `crypto-service-sdk` meets its security
requirements: what it protects, from whom, where the trust boundaries
are, how secure design principles are applied, and how the common
weaknesses of an HTTP client library are countered. Every claim names
the code or test that makes it true; a change that moves a boundary
updates this page in the same pull request
([CONTRIBUTING.md](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/CONTRIBUTING.md#how-a-pull-request-is-reviewed)).
The last review against it is
[security-review-2026-11.md](security-review-2026-11.md).

Paths below are relative to the
[repository root](https://github.com/sebastienrousseau/crypto-service-sdk-rust/tree/main).

## Security requirements

1. **Confidentiality of credentials**: the API key and bearer token go
   only to the configured crypto-server origin, never to a log, a
   `Debug` or `Display` output, an error, or another origin.
2. **Confidentiality of key material and plaintexts**: keys, passwords,
   plaintexts and shared secrets are never printed, are zeroised when
   the SDK drops them, and travel only inside the request to the server.
3. **Integrity of the exchange**: over `https://`, the server is
   authenticated by TLS with certificate verification always on.
4. **No duplicated side effects**: a call that creates or deletes server
   state is not repeated when the server may already have acted on it.
5. **Robustness against a hostile or broken server or network**: no
   answer can make the SDK crash, hang without bound, exhaust memory, or
   echo secrets into an error.
6. **No cryptography in the client**: the SDK never implements or
   chooses a cryptographic algorithm; crypto-server does (ADR 1).
7. **Supply chain**: what is published to crates.io is what was reviewed
   in this repository, built by its release workflow from a signed tag.

## Threat model

### Assets

| Asset | Where it lives in the SDK |
| :--- | :--- |
| API key, bearer token | `SecretString` in `ClientBuilder`; a sensitive `HeaderValue` in the client's header map |
| Keys, passwords, plaintexts, shared and session secrets | `SecretBytes`, `SecretString`, `HpkeData` in request and answer types |
| Request bodies (JSON with the above) | a `Vec<u8>` handed to the transport |
| 2xx answer bodies | `Zeroizing<Vec<u8>>` until decoded (`success_body` in `src/client.rs`) |
| The published crate | the `.crate` on crates.io and the GitHub release |

### Actors

- **The caller**: the application that links the SDK. Trusted: it
  chooses the base URL, the credentials and every argument.
- **crypto-server**: trusted to perform the operations and to hold keys,
  but its answers are parsed as untrusted input (it may be misconfigured,
  compromised, or not crypto-server at all).
- **A network attacker**: can observe, drop, delay, replay or alter
  traffic between the SDK and the server.
- **A malicious contributor or dependency**: tries to get code into the
  crate or its dependency tree.
- **Someone with access to the process's logs or crash reports**: must
  not find secrets there.

### Entry points

| Entry point | Code |
| :--- | :--- |
| Builder options: base URL, credentials, timeouts, retry policy, `traceparent`, transport | `src/builder.rs` |
| One method per operation, with a typed request | `src/operations.rs`, `src/types/` |
| `send_raw` with a caller-chosen method, path, body and headers | `src/client.rs` |
| Every byte of every answer: status, headers, body | `src/transport.rs`, `src/client.rs`, `src/error.rs`, `src/types/` |
| `Retry-After` header | `parse_retry_after` in `src/retry.rs` |
| The release: tag, workflow, crates.io publish | `.github/workflows/release.yml` |

## Trust boundaries

```text
 caller ──(1)──► SDK ──(2)──► network ──(3)──► crypto-server
                  ▲
                  └──(4) dependencies (crates.io)   CI and release ──(5)──► crates.io
```

1. **Caller to SDK.** The caller is trusted, but its input is checked
   where a mistake would leak a credential: the base URL must be an
   absolute `http` or `https` URL without user info, query or fragment
   (`check_base_url` in `src/builder.rs`), credentials and a fixed
   `traceparent` must be valid header values, and a `send_raw` path must
   start with `/` (`Client::send_raw`).
2. **SDK to network.** Requests leave through one `Transport`.
   `ReqwestTransport` (`src/transport.rs`) uses rustls with the platform
   verifier: certificate and host name verification are always on, with
   no option to turn them off; redirects are refused, so a `Location`
   header cannot carry the credentials elsewhere.
3. **Network to SDK.** Every answer is untrusted input: bodies are read
   up to 64 MiB after decompression, a non-2xx answer becomes
   `Error::Api` with a parsed problem or `about:blank`, a 2xx body of the
   wrong shape becomes `Error::Decode` naming only a line and column.
4. **Dependencies.** Eight runtime dependencies, all from crates.io,
   named in ADR 2; `cargo deny` checks advisories, licences, sources and
   bans OpenSSL and native-tls (`deny.toml`).
5. **CI and release.** Workflows run with read-only tokens by default,
   actions pinned to commit SHAs; the release needs a signed annotated
   tag verified against `KEYS.asc`, the `release` environment with a
   required reviewer, and publishes with a short-lived crates.io
   trusted-publishing token.

A custom `Transport` (`ClientBuilder::transport`) moves boundary 2 into
the caller's code: it receives the credentials and bodies, and the
guarantees above for TLS, redirects and the body limit are then its own.

## Secure design principles

| Principle (Saltzer and Schroeder) | How it is applied |
| :--- | :--- |
| Economy of mechanism | One request pipeline for every operation (`Client::exchange`), one macro table for every route (`src/operations.rs`), no cryptography (ADR 1), eight runtime dependencies. `#![forbid(unsafe_code)]` in `src/lib.rs`. |
| Fail-safe defaults | No default URL; retries off (`RetryPolicy::default`); a 30 s per-attempt timeout (`DEFAULT_TIMEOUT`); TLS verification on with no switch; redirects refused; unknown answer shapes are errors, not guesses. |
| Complete mediation | Every call, typed or raw, goes through `Client::exchange`, which applies the headers, the deadline, the retry policy and the per-attempt timeout; every answer goes through `decode` or is returned raw by `send_raw` only. |
| Open design | The code, the OpenAPI-driven types and this case are public; nothing depends on a secret other than the caller's credentials. |
| Separation of privilege | Publishing needs both a signed tag that `git verify-tag` accepts against `KEYS.asc` and approval in the `release` environment. |
| Least privilege | The SDK holds only what the caller hands it and sends credentials only to the base URL. Workflows default to `contents: read` (`permissions: {}` in `release.yml`), and only the job that needs a write scope gets it. |
| Least common mechanism | Clients share nothing but what the caller clones: each `Client` owns its connection pool and options; there is no global state. |
| Psychological acceptability | Secrets need no special handling by the caller: `SecretString` and `SecretBytes` convert from `&str`, `String`, `Vec<u8>` and arrays, and redact themselves. |

## Common weaknesses and how they are countered

Mapped to the CWE Top 25 (2024) and the OWASP Top 10 items that apply
to an HTTP client library.

| Weakness | Counter-measure | Evidence |
| :--- | :--- | :--- |
| CWE-787, CWE-125, CWE-416 memory safety | Safe Rust only: `#![forbid(unsafe_code)]` | `src/lib.rs` |
| CWE-200, CWE-532 exposure of secrets in output and logs | `Debug` of `SecretBytes`, `SecretString`, `HpkeData`, `Client`, `ClientBuilder`, `HttpRequest` and `HttpResponse` redacts values; errors carry no values; the crate never logs | `debug_never_shows_the_secret`, `requests_show_no_header_values_or_body_in_debug`, `the_builder_refuses_bad_headers_and_redacts_credentials`, `credentials_and_a_fixed_traceparent_travel_and_never_show` |
| CWE-201, CWE-522 credentials sent to the wrong party | Base URL without user info; redirects refused; `send_raw` paths from `/` only, so a path cannot change the host | `the_builder_refuses_bad_urls`, `a_redirect_is_returned_not_followed_with_the_credentials`, `send_raw_refuses_a_path_that_would_change_the_host` |
| CWE-295 improper certificate validation; OWASP A02 | rustls with the platform verifier, no option to disable it; OpenSSL and native-tls banned | `ReqwestTransport::with_limit`, `deny.toml` |
| CWE-319 cleartext transmission | `https://` is supported and recommended; `http://` is accepted (see below) | `check_base_url` |
| CWE-113, CWE-93 header injection (CRLF) | Credentials and `traceparent` must be valid header values or `build` fails | `the_builder_refuses_bad_headers_and_redacts_credentials` |
| CWE-20 improper input validation | Typed requests serialised by serde; answers decoded into typed structs; hex and base64 strictly parsed | `hex_refuses_odd_lengths_and_other_characters`, `base64_is_standard_and_padded`, `a_2xx_body_of_the_wrong_shape_is_a_decode_error_without_the_value`, fuzz targets `problem` and `response` |
| CWE-400, CWE-770 resource exhaustion | Body limit of 64 MiB after decompression; per-attempt timeout and optional deadline; retries capped and a long `Retry-After` ends them | `the_body_limit_and_a_cut_body_are_transport_errors`, `a_silent_server_times_out_each_attempt`, `the_deadline_bounds_the_whole_call`, `retries_stop_at_the_budget_or_a_long_retry_after` |
| CWE-190 integer overflow | Saturating arithmetic in backoff, bounded types in `Retry-After` date parsing; an oversize number of seconds becomes `u64::MAX` and ends retries | `backoff_is_full_jitter_under_a_doubling_cap`, `retry_after_refuses_anything_else` |
| CWE-226, CWE-244 secrets left in memory | `SecretBytes`, `SecretString` and 2xx bodies are zeroised on drop | `src/secret.rs`, `success_body` in `src/client.rs` |
| Duplicated side effects (CWE-841 class) | A call that creates or deletes state is retried only after `429` or `503` | `the_stateful_table_matches_request_ts`, `a_stateful_call_is_not_retried_after_a_504_or_a_lost_connection` |
| CWE-1104, OWASP A06 vulnerable components | `cargo deny` with no ignored advisories in CI and `make check`; weekly Dependabot | `deny.toml`, `.github/dependabot.yml` |
| OWASP A08 software and data integrity | Signed commits and tags, SHA-pinned actions, provenance attestations, reproducible `.crate` | `.github/workflows/release.yml`, [Reproducing a release](REPRODUCING.md) |

## Residual risks, accepted

- **Plain `http://` to any host.** The builder accepts `http://` for any
  host, so credentials and bodies can cross a network in clear text when
  the caller configures it. Restricting `http://` to loopback would
  break callers that reach crypto-server over a private network or a
  service mesh that adds TLS outside the process, so it is not done in a
  `0.0.x` step without an opt-in path agreed across the SDKs. The
  README and examples use `https://` for remote servers and
  `http://127.0.0.1` only for a local one; callers should use `https://`
  for any server not on the same host.
- **Copies outside the SDK's control.** Request bodies handed to the
  HTTP stack, the credential `HeaderValue`s, and copies the allocator or
  `hyper` make are not zeroised (SECURITY.md says so).
- **Server-written text in errors.** `ApiError`'s `Display` shows the
  problem's `title` and `type`, and `Debug` the whole problem, as the
  server wrote them. A hostile server could put misleading text or
  control characters there; a caller that logs errors from an untrusted
  server should escape them.
- **A custom `Transport`** takes over boundary 2 (above).
- **Single maintainer.** Review is by the maintainer and CI; see
  [Governance](project/governance.md).
