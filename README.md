<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

<p align="center">
  <img src="https://cloudcdn.pro/crypto-service/v1/logos/crypto-service.svg" alt="Crypto Service logo" width="128" />
</p>

<h1 align="center">Crypto Service SDK for Rust</h1>

<p align="center">
  A typed async and blocking Rust client for the Crypto Service REST API: hashing, AEAD, server-held signing and decryption keys, ML-KEM, ML-DSA, SLH-DSA, HPKE, KMS and OPAQUE, all performed by crypto-server.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/crypto-service-sdk-rust/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/crypto-service-sdk-rust/ci.yml?style=for-the-badge&logo=github" alt="Build" height="28" /></a>
  <a href="https://crates.io/crates/crypto-service-sdk"><img src="https://img.shields.io/crates/v/crypto-service-sdk.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Registry" height="28" /></a>
  <a href="https://docs.rs/crypto-service-sdk"><img src="https://img.shields.io/docsrs/crypto-service-sdk?style=for-the-badge&labelColor=555555&logo=docsdotrs" alt="Docs" height="28" /></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/sebastienrousseau/crypto-service-sdk-rust"><img src="https://img.shields.io/ossf-scorecard/github.com/sebastienrousseau/crypto-service-sdk-rust?style=for-the-badge&label=OpenSSF%20Scorecard&logo=openssf" alt="OpenSSF Scorecard" height="28" /></a>
  <a href="LICENSE-APACHE"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg?style=for-the-badge" alt="License: Apache-2.0 OR MIT" height="28" /></a>
  <a href="https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/docs/POLICIES.md"><img src="https://img.shields.io/badge/Rust-1.85%2B-93450a.svg?style=for-the-badge&logo=rust" alt="Rust 1.85 or newer" height="28" /></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/sebastienrousseau/crypto-service-sdk-rust/main/.github/demo.gif" alt="cargo run --example hash and --example ml_kem against a local crypto-server: a SHA-256 digest, then an ML-KEM-768 key held by the server, an encapsulation to its public key and a decapsulation with its keyId whose shared secrets match" width="100%" />
</p>

---

## Contents

**Getting started**

- [Install](#install): from crates.io, or the git repository
- [Requirements](#requirements): toolchain floor, platforms, a server
- [Quick Start](#quick-start): a digest and a typed error in a few lines

**The Crypto Service ecosystem**

- [The Crypto Service ecosystem](#the-crypto-service-ecosystem): the server, its packages and the SDKs

**Library reference**

- [Capabilities at a glance](#capabilities-at-a-glance): the current surface by theme
- [Ecosystem comparison](#ecosystem-comparison): short matrix; full table at [`docs/COMPARISON.md`](docs/COMPARISON.md)
- [Benchmarks](#benchmarks): scenarios; results at [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- [Features](#features): module-level capability list
- [Configuration](#configuration): client options
- [Examples](#examples): runnable example index

**Operational**

- [When not to use Crypto Service](#when-not-to-use-crypto-service): limitations
- [Development](#development): make targets, fuzzing, CI
- [Security](#security): guarantees and their limits
- [Documentation](#documentation): all reference docs
- [Stability guarantees](#stability-guarantees): SemVer axis, server compatibility, toolchain floor
- [License](#license)

---

## Install

### As a Rust library

```toml
[dependencies]
crypto-service-sdk = "0.0.40"
tokio = { version = "1.49", features = ["macros", "rt-multi-thread"] }
```

0.0.40 is the first release published to crates.io. Before it is out,
depend on the repository instead:
`crypto-service-sdk = { git = "https://github.com/sebastienrousseau/crypto-service-sdk-rust" }`.
Add `features = ["blocking"]` for `blocking::Client`. HTTPS uses rustls
(no OpenSSL) with the platform's trust store.

---

## Requirements

- Rust 1.85 or newer (`rust-version` in `Cargo.toml`), built and tested
  in CI on 1.85.0 and stable on Linux ([toolchain policy](docs/POLICIES.md)).
- A crypto-server to talk to. CI runs the conformance kit in
  `conformance/` against crypto-server at the commit in `ci/server.ref`.
- Tokio for the async client. The blocking client brings its own
  runtime and needs none from the caller.

---

## Quick Start

```rust,no_run
use crypto_service_sdk::{Client, Error, HashAlgorithm, HashRequest};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let url = std::env::var("CRYPTO_SERVICE_URL").expect("set CRYPTO_SERVICE_URL");
    let key = std::env::var("CRYPTO_SERVICE_API_KEY").expect("set CRYPTO_SERVICE_API_KEY");
    let client = Client::builder(url).api_key(key).build()?;

    let result = client
        .hash(&HashRequest {
            algorithm: HashAlgorithm::Sha256,
            data: "abc".into(),
        })
        .await?;
    println!("{} {}", result.algorithm, result.digest);
    Ok(())
}
```

`hash` posts to `POST /v2/hash` and returns the digest as `Hex` bytes.
Every failure is an `Error`: a non-2xx answer is `Error::Api` with the
server's RFC 9457 problem (`type`, `title`, `status`, `detail`, `code`,
`errors[]`), and no answer at all is `Error::Transport`.

```rust,no_run
use crypto_service_sdk::{Client, Error, SignRequest};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let url = std::env::var("CRYPTO_SERVICE_URL").expect("set CRYPTO_SERVICE_URL");
    let key = std::env::var("CRYPTO_SERVICE_API_KEY").expect("set CRYPTO_SERVICE_API_KEY");
    let client = Client::builder(url).api_key(key).build()?;

    let request = SignRequest {
        key_id: "k_AAAAAAAAAAAAAAAAAAAAAA".into(),
        message: "pay 10 EUR".into(),
    };
    match client.sign(&request).await {
        Err(Error::Api(api)) => {
            println!("{} {} {:?}", api.status, api.problem.kind, api.code());
            assert_eq!(api.code(), Some("KEY_NOT_FOUND"));
        }
        other => panic!("expected a problem, got {other:?}"),
    }
    Ok(())
}
```

---

## The Crypto Service ecosystem

This crate is one of the Crypto Service SDKs. Crypto Service has one
engine, crypto-server, and thin typed clients per language that all pass
one shared conformance kit. The SDKs release in lockstep at one version;
this crate's first release is 0.0.40.

| Component | Purpose | Use case |
| :--- | :--- | :--- |
| [`crypto-service`][core] | crypto-server and 18 npm packages (library, server, CLI, SDK, middleware, KMS, MCP, LSP, CBOM and more) | The server this client calls |
| [`crypto-service-sdk-python`][python] | Typed Python client | Call crypto-server from Python |
| [`crypto-service-sdk-go`][go] | Typed Go client | Call crypto-server from Go |
| [`crypto-service-sdk-java`][java] | Typed Java client | Call crypto-server from the JVM |
| [`crypto-service-sdk-dotnet`][dotnet] | Typed .NET client | Call crypto-server from .NET |
| [`crypto-service-sdk-cpp`][cpp] | Typed C++ client | Call crypto-server from C++ |
| **`crypto-service-sdk-rust`** | Typed async and blocking Rust client | Call crypto-server from a Rust service |
| [`crypto-service.co`][site] | Website and documentation | Read about the service |

---

## Capabilities at a glance

| Area | Capability | Status |
| :--- | :--- | :--- |
| Probes and meta | `root()`, `health()`, `live()`, `ready()`, `algorithms()` | Supported |
| Compliance documents | `get_dora_compliance()`, `get_cbom()` (CycloneDX 1.6); informational, not an assessment | Supported |
| Hashing and MACs | `hash()`, `mac()`, `mac_verify()` | Supported |
| Key derivation and passwords | `kdf()`, `password_hash()`, `password_verify()`, `password_encrypt()`, `password_decrypt()` | Supported |
| Symmetric | `encrypt()`, `decrypt()`, `secretbox_seal()`, `secretbox_open()`, `key_wrap()`, `key_unwrap()` | Supported |
| Server-held keys | `generate_key_pair()`, `export_key()`, `keys_delete()`, `sign()`, `verify()`, `stream_sign()`, `stream_verify()` | Supported |
| Post-quantum | ML-KEM-768, the X25519 + ML-KEM-768 hybrid, ML-DSA, SLH-DSA, ISO 20022 dual signatures | Supported |
| Public-key encryption | sealed boxes (classical and hybrid), multi-recipient, post-quantum streams, HPKE | Supported |
| KMS | `kms_create_key()`, `kms_encrypt()`, `kms_decrypt()`, `kms_generate_data_key()`, `kms_wrap()`, `kms_unwrap()` | Supported |
| OPAQUE | the four server-side registration and login steps | Supported |
| Low level | `send_raw()`: any method and path, any status | Supported |
| v1 OpenPGP routes, `/metrics` | Deprecated (v1 sunsets 2027-01-01) or operational | Not wrapped; use `send_raw()` |

59 of 59 v2 operations have a method, plus the four probes; see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how they are built.

---

## Ecosystem comparison

The SDKs share one method surface, one resilience contract and one
conformance kit, run against a live crypto-server in each SDK's CI.

| Project | Language (minimum) | Conformance kit in CI | Async and blocking |
| :--- | :---: | :---: | :---: |
| crypto-sdk (TypeScript, in `crypto-service`) | Node 24 | Reference runner | Async |
| **crypto-service-sdk-rust** | **Rust 1.85** | **Yes** | **Both** |
| Other Crypto Service SDKs | See each README | Yes | See each README |
| Raw HTTP | Any | No | Yours to write |

See [`docs/COMPARISON.md`](docs/COMPARISON.md) for the evidence and the
complete matrix.

---

## Benchmarks

Criterion benchmarks with the scenario names every SDK shares:
`encode_request`, `decode_response` and `decode_problem` measure the
client-side cost with no network, and `round_trip_hash` a loopback round
trip against `CRYPTO_SERVICE_URL`. No numbers are published yet; they
will be generated into [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) with
their environment.

---

## Features

- **`Client`** (`src/client.rs`, `src/builder.rs`): `Client::builder(url)`
  with `.api_key(..)` (sent as `x-api-key`), `.token(..)` (Bearer),
  `.timeout(..)` (per attempt, default 30 s), `.deadline(..)` (whole
  call), `.retry(RetryPolicy)`, `.traceparent(..)` and `.transport(..)`.
  One `async` method per operation. `Clone + Send + Sync`; clones share
  one connection pool. Every request sends
  `User-Agent: crypto-service-sdk-rust/0.0.40`.
- **`blocking::Client`** (feature `blocking`): the same methods without
  `async`, on a runtime the client owns.
- **Types** (`src/types/`): one request and one answer type per
  operation, with the encodings the OpenAPI document states: `Hex` and
  `Base64` for binary values, `SecretBytes` and `SecretString` for keys,
  passwords and plaintexts (zeroised on drop, redacted in `Debug`).
- **`Error`** (`src/error.rs`): `Api(ApiError)` with the RFC 9457
  `Problem`, `Transport(TransportError)` with `timed_out`,
  `Decode(DecodeError)` naming only the position of a fault, and
  `Config` for options that cannot work.
- **`RetryPolicy`** (`src/retry.rs`): off by default; full-jitter
  backoff; `Retry-After` honoured up to the maximum delay; calls that
  create or delete server state retried only after `429` or `503`.
- **`Transport`** (`src/transport.rs`): the HTTP exchange, replaceable
  for tests; the default is `reqwest` with rustls, HTTP/2 and gzip.

---

## Configuration

| Option | Default | Set with |
| :--- | :--- | :--- |
| Base URL | none | `Client::builder("https://crypto.example.com")` |
| API key | none | `.api_key(key)` (`x-api-key`) |
| Bearer token | none | `.token(jwt)` |
| Timeout per attempt | 30 seconds (`DEFAULT_TIMEOUT`) | `.timeout(Duration)`; `Duration::ZERO` turns it off |
| Deadline per call | none | `.deadline(Duration)` |
| Retries | none (`max_retries` 0, 200 ms initial, 2 s maximum delay) | `.retry(RetryPolicy::new().max_retries(3))` |
| `traceparent` | none | `.traceparent(Traceparent::Auto)` or `Traceparent::Fixed(..)` |
| HTTP stack | `ReqwestTransport` | `.transport(Arc<dyn Transport>)` |

The client reads no environment variables. The tests, examples and
benchmarks read `CRYPTO_SERVICE_URL`, `CRYPTO_SERVICE_API_KEY` and, for
the conformance kit, `CRYPTO_SERVICE_JWT_SECRET`.

---

## Examples

Each example exits non-zero when the server does not answer as it
expects; CI's conformance job runs them all:

```sh
cargo run --example hash
cargo run --example ml_kem
```

| Example | Shows |
| :--- | :--- |
| [`hash`](examples/hash.rs) | `hash()`: SHA-256 of `abc` |
| [`aead`](examples/aead.rs) | `encrypt()` and `decrypt()`, an XChaCha20-Poly1305 round trip |
| [`sign_verify`](examples/sign_verify.rs) | a server-held Ed25519 key: `generate_key_pair()`, `sign()` by keyId, `verify()`, `keys_delete()` |
| [`ml_kem`](examples/ml_kem.rs) | a server-held ML-KEM-768 key: encapsulate to it, decapsulate by keyId |
| [`errors`](examples/errors.rs) | `Error::Api` with a problem and its `code`, a validation problem's `errors[]`, `Error::Transport` |
| [`concurrent`](examples/concurrent.rs) | one client shared by eight Tokio tasks |
| [`blocking`](examples/blocking.rs) | `blocking::Client` and a KMS round trip with `encoding: hex` |

---

## When not to use Crypto Service

- **You need the cryptography in your own process.** This crate performs
  no cryptography; every operation is an HTTP call to crypto-server. If
  keys must never leave the caller, or the network is not acceptable on
  the hot path, use a local library instead.
- **You cannot run or reach a crypto-server.** The work happens there.
- **You need the v1 OpenPGP routes.** They are deprecated and sunset on
  2027-01-01; this crate does not wrap them (nor `/metrics`), though
  `send_raw()` reaches them.
- **You need the client half of OPAQUE.** The SDK carries the messages;
  blinding, KE1 and KE3 stay with the caller.

---

## Development

```sh
cargo test --locked --all-features
```

`make check` runs rustfmt, clippy (pedantic, `-D warnings`), the build,
the tests at 100% line and region coverage (cargo-llvm-cov), rustdoc with
warnings denied, `cargo deny`, the complexity ceilings (cyclomatic 10,
cognitive 15, Halstead difficulty 30, 60 lines per function, 500 per
file), the version check and the package contents check;
`make coverage-branch` adds 100% branch coverage on nightly. With a
server, `make conformance` runs the kit, the live tests, every example
and every block of this README; `make regression` starts a server
itself. `make fuzz` runs the two cargo-fuzz targets. See
[`DEVELOPMENT.md`](DEVELOPMENT.md) for every gate and its CI job.

---

## Security

The crate has no `unsafe` code. TLS verification is always on (rustls,
the platform's trust store) and cannot be turned off; redirects are
refused, so credentials never follow a `Location`. The API key and token
are redacted in `Debug` and marked sensitive in the HTTP stack. No error
message carries a credential, key, plaintext or body: decode errors name
only a line and column. Keys, passwords and plaintexts are held in
zeroising types, and a 2xx body is zeroised after decoding; request
bodies handed to the HTTP stack are not. Response bodies are read up to
64 MiB. The decoding paths are fuzzed, every dependency is checked by
`cargo deny`, and CodeQL and OpenSSF Scorecard run on `main`; releases
carry an SBOM and build provenance.

Report vulnerabilities according to [`SECURITY.md`](SECURITY.md).

---

## Documentation

[API reference (docs.rs)](https://docs.rs/crypto-service-sdk) ·
[Developer docs](DEVELOPMENT.md) ·
[Ecosystem map](#the-crypto-service-ecosystem)

Also: [Architecture](docs/ARCHITECTURE.md) ·
[Decision records](docs/adr/README.md) ·
[Conformance kit](conformance/README.md) ·
[Changelog](CHANGELOG.md) · [Policies](docs/POLICIES.md) ·
[Packaging](docs/packaging.md) · [Roadmap](docs/ROADMAP.md) ·
[Support](SUPPORT.md) · [Governance](GOVERNANCE.md) ·
[Agent rules](AGENTS.md)

---

## Stability guarantees

The project is pre-1.0 and versions advance in `0.0.1` steps, in lockstep
with the Crypto Service SDKs. The breaking axis is the public Rust API:
method signatures, the `Error` variants, the options and the request and
answer types; cargo-semver-checks guards it against the last crates.io
release from 0.0.40 on. Answer structs and enums are `#[non_exhaustive]`.
The client covers the v2 API of crypto-server at the commit in
`ci/server.ref`; v1 (deprecated, sunset 2027-01-01) and `/metrics` are
outside it. The `internals` feature and `crypto_service_sdk::fuzzing` are
not public API. The Rust floor moves only as described in the
[toolchain policy](docs/POLICIES.md).

---

## License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([`LICENSE-MIT`](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option. Dependencies keep their own licences.

[core]: https://github.com/sebastienrousseau/crypto-service
[python]: https://github.com/sebastienrousseau/crypto-service-sdk-python
[go]: https://github.com/sebastienrousseau/crypto-service-sdk-go
[java]: https://github.com/sebastienrousseau/crypto-service-sdk-java
[dotnet]: https://github.com/sebastienrousseau/crypto-service-sdk-dotnet
[cpp]: https://github.com/sebastienrousseau/crypto-service-sdk-cpp
[site]: https://crypto-service.co
