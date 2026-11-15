<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Crypto Service SDK for Rust

A typed async and blocking client for the v2 REST API of crypto-server.
The client performs no cryptography: every operation is an HTTP call to
the server, which holds the keys and runs the algorithms.

```toml
[dependencies]
crypto-service-sdk = "0.0.40"
```

- [Architecture](ARCHITECTURE.md): how a call travels.
- [Decision records](adr/README.md): why it is built this way.
- [Ecosystem comparison](COMPARISON.md) and [Benchmarks](BENCHMARKS.md).
- [Policies](POLICIES.md), [Packaging](packaging.md) and the
  [Roadmap](ROADMAP.md).
- The API reference is on [docs.rs](https://docs.rs/crypto-service-sdk).
