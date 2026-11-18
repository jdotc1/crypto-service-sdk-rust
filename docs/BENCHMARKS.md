<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Benchmarks

No results are published yet. This page will be generated from criterion
runs, with the machine, toolchain and server commit next to every number.

## Scenarios

The names are shared by every Crypto Service SDK, so results compare
across languages.

| Scenario | File | What it measures |
| :--- | :--- | :--- |
| `encode_request` | `benches/client.rs` | encoding a `HashRequest` with 1 KiB of data |
| `decode_response` | `benches/client.rs` | decoding a recorded hash answer and an ML-KEM key pair answer |
| `decode_problem` | `benches/client.rs` | parsing a recorded RFC 9457 problem |
| `round_trip_hash` | `benches/roundtrip.rs` | `hash()` against `CRYPTO_SERVICE_URL` over loopback |

## Running

```text
make bench                                  # client-side scenarios
CRYPTO_SERVICE_URL=... CRYPTO_SERVICE_API_KEY=... make bench
```

The server's tenant quota (60 requests a minute per principal) limits a
measured round-trip run: use a principal nothing else shares, and expect
`429`s if a run exceeds it. `make bench-smoke` runs each scenario once.
