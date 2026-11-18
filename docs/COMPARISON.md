<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Ecosystem comparison

| | crypto-sdk (TypeScript) | crypto-service-sdk-rust | Raw HTTP |
| :--- | :--- | :--- | :--- |
| Where | `packages/crypto-sdk` in crypto-service | this repository | your code |
| v2 operations with a method | most | 59 of 59 | none |
| Conformance kit | reference runner (server CI) | every vector against a live server in CI, through the typed methods where the body is expressible | no |
| Async / blocking | async | both | yours |
| Retries | opt-in, stateful-route table | the same table and defaults | yours |
| Secrets in memory | strings | zeroised on drop, redacted in `Debug` | yours |
| Errors | `CryptoApiError`, `CryptoTransportError` | `Error::Api`, `Transport`, `Decode`, `Config` | status codes |

The other SDKs (Python, Go, Java, .NET, C++) follow the same contract;
their READMEs state their own details.

## Evidence

- Method coverage: `src/operations.rs`, checked by
  `the_route_table_has_59_v2_operations` and by tests that call every
  method and assert its route.
- Kit results: the CI conformance job prints
  `conformance: N/119 vectors passed; X through typed methods, Y raw`.
