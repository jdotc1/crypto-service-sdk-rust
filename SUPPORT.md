<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Support

## Supported versions

| Version | Status | Fixes |
| :--- | :--- | :--- |
| `0.0.41` | Current (in preparation on `main`) | Yes |
| `0.0.40` | First release, latest on crates.io | Yes, until 0.0.41 is out |

Versions move in `0.0.1` steps, in lockstep with the Crypto Service
SDKs; the latest release receives fixes, and an older one is fixed by
upgrading.

## Getting help

- Usage questions and bugs: open an issue in this repository with the
  crate version, the crypto-server version (`GET /` answers it) and a
  minimal reproducer. Never paste real keys, tokens or plaintexts.
- A problem in the server itself (a wrong answer the kit does not
  cover): [crypto-service issues](https://github.com/sebastienrousseau/crypto-service/issues).
- Security reports: never in an issue; see [SECURITY.md](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/SECURITY.md).

The project is maintained in a personal capacity, with no SLA.
