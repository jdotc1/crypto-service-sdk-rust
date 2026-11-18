<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Packaging

The crate is published to crates.io as `crypto-service-sdk` (library
`crypto_service_sdk`) from the release workflow only (ADR 5).

## What ships

`include` in `Cargo.toml` is an allow-list: the manifest and lockfile,
`README.md`, `CHANGELOG.md`, the licences, `src/`, `tests/`, `examples/`,
`benches/` with their recorded answers, and `conformance/`.
`scripts/check-package.sh` fails CI when the package would ship `docs/`,
`fuzz/`, `scripts/`, CI files, release notes or the demo.

## Features

| Feature | Default | Adds |
| :--- | :---: | :--- |
| `blocking` | no | `blocking::Client` (Tokio multi-thread runtime) |
| `internals` | no | `crypto_service_sdk::fuzzing`, for benches; not public API |

## Release artefacts

Each GitHub release carries the `.crate`, a CycloneDX SBOM
(`crypto-service-sdk-<version>.cdx.json`), `SHA256SUMS` and build
provenance attestations.
