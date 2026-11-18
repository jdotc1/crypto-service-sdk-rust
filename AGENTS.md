<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# AGENTS.md

Invariants for AI-assisted contributors. A human contributor reads
[CONTRIBUTING.md](CONTRIBUTING.md) and [DEVELOPMENT.md](DEVELOPMENT.md);
an agent reads those too, plus this list of things that must never
drift.

## Versioning

- The version is `0.0.x` and moves strictly one step at a time
  (`+0.0.1`), in lockstep with the Crypto Service SDKs. Never propose a
  `0.1.0` or `1.0` jump.
- `Cargo.toml` is the single source of truth. `CITATION.cff`, the
  `CHANGELOG.md` heading, `README.md`, `docs/index.md`, `SECURITY.md`,
  `SUPPORT.md`, the bug report form and both lockfiles restate it;
  `scripts/verify-release-versions` checks them.
- Work for the next iteration happens on `feat/v<next-version>`; one
  release pull request into `main` at a time.

## The conformance kit

- `conformance/` is vendored byte for byte from crypto-service at the
  commit in `ci/server.ref`. Never edit it; update it only by copying a
  newer kit and moving `ci/server.ref` with it. The tests check its
  `SHA256SUMS`.

## Thin client

- No cryptography in this crate: every operation is an HTTP call to
  crypto-server (ADR 1). Hex and base64 translation is the only byte
  handling allowed.
- Never guess an encoding: follow the OpenAPI document; where the server
  guesses (HPKE inputs), send the unambiguous form.

## Secrets

- Never log, print, `Display` or `Debug` a credential, key, password,
  plaintext or body. Keys and plaintexts live in `SecretBytes` and
  `SecretString`. Errors carry positions and server-written titles, never
  values.
- Never commit real keys or credentials; tests use synthetic values.
- TLS verification stays on; there is no option to disable it.

## Gates

- `make check` passes: format, clippy (pedantic, `-D warnings`), build,
  tests at 100% lines and regions, docs, `cargo deny`, versions, package
  contents and complexity (cyclomatic 10, cognitive 15, Halstead 30,
  60 lines per function, 500 per file). `make coverage-branch` keeps
  100% branches. `make conformance` passes against the pinned server.
- No blanket lint suppressions; a specific `#[allow]` carries its reason.
- Every behaviour change lands with its test in the same commit.

## Commits

- Conventional commits, subject at most 50 characters, body wrapped at
  72; `git commit -s` (DCO) and signed. Never rewrite published history,
  never merge into `main`, tag or publish without the maintainer.
