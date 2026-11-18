<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Development

## Toolchain

- Rust from `mise.toml` (1.98.1 locally, and in the release jobs, which
  package with it); the floor is `rust-version` 1.85 and CI builds and
  tests on 1.85.0 and stable. `.cargo/config.toml`
  makes the resolver pick dependency versions 1.85 can build.
- Gate tools: cargo-llvm-cov 0.9.1 (`llvm-tools-preview`), cargo-deny
  0.20.2, rust-code-analysis-cli 0.0.25, cargo-semver-checks 0.51.0,
  cargo-fuzz 0.13.2 with a nightly toolchain, cargo-cyclonedx 0.5.9 for
  the release SBOM, and for the docs markdownlint-cli2, codespell and
  reuse.

## Gates

| Target | What it checks | CI job |
| :--- | :--- | :--- |
| `make fmt-check` | rustfmt, crate and `fuzz/` | Format and lint |
| `make lint` | clippy pedantic, `-D warnings`, cognitive 15 and 60 lines, with and without features | Format and lint |
| `make doc` | rustdoc with warnings denied | Format and lint |
| `make build`, `make test` | every target; unit tests, doctests, live tests skip without a server | Build and unit tests (stable, 1.85.0) |
| `make coverage` | 100% lines and regions of `src/` | Coverage |
| `make coverage-branch` | 100% branches (nightly) | Coverage (branches) |
| `make deny` | RustSec advisories, licences, bans (no OpenSSL), sources | Dependency policy |
| `make complexity` | cyclomatic 10, cognitive 15, Halstead difficulty 30, 60 lines per function, 500 lines per file, every tracked `.rs` | Complexity ceilings |
| `make versions`, `make package-check`, `make api-check` | version restatements and the release toolchain, package allow-list, semver against crates.io | Release checks |
| `make conformance` | the kit, the live blocking test, every example, every README block | Conformance |
| `make bench-smoke` | each benchmark once | Build and Conformance |
| `make fuzz` | each cargo-fuzz target for 60 s | Fuzz (pull requests) |
| `make docs-lint` | markdownlint, codespell, reuse | Docs lint |

`make check` runs the offline gates in order.

## A local server

The live targets need crypto-server at the commit in `ci/server.ref`,
with an API key and a JWT secret (synthetic values only):

```text
cd /path/to/crypto-service && pnpm install --frozen-lockfile && pnpm -r run build
cd packages/crypto-server
PORT=3102 HOST=127.0.0.1 NODE_ENV=development RATE_LIMIT_MAX=100000 \
  CRYPTO_API_KEY=<synthetic key> JWT_SECRET=<32+ synthetic bytes> node dist/index.js
```

then, in this repository:

```text
export CRYPTO_SERVICE_URL=http://127.0.0.1:3102
export CRYPTO_SERVICE_API_KEY=<the same key>
export CRYPTO_SERVICE_JWT_SECRET=<the same secret>
make conformance
```

The conformance runner mints HS256 tokens and runs each kit file as its
own principal, `conformance-<group>`, because the server's tenant quota
is 60 requests a minute per principal and the kit has 119 vectors.
`make regression` does all of this with a server it starts and stops.

## Fuzzing

`fuzz/` is a crate of its own (`cargo +nightly fuzz run <target>`):
`problem` feeds a status and body to the problem parser, `response` a 2xx
body to every answer type. Seeds are in `fuzz/seeds/`.

## Release model

Versions advance by `0.0.1`, in lockstep with the Crypto Service SDKs;
the maintainer opens a release. A release is prepared, then tagged by the
maintainer, and the [release workflow](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/.github/workflows/release.yml)
does the rest:

1. On the release branch: rename `## [<version>] - Unreleased` in
   `CHANGELOG.md` to `## [<version>] - <date>`, update
   `releases/v<version>.md` (two to four Highlights, `-` or `*`
   bullets), and run `make versions release-notes`.
2. Run the workflow by hand first (Actions, Release, Run workflow): a dry
   run builds, tests, packages, writes the SBOM and checksums, and prints
   what a release would carry.
3. After the release pull request is merged, the maintainer creates and
   pushes a signed annotated tag:
   `git tag -s v<version> -m "crypto-service-sdk-rust v<version>"`. The
   workflow refuses a lightweight or unsigned tag, or another message.
4. The tag runs the workflow: the GitHub release titled
   `crypto-service-sdk-rust <version>` with the `.crate`, the CycloneDX
   SBOM (`.cdx.json`) and `SHA256SUMS`, provenance attestations, notes
   composed by `scripts/release_notes.py` (Highlights, What's Changed,
   Checksums, Full Changelog), then `cargo publish` to crates.io with a
   short-lived token from trusted publishing. `scripts/dist.sh` writes
   the files, reproducibly: [docs/REPRODUCING.md](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/docs/REPRODUCING.md)
   rebuilds them and gives the expected checksums.
5. Check the live release and the crate on crates.io and docs.rs, and
   that a rebuild from the tag gives the same `SHA256SUMS`.

### Settings outside the repository

Created by the maintainer, never by automation. State on 2026-11-18:

| Setting | Where | Why | State |
| :--- | :--- | :--- | :--- |
| `release` environment | Settings, Environments | the publish job runs in it, with a required reviewer and a branch policy | In place |
| Trusted publisher | crates.io, `crypto-service-sdk`, Settings, Trusted Publishing | repository `sebastienrousseau/crypto-service-sdk-rust`, workflow `release.yml`, environment `release`: the only way the workflow can publish | In place |
| Bootstrap token | `release` environment secrets | published 0.0.40, the first version, before crates.io could register the trusted publisher (ADR 5) | Deleted after 0.0.40; the workflow no longer reads any token |
| Branch protection on `main` | Settings, Branches | pull requests only, the CI checks required, signed commits | In place |
| GitHub Pages | Settings, Pages, Source: GitHub Actions | the manual's deploy job | Not enabled yet |
| `PAGES_ENABLED` = `true` | Settings, Variables, Actions | turns the manual's deploy job on once Pages is enabled | Not set yet |
| `KEYS.asc` | repository root | the maintainer's signing keys, which the release workflow checks the tag against | In place |
