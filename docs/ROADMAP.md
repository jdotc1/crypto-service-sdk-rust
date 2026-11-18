<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Roadmap

Plans, not promises, for the year to November 2027; each item lands only
with its tests and a changelog entry. Versions keep moving in `0.0.1`
steps, in lockstep with the Crypto Service SDKs. Last reviewed
2026-11-18.

## Done

- 0.0.40, the first release, published to crates.io on 2026-11-17, its
  `.crate` reproducible from the signed tag; later versions publish
  through crates.io trusted publishing only.

## Next releases (to early 2027)

- Follow crypto-server's API: when the server adds an operation or the
  kit grows, move `ci/server.ref` and the vendored kit together, and add
  the method in the same release.
- v1 sunset (2027-01-01): once the server drops the v1 routes, remove
  the README and docs text that points `send_raw` at them.
- Publish the manual on GitHub Pages (the workflow exists; Pages is not
  enabled yet).

## Within the year (to November 2027)

- Generate `docs/BENCHMARKS.md` from criterion runs on a fixed machine.
- Streaming bodies for large stream encryption, once the server offers a
  streaming route.
- Raise the toolchain floor only as [Policies](POLICIES.md) allow (a
  dependency needs it, to a release at least six months old).

## Non-goals

Out of scope; a request for one of these will be declined:

- Cryptography in the client. Every operation stays an HTTP call to
  crypto-server (ADR 1); the crate never generates or uses keys itself,
  it only carries them in `SecretBytes` and `SecretString`.
- An option to turn TLS certificate verification off, or a native-tls or
  OpenSSL backend (`deny.toml` bans them).
- Following redirects, or sending credentials anywhere but the base URL.
- Typed wrappers for the deprecated v1 OpenPGP routes or `/metrics`;
  `send_raw` reaches them.
- Logging, telemetry or any network traffic other than the calls the
  caller makes.
- An async runtime other than Tokio (ADR 4), or a registry other than
  crates.io (ADR 5).
- A version jump to `0.1.0` or `1.0` outside the lockstep `0.0.1` steps.
