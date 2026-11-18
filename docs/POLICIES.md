<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Policies

## Toolchain

The minimum supported Rust is 1.85 (`rust-version`). CI builds and tests
on 1.85.0 and on stable. Raising the floor is a release-noted change
made only when a dependency needs it or a language feature pays for
itself, and never more than to a release at least six months old.

## Versions

`0.0.x`, one `0.0.1` step per release, in lockstep with the Crypto
Service SDKs. Breaking changes are allowed between steps while pre-1.0
and are listed in the changelog.

## Dependencies

Runtime dependencies are few and named in ADR 2. `cargo deny` enforces
advisories, the licence allow-list, and bans OpenSSL. Dependabot opens
weekly updates.

## Server compatibility

Each release names the crypto-server commit it is tested against
(`ci/server.ref`) and vendors that commit's conformance kit.
