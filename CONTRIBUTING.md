<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Contributing

Thank you for helping. This crate is a thin client: the cryptography and
the API belong to [crypto-service](https://github.com/sebastienrousseau/crypto-service),
so a new operation or a change of behaviour starts there, in the OpenAPI
document and the conformance kit, and reaches this crate afterwards.

## Before you open a pull request

1. Open an issue for anything larger than a fix, so the change can be
   agreed first.
2. Branch from the current `feat/v<version>` release branch.
3. Run `make check`; with a crypto-server running, `make conformance`
   (see [DEVELOPMENT.md](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/DEVELOPMENT.md)).
4. Add or change the tests in the same commit as the behaviour.
5. Update `CHANGELOG.md` under the current version.

## Commits

- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:` ...), subject
  in the imperative, at most 50 characters; body wrapped at 72, saying
  what and why.
- Sign off every commit (`git commit -s`): you certify the
  [Developer Certificate of Origin](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/DCO.txt). The DCO workflow checks it.

## Rules that do not bend

- No `unsafe`, no cryptography in the client, no logging or printing of
  credentials, keys, plaintexts or bodies.
- `conformance/` is never edited by hand.
- No new runtime dependency without a reason in the pull request (and an
  ADR when it shapes the crate).
- Synthetic test values only; never a real key or token.

By contributing you agree that your work is licensed under Apache-2.0 OR
MIT, as the rest of the repository.
