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

## How a pull request is reviewed

Every change reaches `main` through a pull request; `main` accepts no
direct push, and its branch protection requires every CI check and a
signature on every commit. The reviewer (today the maintainer, see
[GOVERNANCE.md](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/GOVERNANCE.md))
approves only when all of these hold, and says which one fails
otherwise:

1. **Green CI.** Every required check passes: format, clippy, tests on
   stable and 1.85.0, 100% line, region and branch coverage, complexity,
   `cargo deny`, versions and package contents, semver against crates.io,
   the conformance kit against the pinned server, fuzzing, CodeQL, docs
   lint and the DCO.
2. **Tests that would catch a regression.** A fix carries a test seen to
   fail without it; new behaviour carries tests of its errors as well as
   its success. A test is never weakened to pass.
3. **The security rules.** No `unsafe`, no cryptography, no new way for
   a credential, key, plaintext or body to reach a log, `Debug`,
   `Display` or error message; secrets stay in `SecretBytes` and
   `SecretString`; TLS verification stays on and redirects refused; a
   call that creates or deletes server state is not retried after the
   server may have acted. The change is checked against
   [docs/ASSURANCE.md](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/docs/ASSURANCE.md),
   which is updated when the change moves a trust boundary.
4. **Dependencies.** A new or upgraded dependency has a reason, passes
   `cargo deny`, keeps the toolchain floor, and gets an ADR when it shapes
   the crate. Workflow actions are pinned to a full commit SHA, and a
   workflow gets the least `permissions` it needs.
5. **The public API.** A breaking change is deliberate and in the
   changelog; documentation, README examples and `CHANGELOG.md` match the
   code.
6. **Hygiene.** Conventional commit subjects, a `Signed-off-by` on every
   commit, the two SPDX lines (`SPDX-FileCopyrightText` and
   `SPDX-License-Identifier`) at the top of every new source file, no
   lint suppression without its reason, and `conformance/` untouched.

The reviewer reads the whole diff, runs it locally when CI cannot show
the behaviour (for example a release workflow change, in a dry run),
and leaves the findings as review comments. Dependabot pull requests get
the same review.

By contributing you agree that your work is licensed under Apache-2.0 OR
MIT, as the rest of the repository.
