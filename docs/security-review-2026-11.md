<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Security review, November 2026

| | |
| :--- | :--- |
| Date | 2026-11-18 |
| Reviewer | Sebastien Rousseau, with AI-assisted analysis (Claude) |
| Version reviewed | `main` at `cf4339e` (the v0.0.40 tag), and the 0.0.41 branch that carries the fixes |
| Against | the [assurance case](ASSURANCE.md) and its seven security requirements |

## Scope

- Library code: every module in `src/` (builder, client pipeline,
  transport, retries, errors, encodings, secrets, request and answer
  types, the blocking client).
- Transport and TLS: the `reqwest` and rustls configuration, redirects,
  body limits, timeouts.
- Credential handling: from `ClientBuilder` to the header map, `Debug`
  and error output.
- Input parsing: answer bodies, RFC 9457 problems, `Retry-After`, hex
  and base64.
- Error paths: what each `Error` variant carries and prints.
- CI workflows and their permissions, triggers and pinned actions.
- The release pipeline: tag checks, packaging, SBOM, provenance,
  crates.io publishing.
- The dependency set: `Cargo.lock` and `fuzz/Cargo.lock`, `deny.toml`.

Out of scope: crypto-server itself (reviewed in its own repository) and
the cryptography it performs.

## Method

1. Read every source file and workflow against the assurance case's
   requirements and trust boundaries, following each credential and
   secret from the caller to the network and back to an error.
2. Checked each claim of SECURITY.md and the README's Security section
   for a test that would fail if the claim stopped being true.
3. Tried the inputs a caller or server could choose to break a boundary
   (paths for `send_raw`, redirects, oversized and malformed bodies,
   extreme `Retry-After` values) against the code and its tests.
4. Ran the automated gates: `cargo deny check` (advisories, licences,
   bans, sources: all ok on 2026-11-18), `make check` with 100% line and
   region coverage, clippy pedantic, `actionlint` on the workflows, the
   repository's Dependabot, code-scanning and secret-scanning alerts (no
   open Dependabot or secret-scanning alert; one Scorecard alert about
   the Best Practices badge, not a code issue).
5. Rebuilt the v0.0.40 `.crate` from its signed tag and compared it with
   the release asset and crates.io.

A finding is a bug when the code breaks a stated requirement; it is
fixed in the same pull request with a test seen to fail first. Anything
else is recorded with the reason it is accepted.

## Findings

| # | Severity | Finding | Disposition |
| :--- | :--- | :--- | :--- |
| 1 | Medium | `send_raw` appended the caller's path to the base URL unchecked. A path such as `.evil.example/x` or `@evil.example/x` turned `https://api.example.com` into a URL on another host, which received the `x-api-key` or bearer token (CWE-201). Only paths from `/` were documented. | **Fixed**: a path not starting with `/` is refused with `Error::Config`, nothing sent. Test `send_raw_refuses_a_path_that_would_change_the_host` failed before the fix. |
| 2 | Low | Redirect refusal, the control that keeps credentials from following a `Location`, had no test: removing it would have passed CI. | **Fixed**: test `a_redirect_is_returned_not_followed_with_the_credentials`, seen to fail with the redirect policy removed. |
| 3 | Low | The release jobs packaged with whatever `stable` was that day, and the SBOM had a random serial number and the build time, so a release could not be checked by rebuilding it. (v0.0.40's `.crate` does reproduce, with Cargo 1.98.1 and 1.100.0, not with 1.85.0.) | **Fixed**: the release jobs pin the `mise.toml` toolchain, checked by `scripts/verify-release-versions`; `scripts/dist.sh` writes a reproducible SBOM; [Reproducing a release](REPRODUCING.md) gives the procedure and hashes. |
| 4 | Low | The publish job still read `CRATES_IO_BOOTSTRAP_TOKEN` and preferred it to trusted publishing. The secret is deleted, but re-adding one would have silently brought back a long-lived token. | **Fixed**: the job uses trusted publishing only. |
| 5 | Informational | `fuzz/Cargo.lock` still described the dependency set before the base64 0.23 upgrade, so the fuzz crate was not built against the library's locked versions (the fuzz workflow does not pass `--locked`). | **Fixed**: resynced. Checking it in CI is listed as a small task. |
| 6 | Low | The release workflow verifies the tag's signature against the `KEYS.asc` of the tagged commit, and does not check that the commit is on `main`. Someone able to push a branch and a tag could add their own key and get a GitHub release created; publishing to crates.io still needs approval in the `release` environment. | **Accepted for now**: only the maintainer can push, and the environment gate stands. Hardening (verify against `main`'s `KEYS.asc` and require the commit on `main`) is a follow-up. |
| 7 | Low | An `http://` base URL is accepted for any host, so credentials and bodies can travel in clear text (CWE-319). | **Accepted and documented**: restricting `http://` to loopback would break callers on private networks or behind a mesh that adds TLS; recorded in the assurance case, README and SECURITY.md with the advice to use `https://`. |
| 8 | Informational | `ApiError`'s `Display` and `Debug` show text the server wrote (`title`, `type`, `detail`), which a hostile server could fill with misleading text or control characters (CWE-117 when logged). | **Accepted**: the text is the server's diagnosis and is needed; recorded in the assurance case for callers that log errors from untrusted servers. |
| 9 | Informational | Request bodies, the credential `HeaderValue`s and copies made by `hyper` or the allocator are not zeroised. | **Accepted**: outside what the `http` and `hyper` types allow; already stated in SECURITY.md and the README. |
| 10 | Informational | `traceparent` IDs and retry jitter come from the standard library's `RandomState`, not a cryptographic generator. | **Accepted**: neither is a secret; trace IDs need uniqueness, jitter needs spread. |

No issue was found in: the base URL checks, header-injection handling
(credentials and `traceparent` must be valid header values), the body
limit (applied after decompression), timeouts and the deadline, the
retry safety table, `Retry-After` parsing, decode errors (position and
category only), the zeroising and redaction of every secret-bearing
type, `#![forbid(unsafe_code)]`, workflow permissions (read-only by
default, write scopes only in the jobs that need them, no
`pull_request_target`), action pinning (every action by commit SHA),
the conformance job's handling of `ci/server.ref`, and the dependency
policy.

## Next review

Before the release that changes a trust boundary (a new transport, a
new credential type, a change to the release pipeline), and in any case
by November 2027.
