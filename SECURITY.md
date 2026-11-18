<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Security Policy

## Supported versions

| Version | Status | Security fixes |
| :--- | :--- | :--- |
| `0.0.41` | Current (in preparation on `main`) | Yes |
| `0.0.40` | First release, latest on crates.io | Yes, until 0.0.41 is out |

0.0.40 was the first release, in lockstep with the Crypto Service SDKs.
The latest release receives security fixes; an older release is fixed by
upgrading, since each step is `0.0.1`.

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Report privately through GitHub Private Vulnerability Reporting:
<https://github.com/sebastienrousseau/crypto-service-sdk-rust/security/advisories/new>.
The maintainer is notified automatically.

Please include a description and the potential impact, a minimal
reproducer (preferably a failing test, with synthetic keys only), the
version or commit affected, and any proposed remediation.

These are goals, not guarantees: the project is maintained in a personal
capacity, with no SLA and no out-of-hours cover. Acknowledgement is aimed
at within 5 working days, followed by a severity assessment and a
remediation plan.

A vulnerability in crypto-server itself belongs to
[crypto-service](https://github.com/sebastienrousseau/crypto-service/security/advisories/new).

## Security posture

The full argument (threat model, trust boundaries, secure design
principles, weaknesses countered, accepted risks) is the
[assurance case](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/docs/ASSURANCE.md);
the latest review against it is
[docs/security-review-2026-11.md](https://github.com/sebastienrousseau/crypto-service-sdk-rust/blob/main/docs/security-review-2026-11.md).
In short:

- No `unsafe` code: the crate root has `#![forbid(unsafe_code)]`.
- No cryptography in the client: every operation is performed by the
  server (ADR 1).
- TLS through rustls with the platform's trust store; verification is
  always on and there is no option to turn it off. Redirects are refused.
  An `http://` base URL is accepted for any host and is clear text: use
  `https://` for any server not on the same machine.
- Credentials are sent only as `x-api-key` or `Authorization: Bearer`,
  marked sensitive, and redacted in every `Debug` output.
- Keys, passwords and plaintexts are held in `SecretBytes` and
  `SecretString`, zeroised on drop and redacted in `Debug`; a 2xx body is
  zeroised after decoding. Request bodies handed to the HTTP stack, and
  copies made by the allocator, are outside that guarantee.
- Error messages never include credentials, keys, plaintexts or bodies:
  decode errors name only a line and column.
- A call that creates or deletes server state is retried only after a
  `429` or `503`, never after a `504` or a lost connection.
- `cargo deny check` runs in CI and `make check`, with no ignored
  advisories; the decoding paths are fuzzed.
