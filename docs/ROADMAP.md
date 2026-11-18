<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Roadmap

Plans, not promises; each item lands only with its tests and a changelog
entry.

- Publish 0.0.40 to crates.io and register the trusted publisher.
- Generate `docs/BENCHMARKS.md` from criterion runs on a fixed machine.
- Follow crypto-server's API: when the server adds an operation or the
  kit grows, move `ci/server.ref` and the vendored kit together.
- Consider streaming bodies for large stream encryption once the server
  offers a streaming route.
