<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 1. A thin client over the server

- Status: accepted
- Date: 2026-11-15

## Context

crypto-server implements every algorithm the API offers, holds the
server-side keys, enforces scopes and quotas, and is tested against the
conformance kit. A client could reimplement some operations locally
(hashing, HMAC) for speed, or verify signatures itself.

## Decision

The SDK performs no cryptography. Every operation is an HTTP call to
crypto-server; the client's byte handling is limited to the hex and
base64 encodings the OpenAPI document states. It neither validates key
material nor checks results beyond decoding them.

## Consequences

- One implementation of each algorithm to audit, patch and certify: the
  server's. A fix there reaches every SDK user without a client release.
- Every operation costs a network round trip, and the data travels to
  the server; the README's "When not to use" section says so.
- The client can be small, and its tests are about HTTP, encodings and
  errors, which the conformance kit checks against the real server.
