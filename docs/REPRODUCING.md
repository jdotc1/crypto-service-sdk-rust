<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Reproducing a release

Anyone can rebuild a release's `.crate` from its signed tag and check
that it is the file on the GitHub release and on crates.io, bit for bit.

## What decides the bytes

- **The commit**: the signed tag `v<version>`.
- **`Cargo.lock`**: `--locked` refuses any other resolution.
- **Cargo's version**: the `.crate` is a gzipped tarball whose normalised
  `Cargo.toml` and metadata Cargo writes itself, so a Cargo far from the
  release's can give other bytes. 0.0.40 rebuilt with Cargo 1.98.1 and
  with the 1.100.0 its release ran on gave the same file; Cargo 1.85.0
  did not. From 0.0.41 the release jobs pin the toolchain in `mise.toml`
  (`scripts/verify-release-versions` keeps them equal).
- Not the checkout path, the clock or the machine: Cargo sets fixed
  timestamps and ordering inside the tarball.

## Rebuild the `.crate`

```text
git clone https://github.com/sebastienrousseau/crypto-service-sdk-rust
cd crypto-service-sdk-rust
git config gpg.ssh.allowedSignersFile KEYS.asc
git verify-tag v0.0.40
git checkout v0.0.40
mise exec rust@1.98.1 -- cargo package --locked
sha256sum target/package/crypto-service-sdk-0.0.40.crate
```

Expected for 0.0.40, as in the release's `SHA256SUMS` and in the
crates.io index (`cksum`):

```text
8722be0b8df0e604092c47b7fa0e45922024291c16b9154e6f607e2130b12256  crypto-service-sdk-0.0.40.crate
```

Compare with the published copies:

```text
gh release download v0.0.40 -R sebastienrousseau/crypto-service-sdk-rust -p SHA256SUMS
curl -sSL https://static.crates.io/crates/crypto-service-sdk/crypto-service-sdk-0.0.40.crate | sha256sum
```

## Rebuild every release file (from 0.0.41)

`scripts/dist.sh` is the step the release workflow runs after
`cargo package`: it copies the `.crate` to `dist/`, writes the CycloneDX
SBOM and `SHA256SUMS`. The SBOM is reproducible too: its timestamp is
the commit's (`SOURCE_DATE_EPOCH`, which also makes cargo-cyclonedx omit
its random `serialNumber`), and the checkout's absolute path in its
`bom-ref` is replaced by a fixed one.

```text
cargo install cargo-cyclonedx --locked --version 0.5.9
git checkout v<version>
mise exec -- cargo package --locked
mise exec -- scripts/dist.sh
gh release download v<version> -R sebastienrousseau/crypto-service-sdk-rust -p SHA256SUMS -O - \
  | diff - dist/SHA256SUMS && echo identical
```

Two checkouts of the same commit in different directories give the same
`dist/SHA256SUMS`; that is how the script was checked.

The 0.0.40 SBOM was written before this script, with a random serial
number and the build time, so only its `.crate` reproduces.

## Provenance

Each release file also carries a GitHub build provenance attestation:

```text
gh attestation verify crypto-service-sdk-0.0.40.crate -R sebastienrousseau/crypto-service-sdk-rust
```
