#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Writes the release files to dist/: the .crate that `cargo package
# --locked` left in target/package/, the CycloneDX SBOM and SHA256SUMS.
# The release workflow runs it, and so does anyone reproducing a release
# (docs/REPRODUCING.md), so both get the same bytes:
#
# - the SBOM's timestamp is the commit's (SOURCE_DATE_EPOCH), which also
#   makes cargo-cyclonedx leave out its random serialNumber;
# - the checkout's absolute path, which cargo-cyclonedx writes into the
#   bom-ref of this crate, is replaced by a fixed one.
#
# Needs cargo-cyclonedx 0.5.9 and a clean checkout of the commit.
#
#   cargo package --locked && scripts/dist.sh
set -euo pipefail

cd "$(dirname "$0")/.."

version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1)"
crate="target/package/crypto-service-sdk-$version.crate"
sbom="crypto-service-sdk-$version.cdx"
test -f "$crate" || {
  echo "dist: $crate is missing; run cargo package --locked first" >&2
  exit 1
}

rm -rf dist
mkdir dist
cp "$crate" dist/

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  cargo cyclonedx --format json --target all --override-filename "$sbom"
sed "s#path+file://$PWD#path+file:///crypto-service-sdk-rust#g" "$sbom.json" \
  > "dist/$sbom.json"
rm "$sbom.json"
if grep -qF "$PWD" "dist/$sbom.json"; then
  echo "dist: the SBOM still names $PWD" >&2
  exit 1
fi

(cd dist && sha256sum -- * > SHA256SUMS && cat SHA256SUMS)
