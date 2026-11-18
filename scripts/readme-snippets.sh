#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Runs every code block of README.md against a live server, so the README
# never shows code that does not work:
#
#   - the ```toml block becomes the dependencies of a scratch crate, with
#     crypto-service-sdk patched to this checkout (it resolves before the
#     crate is on crates.io too);
#   - each ```rust block becomes a binary of that crate and is run;
#   - each ```sh block is run with bash, from the repository root.
#
# Needs CRYPTO_SERVICE_URL and CRYPTO_SERVICE_API_KEY.
#
#   scripts/readme-snippets.sh
set -euo pipefail

cd "$(dirname "$0")/.."
: "${CRYPTO_SERVICE_URL:?set CRYPTO_SERVICE_URL}"
: "${CRYPTO_SERVICE_API_KEY:?set CRYPTO_SERVICE_API_KEY}"

root="$PWD"
work="$root/target/readme-snippets"
rm -rf "$work"
mkdir -p "$work/src/bin"

python3 -I - "$root/README.md" "$work" <<'PY'
import pathlib, re, sys
readme, work = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
blocks = re.findall(r"^```(\w+)[^\n]*\n(.*?)^```", readme.read_text(), re.S | re.M)
counts = {}
for lang, body in blocks:
    n = counts[lang] = counts.get(lang, 0) + 1
    if lang == "rust":
        (work / "src/bin" / f"snippet{n}.rs").write_text(body)
    elif lang == "toml":
        (work / "deps.toml").write_text(body)
    elif lang == "sh":
        (work / f"snippet{n}.sh").write_text(body)
    else:
        sys.exit(f"readme-snippets: no runner for a {lang} block")
print("readme-snippets:", ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
PY

test -f "$work/deps.toml" || { echo "readme-snippets: no toml block" >&2; exit 1; }
{
  cat <<'TOML'
[package]
name = "readme-snippets"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

TOML
  cat "$work/deps.toml"
  cat <<TOML

[patch.crates-io]
crypto-service-sdk = { path = "$root" }
TOML
} > "$work/Cargo.toml"

for bin in "$work"/src/bin/*.rs; do
  name="$(basename "$bin" .rs)"
  echo "== README rust block $name"
  cargo run --quiet --manifest-path "$work/Cargo.toml" --bin "$name"
done
for script in "$work"/snippet*.sh; do
  [ -e "$script" ] || continue
  echo "== README sh block $(basename "$script")"
  bash -euo pipefail "$script"
done
echo "readme-snippets: every block ran"
