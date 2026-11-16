#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# 100% branch coverage of src/, measured with cargo-llvm-cov --branch,
# which needs a nightly toolchain with llvm-tools-preview. cargo-llvm-cov
# has no --fail-under-branches, so the summary is checked here.
#
#   scripts/branch-coverage.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Nightly gets its own target directory. In the shared
# target/llvm-cov-target, nightly cargo leaves an instrumented test
# binary under build/ that a later stable `make coverage` reports
# alongside its own: its records never execute there, so stable sees
# about 15 regions and 12 lines missed that its own run covers.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/target/llvm-cov-nightly"

summary="$(cargo +nightly llvm-cov --locked --all-features --lib --branch --json --summary-only)"
printf '%s' "$summary" | python3 -I -c '
import json, sys
branches = json.load(sys.stdin)["data"][0]["totals"]["branches"]
print("branch coverage:", branches["covered"], "of", branches["count"])
sys.exit(0 if branches["covered"] == branches["count"] else 1)
'
