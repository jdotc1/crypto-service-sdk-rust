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

summary="$(cargo +nightly llvm-cov --locked --all-features --lib --branch --json --summary-only)"
printf '%s' "$summary" | python3 -I -c '
import json, sys
branches = json.load(sys.stdin)["data"][0]["totals"]["branches"]
print("branch coverage:", branches["covered"], "of", branches["count"])
sys.exit(0 if branches["covered"] == branches["count"] else 1)
'
