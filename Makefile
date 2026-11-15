# SPDX-License-Identifier: Apache-2.0 OR MIT
# Local gates. `make check` runs what CI runs without a server; the live
# targets (conformance, examples, readme) need a crypto-server:
#   CRYPTO_SERVICE_URL=http://127.0.0.1:3102 CRYPTO_SERVICE_API_KEY=... \
#   CRYPTO_SERVICE_JWT_SECRET=... make conformance
# `make regression` starts one itself (scripts/regression.sh).

CARGO ?= cargo
CLIPPY_FLAGS := -D warnings -W clippy::cognitive_complexity -W clippy::too_many_lines
# The live tests fail instead of skipping when these are missing.
LIVE := CRYPTO_SERVICE_REQUIRE_LIVE=1

.PHONY: check fmt fmt-check lint build test coverage coverage-branch doc deny complexity versions package-check api-check docs-lint manual conformance live-env examples readme bench bench-smoke fuzz regression demo clean

check: fmt-check lint build test coverage doc deny versions package-check complexity

fmt:
	$(CARGO) fmt
	cd fuzz && $(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check
	cd fuzz && $(CARGO) fmt --check

lint:
	$(CARGO) clippy --locked --all-targets --all-features -- $(CLIPPY_FLAGS)
	$(CARGO) clippy --locked --all-targets -- $(CLIPPY_FLAGS)

build:
	$(CARGO) build --locked --all-targets --all-features

test:
	$(CARGO) test --locked --all-features

# 100% of lines and regions in src/, or the target fails. Needs
# cargo-llvm-cov (`cargo install cargo-llvm-cov --locked`) and the
# llvm-tools-preview component. The unit tests alone reach 100%.
coverage:
	$(CARGO) llvm-cov --locked --all-features --lib --fail-under-lines 100 --fail-under-regions 100

# 100% of branches, on nightly (branch coverage is unstable in rustc).
coverage-branch:
	scripts/branch-coverage.sh

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --locked --no-deps --all-features

# Needs cargo-deny (`cargo install cargo-deny --locked`).
deny:
	$(CARGO) deny --locked check

# Cyclomatic 10, cognitive 15, Halstead difficulty 30 and 60 lines per
# function, 500 lines per file, on every tracked .rs file. Needs
# rust-code-analysis-cli 0.0.25.
complexity:
	python3 -I scripts/complexity-gate.py

versions:
	scripts/verify-release-versions

package-check:
	scripts/check-package.sh

api-check:
	scripts/api-check.sh

# Markdown style, spelling and REUSE: npx, codespell and reuse.
docs-lint:
	npx --yes markdownlint-cli2@0.23.3 "**/*.md"
	codespell
	reuse lint

manual:
	scripts/build-manual.sh

live-env:
	@test -n "$(CRYPTO_SERVICE_URL)" || { echo "set CRYPTO_SERVICE_URL"; exit 1; }
	@test -n "$(CRYPTO_SERVICE_API_KEY)" || { echo "set CRYPTO_SERVICE_API_KEY"; exit 1; }
	@test -n "$(CRYPTO_SERVICE_JWT_SECRET)" || { echo "set CRYPTO_SERVICE_JWT_SECRET"; exit 1; }

# The kit, the live blocking test, every example and every README block.
conformance: live-env
	$(LIVE) $(CARGO) test --locked --all-features --test conformance --test blocking -- --nocapture
	$(MAKE) examples
	$(MAKE) readme

EXAMPLES := $(sort $(basename $(notdir $(wildcard examples/*.rs))))

examples: live-env
	$(CARGO) build --locked --all-features --examples
	@for example in $(EXAMPLES); do \
	  echo "== example $$example"; \
	  $(CARGO) run --quiet --locked --all-features --example $$example || exit 1; \
	done

readme: live-env
	scripts/readme-snippets.sh

# Criterion: benches/client.rs (no network) and benches/roundtrip.rs
# (against CRYPTO_SERVICE_URL, skipped without it). Reports land in
# target/criterion/; pass criterion options with BENCH_ARGS.
bench:
	$(CARGO) bench --locked --all-features -- $(BENCH_ARGS)

bench-smoke:
	$(CARGO) bench --locked --all-features -- --test

# Each fuzz target for FUZZ_SECONDS (default 60), from the seeds. Needs
# nightly and cargo-fuzz.
FUZZ_SECONDS ?= 60
fuzz:
	@for target in problem response; do \
	  mkdir -p fuzz/corpus/$$target; \
	  $(CARGO) +nightly fuzz run $$target fuzz/corpus/$$target fuzz/seeds/$$target \
	    -- -max_total_time=$(FUZZ_SECONDS) || exit 1; \
	done

regression:
	scripts/regression.sh

# Renders .github/demo.gif from .github/demo.tape (needs vhs and a server
# in the environment, as for `make examples`).
demo: live-env
	@command -v vhs >/dev/null || { echo "make demo needs vhs (https://github.com/charmbracelet/vhs)"; exit 1; }
	$(CARGO) build --locked --example hash --example ml_kem
	vhs .github/demo.tape

clean:
	$(CARGO) clean
