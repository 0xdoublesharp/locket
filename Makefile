SHELL := /bin/bash

CARGO ?= cargo
CARGO_DENY ?= cargo deny
CARGO_AUDIT ?= cargo audit
CARGO_AUDITABLE ?= cargo auditable
CARGO_GEIGER ?= cargo geiger
CARGO_VET ?= cargo vet
CARGO_MACHETE ?= cargo machete
CARGO_UDEPS ?= cargo +nightly udeps
CARGO_LLVM_COV ?= cargo llvm-cov
CARGO_FUZZ ?= cargo +nightly fuzz
PNPM ?= $(shell command -v pnpm 2>/dev/null)
CARGO_JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 1)
OFFLINE ?= 1
STRICT ?= 0
FUZZ_TARGET ?=
FUZZ_ARTIFACT ?=
FUZZ_TIME ?= 60
FUZZ_MAX_LEN ?= 65536
FUZZ_TIMEOUT ?= 30
FUZZ_RSS_LIMIT_MB ?= 2048
BENCH_FIXTURE_PROFILE ?= smoke
BENCH_FIXTURE_OUT ?= target/bench-fixtures
SLSA_ARTIFACT ?=
SLSA_PROVENANCE ?=
SLSA_EXPECTED_REPOSITORY ?=
SLSA_EXPECTED_BUILDER ?=
SLSA_EXPECTED_BUILD_TYPE ?=
SLSA_EXPECTED_WORKFLOW ?=

ifeq ($(OFFLINE),1)
CARGO_OFFLINE_FLAG := --offline
else
CARGO_OFFLINE_FLAG :=
endif

.PHONY: ci ci-local ci-strict fmt fmt-check clippy test nextest coverage coverage-html coverage-branch mutation supply-chain supply-chain-local audit deny vet unsafe-inventory sbom third-party-notices supply-chain-exceptions dependency-hygiene machete udeps bench-fixtures bench bench-ci bench-report bench-regression perf-agent-idle-memory perf-passphrase-unlock perf-recovery-envelope-unlock perf-cli-cold-start slsa-provenance fuzz-list fuzz-smoke fuzz fuzz-nightly fuzz-minimize leak-canary formal-check docs-check distribution-check app-ui-install app-ui-check app-ui-build vscode-vsix-package release-auditable release-auditable-print-deps clean
.PHONY: kani-check miri-check tauri-security-check reproducible-check

# Local default gate. It avoids network by default and skips missing optional tools
# with explicit warnings. Use `make ci-strict OFFLINE=0 STRICT=1` for release-style
# blocking checks.
ci: ci-local

ci-local: fmt-check tauri-security-check clippy test leak-canary bench-ci supply-chain-local dependency-hygiene

ci-strict: fmt-check tauri-security-check clippy test coverage coverage-branch mutation leak-canary docs-check bench-ci deny audit vet unsafe-inventory sbom dependency-hygiene slsa-provenance fuzz-smoke

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features $(CARGO_OFFLINE_FLAG) -j $(CARGO_JOBS) -- -D warnings

test:
	python3 -B scripts/mutation_smoke_test.py
	scripts/cargo-test.sh

nextest:
	scripts/cargo-test.sh nextest

coverage:
	scripts/coverage.sh line

# coverage-html renders the doublcov HTML report by default (requires npx).
# Set COVERAGE_HTML_TOOL=llvm-cov to fall back to cargo llvm-cov --html
# (no Node/npx); see docs/specs/testing.md:48.
coverage-html:
	COVERAGE_HTML_TOOL="$(COVERAGE_HTML_TOOL)" scripts/coverage.sh html

coverage-branch:
	scripts/coverage.sh branch

mutation:
	scripts/mutation-smoke.sh

supply-chain: supply-chain-local

supply-chain-local:
	scripts/supply-chain.sh local

audit:
	scripts/supply-chain.sh audit

deny:
	scripts/supply-chain.sh deny

vet:
	CARGO_VET="$(CARGO_VET)" STRICT="$(STRICT)" scripts/supply-chain.sh vet

unsafe-inventory:
	CARGO_GEIGER="$(CARGO_GEIGER)" scripts/supply-chain.sh unsafe

sbom:
	scripts/supply-chain.sh sbom

third-party-notices:
	scripts/supply-chain.sh notices

supply-chain-exceptions:
	scripts/supply-chain.sh exceptions

dependency-hygiene:
	CARGO_MACHETE="$(CARGO_MACHETE)" CARGO_UDEPS="$(CARGO_UDEPS)" STRICT="$(STRICT)" scripts/dependency-hygiene.sh local

machete:
	CARGO_MACHETE="$(CARGO_MACHETE)" STRICT="$(STRICT)" scripts/dependency-hygiene.sh machete

udeps:
	CARGO_UDEPS="$(CARGO_UDEPS)" STRICT="$(STRICT)" scripts/dependency-hygiene.sh udeps

bench-fixtures:
	scripts/bench-fixtures.mjs --profile "$(BENCH_FIXTURE_PROFILE)" --out "$(BENCH_FIXTURE_OUT)"

bench: BENCH_FIXTURE_PROFILE = release
bench: bench-fixtures
	scripts/bench-smoke.sh full

bench-ci: BENCH_FIXTURE_PROFILE = smoke
bench-ci: bench-fixtures
	scripts/bench-smoke.sh ci

# bench-report prints target/quality/bench-report.md. If no report exists,
# the script auto-runs `bench-smoke.sh ci` to produce one (set
# BENCH_REPORT_AUTORUN=0 to require `make bench-ci` instead). See
# docs/specs/performance.md:31.
bench-report:
	BENCH_REPORT_AUTORUN="$(BENCH_REPORT_AUTORUN)" scripts/bench-smoke.sh report

bench-regression:
	bash scripts/bench-regression.sh

perf-agent-idle-memory:
	scripts/perf-agent-idle-memory.sh

perf-passphrase-unlock:
	scripts/perf-passphrase-unlock.sh

perf-recovery-envelope-unlock:
	scripts/perf-recovery-envelope-unlock.sh

perf-cli-cold-start:
	bash scripts/perf-cli-cold-start.sh

slsa-provenance:
	@if [ -z "$(SLSA_ARTIFACT)" ] || [ -z "$(SLSA_PROVENANCE)" ] || [ -z "$(SLSA_EXPECTED_REPOSITORY)" ] || [ -z "$(SLSA_EXPECTED_BUILDER)" ] || [ -z "$(SLSA_EXPECTED_BUILD_TYPE)" ] || [ -z "$(SLSA_EXPECTED_WORKFLOW)" ]; then \
		if [ "$(STRICT)" = "1" ]; then \
			echo "SLSA provenance verification requires SLSA_ARTIFACT, SLSA_PROVENANCE, SLSA_EXPECTED_REPOSITORY, SLSA_EXPECTED_BUILDER, SLSA_EXPECTED_BUILD_TYPE, and SLSA_EXPECTED_WORKFLOW" >&2; \
			exit 2; \
		else \
			echo "skip: set SLSA_ARTIFACT, SLSA_PROVENANCE, SLSA_EXPECTED_REPOSITORY, SLSA_EXPECTED_BUILDER, SLSA_EXPECTED_BUILD_TYPE, and SLSA_EXPECTED_WORKFLOW"; \
		fi; \
	else \
		scripts/slsa-provenance-policy.mjs \
			--artifact "$(SLSA_ARTIFACT)" \
			--provenance "$(SLSA_PROVENANCE)" \
			--expected-repository "$(SLSA_EXPECTED_REPOSITORY)" \
			--expected-builder "$(SLSA_EXPECTED_BUILDER)" \
			--expected-build-type "$(SLSA_EXPECTED_BUILD_TYPE)" \
			--expected-workflow "$(SLSA_EXPECTED_WORKFLOW)"; \
	fi

fuzz-list:
	CARGO_FUZZ="$(CARGO_FUZZ)" scripts/fuzz-smoke.sh list

fuzz-smoke:
	CARGO_FUZZ="$(CARGO_FUZZ)" FUZZ_TIME="$(FUZZ_TIME)" FUZZ_MAX_LEN="$(FUZZ_MAX_LEN)" FUZZ_TIMEOUT="$(FUZZ_TIMEOUT)" FUZZ_RSS_LIMIT_MB="$(FUZZ_RSS_LIMIT_MB)" STRICT="$(STRICT)" scripts/fuzz-smoke.sh

fuzz:
	@test -n "$(FUZZ_TARGET)" || (echo "Set FUZZ_TARGET=<target>"; exit 2)
	CARGO_FUZZ="$(CARGO_FUZZ)" FUZZ_TARGETS="$(FUZZ_TARGET)" FUZZ_TIME="$(FUZZ_TIME)" FUZZ_MAX_LEN="$(FUZZ_MAX_LEN)" FUZZ_TIMEOUT="$(FUZZ_TIMEOUT)" FUZZ_RSS_LIMIT_MB="$(FUZZ_RSS_LIMIT_MB)" STRICT="$(STRICT)" scripts/fuzz-smoke.sh run

fuzz-nightly:
	CARGO_FUZZ="$(CARGO_FUZZ)" FUZZ_TIME=900 FUZZ_MAX_LEN="$(FUZZ_MAX_LEN)" FUZZ_TIMEOUT="$(FUZZ_TIMEOUT)" FUZZ_RSS_LIMIT_MB="$(FUZZ_RSS_LIMIT_MB)" STRICT=1 scripts/fuzz-smoke.sh nightly

fuzz-minimize:
	@test -n "$(FUZZ_TARGET)" || (echo "Set FUZZ_TARGET=<target>"; exit 2)
	@test -n "$(FUZZ_ARTIFACT)" || (echo "Set FUZZ_ARTIFACT=<path-to-crash>"; exit 2)
	CARGO_FUZZ="$(CARGO_FUZZ)" FUZZ_TARGET="$(FUZZ_TARGET)" FUZZ_ARTIFACT="$(FUZZ_ARTIFACT)" FUZZ_MAX_LEN="$(FUZZ_MAX_LEN)" FUZZ_TIMEOUT="$(FUZZ_TIMEOUT)" FUZZ_RSS_LIMIT_MB="$(FUZZ_RSS_LIMIT_MB)" scripts/fuzz-minimize.sh

leak-canary:
	scripts/leak-canary.sh

formal-check:
	scripts/formal-check.sh

kani-check miri-check:
	@if [ -f "scripts/$@.sh" ]; then \
		CARGO="$(CARGO)" STRICT="$(STRICT)" bash "scripts/$@.sh"; \
	elif [ "$(STRICT)" = "1" ]; then \
		echo "scripts/$@.sh is required for $@" >&2; exit 127; \
	else \
		echo "skip: scripts/$@.sh is unavailable"; \
	fi

docs-check:
	scripts/docs-check.mjs

distribution-check:
	scripts/validate-distribution.sh

tauri-security-check:
	node scripts/check-tauri-security.mjs

reproducible-check:
	CARGO="$(CARGO)" CARGO_JOBS="$(CARGO_JOBS)" scripts/reproducible-build-check.sh

app-ui-install:
	@if [ -z "$(PNPM)" ]; then \
		echo "skip: pnpm not on PATH"; \
	else \
		$(PNPM) --dir crates/locket-app/ui install --frozen-lockfile; \
	fi

app-ui-check: app-ui-install
	@if [ -z "$(PNPM)" ]; then \
		echo "skip: pnpm not on PATH"; \
	else \
		$(PNPM) --dir crates/locket-app/ui lint && \
		$(PNPM) --dir crates/locket-app/ui typecheck && \
		$(PNPM) --dir crates/locket-app/ui test; \
	fi

app-ui-build: app-ui-install
	@if [ -z "$(PNPM)" ]; then \
		echo "skip: pnpm not on PATH"; \
	else \
		$(PNPM) --dir crates/locket-app/ui build; \
	fi

vscode-vsix-package:
	PNPM="$(PNPM)" scripts/package-vscode-extension.sh

# release-auditable builds the shipped binaries with cargo-auditable so that
# the resolved dependency graph is embedded into each artifact, then verifies
# the embedded SBOM is readable with `cargo audit bin`. See
# scripts/release-build.sh and docs/specs/engineering.md:125.
release-auditable:
	CARGO="$(CARGO)" CARGO_AUDITABLE="$(CARGO_AUDITABLE)" CARGO_AUDIT="$(CARGO_AUDIT)" scripts/release-build.sh

release-auditable-print-deps:
	CARGO="$(CARGO)" CARGO_AUDITABLE="$(CARGO_AUDITABLE)" CARGO_AUDIT="$(CARGO_AUDIT)" scripts/release-build.sh --print-deps

clean:
	$(CARGO) clean
	rm -rf coverage target/quality
