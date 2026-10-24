# Architecture Decision Records (ADRs)

A short log of the decisions that shaped SecFund: context, decision and consequences.

## ADR-1 — Standard library only (zero runtime dependencies)

**Context.** Security tools are targets of *supply-chain attacks*; every dependency widens the surface to audit.
**Decision.** All runtime code uses only the stdlib (`hashlib`, `hmac`, `ssl`, `ipaddress`, `secrets`, `argparse`...). Quality tooling lives in `[dev]`.
**Consequences.** (+) Trivial to audit, instant install, nothing for Dependabot to update in production. (−) No Argon2id (not in the stdlib) and no certificate parsing beyond what `ssl` exposes.

## ADR-2 — scrypt as the default hash; PBKDF2 as an option

**Context.** OWASP recommends Argon2id, then scrypt; PBKDF2 only when FIPS-140 is required.
**Decision.** `scrypt` (N=2^17, r=8, p=1) by default via `hashlib.scrypt`; `pbkdf2` (≥ 600,000 iterations) available. Self-describing format (`scrypt$n$r$p$salt$hash`) and `needs_rehash()` to migrate parameters at login.
**Consequences.** (+) GPU/ASIC resistance with the stdlib. (−) ~128 MB of memory per hash: the parameter limits at verification time (ADR-4) stop that from becoming a DoS vector. Teams that can add dependencies should prefer Argon2id.

## ADR-3 — HMAC-signed FIM baseline, with downgrade protection

**Context.** A plain-text baseline does not protect against an attacker who already modifies files on the host: they simply recompute the baseline.
**Decision.** HMAC-SHA256 over a canonical serialization; external key (a `0600` file or `SECFUND_KEY`). If a key is provided and there is **no signature**, verification fails.
**Consequences.** (+) Tampering and signature stripping are detected (exit 4). (−) Security now depends on key custody; HMAC (symmetric) requires the key at the verifier. Possible evolution: asymmetric signatures (Ed25519), which are not in the stdlib.

## ADR-4 — All external data is hostile

**Context.** Logs contain attacker-controlled fields; hashes and baselines come from storage that may be compromised.
**Decision.** Anchored and validated parsers (`ipaddress`, size limits), terminal-output sanitization, hash cost parameters bounded *before* any computation, network reads with byte limits and timeouts.
**Consequences.** (+) Closes entire bug classes (IP forging, terminal injection, parameter-based DoS). (−) Some very unusual legitimate lines may be dropped (documented).

## ADR-5 — Unified `Issue` model + SARIF as the interoperability format

**Context.** Each module produced a different output, hard to integrate with CI and dashboards.
**Decision.** Every module converts its results to `Issue` (rule, severity, location, MITRE/OWASP technique, remediation). `report.py` exports text, JSON and **SARIF 2.1.0**; `--fail-on` turns severity into an exit code.
**Consequences.** (+) A single output contract, direct integration with GitHub Code Scanning and pipelines. (−) SARIF requires a "location" even for findings that are not files (URL, host:port), so the target is used as the URI.

## ADR-6 — Header grade with constant weights

**Context.** In version 1.0 an item's weight changed with its status (e.g., a weak CSP was worth 12, a correct one 25), so the grade's denominator varied and fixing a problem could **lower** the grade.
**Decision.** Each item has a fixed maximum weight; OK earns 100%, WEAK 50%, MISSING 0%.
**Consequences.** (+) The grade is monotonic, proven by `test_grade_is_monotonic`. (−) 1.0 grades are not directly comparable with 1.1+.

## ADR-7 — English as the project language

**Context.** The first releases were written in Portuguese; the project is meant to be read by an international audience (recruiters, contributors, security tooling).
**Decision.** Code, messages, severities, reports, tests and documentation are all in English. Rule IDs, MITRE/OWASP references and SARIF fields are language-neutral.
**Consequences.** (+) Wider audience; consistent vocabulary across JSON/SARIF consumers. (−) Breaking change in output values (`CRITICO` → `CRITICAL`, etc.), documented in the changelog as 1.2.0.
