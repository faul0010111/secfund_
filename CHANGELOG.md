# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0] — 2026-10-24

### Changed
- **The whole project is now in English**: CLI messages and help, reports, docstrings, tests and documentation.
- **BREAKING (output values):** severities are now `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` (were `CRITICO`/`ALTO`/`MEDIO`/`BAIXO`); header statuses are `OK`/`MISSING`/`WEAK` (were `OK`/`AUSENTE`/`FRACO`); password verdicts are `STRONG`/`MEDIUM`/`WEAK` (were `FORTE`/`MÉDIA`/`FRACA`); `logs` kinds are `Brute force`/`Password spraying`/`Distributed attack`. JSON/SARIF consumers that filter on these values must be updated. Rule IDs, MITRE/OWASP references, field names and exit codes are unchanged.
- `fim check` labels are now `MODIFIED`/`NEW`/`REMOVED`/`PERMISSIONS`; the baseline format is unchanged.
- The `headers --url` User-Agent now reports the real package version.

## [1.1.0] — 2026-10-18

### Added
- **`tls` module**: certificate validity/chain/hostname, expiration, negotiated protocol and cipher.
- **JSON and SARIF 2.1.0 reports** for every module, plus `--output` and `--fail-on` (CI gate).
- `logs`: **distributed attack** detection, CIDR allowlist, IPv6, ISO 8601 timestamps, `sshd-session`.
- `fim`: **HMAC-SHA256 signed baseline**, `keygen` command, `--exclude`, atomic writes, tolerance for unreadable files.
- `password`: **scrypt** hashing (default), `--verify`, `needs_rehash`, `--generate`, breach checking via **k-anonymity** or an offline file, *leetspeak* variant detection, Unicode normalization.
- `headers`: **cookie flag** analysis and `Cross-Origin-Opener-Policy`.
- Packaging (`pyproject.toml`, `secfund` command), CI, CodeQL, Dependabot, Makefile, `py.typed`.
- 126 tests (97% coverage), `ruff`, `mypy --strict`, `bandit`.

### Security
- `logs`: protection against **log injection** (IP forging and terminal injection), oversized lines are discarded.
- `fim`: detection of **signature stripping** (downgrade) and tampered baselines (exit 4).
- `password`: cost parameters of a stored hash are validated before any computation (prevents DoS).

### Fixed
- `headers`: the grade's denominator changed with item status, so fixing a problem could lower the grade.
- `headers`: multiple `Set-Cookie` headers were overwritten when fetched over the network.
- `logs`: a login accepted *before* the failures was flagged as a compromise.

### Changed
- FIM baseline format (v2); 1.0 baselines must be recreated.
- `hash_password` now takes `algorithm`; the default changed from PBKDF2 to scrypt.

## [1.0.0] — 2026-10-17
- Initial release: `logs`, `fim`, `password` and `headers`.
