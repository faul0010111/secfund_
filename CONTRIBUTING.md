# Contributing

1. Fork the repository and create one branch per change.
2. Install the dev tooling: `make install`.
3. Before opening a PR, run `make all` (lint, types, SAST and tests with coverage ≥ 90%).
4. Every security fix must come with a **test that fails without it**.

## Project rules

- **No runtime dependencies.** If something needs one, open a discussion first (see ADR-1).
- **External input is hostile:** validate it, bound its size and never use `eval`/`exec`/`shell=True`.
- Code, messages and documentation are in English (see ADR-7).
- New detection rules need: an ID `SF-<MODULE>-NNN` in `report.RULES`, a MITRE/OWASP technique, a remediation and a test.
