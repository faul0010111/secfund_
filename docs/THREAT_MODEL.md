# Threat Model — SecFund

Methodology: **STRIDE** per component, with the adopted mitigation, the test that proves it and the residual risk.
Document version: 1.2 (tracks SecFund 1.2.0).

## 1. Scope and assets

| Asset | Why it matters |
|---|---|
| Servers with exposed SSH | A common entry point for credential attacks |
| Application/configuration files | Target of web shells, backdoors and defacement |
| User credentials | Compromise leads to lateral movement |
| Web applications and TLS channels | Weak headers/ciphers amplify the impact of XSS, clickjacking and interception |
| **The tool itself** (baseline, HMAC key, reports) | If tampered with, it gives a false sense of security |

**Trust boundaries:** (1) log files, baselines and stored hashes are **untrusted input**; (2) network responses (headers, certificates, the HIBP API) are **untrusted input**; (3) the HMAC key and the command line are **trusted**.

**Attacker assumption:** controls the content of log fields (e.g., the SSH username), can modify files on the monitored host and tries to cover their tracks. Does not control the HMAC key stored off the host.

## 2. Threats and mitigations

| # | STRIDE | Threat | Mitigation | Test | Residual |
|---|---|---|---|---|---|
| 1 | Spoofing | **Log injection**: username `x from 9.9.9.9 port 1` forges the attributed IP, framing an innocent host | End-anchored regexes; greedy username group; IP validated with `ipaddress` | `test_username_cannot_forge_source_ip` | Low |
| 2 | Tampering | **Terminal injection**: ANSI/control characters in the username manipulate the analyst's screen | Sanitize non-printable characters + truncation | `test_control_characters_are_sanitized` | Low |
| 3 | Tampering | Attacker rewrites `baseline.json` after changing files | Baseline signed with HMAC-SHA256; key kept off the host | `test_tampered_baseline_detected` | Medium: without the key the baseline cannot be verified |
| 4 | Tampering | **Downgrade**: strip the signature to avoid the check | Key provided + unsigned baseline = failure (exit 4) | `test_signature_stripping_downgrade_rejected` | Low |
| 5 | Tampering | Corrupted/old-format baseline masking changes | Version/structure validation; explicit error | `test_corrupt_and_old_format_rejected` | Low |
| 6 | Info disclosure | HMAC key readable by other users | `0600` + `O_EXCL`; CLI warning on loose permissions | `TestKeys`, `TestKeyPermissionWarning` | Medium: depends on operator hygiene |
| 7 | Info disclosure | Password in shell history / `ps` | `getpass` by default; `--password` documented as insecure | — | Medium if the operator ignores the warning |
| 8 | Info disclosure | Sending the password to an external service during a breach check | k-anonymity: only 5 chars of the SHA-1; 100% offline mode available | `test_k_anonymity_only_sends_five_chars` | Low |
| 9 | Info disclosure | Weak hash enables offline cracking | scrypt (N=2^17) by default; PBKDF2 ≥ 600k; unique salt; NFKC | `TestHashing` | Low |
| 10 | Denial of service | **Forged hash** with absurd cost (`n=2^30`, huge iteration counts) stalls verification | Limits on `n`, `r`, `p`, iterations and digest size before computing | `test_hostile_parameters_rejected_*` | Low |
| 11 | Denial of service | Huge lines / huge log exhaust CPU or memory | 2048-char line cap; streaming reads | `test_overlong_line_discarded`, `test_log_file_is_streamed_not_loaded` | Medium: events still held in memory |
| 12 | Denial of service | Oversized HIBP response | Read capped at 4 MB; timeout | — | Low |
| 13 | Elevation / SSRF | `--url` pointing at `file://` or exotic schemes | `http`/`https` only | `test_rejects_non_http_scheme` | Medium if exposed as a service (internal network reachable) |
| 14 | Tampering | Symlink points outside the monitored directory | `followlinks=False`; symlinks skipped | `test_symlinks_are_not_followed` | Low |
| 15 | Spoofing | Slow distributed attack evades per-IP thresholds | Per-user detection (many IPs) | `test_detects_distributed_attack` | Medium: fixed window; "low and slow" attacks pass |
| 16 | Repudiation | Findings without a trail / hard to integrate | Deterministic output, JSON/SARIF, exit codes | `TestExporters` | Low |
| 17 | Spoofing | MITM during the TLS audit (client accepting an invalid certificate) | Default validation; the unvalidated connection only reads protocol/cipher and **sends no data** | `test_self_signed_is_flagged_*` | Low |
| 18 | Tampering | CI / dependency compromise | Zero runtime deps; least-privilege permissions; Dependabot; CodeQL | — | Medium: actions pinned by tag, not by SHA |

## 3. Technique coverage (MITRE ATT&CK)

| Technique | Module |
|---|---|
| T1110.001 Password Guessing · T1110.003 Password Spraying | `logs` |
| T1078 Valid Accounts (login accepted after failures) | `logs` |
| T1565 Data Manipulation · T1505.003 Web Shell (new file) | `fim` |
| T1070 Indicator Removal (removed file) · T1222 File Permissions | `fim` |
| T1557 Adversary-in-the-Middle (HSTS/TLS) | `headers`, `tls` |
| T1189 Drive-by Compromise (mitigated by CSP) | `headers` |

| Framework | Items |
|---|---|
| OWASP Top 10 2021 | A02 Cryptographic Failures · A05 Security Misconfiguration · A07 Identification & Authentication Failures · A08 Software & Data Integrity Failures |
| NIST SP 800-63B | Length, common/breached-password blocking, Unicode normalization, slow hashing |
| CIS Controls v8 | 3 (Data) · 5 (Accounts) · 8 (Audit logs) · 16 (Application security) |

## 4. Out of scope

Real-time detection, multi-host correlation (SIEM), malware analysis, automated response (IP blocking), active cipher/protocol scanning and penetration testing.
