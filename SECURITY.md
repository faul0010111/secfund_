# Security Policy

## Supported versions

| Version | Support |
|---|---|
| 1.2.x | ✅ security fixes |
| 1.1.x | ⚠️ upgrade to 1.2 (same code, English output; severity values changed) |
| 1.0.x | ❌ upgrade (includes fixes for log injection and the grade calculation) |

## How to report a vulnerability

Do not open a public issue. Use the **"Report a vulnerability"** feature in the repository's *Security* tab (GitHub Private Vulnerability Reporting) or email `your-email@example.com` with:

1. a description and the impact;
2. steps to reproduce (ideally a minimal log/file);
3. the affected version.

Commitment: acknowledgement within 7 days and a fix or mitigation plan within 30 days.

## Scope

In scope: flaws in the parsers (injection, ReDoS, DoS), in signature/hash verification, in key handling and in network input validation.
Out of scope: "incomplete" detection results (false negatives documented under *Known limitations*), and use of the tool against systems without authorization.

## Responsible use

SecFund is a **defensive** tool. The network features (`headers --url`, `tls`) must only be run against assets you own or are authorized in writing to assess.
