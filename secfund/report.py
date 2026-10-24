"""Unified findings model and exporters (JSON and SARIF 2.1.0).

SARIF is the industry-standard format for security analysis results: it can be uploaded to
GitHub Code Scanning (Security tab) and consumed by IDEs and CI pipelines.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from . import __version__

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
FAIL_LEVELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}

_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
# "security-severity" scale (0-10) used by GitHub to rank alerts.
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}

RULES: dict[str, str] = {
    "SF-LOGS-001": "SSH brute force: many failed authentications from a single IP",
    "SF-LOGS-002": "SSH password spraying: few attempts per account across many accounts from one IP",
    "SF-LOGS-003": "Distributed brute force: many IPs attacking the same account",
    "SF-FIM-001": "Monitored file was modified",
    "SF-FIM-002": "New file appeared in a monitored directory",
    "SF-FIM-003": "Monitored file was removed",
    "SF-FIM-004": "Monitored file permissions changed",
    "SF-HDR-001": "Missing HTTP security header",
    "SF-HDR-002": "Misconfigured HTTP security header",
    "SF-HDR-003": "Cookie without security attributes (Secure/HttpOnly/SameSite)",
    "SF-HDR-004": "Server technology or version disclosure",
    "SF-TLS-001": "Invalid or untrusted TLS certificate",
    "SF-TLS-002": "Expired or soon-to-expire TLS certificate",
    "SF-TLS-003": "Obsolete TLS protocol or failed handshake",
    "SF-TLS-004": "Weak cipher suite",
}


@dataclass(frozen=True)
class Issue:
    """Normalized finding, independent of the module that produced it."""

    rule_id: str
    module: str
    severity: str
    title: str
    detail: str = ""
    location: str = ""
    line: int = 0
    technique: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")


def summarize(issues: Iterable[Issue]) -> dict[str, int]:
    counts = Counter(i.severity for i in issues)
    return {s: counts.get(s, 0) for s in SEVERITIES}


def exit_code(issues: Iterable[Issue], fail_on: str = "low") -> int:
    """0 = nothing at the requested level; 1 = findings; 2 = CRITICAL finding. Useful as a CI gate."""
    if fail_on == "never":
        return 0
    limit = SEVERITIES.index(FAIL_LEVELS[fail_on])
    hits = [i for i in issues if SEVERITIES.index(i.severity) <= limit]
    if not hits:
        return 0
    return 2 if any(i.severity == "CRITICAL" for i in hits) else 1


def to_json(issues: list[Issue]) -> str:
    doc = {
        "tool": {"name": "secfund", "version": __version__},
        "summary": summarize(issues),
        "issues": [asdict(i) for i in issues],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def to_sarif(issues: list[Issue]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for i in issues:
        if i.rule_id not in rules:
            description = RULES.get(i.rule_id, i.rule_id)
            rules[i.rule_id] = {
                "id": i.rule_id,
                "name": i.rule_id.replace("-", ""),
                "shortDescription": {"text": description},
                "help": {"text": description},  # generic; the specific remediation goes in each result
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[i.severity],
                    "tags": ["security", i.module] + ([i.technique] if i.technique else []),
                },
            }
        uri = (i.location or "N/A").replace("\\", "/")
        message = " ".join(part for part in (f"{i.title}.", i.detail, i.remediation) if part).strip()
        results.append(
            {
                "ruleId": i.rule_id,
                "level": _SARIF_LEVEL[i.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": max(i.line, 1)},  # GitHub requires startLine >= 1
                        }
                    }
                ],
                "properties": {"severity": i.severity, "technique": i.technique, "remediation": i.remediation},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "SecFund", "version": __version__, "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
