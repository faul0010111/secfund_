"""Detection of brute force, password spraying and distributed attacks in SSH logs.

MITRE ATT&CK mapping: T1110.001 (Password Guessing), T1110.003 (Password Spraying),
T1078 (Valid Accounts, when a login is accepted right after the failures).

The log is treated as UNTRUSTED input (the attacker controls the username):
  * the regexes are anchored at the end of the line and the username group is greedy, so a name
    such as ``x from 9.9.9.9 port 1`` cannot forge the IP attributed to the event (which would
    frame an innocent IP and trigger wrongful blocks);
  * the IP is validated with ``ipaddress`` and the username is sanitized (no control/ANSI
    characters that could manipulate the analyst's terminal) and truncated;
  * very long lines are discarded, bounding the cost of the regexes.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .report import Issue

MAX_LINE = 2048
MAX_USER_LEN = 64

KIND_BRUTE = "Brute force"
KIND_SPRAY = "Password spraying"
KIND_DISTRIBUTED = "Distributed attack"
_RULE_BY_KIND = {KIND_BRUTE: "SF-LOGS-001", KIND_SPRAY: "SF-LOGS-002", KIND_DISTRIBUTED: "SF-LOGS-003"}

# Accepts traditional syslog ("Oct 17 21:53:01") and rsyslog ISO 8601; sshd and sshd-session (OpenSSH >= 9.8).
_PROC = r"\S+\s+sshd(?:-session)?\[\d+\]:\s+(?P<msg>.*)"
LINE_SYSLOG = re.compile(rf"^(?P<ts>[A-Z][a-z]{{2}}\s+\d{{1,2}}\s\d{{2}}:\d{{2}}:\d{{2}})\s+{_PROC}$")
LINE_ISO = re.compile(
    rf"^(?P<ts>\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?(?:Z|[+-]\d{{2}}:\d{{2}})?)\s+{_PROC}$"
)
FAILED_RE = re.compile(
    r"^Failed (?:password|keyboard-interactive/pam) for (?:invalid user )?(?P<user>.+) "
    r"from (?P<ip>\S+) port \d+(?: ssh\d)?\s*$"
)
ACCEPTED_RE = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>.+) "
    r"from (?P<ip>\S+) port \d+(?: ssh\d)?(?::.*)?\s*$"
)


@dataclass
class Event:
    ts: datetime
    ip: str
    user: str
    kind: str  # "failed" | "accepted"
    line: int = 0


@dataclass
class Finding:
    ip: str
    severity: str
    kind: str
    attempts: int
    users: list[str] = field(default_factory=list)
    compromised: bool = False
    technique: str = "T1110.001"
    sources: list[str] = field(default_factory=list)
    line: int = 0

    @property
    def rule_id(self) -> str:
        return _RULE_BY_KIND[self.kind]

    def __str__(self) -> str:
        flag = " [POSSIBLE COMPROMISE: login accepted after the failures]" if self.compromised else ""
        return (
            f"[{self.severity}] {self.kind} from {self.ip}: {self.attempts} failures, "
            f"{len(self.users)} user(s) ({self.technique}){flag}"
        )


def _clean(text: str, limit: int = MAX_USER_LEN) -> str:
    safe = "".join(c if c.isprintable() else "?" for c in text)
    return safe if len(safe) <= limit else safe[:limit] + "..."


def parse_line(line: str, year: int, lineno: int = 0) -> Event | None:
    line = line.rstrip("\r\n")
    if len(line) > MAX_LINE:
        return None
    m = LINE_SYSLOG.match(line)
    if m:
        try:
            ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    else:
        m = LINE_ISO.match(line)
        if not m:
            return None
        try:
            ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    msg = m["msg"]
    for regex, kind in ((FAILED_RE, "failed"), (ACCEPTED_RE, "accepted")):
        g = regex.match(msg)
        if g:
            try:
                ip = str(ipaddress.ip_address(g["ip"]))
            except ValueError:
                return None
            return Event(ts, ip, _clean(g["user"]), kind, lineno)
    return None


def parse_log(lines: Iterable[str], year: int | None = None) -> list[Event]:
    """Reads the log as a stream (lines are not kept in memory, only the relevant events)."""
    year = year or datetime.now().year
    events = [e for n, line in enumerate(lines, 1) if (e := parse_line(line, year, n))]
    events.sort(key=lambda e: e.ts)
    return events


def analyze(
    events: list[Event],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
    *,
    spray_users: int = 4,
    distributed_ips: int = 5,
    allowlist: Iterable[str] = (),
) -> list[Finding]:
    """Sliding window per IP (brute force/spraying) and per user (distributed attack).

    ``allowlist`` accepts IPs or CIDRs to ignore (e.g., internal vulnerability scanners).
    """
    nets = [ipaddress.ip_network(n, strict=False) for n in allowlist]

    def allowed(ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in nets)

    events = sorted(events, key=lambda e: e.ts)
    findings: list[Finding] = []

    # --- Per IP ---------------------------------------------------------------------------
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if not allowed(e.ip):
            by_ip[e.ip].append(e)

    for ip, evs in by_ip.items():
        fails = [e for e in evs if e.kind == "failed"]
        best: list[Event] = []
        start = 0
        for end in range(len(fails)):
            while fails[end].ts - fails[start].ts > window:
                start += 1
            if end - start + 1 > len(best):
                best = fails[start : end + 1]
        if len(best) < threshold:
            continue

        users = sorted({e.user for e in best})
        spraying = len(users) >= spray_users
        kind = KIND_SPRAY if spraying else KIND_BRUTE
        compromised = any(e.kind == "accepted" and best[0].ts <= e.ts <= best[-1].ts + window for e in evs)
        severity = "CRITICAL" if compromised else "HIGH" if len(best) >= threshold * 3 else "MEDIUM"
        findings.append(
            Finding(
                ip, severity, kind, len(best), users, compromised,
                "T1110.003" if spraying else "T1110.001", [ip], best[0].line,
            )
        )  # fmt: skip

    # --- Per user: many different IPs against the same account ----------------------------------
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "failed" and not allowed(e.ip):
            by_user[e.user].append(e)

    for user, fails in by_user.items():
        seen: Counter[str] = Counter()
        best_win: list[Event] = []
        best_ips = 0
        start = 0
        for end, ev in enumerate(fails):
            seen[ev.ip] += 1
            while ev.ts - fails[start].ts > window:
                old = fails[start].ip
                seen[old] -= 1
                if seen[old] == 0:
                    del seen[old]
                start += 1
            if len(seen) > best_ips or (len(seen) == best_ips and end - start + 1 > len(best_win)):
                best_ips, best_win = len(seen), fails[start : end + 1]
        if best_ips < distributed_ips or len(best_win) < threshold:
            continue
        sources = sorted({e.ip for e in best_win})
        accepted = any(
            e.kind == "accepted" and e.user == user and e.ip in sources
            and best_win[0].ts <= e.ts <= best_win[-1].ts + window
            for e in events
        )  # fmt: skip
        findings.append(
            Finding(
                f"{len(sources)} distinct IPs", "CRITICAL" if accepted else "HIGH", KIND_DISTRIBUTED,
                len(best_win), [user], accepted, "T1110.001", sources, best_win[0].line,
            )
        )  # fmt: skip

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    return sorted(findings, key=lambda f: (order[f.severity], -f.attempts))


def to_issues(findings: list[Finding], location: str = "") -> list[Issue]:
    issues: list[Issue] = []
    for f in findings:
        if f.compromised:
            fix = (
                "Treat as an incident: revoke sessions, rotate credentials, check for persistence "
                "(authorized_keys, cron, new users) and block the source."
            )
        else:
            fix = "Block the source (fail2ban/firewall), disable password and root login, require SSH keys or MFA."
        detail = f"{f.attempts} failures; users: {', '.join(f.users[:8])}; sources: {', '.join(f.sources[:8])}" + (
            "; login accepted after the failures" if f.compromised else ""
        )
        issues.append(
            Issue(f.rule_id, "logs", f.severity, f"{f.kind} from {f.ip}", detail, location, f.line, f.technique, fix)
        )
    return issues
