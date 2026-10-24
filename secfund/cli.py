"""SecFund CLI. Usage: python -m secfund <command> ...

Exit codes: 0 = clean | 1 = findings | 2 = CRITICAL finding | 3 = usage/I-O error | 4 = tampered baseline.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__, fim, headers, logs, passwords, report, tls


def _emit(a: argparse.Namespace, issues: list[report.Issue], text: str) -> int:
    if a.format == "json":
        payload = report.to_json(issues)
    elif a.format == "sarif":
        payload = report.to_sarif(issues)
    else:
        payload = text
    if a.output:
        Path(a.output).write_text(payload + "\n", encoding="utf-8")
        print(f"Report saved to {a.output}", file=sys.stderr)
    else:
        print(payload)
    return report.exit_code(issues, a.fail_on)


def _key(a: argparse.Namespace) -> bytes | None:
    if getattr(a, "key_file", None):
        path = Path(a.key_file)
        if os.name == "posix" and path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(f"Warning: {path} is accessible by other users; use chmod 600.", file=sys.stderr)
        return fim.load_key_file(path)
    env = os.environ.get("SECFUND_KEY")
    return fim.parse_key(env) if env else None


# --- Commands ------------------------------------------------------------------------------


def cmd_logs(a: argparse.Namespace) -> int:
    path = Path(a.file)
    with path.open(encoding="utf-8", errors="replace") as fh:
        events = logs.parse_log(fh, year=a.year)
    findings = logs.analyze(
        events, a.threshold, timedelta(minutes=a.window), distributed_ips=a.distributed_ips, allowlist=a.allow_ip
    )
    lines = [f"{len(events)} events analyzed | threshold={a.threshold} failures/{a.window}min", ""]
    if not findings:
        lines.append("No suspicious activity found.")
    for f in findings:
        lines.append(str(f))
        lines.append(f"    target users: {', '.join(f.users[:8])}")
        if len(f.sources) > 1:
            lines.append(f"    sources: {', '.join(f.sources[:8])}")
    if findings:
        lines += [
            "",
            "Recommendations: block sources (fail2ban/firewall), require SSH keys, disable root and password login.",
        ]
    return _emit(a, logs.to_issues(findings, str(path)), "\n".join(lines))


def cmd_fim(a: argparse.Namespace) -> int:
    if a.action == "keygen":
        if not a.key_file:
            raise ValueError("keygen requires --key-file <destination>")
        fim.generate_key_file(a.key_file)
        print(f"Key created at {a.key_file} (store it OUTSIDE the monitored host).")
        return 0
    if not a.path:
        raise ValueError(f"'fim {a.action}' requires the directory to monitor")
    key = _key(a)
    if a.action == "init":
        n = fim.save_baseline(a.path, a.baseline, key, a.exclude)
        mode = "signed with HMAC-SHA256" if key else "UNSIGNED (use --key-file to detect tampering)"
        print(f"Baseline created: {n} files -> {a.baseline} ({mode})")
        return 0
    diff = fim.verify(a.path, a.baseline, key, a.exclude)
    issues = fim.to_issues(diff, a.path)
    lines = [f"[{label}] {Path(a.path, rel).as_posix()}" for key_, label in fim.LABELS.items() for rel in diff[key_]]
    lines.append("Integrity OK." if not issues else f"\n{len(issues)} change(s) detected.")
    return _emit(a, issues, "\n".join(lines))


def cmd_password(a: argparse.Namespace) -> int:
    if a.verify:
        pw = a.password or getpass.getpass("Password: ")
        ok = passwords.verify_password(pw, a.verify)
        print("Password matches." if ok else "Password does NOT match.")
        if ok and passwords.needs_rehash(a.verify, a.algo):
            print("Warning: hash uses an outdated algorithm/parameters; rehash at the next login.")
        return 0 if ok else 1

    if a.generate:
        pw = passwords.generate_password(a.length)
        print(f"Generated password: {pw}")
    else:
        pw = a.password or getpass.getpass("Password (input is hidden): ")

    pwned: int | None = None
    if a.pwned_file:
        pwned = passwords.pwned_count_file(pw, a.pwned_file)
    elif a.pwned:
        print("Querying HIBP via k-anonymity (only 5 characters of the SHA-1 leave this machine)...")
        pwned = passwords.pwned_count_range(pw, passwords.fetch_range_online)

    r = passwords.audit_password(pw, pwned)
    print(f"Verdict: {r.verdict} | score {r.score}/100 | ~{r.entropy_bits} bits (upper bound)")
    for issue in r.issues:
        print(f" - {issue}")
    if a.hash:
        print(f"\n{a.algo} hash (store THIS, never the password):")
        print(passwords.hash_password(pw, a.algo))
    return 0 if r.verdict != "WEAK" else 1


def cmd_headers(a: argparse.Namespace) -> int:
    if a.json_file:
        hdrs = json.loads(Path(a.json_file).read_text(encoding="utf-8"))
        where = a.json_file
    else:
        hdrs = headers.fetch_headers(a.url)
        where = a.url
    results, pct, letter = headers.analyze_headers(hdrs)
    lines = [f"[{r.status:<7}] {r.header}: {r.detail}" for r in results]
    lines.append(f"\nGrade: {letter} ({pct}%)")
    return _emit(a, headers.to_issues(results, where), "\n".join(lines))


def cmd_tls(a: argparse.Namespace) -> int:
    target = urlsplit(a.target if "//" in a.target else f"//{a.target}")
    if not target.hostname:
        raise ValueError("invalid target (use host, host:port or https://host)")
    info = tls.fetch_tls(target.hostname, target.port or 443, a.timeout)
    issues = tls.evaluate(info)
    expires = info.not_after.date().isoformat() if info.not_after else "n/a"
    lines = [
        f"Target:      {info.host}:{info.port}",
        f"Protocol:    {info.protocol or 'n/a'}",
        f"Cipher:      {info.cipher or 'n/a'} ({info.cipher_bits} bits)",
        f"Certificate: CN={info.subject or 'n/a'} | issuer={info.issuer or 'n/a'} | expires {expires}",
        f"Chain/hostname: {'valid' if info.verified else 'INVALID (' + info.verify_error + ')'}",
        "",
    ]
    lines += [f"[{i.severity}] {i.title}" for i in issues] or ["No issues found."]
    return _emit(a, issues, "\n".join(lines))


# --- Parser --------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    out = argparse.ArgumentParser(add_help=False)
    out.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="report format")
    out.add_argument("--output", "-o", help="write the report to this file")
    out.add_argument(
        "--fail-on", choices=[*report.FAIL_LEVELS, "never"], default="low",
        help="minimum severity that makes the command exit non-zero (CI gate)",
    )  # fmt: skip

    p = argparse.ArgumentParser(prog="secfund", description="Defensive cybersecurity fundamentals toolkit.")
    p.add_argument("--version", action="version", version=f"secfund {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("logs", parents=[out], help="Detect brute force/spraying/distributed attacks in SSH logs")
    s.add_argument("file")
    s.add_argument("--threshold", type=int, default=5, help="failures within the window that trigger an alert")
    s.add_argument("--window", type=int, default=5, help="window in minutes")
    s.add_argument("--distributed-ips", type=int, default=5, help="distinct IPs against the same account")
    s.add_argument("--allow-ip", action="append", default=[], metavar="CIDR", help="ignore IP/CIDR (repeatable)")
    s.add_argument("--year", type=int, default=None, help="log year (syslog timestamps carry no year)")
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("fim", parents=[out], help="File integrity monitor (signed baseline)")
    s.add_argument("action", choices=["init", "check", "keygen"])
    s.add_argument("path", nargs="?")
    s.add_argument("--baseline", default="baseline.json")
    s.add_argument("--key-file", help="HMAC key in hex (or SECFUND_KEY env var); for keygen, the destination")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="ignore files (repeatable)")
    s.set_defaults(func=cmd_fim)

    s = sub.add_parser("password", help="Audit, generate, hash and verify passwords")
    s.add_argument("--password", help="(avoid: it shows up in your shell history)")
    s.add_argument("--generate", action="store_true", help="generate a secure random password")
    s.add_argument("--length", type=int, default=20)
    s.add_argument("--hash", action="store_true", help="print the hash for storage")
    s.add_argument("--algo", choices=["scrypt", "pbkdf2"], default="scrypt")
    s.add_argument("--verify", metavar="HASH", help="check the password against a stored hash")
    s.add_argument("--pwned", action="store_true", help="query HIBP (k-anonymity)")
    s.add_argument("--pwned-file", help="offline check against a SHA-1 HASH:COUNT file")
    s.set_defaults(func=cmd_password)

    s = sub.add_parser("headers", parents=[out], help="Analyze HTTP security headers")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="only sites you own or are authorized to assess")
    g.add_argument("--json-file", help="headers saved as JSON (offline)")
    s.set_defaults(func=cmd_headers)

    s = sub.add_parser("tls", parents=[out], help="Audit a host's TLS certificate and protocol")
    s.add_argument("target", help="host, host:port or https://host (authorized hosts only)")
    s.add_argument("--timeout", type=float, default=10.0)
    s.set_defaults(func=cmd_tls)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(errors="replace")  # non-UTF-8 consoles must not crash the CLI
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except fim.BaselineError as e:
        print(f"INTEGRITY ALERT: {e}", file=sys.stderr)
        return 4
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
