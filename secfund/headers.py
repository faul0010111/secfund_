"""HTTP security header analyzer (OWASP Secure Headers Project).

Defensive use: only analyze sites you own or are authorized to assess.
Mapping: OWASP Top 10 A05:2021 (Security Misconfiguration).
"""

from __future__ import annotations

import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass

from . import __version__
from .report import Issue

HeaderValue = str | list[str]


@dataclass
class HeaderResult:
    header: str
    status: str  # OK | MISSING | WEAK
    detail: str
    weight: int  # MAXIMUM weight of the item in the grade (constant, independent of status)


# header -> (severity, technique, remediation)
_META: dict[str, tuple[str, str, str]] = {
    "Strict-Transport-Security": (
        "MEDIUM", "OWASP A05:2021 / T1557",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "Content-Security-Policy": (
        "MEDIUM", "OWASP A05:2021 / A03:2021", "Define a restrictive CSP (default-src 'self') without unsafe-inline.",
    ),
    "Anti-clickjacking": (
        "MEDIUM", "OWASP A05:2021 / T1185", "Use CSP frame-ancestors 'none' or 'X-Frame-Options: DENY'.",
    ),
    "X-Content-Type-Options": ("LOW", "OWASP A05:2021", "Send 'X-Content-Type-Options: nosniff'."),
    "Referrer-Policy": ("LOW", "OWASP A05:2021", "Send 'Referrer-Policy: strict-origin-when-cross-origin'."),
    "Permissions-Policy": ("LOW", "OWASP A05:2021", "Restrict browser APIs (e.g., 'geolocation=()')."),
    "Cross-Origin-Opener-Policy": ("LOW", "OWASP A05:2021", "Send 'Cross-Origin-Opener-Policy: same-origin'."),
    "Set-Cookie": (
        "MEDIUM", "OWASP A05:2021 / A07:2021", "Mark session cookies with Secure; HttpOnly; SameSite=Lax/Strict.",
    ),
    "Server": ("LOW", "OWASP A05:2021", "Hide the server version (ServerTokens Prod / server_tokens off)."),
    "X-Powered-By": ("LOW", "OWASP A05:2021", "Remove the X-Powered-By header."),
}  # fmt: skip


def _first(value: HeaderValue | None) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return value[0] if value else ""
    return value


def _check(headers: Mapping[str, HeaderValue]) -> list[HeaderResult]:
    h = {k.lower(): v for k, v in headers.items()}
    out: list[HeaderResult] = []

    hsts = _first(h.get("strict-transport-security"))
    if not hsts:
        out.append(
            HeaderResult("Strict-Transport-Security", "MISSING", "No HSTS: risk of downgrade/SSL stripping.", 20)
        )
    else:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0])
        except (IndexError, ValueError):
            age = 0
        if age < 15552000:
            out.append(HeaderResult("Strict-Transport-Security", "WEAK", f"max-age={age} (< 6 months).", 20))
        else:
            out.append(HeaderResult("Strict-Transport-Security", "OK", hsts, 20))

    csp = _first(h.get("content-security-policy"))
    if not csp:
        out.append(HeaderResult("Content-Security-Policy", "MISSING", "No CSP: XSS impact is higher.", 25))
    elif "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp.split():
        out.append(HeaderResult("Content-Security-Policy", "WEAK", "Uses unsafe-inline/unsafe-eval/wildcard.", 25))
    else:
        out.append(HeaderResult("Content-Security-Policy", "OK", "Restrictive policy.", 25))

    xfo = _first(h.get("x-frame-options"))
    if "frame-ancestors" in csp or xfo.upper() in ("DENY", "SAMEORIGIN"):
        out.append(HeaderResult("Anti-clickjacking", "OK", "frame-ancestors or X-Frame-Options present.", 15))
    else:
        out.append(HeaderResult("Anti-clickjacking", "MISSING", "Clickjacking risk.", 15))

    if _first(h.get("x-content-type-options")).lower() == "nosniff":
        out.append(HeaderResult("X-Content-Type-Options", "OK", "nosniff", 10))
    else:
        out.append(HeaderResult("X-Content-Type-Options", "MISSING", "Allows MIME sniffing.", 10))

    referrer = _first(h.get("referrer-policy"))
    if referrer:
        out.append(HeaderResult("Referrer-Policy", "OK", referrer, 10))
    else:
        out.append(HeaderResult("Referrer-Policy", "MISSING", "URL leakage via the Referer header.", 10))

    if h.get("permissions-policy"):
        out.append(HeaderResult("Permissions-Policy", "OK", "Defined.", 5))
    else:
        out.append(HeaderResult("Permissions-Policy", "MISSING", "Browser APIs unrestricted.", 5))

    if h.get("cross-origin-opener-policy"):
        coop = _first(h["cross-origin-opener-policy"])
        out.append(HeaderResult("Cross-Origin-Opener-Policy", "OK", coop, 5))
    else:
        out.append(HeaderResult("Cross-Origin-Opener-Policy", "MISSING", "No window isolation (XS-Leaks).", 5))

    raw_cookies = h.get("set-cookie")
    if raw_cookies:
        cookies = [raw_cookies] if isinstance(raw_cookies, str) else raw_cookies
        weak: list[str] = []
        for cookie in cookies:
            parts = [p.strip() for p in cookie.split(";")]
            attrs = {p.split("=", 1)[0].lower() for p in parts[1:]}
            required = (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
            missing = [label for label, key in required if key not in attrs]
            if missing:
                weak.append(f"{parts[0].split('=', 1)[0] or '?'}: missing {', '.join(missing)}")
        if weak:
            out.append(HeaderResult("Set-Cookie", "WEAK", "; ".join(weak), 10))
        else:
            out.append(HeaderResult("Set-Cookie", "OK", f"{len(cookies)} cookie(s) with security attributes.", 10))

    server = _first(h.get("server"))
    if server and any(c.isdigit() for c in server):
        out.append(HeaderResult("Server", "WEAK", f"Exposes version: {server}", 5))
    else:
        out.append(HeaderResult("Server", "OK", "No version exposed.", 5))
    if h.get("x-powered-by"):
        out.append(HeaderResult("X-Powered-By", "WEAK", f"Exposes technology: {_first(h['x-powered-by'])}", 0))
    return out


def grade(results: list[HeaderResult]) -> tuple[int, str]:
    """Grade 0-100: OK earns the full weight, WEAK half, MISSING zero. X-Powered-By is not scored."""
    scored = [r for r in results if r.weight > 0]
    total = sum(r.weight for r in scored)
    earned = sum(r.weight if r.status == "OK" else r.weight / 2 if r.status == "WEAK" else 0 for r in scored)
    pct = int(100 * earned / total) if total else 0
    letter = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 55 else "D" if pct >= 35 else "F"
    return pct, letter


def analyze_headers(headers: Mapping[str, HeaderValue]) -> tuple[list[HeaderResult], int, str]:
    results = _check(headers)
    pct, letter = grade(results)
    return results, pct, letter


def to_issues(results: list[HeaderResult], location: str = "") -> list[Issue]:
    issues: list[Issue] = []
    for r in results:
        if r.status == "OK":
            continue
        severity, technique, fix = _META[r.header]
        if r.header in ("Server", "X-Powered-By"):
            rule = "SF-HDR-004"
        elif r.header == "Set-Cookie":
            rule = "SF-HDR-003"
        else:
            rule = "SF-HDR-002" if r.status == "WEAK" else "SF-HDR-001"
        title = f"{r.header}: {r.status.lower()}"
        issues.append(Issue(rule, "headers", severity, title, r.detail, location, 0, technique, fix))
    return issues


def fetch_headers(url: str, timeout: float = 10.0) -> dict[str, HeaderValue]:
    """HEAD request. Note: some servers only send Set-Cookie on GET."""
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    # Scheme restricted to http(s) above: blocks file://, ftp:// etc. (mitigates LFI/SSRF if the code is reused).
    req = urllib.request.Request(  # noqa: S310
        url, method="HEAD", headers={"User-Agent": f"SecFund/{__version__} (defensive audit)"}
    )
    out: dict[str, HeaderValue] = {}
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
        for key, value in resp.headers.items():
            if key.lower() == "set-cookie":
                cookies = out.setdefault("Set-Cookie", [])
                if isinstance(cookies, list):
                    cookies.append(value)
            else:
                out[key] = value
    return out
