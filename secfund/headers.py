"""Analisador de security headers HTTP (OWASP Secure Headers Project).

Uso defensivo: analise apenas sites que você possui ou tem autorização para avaliar.
Mapeamento: OWASP Top 10 A05:2021 (Security Misconfiguration).
"""

from __future__ import annotations

import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass

from .report import Issue

HeaderValue = str | list[str]


@dataclass
class HeaderResult:
    header: str
    status: str  # OK | AUSENTE | FRACO
    detail: str
    weight: int  # peso MÁXIMO do item na nota (constante, independe do status)


# header -> (severidade, técnica, remediação)
_META: dict[str, tuple[str, str, str]] = {
    "Strict-Transport-Security": (
        "MEDIO", "OWASP A05:2021 / T1557",
        "Envie 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "Content-Security-Policy": (
        "MEDIO", "OWASP A05:2021 / A03:2021", "Defina uma CSP restritiva (default-src 'self') sem unsafe-inline.",
    ),
    "Anti-clickjacking": (
        "MEDIO", "OWASP A05:2021 / T1185", "Use CSP frame-ancestors 'none' ou 'X-Frame-Options: DENY'.",
    ),
    "X-Content-Type-Options": ("BAIXO", "OWASP A05:2021", "Envie 'X-Content-Type-Options: nosniff'."),
    "Referrer-Policy": ("BAIXO", "OWASP A05:2021", "Envie 'Referrer-Policy: strict-origin-when-cross-origin'."),
    "Permissions-Policy": ("BAIXO", "OWASP A05:2021", "Restrinja APIs do navegador (ex.: 'geolocation=()')."),
    "Cross-Origin-Opener-Policy": ("BAIXO", "OWASP A05:2021", "Envie 'Cross-Origin-Opener-Policy: same-origin'."),
    "Set-Cookie": (
        "MEDIO", "OWASP A05:2021 / A07:2021", "Marque cookies de sessão com Secure; HttpOnly; SameSite=Lax/Strict.",
    ),
    "Server": ("BAIXO", "OWASP A05:2021", "Oculte a versão do servidor (ServerTokens Prod / server_tokens off)."),
    "X-Powered-By": ("BAIXO", "OWASP A05:2021", "Remova o header X-Powered-By."),
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
        out.append(HeaderResult("Strict-Transport-Security", "AUSENTE", "Sem HSTS: risco de downgrade/SSL strip.", 20))
    else:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0])
        except (IndexError, ValueError):
            age = 0
        if age < 15552000:
            out.append(HeaderResult("Strict-Transport-Security", "FRACO", f"max-age={age} (< 6 meses).", 20))
        else:
            out.append(HeaderResult("Strict-Transport-Security", "OK", hsts, 20))

    csp = _first(h.get("content-security-policy"))
    if not csp:
        out.append(HeaderResult("Content-Security-Policy", "AUSENTE", "Sem CSP: o impacto de XSS é maior.", 25))
    elif "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp.split():
        out.append(HeaderResult("Content-Security-Policy", "FRACO", "Usa unsafe-inline/unsafe-eval/curinga.", 25))
    else:
        out.append(HeaderResult("Content-Security-Policy", "OK", "Política restritiva.", 25))

    xfo = _first(h.get("x-frame-options"))
    if "frame-ancestors" in csp or xfo.upper() in ("DENY", "SAMEORIGIN"):
        out.append(HeaderResult("Anti-clickjacking", "OK", "frame-ancestors ou X-Frame-Options presente.", 15))
    else:
        out.append(HeaderResult("Anti-clickjacking", "AUSENTE", "Risco de clickjacking.", 15))

    if _first(h.get("x-content-type-options")).lower() == "nosniff":
        out.append(HeaderResult("X-Content-Type-Options", "OK", "nosniff", 10))
    else:
        out.append(HeaderResult("X-Content-Type-Options", "AUSENTE", "Permite MIME sniffing.", 10))

    referrer = _first(h.get("referrer-policy"))
    if referrer:
        out.append(HeaderResult("Referrer-Policy", "OK", referrer, 10))
    else:
        out.append(HeaderResult("Referrer-Policy", "AUSENTE", "Vazamento de URL no header Referer.", 10))

    if h.get("permissions-policy"):
        out.append(HeaderResult("Permissions-Policy", "OK", "Definida.", 5))
    else:
        out.append(HeaderResult("Permissions-Policy", "AUSENTE", "APIs do navegador sem restrição.", 5))

    if h.get("cross-origin-opener-policy"):
        coop = _first(h["cross-origin-opener-policy"])
        out.append(HeaderResult("Cross-Origin-Opener-Policy", "OK", coop, 5))
    else:
        out.append(HeaderResult("Cross-Origin-Opener-Policy", "AUSENTE", "Sem isolamento de janela (XS-Leaks).", 5))

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
                weak.append(f"{parts[0].split('=', 1)[0] or '?'}: sem {', '.join(missing)}")
        if weak:
            out.append(HeaderResult("Set-Cookie", "FRACO", "; ".join(weak), 10))
        else:
            out.append(HeaderResult("Set-Cookie", "OK", f"{len(cookies)} cookie(s) com atributos de segurança.", 10))

    server = _first(h.get("server"))
    if server and any(c.isdigit() for c in server):
        out.append(HeaderResult("Server", "FRACO", f"Expõe versão: {server}", 5))
    else:
        out.append(HeaderResult("Server", "OK", "Sem versão exposta.", 5))
    if h.get("x-powered-by"):
        out.append(HeaderResult("X-Powered-By", "FRACO", f"Expõe tecnologia: {_first(h['x-powered-by'])}", 0))
    return out


def grade(results: list[HeaderResult]) -> tuple[int, str]:
    """Nota 0-100: OK vale o peso inteiro, FRACO metade, AUSENTE zero. X-Powered-By não pontua."""
    scored = [r for r in results if r.weight > 0]
    total = sum(r.weight for r in scored)
    earned = sum(r.weight if r.status == "OK" else r.weight / 2 if r.status == "FRACO" else 0 for r in scored)
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
            rule = "SF-HDR-002" if r.status == "FRACO" else "SF-HDR-001"
        title = f"{r.header}: {r.status.lower()}"
        issues.append(Issue(rule, "headers", severity, title, r.detail, location, 0, technique, fix))
    return issues


def fetch_headers(url: str, timeout: float = 10.0) -> dict[str, HeaderValue]:
    """HEAD request. Observação: alguns servidores só enviam Set-Cookie em GET."""
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("URL deve começar com http:// ou https://")
    # Esquema restrito a http(s) acima: bloqueia file://, ftp:// etc. (mitiga LFI/SSRF se o código for reaproveitado).
    req = urllib.request.Request(  # noqa: S310
        url, method="HEAD", headers={"User-Agent": "SecFund/1.1 (auditoria defensiva)"}
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
