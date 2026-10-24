"""TLS audit: certificate validity, expiration, protocol version and cipher suite.

Mapping: OWASP A02:2021 (Cryptographic Failures), CIS Control 3.10 (encryption in transit).
Defensive use: only hosts you own or are authorized to assess.

Known limitation: it evaluates what was NEGOTIATED by a modern client (TLS >= 1.2). It does not
enumerate every version/cipher the server accepts (that requires active scanning, e.g. testssl.sh).
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, cast

from .report import Issue

OBSOLETE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "ANON")


@dataclass
class TlsInfo:
    host: str
    port: int = 443
    protocol: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    not_after: datetime | None = None
    subject: str = ""
    issuer: str = ""
    san: list[str] = field(default_factory=list)
    verified: bool = False
    verify_error: str = ""
    handshake_error: str = ""


def _rdn_value(rdns: tuple[tuple[tuple[str, str], ...], ...], keys: tuple[str, ...]) -> str:
    for rdn in rdns:
        for key, value in rdn:
            if key in keys:
                return value
    return ""


def _fill_connection(info: TlsInfo, conn: ssl.SSLSocket) -> None:
    info.protocol = conn.version() or ""
    cipher = conn.cipher()
    if cipher:
        info.cipher, _, info.cipher_bits = cipher[0], cipher[1], int(cipher[2] or 0)


def _fill_cert(info: TlsInfo, conn: ssl.SSLSocket) -> None:
    # typeshed types getpeercert() too broadly; the real structure is documented in the ssl module.
    cert = cast("dict[str, Any]", conn.getpeercert())
    if not cert:
        return
    if "notAfter" in cert:
        info.not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(str(cert["notAfter"])), tz=timezone.utc)
    info.subject = _rdn_value(cert.get("subject", ()), ("commonName",))
    info.issuer = _rdn_value(cert.get("issuer", ()), ("organizationName", "commonName"))
    info.san = [value for _, value in cert.get("subjectAltName", ())]


def fetch_tls(host: str, port: int = 443, timeout: float = 10.0) -> TlsInfo:
    """Connects, validates chain/hostname and collects protocol, cipher and certificate."""
    info = TlsInfo(host, port)
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as conn,
        ):
            _fill_connection(info, conn)
            _fill_cert(info, conn)
            info.verified = True
    except ssl.SSLCertVerificationError as e:
        info.verify_error = e.verify_message or str(e)
        # Reconnect WITHOUT validation only to read protocol/cipher; no data is sent.
        loose = ssl.create_default_context()
        loose.check_hostname = False
        # Read-only inspection of handshake parameters (version/cipher); no application data is sent.
        loose.verify_mode = ssl.CERT_NONE  # nosec B501
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                loose.wrap_socket(sock, server_hostname=host) as conn,
            ):
                _fill_connection(info, conn)
        except ssl.SSLError as inner:
            info.handshake_error = str(inner)
    except ssl.SSLError as e:
        info.handshake_error = e.reason or str(e)
    return info


def evaluate(info: TlsInfo, now: datetime | None = None) -> list[Issue]:
    now = now or datetime.now(timezone.utc)
    where = f"{info.host}:{info.port}"
    issues: list[Issue] = []

    if info.handshake_error:
        issues.append(Issue(
            "SF-TLS-003", "tls", "HIGH", "TLS handshake failed", info.handshake_error, where, 0, "OWASP A02:2021",
            "Enable TLS 1.2/1.3 with modern ciphers; current clients refuse legacy protocols.",
        ))  # fmt: skip

    if info.verify_error:
        expired = "expired" in info.verify_error.lower()
        issues.append(Issue(
            "SF-TLS-001", "tls", "CRITICAL" if expired else "HIGH", "Certificate not trusted",
            info.verify_error, where, 0, "OWASP A02:2021 / T1557",
            "Install a valid certificate issued by a trusted CA, with a SAN for the hostname and the full chain.",
        ))  # fmt: skip

    if info.not_after is not None:
        days = (info.not_after - now).days
        if days < 0:
            severity = "CRITICAL"
        elif days < 15:
            severity = "HIGH"
        elif days < 30:
            severity = "MEDIUM"
        else:
            severity = ""
        if severity:
            state = f"expired {-days} day(s) ago" if days < 0 else f"expires in {days} day(s)"
            issues.append(Issue(
                "SF-TLS-002", "tls", severity, f"Certificate {state}", info.not_after.date().isoformat(), where, 0,
                "OWASP A02:2021", "Automate renewal (ACME/Let's Encrypt) and monitor expiration.",
            ))  # fmt: skip

    if info.protocol in OBSOLETE_PROTOCOLS:
        issues.append(Issue(
            "SF-TLS-003", "tls", "HIGH", f"Obsolete protocol negotiated: {info.protocol}", "", where, 0,
            "OWASP A02:2021", "Disable SSLv3/TLS 1.0/1.1; keep only TLS 1.2 and 1.3.",
        ))  # fmt: skip

    cipher_upper = info.cipher.upper()
    if any(m in cipher_upper for m in WEAK_CIPHER_MARKERS) or (0 < info.cipher_bits < 128):
        issues.append(Issue(
            "SF-TLS-004", "tls", "HIGH", f"Weak cipher suite: {info.cipher} ({info.cipher_bits} bits)", "", where, 0,
            "OWASP A02:2021", "Use only AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE key exchange.",
        ))  # fmt: skip
    return issues
