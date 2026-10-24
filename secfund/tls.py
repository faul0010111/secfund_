"""Auditoria de TLS: validade do certificado, expiração, versão do protocolo e cipher suite.

Mapeamento: OWASP A02:2021 (Cryptographic Failures), CIS Control 3.10 (criptografia em trânsito).
Uso defensivo: apenas hosts que você possui ou tem autorização para avaliar.

Limitação conhecida: avalia o que foi NEGOCIADO por um cliente moderno (TLS >= 1.2). Não enumera
todas as versões/ciphers que o servidor aceita (isso exige varredura ativa, ex.: testssl.sh).
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
    # O typeshed tipa getpeercert() de forma ampla demais; a estrutura real está documentada no módulo ssl.
    cert = cast("dict[str, Any]", conn.getpeercert())
    if not cert:
        return
    if "notAfter" in cert:
        info.not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(str(cert["notAfter"])), tz=timezone.utc)
    info.subject = _rdn_value(cert.get("subject", ()), ("commonName",))
    info.issuer = _rdn_value(cert.get("issuer", ()), ("organizationName", "commonName"))
    info.san = [value for _, value in cert.get("subjectAltName", ())]


def fetch_tls(host: str, port: int = 443, timeout: float = 10.0) -> TlsInfo:
    """Conecta, valida a cadeia/hostname e coleta protocolo, cipher e certificado."""
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
        # Reconecta SEM validar apenas para ler protocolo/cipher; nenhum dado é enviado.
        loose = ssl.create_default_context()
        loose.check_hostname = False
        # Somente leitura de parâmetros do handshake (versão/cipher); nenhum dado da aplicação é enviado.
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
            "SF-TLS-003", "tls", "ALTO", "Handshake TLS falhou", info.handshake_error, where, 0, "OWASP A02:2021",
            "Habilite TLS 1.2/1.3 com ciphers modernos; clientes atuais recusam protocolos antigos.",
        ))  # fmt: skip

    if info.verify_error:
        expired = "expired" in info.verify_error.lower()
        issues.append(Issue(
            "SF-TLS-001", "tls", "CRITICO" if expired else "ALTO", "Certificado não confiável",
            info.verify_error, where, 0, "OWASP A02:2021 / T1557",
            "Instale um certificado válido emitido por CA confiável, com SAN para o hostname e cadeia completa.",
        ))  # fmt: skip

    if info.not_after is not None:
        days = (info.not_after - now).days
        if days < 0:
            severity = "CRITICO"
        elif days < 15:
            severity = "ALTO"
        elif days < 30:
            severity = "MEDIO"
        else:
            severity = ""
        if severity:
            state = f"expirou há {-days} dia(s)" if days < 0 else f"expira em {days} dia(s)"
            issues.append(Issue(
                "SF-TLS-002", "tls", severity, f"Certificado {state}", info.not_after.date().isoformat(), where, 0,
                "OWASP A02:2021", "Automatize a renovação (ACME/Let's Encrypt) e monitore a expiração.",
            ))  # fmt: skip

    if info.protocol in OBSOLETE_PROTOCOLS:
        issues.append(Issue(
            "SF-TLS-003", "tls", "ALTO", f"Protocolo obsoleto negociado: {info.protocol}", "", where, 0,
            "OWASP A02:2021", "Desative SSLv3/TLS 1.0/1.1; mantenha apenas TLS 1.2 e 1.3.",
        ))  # fmt: skip

    cipher_upper = info.cipher.upper()
    if any(m in cipher_upper for m in WEAK_CIPHER_MARKERS) or (0 < info.cipher_bits < 128):
        issues.append(Issue(
            "SF-TLS-004", "tls", "ALTO", f"Cipher suite fraca: {info.cipher} ({info.cipher_bits} bits)", "", where, 0,
            "OWASP A02:2021", "Use apenas suites AEAD (AES-GCM, ChaCha20-Poly1305) com troca de chaves ECDHE.",
        ))  # fmt: skip
    return issues
