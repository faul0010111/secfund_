"""Auditoria de senhas, armazenamento seguro (scrypt / PBKDF2) e checagem de vazamentos.

Referências: NIST SP 800-63B (comprimento > complexidade, bloquear senhas comuns/vazadas,
normalizar Unicode), OWASP Password Storage Cheat Sheet (scrypt N=2^17,r=8,p=1;
PBKDF2-HMAC-SHA256 >= 600.000 iterações quando FIPS-140 é exigido).

O hash armazenado é entrada NÃO confiável: seus parâmetros de custo são limitados na verificação,
senão um hash forjado com ``n=2**30`` viraria um vetor de negação de serviço (DoS).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import secrets
import string
import unicodedata
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# Lista mínima embutida para a demo; em produção use uma lista maior ou a checagem de vazamentos.
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "password", "qwerty", "abc123", "111111",
    "senha", "senha123", "admin", "admin123", "letmein", "welcome", "iloveyou",
    "654321", "qwerty123", "password1", "000000", "brasil", "mudar123", "changeme",
}  # fmt: skip
KEYBOARD_WALKS = ("qwerty", "asdfgh", "zxcvbn", "123456", "654321")
_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t"})

PBKDF2_ITERATIONS = 600_000
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1
_MAX_ITERATIONS = 10_000_000
_MAX_SCRYPT_N, _MAX_SCRYPT_R, _MAX_SCRYPT_P = 2**18, 16, 4
_DKLEN = 32

PWNED_API = "https://api.pwnedpasswords.com/range/"


@dataclass
class Audit:
    score: int
    entropy_bits: float
    verdict: str
    issues: list[str] = field(default_factory=list)


def _prep(password: str) -> bytes:
    """NIST 800-63B: normaliza Unicode (NFKC) para que 'é' composto e decomposto gerem o mesmo hash."""
    return unicodedata.normalize("NFKC", password).encode("utf-8")


# --- Auditoria ------------------------------------------------------------------------------


def estimate_entropy(password: str) -> float:
    """Estimativa simples: len * log2(alfabeto observado). É um LIMITE SUPERIOR, não uma garantia."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    return len(password) * math.log2(pool) if pool else 0.0


def _is_common_variant(password: str) -> bool:
    """Pega 'P@ssw0rd2026!' = 'password' + leetspeak + sufixo, o padrão que dicionários de ataque testam."""
    # Primeiro remove o sufixo (números/símbolos); só depois troca leetspeak, senão '!' final viraria 'i'.
    base = re.sub(r"[\d\W_]+$", "", password.lower()).translate(_LEET)
    return base in COMMON_PASSWORDS


def audit_password(password: str, pwned_count: int | None = None) -> Audit:
    issues: list[str] = []
    low = password.lower()
    common = low in COMMON_PASSWORDS
    variant = not common and _is_common_variant(password)

    if len(password) < 12:
        issues.append("Menos de 12 caracteres (NIST recomenda priorizar o comprimento).")
    if common:
        issues.append("Senha presente em lista de senhas comuns.")
    if variant:
        issues.append("Variação trivial de senha comum (leetspeak/sufixo numérico).")
    if any(w in low for w in KEYBOARD_WALKS):
        issues.append("Contém sequência de teclado.")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Caracteres repetidos em sequência (ex.: aaa).")
    if re.fullmatch(r"[A-Za-z]+\d{1,4}[!@#$%]?", password):
        issues.append("Padrão previsível: palavra + números (+ símbolo).")
    if pwned_count:
        issues.append(f"Aparece em {pwned_count:,} vazamentos de dados conhecidos.".replace(",", "."))

    entropy = estimate_entropy(password)
    score = max(0, min(100, int(entropy * 1.1) - 25 * len(issues)))
    if common or pwned_count:
        score = min(score, 5)
    elif variant:
        score = min(score, 20)
    verdict = "FORTE" if score >= 75 else "MÉDIA" if score >= 45 else "FRACA"
    return Audit(score, round(entropy, 1), verdict, issues)


def generate_password(length: int = 20) -> str:
    """Senha aleatória criptograficamente segura (módulo ``secrets``) com as 4 classes de caracteres."""
    if length < 12:
        raise ValueError("comprimento mínimo: 12")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+[]{};:,.?"]
    chars = [secrets.choice(c) for c in classes]
    pool = "".join(classes)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# --- Armazenamento --------------------------------------------------------------------------


def _valid_scrypt(n: int, r: int, p: int) -> bool:
    return 2 <= n <= _MAX_SCRYPT_N and n & (n - 1) == 0 and 1 <= r <= _MAX_SCRYPT_R and 1 <= p <= _MAX_SCRYPT_P


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, *, dklen: int = _DKLEN) -> bytes:
    # O OpenSSL exige ~128*n*r bytes; damos 2x de folga.
    return hashlib.scrypt(_prep(password), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=256 * n * r + (1 << 20))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password(
    password: str,
    algorithm: str = "scrypt",
    *,
    iterations: int = PBKDF2_ITERATIONS,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> str:
    """Hash autodescritivo: ``scrypt$n$r$p$salt$hash`` ou ``pbkdf2_sha256$iter$salt$hash``."""
    salt = secrets.token_bytes(16)
    if algorithm == "scrypt":
        if not _valid_scrypt(n, r, p):
            raise ValueError("parâmetros scrypt fora do intervalo permitido")
        return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(_scrypt(password, salt, n, r, p))}"
    if algorithm == "pbkdf2":
        if not 1 <= iterations <= _MAX_ITERATIONS:
            raise ValueError("número de iterações fora do intervalo permitido")
        dk = hashlib.pbkdf2_hmac("sha256", _prep(password), salt, iterations, dklen=_DKLEN)
        return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(dk)}"
    raise ValueError(f"algoritmo desconhecido: {algorithm!r}")


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = stored.split("$")
        if parts[0] == "scrypt" and len(parts) == 6:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            if not _valid_scrypt(n, r, p):
                return False
            salt, expected = base64.b64decode(parts[4], validate=True), base64.b64decode(parts[5], validate=True)
            if not 16 <= len(expected) <= 64:
                return False
            dk = _scrypt(password, salt, n, r, p, dklen=len(expected))
        elif parts[0] == "pbkdf2_sha256" and len(parts) == 4:
            iterations = int(parts[1])
            if not 1 <= iterations <= _MAX_ITERATIONS:
                return False
            salt, expected = base64.b64decode(parts[2], validate=True), base64.b64decode(parts[3], validate=True)
            if not 16 <= len(expected) <= 64:
                return False
            dk = hashlib.pbkdf2_hmac("sha256", _prep(password), salt, iterations, dklen=len(expected))
        else:
            return False
    except (ValueError, TypeError):
        return False
    # Comparação em tempo constante evita timing attacks.
    return hmac.compare_digest(dk, expected)


def needs_rehash(stored: str, algorithm: str = "scrypt") -> bool:
    """True se o hash usa outro algoritmo ou parâmetros mais fracos que os atuais (re-hash no próximo login)."""
    try:
        parts = stored.split("$")
        if algorithm == "scrypt":
            return not (
                parts[0] == "scrypt" and int(parts[1]) >= SCRYPT_N and int(parts[2]) >= SCRYPT_R
                and int(parts[3]) >= SCRYPT_P
            )  # fmt: skip
        return not (parts[0] == "pbkdf2_sha256" and int(parts[1]) >= PBKDF2_ITERATIONS)
    except (ValueError, IndexError):
        return True


# --- Vazamentos (k-anonymity, modelo Have I Been Pwned) -------------------------------------


def _sha1_hex(password: str) -> str:
    # SHA-1 é exigido pelo protocolo HIBP; aqui NÃO é usado para proteger credenciais.
    return hashlib.sha1(_prep(password), usedforsecurity=False).hexdigest().upper()


def parse_range_response(text: str, suffix: str) -> int:
    for line in text.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            return int(count) if count.isdigit() else 1
    return 0


def pwned_count_range(password: str, fetch: Callable[[str], str]) -> int:
    """Só os 5 primeiros caracteres do SHA-1 saem da máquina (k-anonymity); o resto é comparado localmente."""
    digest = _sha1_hex(password)
    return parse_range_response(fetch(digest[:5]), digest[5:])


def fetch_range_online(prefix: str, timeout: float = 10.0) -> str:
    if not re.fullmatch(r"[0-9A-F]{5}", prefix):
        raise ValueError("prefixo deve ter 5 caracteres hexadecimais maiúsculos")
    # URL base https fixa + prefixo validado por regex: nada controlado pelo usuário chega ao esquema/host.
    req = urllib.request.Request(  # noqa: S310
        PWNED_API + prefix, headers={"User-Agent": "SecFund", "Add-Padding": "true"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
        return str(resp.read(4_000_000).decode("utf-8", "replace"))


def pwned_count_file(password: str, path: str | Path) -> int:
    """Checagem 100% offline contra arquivo de hashes SHA-1 (formato HASH:CONTAGEM, um por linha)."""
    digest = _sha1_hex(password)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            candidate, _, count = line.strip().partition(":")
            if candidate.upper() == digest:
                return int(count) if count.isdigit() else 1
    return 0
