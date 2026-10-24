"""Password auditing, secure storage (scrypt / PBKDF2) and breach checking.

References: NIST SP 800-63B (length over complexity, block common/breached passwords,
normalize Unicode), OWASP Password Storage Cheat Sheet (scrypt N=2^17,r=8,p=1;
PBKDF2-HMAC-SHA256 >= 600,000 iterations when FIPS-140 is required).

The stored hash is UNTRUSTED input: its cost parameters are bounded at verification time,
otherwise a forged hash with ``n=2**30`` would become a denial-of-service (DoS) vector.
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

# Minimal built-in list for the demo (includes a few common Portuguese-language entries);
# for real coverage use the breach check (--pwned / --pwned-file).
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
    """NIST 800-63B: normalize Unicode (NFKC) so composed and decomposed 'é' produce the same hash."""
    return unicodedata.normalize("NFKC", password).encode("utf-8")


# --- Auditing ------------------------------------------------------------------------------


def estimate_entropy(password: str) -> float:
    """Simple estimate: len * log2(observed alphabet). It is an UPPER BOUND, not a guarantee."""
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
    """Catches 'P@ssw0rd2026!' = 'password' + leetspeak + suffix, the pattern attack dictionaries try."""
    # Strip the suffix (digits/symbols) first; only then swap leetspeak, otherwise a trailing '!' becomes 'i'.
    base = re.sub(r"[\d\W_]+$", "", password.lower()).translate(_LEET)
    return base in COMMON_PASSWORDS


def audit_password(password: str, pwned_count: int | None = None) -> Audit:
    issues: list[str] = []
    low = password.lower()
    common = low in COMMON_PASSWORDS
    variant = not common and _is_common_variant(password)

    if len(password) < 12:
        issues.append("Shorter than 12 characters (NIST recommends prioritizing length).")
    if common:
        issues.append("Found in a list of common passwords.")
    if variant:
        issues.append("Trivial variation of a common password (leetspeak/numeric suffix).")
    if any(w in low for w in KEYBOARD_WALKS):
        issues.append("Contains a keyboard sequence.")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Repeated characters in a row (e.g., aaa).")
    if re.fullmatch(r"[A-Za-z]+\d{1,4}[!@#$%]?", password):
        issues.append("Predictable pattern: word + digits (+ symbol).")
    if pwned_count:
        issues.append(f"Found in {pwned_count:,} known data breach(es).")

    entropy = estimate_entropy(password)
    score = max(0, min(100, int(entropy * 1.1) - 25 * len(issues)))
    if common or pwned_count:
        score = min(score, 5)
    elif variant:
        score = min(score, 20)
    verdict = "STRONG" if score >= 75 else "MEDIUM" if score >= 45 else "WEAK"
    return Audit(score, round(entropy, 1), verdict, issues)


def generate_password(length: int = 20) -> str:
    """Cryptographically secure random password (``secrets`` module) using all 4 character classes."""
    if length < 12:
        raise ValueError("minimum length: 12")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+[]{};:,.?"]
    chars = [secrets.choice(c) for c in classes]
    pool = "".join(classes)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# --- Storage -------------------------------------------------------------------------------


def _valid_scrypt(n: int, r: int, p: int) -> bool:
    return 2 <= n <= _MAX_SCRYPT_N and n & (n - 1) == 0 and 1 <= r <= _MAX_SCRYPT_R and 1 <= p <= _MAX_SCRYPT_P


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, *, dklen: int = _DKLEN) -> bytes:
    # OpenSSL needs ~128*n*r bytes; allow 2x headroom.
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
    """Self-describing hash: ``scrypt$n$r$p$salt$hash`` or ``pbkdf2_sha256$iter$salt$hash``."""
    salt = secrets.token_bytes(16)
    if algorithm == "scrypt":
        if not _valid_scrypt(n, r, p):
            raise ValueError("scrypt parameters out of the allowed range")
        return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(_scrypt(password, salt, n, r, p))}"
    if algorithm == "pbkdf2":
        if not 1 <= iterations <= _MAX_ITERATIONS:
            raise ValueError("iteration count out of the allowed range")
        dk = hashlib.pbkdf2_hmac("sha256", _prep(password), salt, iterations, dklen=_DKLEN)
        return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(dk)}"
    raise ValueError(f"unknown algorithm: {algorithm!r}")


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
    # Constant-time comparison prevents timing attacks.
    return hmac.compare_digest(dk, expected)


def needs_rehash(stored: str, algorithm: str = "scrypt") -> bool:
    """True if the hash uses another algorithm or weaker parameters than current (rehash at next login)."""
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


# --- Breaches (k-anonymity, Have I Been Pwned model) ---------------------------------------


def _sha1_hex(password: str) -> str:
    # SHA-1 is required by the HIBP protocol; here it is NOT used to protect credentials.
    return hashlib.sha1(_prep(password), usedforsecurity=False).hexdigest().upper()


def parse_range_response(text: str, suffix: str) -> int:
    for line in text.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            return int(count) if count.isdigit() else 1
    return 0


def pwned_count_range(password: str, fetch: Callable[[str], str]) -> int:
    """Only the first 5 characters of the SHA-1 leave the machine (k-anonymity); the rest is matched locally."""
    digest = _sha1_hex(password)
    return parse_range_response(fetch(digest[:5]), digest[5:])


def fetch_range_online(prefix: str, timeout: float = 10.0) -> str:
    if not re.fullmatch(r"[0-9A-F]{5}", prefix):
        raise ValueError("prefix must be 5 uppercase hexadecimal characters")
    # Fixed https base URL + regex-validated prefix: nothing user-controlled reaches the scheme/host.
    req = urllib.request.Request(  # noqa: S310
        PWNED_API + prefix, headers={"User-Agent": "SecFund", "Add-Padding": "true"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
        return str(resp.read(4_000_000).decode("utf-8", "replace"))


def pwned_count_file(password: str, path: str | Path) -> int:
    """100% offline check against a SHA-1 hash file (HASH:COUNT format, one per line)."""
    digest = _sha1_hex(password)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            candidate, _, count = line.strip().partition(":")
            if candidate.upper() == digest:
                return int(count) if count.isdigit() else 1
    return 0
