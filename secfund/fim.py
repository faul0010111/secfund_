"""File integrity monitor (FIM) with an HMAC-SHA256 signed baseline.

Mapping: MITRE T1565 (Data Manipulation), T1505.003 (Web Shell), T1070 (Indicator Removal),
CIS Control 3. Without a signature, whoever modifies the files can also rewrite the baseline and
hide the trail; with an HMAC (key stored outside the monitored host) tampering is detected.

An attacker may also try to "downgrade" verification by stripping the signature from the baseline:
therefore, if a key is provided and the baseline is NOT signed, verification fails.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .report import Issue

BASELINE_VERSION = 2
MIN_KEY_BYTES = 16


class BaselineError(Exception):
    """Baseline is invalid, tampered with, or incompatible with the provided key."""


def sha256_file(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def _excluded(rel: str, patterns: Iterable[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in patterns)


def snapshot(
    root: str | Path, exclude: Iterable[str] = (), skipped: list[str] | None = None
) -> dict[str, dict[str, Any]]:
    """Builds {relative_path: {sha256, size, mode}} without following symlinks.

    Unreadable files (permissions etc.) are recorded in ``skipped`` instead of aborting the scan.
    """
    root_path = Path(root).resolve()
    patterns = list(exclude)
    result: dict[str, dict[str, Any]] = {}
    for dirpath, dirs, files in os.walk(root_path, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            p = Path(dirpath) / name
            rel = p.relative_to(root_path).as_posix()
            if p.is_symlink() or _excluded(rel, patterns):
                continue
            try:
                st = p.stat()
                result[rel] = {"sha256": sha256_file(p), "size": st.st_size, "mode": oct(st.st_mode & 0o777)}
            except OSError:
                if skipped is not None:
                    skipped.append(rel)
    return result


# --- Keys and signing ----------------------------------------------------------------------


def parse_key(text: str) -> bytes:
    try:
        key = bytes.fromhex(text.strip())
    except ValueError as e:
        raise ValueError("invalid key: expected hexadecimal text") from e
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"key too short (minimum {MIN_KEY_BYTES} bytes)")
    return key


def load_key_file(path: str | Path) -> bytes:
    return parse_key(Path(path).read_text(encoding="utf-8"))


def generate_key_file(path: str | Path) -> None:
    """Creates a random 256-bit key with 0600 permissions; never overwrites an existing file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(secrets.token_hex(32) + "\n")


def _canonical(doc: dict[str, Any]) -> bytes:
    payload = {k: doc[k] for k in ("version", "algorithm", "created", "files")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign(doc: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(doc), hashlib.sha256).hexdigest()


# --- Baseline ------------------------------------------------------------------------------


def _baseline_exclusions(root: Path, baseline_path: Path, exclude: Iterable[str]) -> list[str]:
    patterns = list(exclude)
    with contextlib.suppress(ValueError):  # baseline outside the monitored root (recommended): nothing to exclude
        patterns.append(baseline_path.resolve().relative_to(root.resolve()).as_posix())
    return patterns


def save_baseline(
    root: str | Path, baseline_path: str | Path, key: bytes | None = None, exclude: Iterable[str] = ()
) -> int:
    root_p, base_p = Path(root), Path(baseline_path)
    files = snapshot(root_p, _baseline_exclusions(root_p, base_p, exclude))
    doc: dict[str, Any] = {
        "version": BASELINE_VERSION,
        "algorithm": "sha256",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": files,
    }
    doc["signature"] = _sign(doc, key) if key else None
    tmp = base_p.with_name(base_p.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, base_p)  # atomic write
    return len(files)


def load_baseline(path: str | Path, key: bytes | None = None) -> dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        if doc.get("version") != BASELINE_VERSION or not isinstance(doc.get("files"), dict):
            raise BaselineError("unknown baseline format (recreate it with 'fim init')")
    except json.JSONDecodeError as e:
        raise BaselineError(f"unreadable baseline: {e}") from e
    signature = doc.get("signature")
    if signature and not key:
        raise BaselineError("signed baseline: provide the key (--key-file or SECFUND_KEY)")
    if key and not signature:
        raise BaselineError("baseline has NO signature, but a key was provided: possible signature stripping")
    if key and not hmac.compare_digest(str(signature), _sign(doc, key)):
        raise BaselineError("invalid signature: baseline tampered with, or wrong key")
    files: dict[str, Any] = doc["files"]
    return files


def compare(baseline: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    common = set(baseline) & set(current)
    return {
        "added": sorted(set(current) - set(baseline)),
        "removed": sorted(set(baseline) - set(current)),
        "modified": sorted(p for p in common if baseline[p]["sha256"] != current[p]["sha256"]),
        "permissions": sorted(
            p for p in common
            if baseline[p]["sha256"] == current[p]["sha256"] and baseline[p]["mode"] != current[p]["mode"]
        ),
    }  # fmt: skip


def verify(
    root: str | Path, baseline_path: str | Path, key: bytes | None = None, exclude: Iterable[str] = ()
) -> dict[str, list[str]]:
    root_p, base_p = Path(root), Path(baseline_path)
    baseline = load_baseline(base_p, key)
    return compare(baseline, snapshot(root_p, _baseline_exclusions(root_p, base_p, exclude)))


_RULES = {
    "modified": ("SF-FIM-001", "HIGH", "T1565"),
    "added": ("SF-FIM-002", "MEDIUM", "T1505.003"),
    "removed": ("SF-FIM-003", "MEDIUM", "T1070"),
    "permissions": ("SF-FIM-004", "LOW", "T1222"),
}
# Display labels, in report order.
LABELS = {"modified": "MODIFIED", "added": "NEW", "removed": "REMOVED", "permissions": "PERMISSIONS"}
_TITLE = {
    "modified": "File modified",
    "added": "New file",
    "removed": "File removed",
    "permissions": "Permissions changed",
}


def to_issues(diff: dict[str, list[str]], root: str | Path = "") -> list[Issue]:
    issues: list[Issue] = []
    for key, (rule, severity, technique) in _RULES.items():
        for rel in diff[key]:
            issues.append(
                Issue(
                    rule, "fim", severity, f"{_TITLE[key]}: {rel}", "", (Path(root) / rel).as_posix(),
                    0, technique, "Confirm the change was authorized; if not, isolate the host and investigate.",
                )
            )  # fmt: skip
    return issues
