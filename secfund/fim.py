"""Monitor de integridade de arquivos (FIM) com baseline assinada por HMAC-SHA256.

Mapeamento: MITRE T1565 (Data Manipulation), T1505.003 (Web Shell), T1070 (Indicator Removal),
CIS Control 3. Sem assinatura, quem altera os arquivos também pode regravar a baseline e esconder
o rastro; com HMAC (chave guardada fora do host monitorado) a adulteração é detectada.

Um atacante também pode tentar "rebaixar" a verificação removendo a assinatura da baseline:
por isso, se uma chave é fornecida e a baseline NÃO está assinada, a verificação falha.
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
    """Baseline inválida, adulterada ou incompatível com a chave informada."""


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
    """Gera {caminho_relativo: {sha256, size, mode}} sem seguir symlinks.

    Arquivos ilegíveis (permissão etc.) são anotados em ``skipped`` em vez de abortar a varredura.
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


# --- Chaves e assinatura -------------------------------------------------------------------


def parse_key(text: str) -> bytes:
    try:
        key = bytes.fromhex(text.strip())
    except ValueError as e:
        raise ValueError("chave inválida: esperado texto hexadecimal") from e
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"chave curta demais (mínimo {MIN_KEY_BYTES} bytes)")
    return key


def load_key_file(path: str | Path) -> bytes:
    return parse_key(Path(path).read_text(encoding="utf-8"))


def generate_key_file(path: str | Path) -> None:
    """Cria uma chave aleatória de 256 bits com permissão 0600; nunca sobrescreve."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(secrets.token_hex(32) + "\n")


def _canonical(doc: dict[str, Any]) -> bytes:
    payload = {k: doc[k] for k in ("version", "algorithm", "created", "files")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign(doc: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(doc), hashlib.sha256).hexdigest()


# --- Baseline -------------------------------------------------------------------------------


def _baseline_exclusions(root: Path, baseline_path: Path, exclude: Iterable[str]) -> list[str]:
    patterns = list(exclude)
    with contextlib.suppress(ValueError):  # baseline fora da raiz monitorada (recomendado) -> nada a excluir
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
    os.replace(tmp, base_p)  # escrita atômica
    return len(files)


def load_baseline(path: str | Path, key: bytes | None = None) -> dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        if doc.get("version") != BASELINE_VERSION or not isinstance(doc.get("files"), dict):
            raise BaselineError("formato de baseline desconhecido (recrie com 'fim init')")
    except json.JSONDecodeError as e:
        raise BaselineError(f"baseline ilegível: {e}") from e
    signature = doc.get("signature")
    if signature and not key:
        raise BaselineError("baseline assinada: informe a chave (--key-file ou SECFUND_KEY)")
    if key and not signature:
        raise BaselineError("baseline SEM assinatura, mas uma chave foi informada: possível remoção da assinatura")
    if key and not hmac.compare_digest(str(signature), _sign(doc, key)):
        raise BaselineError("assinatura inválida: baseline adulterada ou chave incorreta")
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
    "modified": ("SF-FIM-001", "ALTO", "T1565"),
    "added": ("SF-FIM-002", "MEDIO", "T1505.003"),
    "removed": ("SF-FIM-003", "MEDIO", "T1070"),
    "permissions": ("SF-FIM-004", "BAIXO", "T1222"),
}
_LABEL = {"modified": "modificado", "added": "novo", "removed": "removido", "permissions": "permissão alterada"}


def to_issues(diff: dict[str, list[str]], root: str | Path = "") -> list[Issue]:
    issues: list[Issue] = []
    for key, (rule, severity, technique) in _RULES.items():
        for rel in diff[key]:
            issues.append(
                Issue(
                    rule, "fim", severity, f"Arquivo {_LABEL[key]}: {rel}", "", (Path(root) / rel).as_posix(),
                    0, technique, "Confirme se a mudança foi autorizada; se não, isole o host e investigue.",
                )
            )  # fmt: skip
    return issues
