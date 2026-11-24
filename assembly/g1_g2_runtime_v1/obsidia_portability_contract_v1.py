"""Contrat de portabilité P1 : lecture seule, jamais une autorité.

Distingue pour chaque dépendance déclarée :
  AVAILABLE_PINNED            fichier présent, SHA256 == empreinte épinglée, source attendue
  MISSING                     fichier absent
  HASH_DIVERGENT              fichier présent, empreinte différente de l'épinglage
  WRONG_VERSION_SUPERSEDED    empreinte d'une version connue comme remplacée
  UNEXPECTED_SOURCE           le module s'importe depuis un autre chemin que celui attendu
  UNPINNED_PRESENT            fichier présent mais aucune empreinte de référence (jamais accepté)

Un pin prouve l'identité d'octets avec une source revue ; il ne prouve ni
l'authenticité du producteur, ni une autorisation. `portable_closure_verified`
n'est vrai que si TOUTES les dépendances requises sont AVAILABLE_PINNED.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Optional

AVAILABLE_PINNED = "AVAILABLE_PINNED"
MISSING = "MISSING"
HASH_DIVERGENT = "HASH_DIVERGENT"
WRONG_VERSION_SUPERSEDED = "WRONG_VERSION_SUPERSEDED"
UNEXPECTED_SOURCE = "UNEXPECTED_SOURCE"
UNPINNED_PRESENT = "UNPINNED_PRESENT"

_SCHEMA = "OBSIDIA_P1_PORTABILITY_MANIFEST_V1"
_DEFAULT_MANIFEST = Path(__file__).resolve().parent / "portability_manifest_v1.json"


def load_manifest(path: Optional[Path] = None) -> dict[str, Any]:
    return json.loads(Path(path or _DEFAULT_MANIFEST).read_text(encoding="utf-8"))


def isolated_origin_resolver(runtime_root: Path) -> Callable[[str], Optional[str]]:
    """Résout un module dans un interpréteur isolé (-I) restreint au runtime."""
    root = Path(runtime_root).resolve()

    def resolve(module: str) -> Optional[str]:
        code = (
            "import importlib.util, sys\n"
            f"sys.path[:0] = [{str(root / 'scripts')!r}, {str(root)!r}]\n"
            "try:\n"
            f"    spec = importlib.util.find_spec({module!r})\n"
            "except Exception:\n"
            "    spec = None\n"
            "print(spec.origin if spec and spec.origin else '')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-I", "-B", "-c", code],
            capture_output=True, text=True, timeout=30,
        )
        out = proc.stdout.strip()
        return out or None

    return resolve


def _same_path(a: str, b: Path) -> bool:
    try:
        return Path(a).resolve() == b.resolve()
    except OSError:
        return False


def inspect_portability(
    manifest: dict[str, Any], *, runtime_root: Path,
    resolver: Optional[Callable[[str], Optional[str]]] = None,
) -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    resolve = resolver or isolated_origin_resolver(root)
    entries_out: list[dict[str, Any]] = []
    if manifest.get("schema") != _SCHEMA or not isinstance(manifest.get("entries"), list):
        return _result([], "PORTABILITY_MANIFEST_INVALID")
    for entry in manifest["entries"]:
        module = entry["module"]
        file = root / entry["relative_path"]
        expected = entry.get("expected_sha256")
        record: dict[str, Any] = {
            "module": module, "path": str(file), "expected_sha256": expected,
            "actual_sha256": None, "required": bool(entry.get("required", True)),
        }
        if not file.is_file() or file.is_symlink():
            record["status"] = MISSING
            entries_out.append(record)
            continue
        actual = hashlib.sha256(file.read_bytes()).hexdigest()
        record["actual_sha256"] = actual
        if expected is None:
            record["status"] = UNPINNED_PRESENT
        elif actual in set(entry.get("superseded_sha256") or ()):
            record["status"] = WRONG_VERSION_SUPERSEDED
        elif actual != expected:
            record["status"] = HASH_DIVERGENT
        else:
            origin = resolve(module)
            record["resolved_origin"] = origin
            record["status"] = (
                AVAILABLE_PINNED if origin and _same_path(origin, file) else UNEXPECTED_SOURCE
            )
        entries_out.append(record)
    return _result(entries_out, None)


def _result(entries: list[dict[str, Any]], reason: Optional[str]) -> dict[str, Any]:
    blocking = [
        e["module"] for e in entries
        if e["required"] and e["status"] != AVAILABLE_PINNED
    ]
    closed = reason is None and not blocking and bool(entries)
    return {
        "schema_version": "OBSIDIA_P1_PORTABILITY_INSPECTION_V1",
        "status": "PORTABLE_CLOSURE_VERIFIED" if closed else "HOLD",
        "reason": reason or (("PORTABLE_CLOSURE_BLOCKED:" + ",".join(blocking)) if blocking else None),
        "portable_closure_verified": closed,
        "blocking_modules": blocking,
        "entries": entries,
        "readonly": True,
        "decision_authority": "KX108_ONLY",
        "pin_is_authority": False,
        "execution_authorized": False,
        "release_authorized": False,
    }
