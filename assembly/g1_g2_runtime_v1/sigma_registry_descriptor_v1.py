"""Description statique du registre Sigma sans charger les agents métiers.

Le registre historique dépend d'adaptateurs périphériques non tous inclus dans
G1/G2. Son import n'est donc pas une sonde sûre de disponibilité. Un manifeste
AST n'atteste ni l'instanciation ni l'exécution d'agents Sigma.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any

_EXPECTED = ("bank", "trading", "ecom", "gps_defense_aviation")
_SOURCE_SHA256_LF = "a9552f6e1049b5efda4b24df59fe57bcd3f15d531821257fb77cbda19340a0a3"
_MAX_BYTES = 100000


def inspect_sigma_registry_descriptor(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        path = Path(__file__).resolve().parent / "sigma" / "registry.py"
    if (not path.is_file() or path.is_symlink()
            or any(p.is_symlink() or getattr(p, "is_junction", lambda: False)()
                   for p in (path.parent, path.parent.parent))):
        return {"status": "HOLD", "reason": "SIGMA_REGISTRY_SOURCE_UNAVAILABLE"}
    try:
        data = path.read_bytes()
        if not 0 < len(data) < _MAX_BYTES or data != path.read_bytes():
            raise ValueError("changed or oversized")
        source = data.decode("utf-8-sig").replace("\r\n", "\n")
        if hashlib.sha256(source.encode("utf-8")).hexdigest() != _SOURCE_SHA256_LF:
            return {"status": "HOLD", "reason": "SIGMA_REGISTRY_SOURCE_SHA_MISMATCH"}
        tree = ast.parse(source)
    except (OSError, SyntaxError, UnicodeError, ValueError):
        return {"status": "HOLD", "reason": "SIGMA_REGISTRY_SOURCE_INVALID"}
    domains = None
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            if (len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)
                    and stmt.targets[0].id == "_CANONICAL_DOMAINS"
                    and isinstance(stmt.value, ast.Tuple)):
                values = stmt.value.elts
                if all(isinstance(v, ast.Constant) and type(v.value) is str for v in values):
                    domains = tuple(v.value for v in values)
    if domains != _EXPECTED:
        return {"status": "HOLD", "reason": "SIGMA_CANONICAL_DOMAINS_DRIFT"}
    return {
        "status": "SIGMA_DOMAINS_DECLARED_ONLY_NOT_RUNTIME_VERIFIED",
        "schema_version": "OBSIDIA_SIGMA_STATIC_REGISTRY_V1",
        "source_sha256_lf": _SOURCE_SHA256_LF,
        "domains": list(domains), "agent_runtime_imported": False,
        "agent_count_verified": False, "agents_executed": False,
        "advisory_only": True, "decision_authority": "KX108_ONLY",
        "readonly": True, "release_authorized": False,
        "dependency_closure": "HOLD_NOT_CLAIMED",
    }
