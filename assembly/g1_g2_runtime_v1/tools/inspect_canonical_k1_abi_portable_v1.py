"""OBSIDIA G1/G2 — contrat canonique Sigma/Obsidure, lecture seule.

Ce relevé ne charge/import aucun module du FIX, ne copie aucun code dans le
dépôt PUBLIC et n'exécute pas de test métier. Il ne modifie aucun worktree.
Son rôle est d'identifier les interfaces réelles avant de raccorder C2.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path


PORTABLE_HOST = "DESKTOP-Q5MD7J7"
SOURCE_HEAD = "ecaf6729f1bcdb05bb8896b7c698d1ae90e56de7"
SOURCE_RELATIVE = Path(".codex/visualizations/2026/11/kx108_zero_vote_guard_fix")
FILES = (
    "sigma/base.py",
    "sigma/registry.py",
    "sigma/protocols.py",
    "periphery/agents/agent_obsidure.py",
    "scripts/obsidure_bounded_apply.py",
    "scripts/obsidia_family_wiring_apply_bridge_v0.py",
)
MAX_FILE_BYTES = 2_000_000
MAX_SYMBOLS = 70
MAX_DEPENDENCIES = 70


class ScopeHold(Exception):
    """La preuve locale ne respecte pas la portée de lecture annoncée."""


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    if result.returncode:
        raise ScopeHold("GIT_CHECK_FAILED:" + "_".join(args[:2]))
    return result.stdout


def _public_symbols(body: list[ast.stmt]) -> list[dict]:
    def signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
        args = node.args
        return {
            "name": node.name,
            "parameters": [arg.arg for arg in args.posonlyargs + args.args + args.kwonlyargs],
            "positional_only": [arg.arg for arg in args.posonlyargs],
            "keyword_only": [arg.arg for arg in args.kwonlyargs],
            "variadic": bool(args.vararg or args.kwarg),
        }

    items: list[dict] = []
    for node in body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node.name.startswith("_"):
            continue
        if isinstance(node, ast.ClassDef):
            methods = [signature(child) for child in node.body if
                       isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and not child.name.startswith("_")]
            items.append({"kind": "class", "name": node.name, "public_methods": methods})
            continue
        items.append({
            "kind": "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
            **signature(node),
        })
    if len(items) > MAX_SYMBOLS or any(
        len(item.get("public_methods", ())) > MAX_SYMBOLS for item in items
    ):
        raise ScopeHold("TOO_MANY_PUBLIC_SYMBOLS")
    return items


def _imports(tree: ast.AST) -> list[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # Les noms de modules/imports suffisent, pas les valeurs source.
            prefix = "." * node.level + (node.module or "")
            names.add(prefix)
    relevant = sorted(name for name in names if name.startswith((
        "sigma", "periphery", "scripts", "obsidia", "obsidure", "."
    )))
    if len(relevant) > MAX_DEPENDENCIES:
        raise ScopeHold("TOO_MANY_IMPORT_REFERENCES")
    return relevant


def inspect_python(raw: bytes) -> dict:
    """Analyse uniquement AST ; aucun `exec`, `eval` ou import utilisateur."""
    if len(raw) > MAX_FILE_BYTES:
        raise ScopeHold("FILE_TOO_LARGE")
    try:
        tree = ast.parse(raw.decode("utf-8-sig"))
    except (SyntaxError, UnicodeError, ValueError) as exc:
        raise ScopeHold("SOURCE_AST_INVALID:" + type(exc).__name__) from exc
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "public_symbols": _public_symbols(tree.body),
        "static_imports": _imports(tree),
    }


def _read_checked(root: Path, rel: str, frozen_head: str = SOURCE_HEAD) -> bytes:
    file_path = root / rel
    if file_path.is_symlink() or not file_path.is_file():
        raise ScopeHold("FILE_MISSING_OR_LINK:" + rel)
    resolved = file_path.resolve(strict=True)
    if os.path.commonpath((str(root), str(resolved))) != str(root):
        raise ScopeHold("FILE_OUTSIDE_SOURCE:" + rel)
    if file_path.stat().st_size > MAX_FILE_BYTES:
        raise ScopeHold("FILE_TOO_LARGE:" + rel)
    raw = file_path.read_bytes()
    # Une branche peut avancer (Gencoin, par exemple) sans toucher aux rails
    # G1/G2. On accepte ce cas UNIQUEMENT si les octets sont strictement
    # identiques au commit K1 gelé ET au HEAD courant, sans appliquer de patch.
    if raw != _git(root, "show", frozen_head + ":" + rel):
        raise ScopeHold("SOURCE_FILE_DIFFERS_FROM_FROZEN_K1_HEAD:" + rel)
    if raw != _git(root, "show", "HEAD:" + rel):
        raise ScopeHold("SOURCE_FILE_DRIFT_FROM_CURRENT_HEAD:" + rel)
    return raw


def run() -> int:
    machine = platform.node().upper()
    if machine != PORTABLE_HOST:
        print("STOP=WRONG_MACHINE:" + machine)
        return 2
    root = (Path.home() / SOURCE_RELATIVE).resolve(strict=False)
    if not root.is_dir():
        print("STOP=K1_FIX_NOT_FOUND")
        return 2
    try:
        head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
        branch = _git(root, "branch", "--show-current").decode("utf-8").strip()
        print("MACHINE_VERIFIED=" + machine)
        print("FROZEN_SOURCE_HEAD=" + SOURCE_HEAD)
        print("CURRENT_HEAD=" + head)
        print("SOURCE_HEAD_ADVANCED=" + str(head != SOURCE_HEAD).lower())
        print("SOURCE_BRANCH=" + branch)
        print("MODE=AST_ONLY_NO_IMPORT_NO_COPY_NO_EXECUTION")
        for rel in FILES:
            contract = inspect_python(_read_checked(root, rel))
            print("ABI=" + json.dumps({"path": rel, **contract},
                                     ensure_ascii=True, separators=(",", ":")))
    except (ScopeHold, OSError, subprocess.TimeoutExpired) as exc:
        print("STOP=" + str(exc).replace("\n", " "))
        return 2
    print("K1_CANONICAL_ABI_READONLY_PASS=True")
    print("ALL_SIX_FILES_MATCH_FROZEN_K1_AND_CURRENT_HEAD=True")
    print("RELEASE_AUTHORIZATION=False")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
