"""Audit AST borné du producteur C278 existant sur le PC portable.

Jamais d'import d'Obsidure, pas d'exécution du runner/tests, pas de copie,
pas de modification du FIX ou de la branche Git. La lecture du code ne
constitue pas une attestation du processus de test historique.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

_MACHINE = "DESKTOP-Q5MD7J7"
_RELATIVE = (
    "periphery/agents/obsidure_repair_bridge.py",
    "periphery/agents/obsidure_repair_contract.py",
    "periphery/agents/agent_obsidure.py",
)
_SYMBOLS = ("test_repair_proposal", "_run_declared_tests")
_MAX_SOURCE_BYTES = 2_000_000


def _git_read(repo: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "UNAVAILABLE"
    return proc.stdout.strip() if proc.returncode == 0 else "UNAVAILABLE"


def _call_target(node: ast.Call) -> str:
    target = node.func
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        prefix = target.value
        if isinstance(prefix, ast.Name):
            return prefix.id + "." + target.attr
        return target.attr
    return "DYNAMIC"


def profile_producer_source(source: str) -> dict[str, object]:
    """Analyse statique : indicateurs, jamais verdict d'isolation certifiée."""
    tree = ast.parse(source)
    found = {node.name: node for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    symbols: dict[str, object] = {}
    for name in _SYMBOLS:
        func = found.get(name)
        if func is None:
            symbols[name] = {"present": False}
            continue
        calls = sorted({_call_target(node) for node in ast.walk(func)
                        if isinstance(node, ast.Call)})
        assigned_literals = sorted({node.value for node in ast.walk(func)
                                    if isinstance(node, ast.Constant)
                                    and isinstance(node.value, str)
                                    and node.value in ("FULL", "PARTIAL", "PYTHONPATH")})
        symbols[name] = {
            "present": True,
            "line": func.lineno,
            "subprocess_run_call": "subprocess.run" in calls,
            "sandbox_write_calls": [x for x in calls if x in (
                "mkdir", "write_text", "write_bytes", "open", "copy2",
                "sb.mkdir", "out.write_text", "out.parent.mkdir",
            )],
            "direct_signature_calls": [x for x in calls if x in (
                "SignData", "sign", "sign_data", "private.sign", "hmac.new",
                "rsa.sign", "receipt.sign",
            )],
            "literal_isolation_labels": assigned_literals,
        }
    return {
        "required_symbols_present": all(symbols[name]["present"] for name in _SYMBOLS),
        "symbols": symbols,
        "signed_test_process_proven": False,
        "real_import_origin_proven": False,
        "sandbox_test_execution_proven": False,
        "human_approval_verified": False,
        "release_authorized": False,
    }


def _safe_path_under(repo: Path, rel: str) -> Path | None:
    candidate = repo / rel
    for item in (repo, *[repo / Path(*Path(rel).parts[:i])
                         for i in range(1, len(Path(rel).parts) + 1)]):
        if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
            return None
    return candidate if candidate.is_file() else None


def inspect_portable_fix() -> dict[str, object]:
    machine = os.environ.get("COMPUTERNAME", "").upper()
    if machine != _MACHINE:
        return {"status": "HOLD", "reason": "C278_WRONG_MACHINE", "machine": machine}
    repo = (Path.home() / ".codex" / "visualizations" / "2026" / "11"
            / "kx108_zero_vote_guard_fix")
    if not repo.is_dir() or _git_read(repo, "rev-parse", "--show-toplevel") == "UNAVAILABLE":
        return {"status": "HOLD", "reason": "C278_FIX_REPO_NOT_FOUND"}
    files: dict[str, object] = {}
    for rel in _RELATIVE:
        path = _safe_path_under(repo, rel)
        if path is None or path.stat().st_size > _MAX_SOURCE_BYTES:
            return {"status": "HOLD", "reason": "C278_SOURCE_MISSING_OR_UNSAFE", "path": rel}
        data = path.read_bytes()
        if len(data) > _MAX_SOURCE_BYTES or data != path.read_bytes():
            return {"status": "HOLD", "reason": "C278_SOURCE_CHANGED_DURING_AUDIT", "path": rel}
        files[rel] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        if rel == _RELATIVE[0]:
            try:
                files[rel]["ast_profile"] = profile_producer_source(data.decode("utf-8-sig"))
            except (UnicodeError, SyntaxError):
                return {"status": "HOLD", "reason": "C278_SOURCE_AST_PARSE_FAILED", "path": rel}
    p = files[_RELATIVE[0]]["ast_profile"]
    if not p["required_symbols_present"]:
        return {
            "status": "HOLD", "reason": "C278_REQUIRED_PRODUCER_SYMBOLS_MISSING",
            "machine": machine, "git_head": _git_read(repo, "rev-parse", "HEAD"),
            "files": files,
        }
    return {
        "status": "C278_STATIC_SOURCE_PROFILE_ONLY",
        "machine": machine,
        "repo": str(repo),
        "git_head": _git_read(repo, "rev-parse", "HEAD"),
        "git_branch": _git_read(repo, "branch", "--show-current"),
        "mode": "AST_ONLY_NO_IMPORT_NO_EXECUTION_NO_COPY_NO_WRITE",
        "files": files,
        "required_symbols_present": p["required_symbols_present"],
        "test_process_attested": False,
        "test_isolation_certified": False,
        "signed_receipt_created": False,
        "source_worktree_modified": False,
        "kx108_authority": "UNCHANGED",
        "release": "HOLD",
    }


def main() -> int:
    try:
        result = inspect_portable_fix()
    except (OSError, ValueError):
        result = {"status": "HOLD", "reason": "C278_READONLY_INSPECTION_FAILED"}
    print("C278_PRODUCER_PROFILE=" + json.dumps(
        result, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ))
    if result["status"] != "C278_STATIC_SOURCE_PROFILE_ONLY":
        return 2
    print("C278_PRODUCER_STATIC_READONLY_PASS=True")
    print("C278_TEST_PROVENANCE_ATTESTED=False")
    print("C278_SIGNER_JOIN=HOLD")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
