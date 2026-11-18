"""G1/G2 — AST des effets/retours Obsidure, en lecture seule sur le portable.

La sortie ne contient aucun corps de fonction, octet de proposition, secret
ou contenu de fichier. Elle n'autorise pas APPLY et n'importe aucun module
du FIX ; un appel indirect peut toujours avoir des effets non visibles.
"""
from __future__ import annotations

import ast
import hashlib
import json
import platform
import subprocess
from pathlib import Path

from inspect_canonical_k1_abi_portable_v1 import (
    PORTABLE_HOST, SOURCE_HEAD, SOURCE_RELATIVE, ScopeHold, _git, _read_checked,
)

_MODULE_ROOT = Path(__file__).resolve().parents[1]
_SNAPSHOT = _MODULE_ROOT / "contracts" / "K1_CANONICAL_ABI_SNAPSHOT_20261118.json"
TARGETS = {
    "periphery/agents/agent_obsidure.py": (
        "AgentObsidure.evaluate_repair_proposal",
        "AgentObsidure.get_last_repair_runtime_evidence",
        "AgentObsidure.apply_proposal",  # observer, ne jamais appeler
    ),
    "scripts/obsidure_bounded_apply.py": (
        "load_and_validate_proposal",
        "dryrun_bounded",
        "run_bounded_apply",  # observer, ne jamais appeler
        "run_obsidure_bounded_apply_pipeline",  # observer, ne jamais appeler
    ),
    "scripts/obsidia_family_wiring_apply_bridge_v0.py": (
        "build_child_execution_from_obsidure_proposal",
    ),
}
MAX_OUTPUT_CALLS = 240
MAX_RETURN_VARIANTS = 80
MAX_EFFECT_TARGETS = 120

_READS = {"read_bytes", "read_text", "open", "load", "loads"}
_WRITES = {
    "write_bytes", "write_text", "mkdir", "makedirs", "unlink", "remove",
    "rmdir", "rmtree", "rename", "replace", "touch", "write", "writelines",
    "dump", "dumps", "copy", "copy2", "copyfile", "move", "chmod",
}
_EXEC = {"run", "Popen", "call", "check_call", "check_output", "system", "exec", "eval"}
_NETWORK = {"connect", "send", "sendall", "post", "put", "delete", "urlopen", "request"}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    return "<dynamic>"


def _return_shape(value: ast.AST | None) -> dict:
    if value is None or (isinstance(value, ast.Constant) and value.value is None):
        return {"kind": "NONE"}
    if isinstance(value, ast.Dict):
        keys = [k.value for k in value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        # Seules les cles structurelles, jamais les valeurs ou les corps.
        return {"kind": "DICT", "keys": sorted(set(keys))[:40]}
    if isinstance(value, ast.Call):
        return {"kind": "CALL", "target": _name(value.func)}
    if isinstance(value, ast.Name):
        return {"kind": "NAME", "name": value.id}
    if isinstance(value, ast.Constant):
        return {"kind": "CONSTANT", "type": type(value.value).__name__}
    return {"kind": type(value).__name__.upper()}


def _get_function(tree: ast.Module, dotted: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    parts = dotted.split(".")
    scope: list[ast.stmt] = tree.body
    for owner in parts[:-1]:
        matches = [n for n in scope if isinstance(n, ast.ClassDef) and n.name == owner]
        if len(matches) != 1:
            raise ScopeHold("CANONICAL_CLASS_NOT_FOUND:" + dotted)
        scope = matches[0].body
    functions = [n for n in scope if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name == parts[-1]]
    if len(functions) != 1:
        raise ScopeHold("CANONICAL_FUNCTION_NOT_FOUND:" + dotted)
    return functions[0]


def inspect_effects(raw: bytes, path: str, entrypoints: tuple[str, ...]) -> dict:
    if len(raw) > 2_000_000:
        raise ScopeHold("SOURCE_TOO_LARGE:" + path)
    try:
        tree = ast.parse(raw.decode("utf-8-sig"))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise ScopeHold("SOURCE_AST_INVALID:" + type(exc).__name__) from exc
    inspected = {}
    for symbol in entrypoints:
        func = _get_function(tree, symbol)
        calls: set[str] = set()
        effect_calls: dict[str, set[str]] = {
            "file_reads_or_parses": set(), "possible_file_writes": set(),
            "possible_process_exec": set(), "possible_network": set(),
        }
        assigned_attributes: set[str] = set()
        returns: list[dict] = []
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                call = _name(node.func)
                calls.add(call)
                name = call.rsplit(".", 1)[-1]
                if name in _READS:
                    effect_calls["file_reads_or_parses"].add(call)
                if name in _WRITES:
                    effect_calls["possible_file_writes"].add(call)
                if name in _EXEC:
                    effect_calls["possible_process_exec"].add(call)
                if name in _NETWORK:
                    effect_calls["possible_network"].add(call)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Attribute):
                        assigned_attributes.add(_name(target))
            elif isinstance(node, ast.Return):
                shape = _return_shape(node.value)
                if shape not in returns:
                    returns.append(shape)
        if len(calls) > MAX_OUTPUT_CALLS or len(returns) > MAX_RETURN_VARIANTS or len(assigned_attributes) > MAX_EFFECT_TARGETS:
            raise ScopeHold("EFFECT_INSPECTION_OUTPUT_TOO_LARGE:" + symbol)
        inspected[symbol] = {
            "return_shapes": returns,
            "direct_calls": sorted(calls),
            "direct_effect_indicators": {key: sorted(value) for key, value in effect_calls.items()},
            "attribute_assignments": sorted(assigned_attributes),
            "effect_certification": "INDETERMINATE_STATIC_ONLY",
        }
    return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "entrypoints": inspected}


def run() -> int:
    machine = platform.node().upper()
    if machine != PORTABLE_HOST:
        print("STOP=WRONG_MACHINE:" + machine)
        return 2
    source_root = (Path.home() / SOURCE_RELATIVE).resolve(strict=False)
    if not source_root.is_dir():
        print("STOP=K1_FIX_NOT_FOUND")
        return 2
    try:
        snapshot = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
        if snapshot.get("frozen_k1_head") != SOURCE_HEAD or snapshot.get("source_machine") != PORTABLE_HOST:
            raise ScopeHold("PINNED_SNAPSHOT_MISMATCH")
        expected = {item["path"]: item for item in snapshot["files"]}
        current_head = _git(source_root, "rev-parse", "HEAD").decode("ascii").strip()
        print("MACHINE_VERIFIED=" + machine)
        print("FROZEN_SOURCE_HEAD=" + SOURCE_HEAD)
        print("CURRENT_HEAD=" + current_head)
        print("MODE=AST_ONLY_NO_IMPORT_NO_COPY_NO_EXECUTION")
        for path, symbols in TARGETS.items():
            spec = expected.get(path)
            if not spec or set(spec.get("entrypoints", {})) != set(symbols):
                raise ScopeHold("PINNED_ENTRYPOINTS_MISMATCH:" + path)
            raw = _read_checked(source_root, path)
            if hashlib.sha256(raw).hexdigest() != spec["sha256"]:
                raise ScopeHold("PINNED_SHA256_MISMATCH:" + path)
            effects = inspect_effects(raw, path, symbols)
            print("EFFECT=" + json.dumps(effects, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    except (ScopeHold, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print("STOP=" + str(exc).replace("\n", " "))
        return 2
    print("K1_OBSIDURE_EFFECTS_READONLY_PASS=True")
    print("RUNTIME_BEHAVIOR_PROVEN=False")
    print("RELEASE_AUTHORIZATION=False")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
