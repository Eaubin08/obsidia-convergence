"""G1/G2 V2 : complète la chaîne de dépendances du bridge C2 sur le portable.

Ne remplace aucun fichier du paquet existant. Capture le bridge manquant,
puis suit ses imports Python statiquement (fichiers G1/G2 uniquement).
Par défaut : CHECK_ONLY. --push explicite : commit + push du complément.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from export_k1_missing_deps_portable_v1 import (
    ASSEMBLY, DEST_BRANCH, SOURCE_MACHINE, SOURCE_REL,
    ExportHold, git, guarded_read, validate_repos,
)


SEED = ("scripts/obsidia_family_wiring_apply_bridge_v0.py",)
MANIFEST = ASSEMBLY / "DEPS_PORTABLE_C2_BRIDGE_MANIFEST.json"
MAX_CAPTURE_FILES = 20
MAX_CAPTURE_BYTES = 1_400_000


def _module_path(name: str) -> str | None:
    """Only source modules within the explicitly scoped governance rails."""
    if name.startswith("obsidia_") and name not in (
        "obsidia_cli", "obsidia_gateway", "obsidia_api",
    ):
        return f"scripts/{name}.py"
    if name.startswith("scripts.obsidia_"):
        return f"scripts/{name.removeprefix('scripts.').replace('.', '/')}.py"
    for base in ("sigma.domains.", "sigma.", "periphery.world_calls."):
        if name.startswith(base):
            suffix = name[len(base):]
            if not suffix or not all(part.isidentifier() for part in suffix.split(".")):
                return None
            if base == "sigma.domains.":
                return "sigma/domains/" + suffix.replace(".", "/") + ".py"
            if base == "sigma.":
                return "sigma/" + suffix.replace(".", "/") + ".py"
            return "periphery/world_calls/" + suffix.replace(".", "/") + ".py"
    return None


def _static_imports(raw: bytes, source_name: str) -> set[str]:
    try:
        tree = ast.parse(raw.decode("utf-8-sig"), filename=source_name)
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise ExportHold(f"SOURCE_AST_INVALID:{source_name}") from exc
    deps = set()
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue
            names = [node.module or ""]
            if node.module in ("scripts", "sigma.domains", "sigma", "periphery.world_calls"):
                names.extend(f"{node.module}.{alias.name}" for alias in node.names)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr == "import_module" and node.args
              and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str)):
            names = [node.args[0].value]
        for name in names:
            rel = _module_path(name)
            if rel and rel != source_name:
                deps.add(rel)
    return deps


def select_bridge_closure(source: Path, dest: Path) -> dict[str, bytes]:
    queued = list(SEED)
    visited: set[str] = set()
    selected: dict[str, bytes] = {}
    while queued:
        rel = queued.pop(0)
        if rel in visited:
            continue
        visited.add(rel)
        target = dest / ASSEMBLY / rel
        if target.exists():
            if target.is_symlink() or target.is_junction() or not target.is_file():
                raise ExportHold(f"ASSEMBLY_TARGET_REDIRECTED:{rel}")
            continue
        if not (source / rel).is_file():
            raise ExportHold(f"SOURCE_DEPENDENCY_MISSING:{rel}")
        raw = guarded_read(source, rel)
        selected[rel] = raw
        if len(selected) > MAX_CAPTURE_FILES or sum(map(len, selected.values())) > MAX_CAPTURE_BYTES:
            raise ExportHold("C2_DEPENDENCY_CLOSURE_TOO_LARGE__REVIEW_REQUIRED")
        for found in sorted(_static_imports(raw, rel)):
            if found not in visited and (source / found).is_file():
                queued.append(found)
    if not selected:
        raise ExportHold("C2_BRIDGE_ALREADY_CAPTURED__NO_CHANGES")
    if (dest / MANIFEST).exists():
        raise ExportHold("C2_BRIDGE_MANIFEST_ALREADY_EXISTS__NO_OVERWRITE")
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    source = Path.home() / SOURCE_REL
    dest = Path(__file__).resolve().parents[3]
    try:
        source_head, base_sha = validate_repos(source, dest)
        selected = select_bridge_closure(source, dest)
        print(f"MACHINE_VERIFIED={SOURCE_MACHINE}")
        print(f"MODE={'PUBLIC_PUSH' if args.push else 'CHECK_ONLY'}")
        print(f"SOURCE_HEAD={source_head}")
        print(f"FILES_SELECTED={len(selected)}")
        manifest = {
            "schema": "OBSIDIA_G1G2_PORTABLE_C2_DEPENDENCY_CLOSURE_V2",
            "source_machine": SOURCE_MACHINE,
            "source_head": source_head,
            "destination_base_sha": base_sha,
            "captured_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "C2_BRIDGE_STATIC_DEPENDENCY_CLOSURE_ONLY",
            "source_worktree_modified": False,
            "tests_executed": False,
            "files": [],
        }
        for rel, content in sorted(selected.items()):
            sha = hashlib.sha256(content).hexdigest()
            manifest["files"].append({"path": rel, "sha256": sha, "bytes": len(content)})
            print(f"SOURCE={rel} SHA256={sha}")
        if not args.push:
            print("C2_CLOSURE_CHECK_PASS__REVIEW_BEFORE_PUBLIC_PUSH")
            return 0
        new_paths: list[str] = []
        for rel, content in sorted(selected.items()):
            target = dest / ASSEMBLY / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            if hashlib.sha256(target.read_bytes()).hexdigest() != hashlib.sha256(content).hexdigest():
                raise ExportHold(f"DEST_SHA_MISMATCH:{rel}")
            new_paths.append((ASSEMBLY / rel).as_posix())
        report = dest / MANIFEST
        report.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        new_paths.append(MANIFEST.as_posix())
        git(dest, "add", "--", *new_paths)
        if set(git(dest, "diff", "--cached", "--name-only").splitlines()) != set(new_paths):
            raise ExportHold("STAGED_FILES_UNEXPECTED__NO_COMMIT")
        git(dest, "commit", "-m", "Capture portable C2 bridge and bounded static dependencies")
        git(dest, "push", "origin", DEST_BRANCH)
        print("G1G2_C2_BRIDGE_GITHUB_PUSH_PASS=True")
        print(f"DEST_COMMIT={git(dest, 'rev-parse', 'HEAD')}")
        print("SOURCE_WORKTREE_UNCHANGED=True")
        return 0
    except ExportHold as exc:
        print(f"STOP={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
