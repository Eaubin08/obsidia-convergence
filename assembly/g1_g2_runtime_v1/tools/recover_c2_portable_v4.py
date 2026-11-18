"""Recover the staged C2 V3 export and close its local Python imports.

Portable DESKTOP-Q5MD7J7 only. No FIX mutation, service start, or runtime APPLY.
CHECK_ONLY by default. --push copies only verified missing import dependencies
and commits the exact V3 files already staged after its whitespace-check stop.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from export_k1_missing_deps_portable_v1 import (
    ASSEMBLY, DEST_BRANCH, ORIGIN, SOURCE_BRANCH, SOURCE_MACHINE, SOURCE_REL,
    ExportHold, git, guarded_read,
)


V3_SOURCE = "scripts/obsidure_bounded_apply.py"
V3_SHA256 = "4908e421a031752057a7b92c35ab942dafffb2b726f235be3fadb2bd86fca5cf"
SOURCE_FROZEN_HEAD = "ecaf6729f1bcdb05bb8896b7c698d1ae90e56de7"
SOURCE_ACCEPTED_BRANCHES = frozenset({
    SOURCE_BRANCH,
    "feat/gencoin-world-bus-dryrun-v1",
})
EXCLUDED_CONCURRENT_WIP = frozenset({"periphery/world_calls/world_action_bus.py"})
V3_MANIFEST = ASSEMBLY / "DEPS_PORTABLE_C2_OBSIDURE_MANIFEST.json"
V4_MANIFEST = ASSEMBLY / "DEPS_PORTABLE_C2_RECOVERY_MANIFEST.json"
KNOWN_STAGED = {
    (ASSEMBLY / V3_SOURCE).as_posix(), V3_MANIFEST.as_posix(),
}
MAX_NEW_FILES = 50
MAX_NEW_BYTES = 3_000_000
MAX_SCANNED = 120
SEEDS = (V3_SOURCE,)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_recovery(source: Path, dest: Path) -> tuple[str, str, str]:
    if os.environ.get("COMPUTERNAME", "").upper() != SOURCE_MACHINE:
        raise ExportHold("WRONG_MACHINE__PORTABLE_ONLY")
    if not source.is_dir() or not dest.is_dir():
        raise ExportHold("SOURCE_OR_DEST_MISSING")
    if Path(git(source, "rev-parse", "--show-toplevel")).resolve() != source.resolve():
        raise ExportHold("SOURCE_IS_NOT_K1_FIX")
    source_branch = git(source, "branch", "--show-current")
    if source_branch not in SOURCE_ACCEPTED_BRANCHES:
        raise ExportHold("SOURCE_BRANCH_NOT_IN_VERIFIED_SET")
    source_head = git(source, "rev-parse", "HEAD")
    if source_head != SOURCE_FROZEN_HEAD:
        raise ExportHold("SOURCE_HEAD_CHANGED__REVIEW_REQUIRED")
    if Path(git(dest, "rev-parse", "--show-toplevel")).resolve() != dest.resolve():
        raise ExportHold("DEST_REPO_MISMATCH")
    if git(dest, "branch", "--show-current") != DEST_BRANCH:
        raise ExportHold("DEST_BRANCH_MISMATCH")
    remote = git(dest, "remote", "get-url", "origin").rstrip("/").removesuffix(".git")
    if remote != ORIGIN:
        raise ExportHold("DEST_REMOTE_MISMATCH")
    head = git(dest, "rev-parse", "HEAD")
    upstream = git(dest, "ls-remote", "origin", f"refs/heads/{DEST_BRANCH}").split()
    if not upstream or head != upstream[0]:
        raise ExportHold("DEST_NOT_AT_REMOTE_HEAD__PULL_FF_ONLY")
    if git(dest, "diff", "--name-only"):
        raise ExportHold("UNSTAGED_USER_CHANGES__PRESERVE")
    if git(dest, "ls-files", "--others", "--exclude-standard"):
        raise ExportHold("UNTRACKED_USER_FILES__PRESERVE")
    staged = set(git(dest, "diff", "--cached", "--name-only").splitlines())
    if staged != KNOWN_STAGED:
        raise ExportHold("UNEXPECTED_STAGED_CHANGES__PRESERVE")
    for indexed_rel in KNOWN_STAGED:
        if git(dest, "rev-parse", f":{indexed_rel}") != git(dest, "hash-object", "--", indexed_rel):
            raise ExportHold(f"INDEX_DIFFERS_FROM_WORKTREE:{indexed_rel}")
    source_bytes = guarded_read(source, V3_SOURCE)
    if sha256(source_bytes) != V3_SHA256:
        raise ExportHold("SOURCE_V3_SHA_MISMATCH__NO_OVERRIDE")
    staged_copy = dest / ASSEMBLY / V3_SOURCE
    if not staged_copy.is_file() or staged_copy.is_symlink() or sha256(staged_copy.read_bytes()) != V3_SHA256:
        raise ExportHold("STAGED_V3_SOURCE_DIFFERENT__PRESERVE")
    manifest_path = dest / V3_MANIFEST
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ExportHold("STAGED_V3_MANIFEST_MISSING")
    try:
        old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ExportHold("STAGED_V3_MANIFEST_INVALID") from exc
    items = old_manifest.get("files", [])
    if (old_manifest.get("source_machine") != SOURCE_MACHINE
            or len(items) != 1 or items[0].get("path") != V3_SOURCE
            or items[0].get("sha256") != V3_SHA256):
        raise ExportHold("STAGED_V3_MANIFEST_CONTRACT_MISMATCH")
    return source_head, head, source_branch


def guard_selected_source_changes(source: Path, selected: dict[str, bytes]) -> None:
    """Never publish the concurrent world-bus WIP or unstaged source edits."""
    if EXCLUDED_CONCURRENT_WIP.intersection(selected):
        raise ExportHold("CONCURRENT_WORLD_BUS_WIP_OUT_OF_SCOPE")
    changed = set(git(source, "diff", "--name-only").splitlines())
    changed.update(git(source, "diff", "--cached", "--name-only").splitlines())
    changed.update(git(source, "ls-files", "--others", "--exclude-standard").splitlines())
    conflicted = changed.intersection(selected)
    if conflicted:
        raise ExportHold("SELECTED_SOURCE_HAS_UNREVIEWED_WIP:" + ",".join(sorted(conflicted)))


def _project_file(module: str, source: Path, dest: Path) -> str | None:
    """Map only imported modules within the active governance Python project."""
    if not module or not all(p.isidentifier() for p in module.split(".")):
        return None
    if module.startswith(("sigma.", "periphery.", "scripts.")):
        rel = module.replace(".", "/") + ".py"
    elif module.startswith(("obsidia_", "obsidure_")):
        rel = "scripts/" + module + ".py"
    elif "." not in module and (source / "scripts" / (module + ".py")).is_file():
        rel = "scripts/" + module + ".py"
    else:
        return None
    if module in ("obsidia_cli", "obsidia_gateway", "obsidia_api"):
        raise ExportHold(f"UNRELATED_RUNTIME_IMPORT_REVIEW_REQUIRED:{module}")
    if (source / rel).is_file() or (dest / ASSEMBLY / rel).is_file():
        return rel
    package_init = rel.removesuffix(".py") + "/__init__.py"
    if ((source / package_init).is_file()
            or (dest / ASSEMBLY / package_init).is_file()):
        return package_init
    return None


def _imports(raw: bytes, rel: str, source: Path, dest: Path) -> set[str]:
    try:
        tree = ast.parse(raw.decode("utf-8-sig"), filename=rel)
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise ExportHold(f"SOURCE_AST_INVALID:{rel}") from exc
    result: set[str] = set()
    current_package = rel[:-3].split("/")[:-1]

    def add(module: str, *, required: bool = False) -> None:
        mapped = _project_file(module, source, dest)
        if mapped:
            result.add(mapped)
        # Mandatory namespace-module imports must exist, even as packages.
        elif required and module.startswith(("periphery.", "sigma.", "scripts.")):
            pkg = module.replace(".", "/")
            if not (source / pkg).is_dir() and not (dest / ASSEMBLY / pkg).is_dir():
                raise ExportHold(f"PROJECT_MODULE_MISSING:{module}:{rel}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name, required=True)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level > len(current_package):
                    raise ExportHold(f"RELATIVE_IMPORT_OUT_OF_SCOPE:{rel}")
                base = ".".join(current_package[:len(current_package) - node.level + 1])
                module = ".".join(filter(None, (base, node.module or "")))
            else:
                module = node.module or ""
            if module:
                add(module, required=True)
            for alias in node.names:
                if alias.name != "*":
                    add(".".join(filter(None, (module, alias.name))))
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr == "import_module" and node.args
              and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str)):
            add(node.args[0].value)
    return result


def _package_inits(rel: str, source: Path, dest: Path) -> set[str]:
    parts = Path(rel).parts[:-1]
    result = set()
    for i in range(1, len(parts) + 1):
        candidate = "/".join(parts[:i]) + "/__init__.py"
        if (source / candidate).is_file() or (dest / ASSEMBLY / candidate).is_file():
            result.add(candidate)
    return result


def collect_recovery(source: Path, dest: Path) -> dict[str, bytes]:
    queued = deque(SEEDS)
    visited: set[str] = set()
    selected: dict[str, bytes] = {}
    while queued:
        rel = queued.popleft()
        if rel in visited:
            continue
        visited.add(rel)
        if len(visited) > MAX_SCANNED:
            raise ExportHold("DEPENDENCY_GRAPH_TOO_WIDE__HOLD")
        installed = dest / ASSEMBLY / rel
        if installed.exists():
            if installed.is_symlink() or installed.is_junction() or not installed.is_file():
                raise ExportHold(f"INSTALLED_IMPORT_REDIRECTED:{rel}")
            raw = installed.read_bytes()
        else:
            raw = guarded_read(source, rel)
            selected[rel] = raw
            if len(selected) > MAX_NEW_FILES or sum(map(len, selected.values())) > MAX_NEW_BYTES:
                raise ExportHold("C2_DEPENDENCY_CLOSURE_TOO_LARGE__HOLD")
        for dependency in sorted(_imports(raw, rel, source, dest) | _package_inits(rel, source, dest)):
            if dependency not in visited:
                queued.append(dependency)
    if (dest / V4_MANIFEST).exists():
        raise ExportHold("V4_MANIFEST_ALREADY_EXISTS__NO_REWRITE")
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    source = Path.home() / SOURCE_REL
    dest = Path(__file__).resolve().parents[3]
    try:
        source_head, base_sha, source_branch = validate_recovery(source, dest)
        selected = collect_recovery(source, dest)
        guard_selected_source_changes(source, selected)
        print(f"MACHINE_VERIFIED={SOURCE_MACHINE}")
        print(f"MODE={'PUBLIC_PUSH' if args.push else 'CHECK_ONLY'}")
        print(f"SOURCE_BRANCH={source_branch}")
        print(f"SOURCE_HEAD={source_head}")
        print(f"DEST_BASE={base_sha}")
        print("RECOVERING_STAGED_V3_FILES=2")
        print(f"EXTRA_FILES_SELECTED={len(selected)}")
        record = []
        for rel, raw in sorted(selected.items()):
            digest = sha256(raw)
            print(f"SOURCE={rel} SHA256={digest} BYTES={len(raw)}")
            record.append({"path": rel, "sha256": digest, "bytes": len(raw)})
        if not args.push:
            print("RECOVERY_CLOSURE_CHECK_PASS__REVIEW_BEFORE_PUBLIC_PUSH")
            return 0
        added_paths = []
        for rel, raw in sorted(selected.items()):
            target = dest / ASSEMBLY / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if sha256(target.read_bytes()) != sha256(raw):
                raise ExportHold(f"DEST_SHA_MISMATCH:{rel}")
            added_paths.append((ASSEMBLY / rel).as_posix())
        manifest = {
            "schema": "OBSIDIA_G1G2_C2_PORTABLE_STAGED_RECOVERY_V4",
            "source_machine": SOURCE_MACHINE,
            "source_branch": source_branch,
            "source_head": source_head,
            "destination_base_sha": base_sha,
            "captured_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "STAGED_V3_PLUS_BOUNDED_C2_OBSIDURE_IMPORT_CLOSURE",
            "staged_v3_source_sha256": V3_SHA256,
            "source_worktree_modified": False,
            "runtime_activated": False,
            "production_apply": False,
            "files": record,
        }
        manifest_path = dest / V4_MANIFEST
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        added_paths.append(V4_MANIFEST.as_posix())
        git(dest, "add", "--", *added_paths)
        if set(git(dest, "diff", "--cached", "--name-only").splitlines()) != KNOWN_STAGED | set(added_paths):
            raise ExportHold("STAGED_FILES_CHANGED__NO_COMMIT")
        # V3 failed solely on git diff --check; preserve byte-identical K1 code.
        # An existing source formatting issue is not a governance authorization.
        git(dest, "commit", "-m", "Recover staged C2 validator and its bounded governance dependencies")
        git(dest, "push", "origin", DEST_BRANCH)
        print("G1G2_C2_RECOVERY_GITHUB_PUSH_PASS=True")
        print(f"DEST_COMMIT={git(dest, 'rev-parse', 'HEAD')}")
        print("SOURCE_WORKTREE_UNCHANGED=True")
        return 0
    except ExportHold as exc:
        print(f"STOP={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
