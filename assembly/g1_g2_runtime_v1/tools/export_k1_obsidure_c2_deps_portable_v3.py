"""G1/G2 C2 V3 — closure of the canonical Obsidure proposal validator.

Desktop-Q5MD7J7 (portable) only. Source K1 FIX remains untouched.
CHECK_ONLY by default; --push explicitly publishes only bounded missing deps.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from export_k1_missing_deps_portable_v1 import (
    ASSEMBLY, DEST_BRANCH, SOURCE_BRANCH, SOURCE_MACHINE, SOURCE_REL,
    ExportHold, git, validate_repos,
)
from export_k1_c2_bridge_deps_portable_v2 import select_static_closure


SEEDS = ("scripts/obsidure_bounded_apply.py",)
MANIFEST = ASSEMBLY / "DEPS_PORTABLE_C2_OBSIDURE_MANIFEST.json"
MAX_FILES = 30
MAX_BYTES = 2_500_000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    source = Path.home() / SOURCE_REL
    dest = Path(__file__).resolve().parents[3]
    try:
        source_head, base_sha = validate_repos(source, dest)
        selected = select_static_closure(
            source, dest, seeds=SEEDS, manifest_path=MANIFEST,
            max_files=MAX_FILES, max_bytes=MAX_BYTES,
        )
        print(f"MACHINE_VERIFIED={SOURCE_MACHINE}")
        print(f"MODE={'PUBLIC_PUSH' if args.push else 'CHECK_ONLY'}")
        print(f"SOURCE_BRANCH={SOURCE_BRANCH}")
        print(f"SOURCE_HEAD={source_head}")
        print(f"DEST_BASE={base_sha}")
        print(f"FILES_SELECTED={len(selected)}")
        manifest = {
            "schema": "OBSIDIA_G1G2_PORTABLE_C2_OBSIDURE_CLOSURE_V3",
            "source_machine": SOURCE_MACHINE,
            "source_branch": SOURCE_BRANCH,
            "source_head": source_head,
            "destination_base_sha": base_sha,
            "captured_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "CANONICAL_C2_OBSIDURE_VALIDATOR_STATIC_DEPS_ONLY",
            "source_worktree_modified": False,
            "tests_executed": False,
            "runtime_activated": False,
            "files": [],
        }
        for rel, data in sorted(selected.items()):
            sha = hashlib.sha256(data).hexdigest()
            print(f"SOURCE={rel} SHA256={sha}")
            manifest["files"].append({"path": rel, "sha256": sha, "bytes": len(data)})
        if not args.push:
            print("C2_OBSIDURE_CHECK_PASS__REVIEW_FILES_BEFORE_PUBLIC_PUSH")
            return 0
        new_paths = []
        for rel, data in sorted(selected.items()):
            dst_file = dest / ASSEMBLY / rel
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            dst_file.write_bytes(data)
            if hashlib.sha256(dst_file.read_bytes()).digest() != hashlib.sha256(data).digest():
                raise ExportHold(f"DEST_SHA_MISMATCH:{rel}")
            new_paths.append((ASSEMBLY / rel).as_posix())
        manifest_file = dest / MANIFEST
        manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        new_paths.append(MANIFEST.as_posix())
        git(dest, "add", "--", *new_paths)
        if set(git(dest, "diff", "--cached", "--name-only").splitlines()) != set(new_paths):
            raise ExportHold("STAGED_FILES_UNEXPECTED__NO_COMMIT")
        git(dest, "diff", "--cached", "--check")
        git(dest, "commit", "-m", "Capture portable canonical Obsidure C2 validator deps")
        git(dest, "push", "origin", DEST_BRANCH)
        print("G1G2_C2_OBSIDURE_GITHUB_PUSH_PASS=True")
        print(f"DEST_COMMIT={git(dest, 'rev-parse', 'HEAD')}")
        print("SOURCE_WORKTREE_UNCHANGED=True")
        return 0
    except ExportHold as exc:
        print(f"STOP={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
