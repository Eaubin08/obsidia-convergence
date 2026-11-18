"""Ciblage G1/G2 : compléter UNIQUEMENT les dépendances manquantes du portable.

Source : DESKTOP-Q5MD7J7, FIX K1 réel (jamais le PC fixe).
Destination : clone obsidia-convergence, branche build/g1-g2-runtime-v1.

Sans --push : vérifications et inventaire uniquement. Avec --push : copie
des fichiers autorisés, manifest SHA256, commit et push. Pas d'import de code,
pas de lancement de tests, aucun serveur et aucune modification du FIX.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SOURCE_MACHINE = "DESKTOP-Q5MD7J7"
SOURCE_REL = Path(".codex/visualizations/2026/11/kx108_zero_vote_guard_fix")
SOURCE_BRANCH = "fix/kx108-zero-vote-guard-v1"
DEST_BRANCH = "build/g1-g2-runtime-v1"
ORIGIN = "https://github.com/Eaubin08/obsidia-convergence"
ASSEMBLY = Path("assembly/g1_g2_runtime_v1")
MANIFEST_REL = ASSEMBLY / "DEPS_PORTABLE_IMPORT_MANIFEST.json"
MAX_BYTES = 2_000_000

# Les imports effectivement absents du paquet 34 K1 V5, plus la fixture C2.
# Ni CLI, ni API, ni Brody, ni serveurs, ni sous-dossiers étrangers au G1/G2.
REQUIRED = (
    "sigma/registry.py",
    "sigma/domains/bank_agents.py",
    "sigma/domains/ecom_agents.py",
    "sigma/domains/meta_agents.py",
    "sigma/domains/gps_defense_aviation_agents.py",
    "sigma/domains/tooling_build_agents.py",
    "sigma/domains/trading_agents.py",
    "scripts/obsidia_candidate_patch_v1.py",
    "scripts/obsidia_bounded_mission_v0.py",
    "scripts/obsidia_mission_authority_v0.py",
    "scripts/obsidia_mission_authority_integration_v0.py",
    "tests/cli/test_governed_content_apply_c2_v0.py",
)
OPTIONAL = ("sigma/__init__.py", "sigma/domains/__init__.py")
KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)
TOKEN_RE = re.compile(
    rb"(?i)(ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
    rb"sk-proj-[a-z0-9_-]{20,}|xoxb-[a-z0-9-]{20,}|"
    rb"AKIA[A-Z0-9]{16})"
)


class ExportHold(Exception):
    pass


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], text=True, capture_output=True,
        encoding="utf-8", errors="replace", check=False,
    )
    if result.returncode:
        raise ExportHold(f"GIT_FAILED:{' '.join(args)}:{result.stderr.strip()[:250]}")
    return result.stdout.strip()


def guarded_read(root: Path, rel: str) -> bytes:
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts or p.suffix != ".py":
        raise ExportHold(f"INVALID_PATH:{rel}")
    target = root / p
    if not target.is_file() or target.is_symlink() or target.is_junction():
        raise ExportHold(f"FILE_MISSING_OR_REDIRECTED:{rel}")
    if not target.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
        raise ExportHold(f"OUTSIDE_SOURCE:{rel}")
    if target.stat().st_size > MAX_BYTES:
        raise ExportHold(f"FILE_TOO_LARGE:{rel}")
    content = target.read_bytes()
    if b"\x00" in content:
        raise ExportHold(f"BINARY_NOT_ALLOWED:{rel}")
    try:
        content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ExportHold(f"NOT_UTF8:{rel}")
    if any(k in content for k in KEY_MARKERS) or TOKEN_RE.search(content):
        raise ExportHold(f"POTENTIAL_SECRET_PUBLICATION_REFUSED:{rel}")
    return content


def validate_repos(source: Path, dest: Path) -> tuple[str, str]:
    machine = os.environ.get("COMPUTERNAME", "").upper()
    if machine != SOURCE_MACHINE:
        raise ExportHold(f"WRONG_MACHINE:{machine}")
    if not source.is_dir() or not dest.is_dir():
        raise ExportHold("PORTABLE_FIX_OR_CONVERGENCE_CLONE_MISSING")
    if Path(git(source, "rev-parse", "--show-toplevel")).resolve() != source.resolve():
        raise ExportHold("NOT_THE_K1_FIX_WORKTREE")
    if git(source, "branch", "--show-current") != SOURCE_BRANCH:
        raise ExportHold("K1_FIX_BRANCH_MISMATCH")
    if Path(git(dest, "rev-parse", "--show-toplevel")).resolve() != dest.resolve():
        raise ExportHold("NOT_CONVERGENCE_REPO")
    if git(dest, "branch", "--show-current") != DEST_BRANCH:
        raise ExportHold("DEST_BRANCH_MISMATCH")
    remote = git(dest, "remote", "get-url", "origin").rstrip("/").removesuffix(".git")
    if remote != ORIGIN:
        raise ExportHold("DEST_ORIGIN_MISMATCH")
    if git(dest, "status", "--porcelain", "--untracked-files=all"):
        raise ExportHold("DEST_DIRTY__PRESERVE_USER_CHANGES")
    local_sha = git(dest, "rev-parse", "HEAD")
    remote_sha = git(dest, "ls-remote", "origin", f"refs/heads/{DEST_BRANCH}").split()
    if not remote_sha or local_sha != remote_sha[0]:
        raise ExportHold("DEST_NOT_AT_REMOTE_HEAD__GIT_PULL_FF_ONLY")
    return git(source, "rev-parse", "HEAD"), local_sha


def collect(source: Path, dest: Path, source_head: str) -> tuple[dict[str, bytes], dict]:
    selected: dict[str, bytes] = {}
    for rel in REQUIRED:
        selected[rel] = guarded_read(source, rel)
    for rel in OPTIONAL:
        if (source / rel).is_file():
            selected[rel] = guarded_read(source, rel)

    manifest_files = []
    for rel, data in sorted(selected.items()):
        target = dest / ASSEMBLY / rel
        if target.exists():
            if target.is_symlink() or target.is_junction() or target.read_bytes() != data:
                raise ExportHold(f"DEST_TARGET_EXISTS_DIFFERENT:{rel}")
        manifest_files.append({
            "path": rel, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "source_head": source_head,
        })
    if (dest / MANIFEST_REL).exists():
        raise ExportHold("MANIFEST_ALREADY_EXISTS__NO_OVERWRITE")
    return selected, {
        "schema": "OBSIDIA_G1G2_PORTABLE_MISSING_DEPS_V1",
        "source_machine": SOURCE_MACHINE,
        "source_branch": SOURCE_BRANCH,
        "source_head": source_head,
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "destination_branch": DEST_BRANCH,
        "scope": "ONLY_MISSING_G1_G2_K1_DEPENDENCIES",
        "source_worktree_modified": False,
        "tests_executed": False,
        "runtime_activated": False,
        "files": manifest_files,
    }


def publish(dest: Path, selected: dict[str, bytes], manifest: dict) -> None:
    new_paths: list[str] = []
    for rel, data in sorted(selected.items()):
        target = dest / ASSEMBLY / rel
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            if hashlib.sha256(target.read_bytes()).hexdigest() != hashlib.sha256(data).hexdigest():
                raise ExportHold(f"DEST_COPY_HASH_MISMATCH:{rel}")
            new_paths.append((ASSEMBLY / rel).as_posix())
    mp = dest / MANIFEST_REL
    mp.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    new_paths.append(MANIFEST_REL.as_posix())
    git(dest, "add", "--", *new_paths)
    staged = set(git(dest, "diff", "--cached", "--name-only").splitlines())
    if staged != set(new_paths):
        raise ExportHold("STAGING_UNEXPECTED_FILES__NO_COMMIT")
    git(dest, "commit", "-m", "Capture portable K1 G1G2 missing runtime dependencies")
    git(dest, "push", "origin", DEST_BRANCH)
    print("G1G2_DEPS_GITHUB_PUSH_PASS=True")
    print(f"DEST_COMMIT={git(dest, 'rev-parse', 'HEAD')}")
    print(f"FILES_COPIED={len(selected)}")
    print("SOURCE_WORKTREE_UNCHANGED=True")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    source = Path.home() / SOURCE_REL
    dest = Path(__file__).resolve().parents[3]
    try:
        source_head, base = validate_repos(source, dest)
        selected, manifest = collect(source, dest, source_head)
        print(f"MACHINE_VERIFIED={SOURCE_MACHINE}")
        print(f"MODE={'PUBLIC_PUSH' if args.push else 'CHECK_ONLY'}")
        print(f"SOURCE_HEAD={source_head}")
        print(f"DEST_BASE={base}")
        print(f"FILES_SELECTED={len(selected)}")
        for item in manifest["files"]:
            print(f"SOURCE={item['path']} SHA256={item['sha256']}")
        if args.push:
            publish(dest, selected, manifest)
        else:
            print("CHECK_PASS__RUN_WITH_--push_AFTER_PUBLICATION_REVIEW")
        return 0
    except ExportHold as exc:
        print(f"STOP={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
