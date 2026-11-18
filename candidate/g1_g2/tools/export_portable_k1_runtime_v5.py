"""Export bounded K1 V5 runtime sources from the portable into GitHub.

No source checkout is changed. No runtime, model, server or test is launched.
The target is ONLY the Obsidia governance convergence repository.

Default: inventory only. --push explicitly copies, commits and pushes
allowlisted governance sources to the existing G1+G2 build branch.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


EXPECTED_MACHINE = "DESKTOP-Q5MD7J7"  # PC PORTABLE, never the fixed desktop
EXPECTED_SOURCE_BRANCH = "fix/kx108-zero-vote-guard-v1"
EXPECTED_DEST_BRANCH = "build/g1-g2-contract-merge-v0"
EXPECTED_REMOTE = "https://github.com/Eaubin08/obsidia-convergence"
IMPORT_SUBDIR = Path("imports/pc1-k1-v5-runtime")
SOURCE_RELATIVE = Path(".codex/visualizations/2026/11/kx108_zero_vote_guard_fix")

# Actual imported K1 driver dependencies + KX108 authority / apply boundary.
# Missing a required source is an explicit HOLD, not a fabricated replacement.
REQUIRED_SOURCES = (
    "scripts/obsidia_kx108_decision_store.py",
    "scripts/obsidia_governed_execution_driver_v0.py",
    "scripts/obsidia_kx108_pre_execution_evidence_adapter_v0.py",
    "scripts/obsidia_batch_execution.py",
    "scripts/obsidia_pre_execution_context.py",
    "scripts/obsidia_test_contract.py",
    "scripts/obsidia_governed_apply_v0.py",
    "scripts/obsidia_governed_rollback_v0.py",
    "scripts/obsidia_branching_ledger.py",
    "scripts/obsidia_batch_selector.py",
    "sigma/protocols.py",
    "sigma/contracts.py",
    "sigma/guard.py",
    "sigma/aggregation.py",
    "sigma/tooling/governed_bounded_apply.py",
    "periphery/world_calls/sovereign_ticket.py",
    "periphery/world_calls/ticket_store.py",
)

OPTIONAL_SOURCES = (
    "periphery/world_calls/k1_dpapi_bootstrap.py",
    "scripts/obsidia_source_content_apply_bridge_v0.py",
)

OPTIONAL_TESTS = (
    "tests/cli/test_k1_governed_singlewrite_v1.py",
    "tests/cli/test_k1_pre_action_binding_positive_v1.py",
    "tests/cli/test_k1_pre_action_binding_red_v1.py",
    "tests/cli/test_kx108_pre_execution_gate_v0.py",
    "tests/cli/test_kx108_post_pre_binding_v0.py",
    "tests/test_kx108_k1_ticket_decision_binding.py",
    "sigma/tests/test_kx108_zero_vote_guard_v1.py",
)

_CREATE_MARKER = b"CREATE_TARGET_FROM_SOURCE"
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)
_PUBLIC_TOKEN_MARKER = re.compile(
    rb"(?i)(?:ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
    rb"sk-proj-[a-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|xoxb-[a-z0-9-]{20,})"
)
MAX_FILE_BYTES = 1_200_000
MAX_CREATE_DISCOVERED = 20


class ExportHold(RuntimeError):
    pass


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    if result.returncode:
        raise ExportHold(f"GIT_FAILED:{' '.join(args)}:{result.returncode}")
    return result.stdout.strip()


def _inside(root: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or rel.suffix != ".py":
        raise ExportHold(f"INVALID_SOURCE_PATH:{relative}")
    path = root / rel
    if not path.is_file() or path.is_symlink() or path.is_junction():
        raise ExportHold(f"SOURCE_UNREADABLE_OR_REDIRECTED:{relative}")
    if not path.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
        raise ExportHold(f"SOURCE_ESCAPES_ROOT:{relative}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ExportHold(f"SOURCE_TOO_LARGE:{relative}")
    return path


def _safe_code(path: Path, relative: str) -> bytes:
    raw = path.read_bytes()
    if any(marker in raw for marker in _PRIVATE_KEY_MARKERS) or _PUBLIC_TOKEN_MARKER.search(raw):
        raise ExportHold(f"POSSIBLE_SECRET_FOUND_REVIEW_BEFORE_PUBLICATION:{relative}")
    try:
        raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ExportHold(f"SOURCE_NOT_UTF8:{relative}") from exc
    if b"\x00" in raw:
        raise ExportHold(f"SOURCE_CONTAINS_NUL:{relative}")
    return raw


def _create_discovery(root: Path) -> list[str]:
    """Only top-level scripts; no 133-repo discovery, no recursive scans."""
    discovered: list[str] = []
    scripts = root / "scripts"
    if not scripts.is_dir():
        raise ExportHold("SCRIPTS_DIR_MISSING")
    for file in sorted(scripts.glob("*.py")):
        if file.name in ("obsidia_cli.py", "obsidia_gateway.py"):
            continue  # CLI is phase G5, not G1/G2
        if file.stat().st_size > MAX_FILE_BYTES or file.is_symlink() or file.is_junction():
            continue
        if _CREATE_MARKER in file.read_bytes():
            discovered.append(file.relative_to(root).as_posix())
    if len(discovered) > MAX_CREATE_DISCOVERED:
        raise ExportHold(f"TOO_MANY_CREATE_SOURCES:{len(discovered)}")
    return discovered


def select_sources(root: Path) -> tuple[dict[str, bytes], list[str]]:
    selected = set(REQUIRED_SOURCES)
    missing_required = [p for p in REQUIRED_SOURCES if not (root / p).is_file()]
    if missing_required:
        raise ExportHold("REQUIRED_SOURCE_MISSING:" + ",".join(missing_required))
    selected.update(p for p in OPTIONAL_SOURCES if (root / p).is_file())
    selected.update(p for p in OPTIONAL_TESTS if (root / p).is_file())
    discovered = _create_discovery(root)
    selected.update(discovered)
    data = {p: _safe_code(_inside(root, p), p) for p in sorted(selected)}
    return data, discovered


def _verify_machine_and_repos(source: Path, destination: Path) -> tuple[str, str]:
    machine = os.environ.get("COMPUTERNAME", "").upper()
    if machine != EXPECTED_MACHINE:
        raise ExportHold(f"WRONG_MACHINE:{machine or 'UNKNOWN'}")
    if not source.is_dir() or not destination.is_dir():
        raise ExportHold("SOURCE_OR_CONVERGENCE_REPO_MISSING")
    if Path(_git(source, "rev-parse", "--show-toplevel")).resolve() != source.resolve():
        raise ExportHold("SOURCE_GIT_ROOT_MISMATCH")
    if _git(source, "branch", "--show-current") != EXPECTED_SOURCE_BRANCH:
        raise ExportHold("WRONG_SOURCE_BRANCH")
    if Path(_git(destination, "rev-parse", "--show-toplevel")).resolve() != destination.resolve():
        raise ExportHold("DEST_GIT_ROOT_MISMATCH")
    if _git(destination, "branch", "--show-current") != EXPECTED_DEST_BRANCH:
        raise ExportHold("WRONG_DEST_BRANCH")
    remote = _git(destination, "remote", "get-url", "origin").rstrip("/").removesuffix(".git")
    if remote != EXPECTED_REMOTE:
        raise ExportHold("GITHUB_REMOTE_MISMATCH")
    if _git(destination, "diff", "--cached", "--name-only"):
        raise ExportHold("DEST_HAS_ALREADY_STAGED_FILES")
    local_head = _git(destination, "rev-parse", "HEAD")
    remote_head = _git(destination, "rev-parse", f"origin/{EXPECTED_DEST_BRANCH}")
    if local_head != remote_head:
        raise ExportHold("DEST_NOT_AT_ORIGIN_HEAD__GIT_PULL_FF_ONLY_FIRST")
    return _git(source, "rev-parse", "HEAD"), local_head


def _manifest(source: Path, selected: dict[str, bytes], discovered: list[str], source_head: str) -> dict:
    return {
        "schema": "OBSIDIA_G1_G2_PORTABLE_K1_RUNTIME_V5_SOURCE_CAPTURE_V1",
        "source_machine": EXPECTED_MACHINE,
        "source_worktree": str(source),
        "source_branch": EXPECTED_SOURCE_BRANCH,
        "source_head": source_head,
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "G1_G2_ONLY__NO_CLI__NO_API__NO_SERVER_START",
        "status": "SOURCE_ONLY__FUNCTIONAL_HOLD",
        "files": [
            {
                "path": path, "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content), "role": "CREATE_DISCOVERED" if path in discovered else "K1_RUNTIME",
            }
            for path, content in selected.items()
        ],
    }


def _push(destination: Path, selected: dict[str, bytes], manifest: dict) -> str:
    relative_root = IMPORT_SUBDIR.as_posix()
    output = destination / IMPORT_SUBDIR
    if output.exists():
        raise ExportHold("DEST_CAPTURE_ALREADY_EXISTS__NO_OVERWRITE")
    for relative, content in selected.items():
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise ExportHold(f"DEST_TARGET_EXISTS:{relative}")
        target.write_bytes(content)
    (output / "IMPORT_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output / ".gitattributes").write_text("* -text\n", encoding="ascii")

    # Verify both physical copies and staged Git bytes (disable CRLF conversion).
    for relative, content in selected.items():
        if (output / relative).read_bytes() != content:
            raise ExportHold(f"COPY_SHA_MISMATCH:{relative}")
    _git(destination, "add", "--", relative_root)
    staged = _git(destination, "diff", "--cached", "--name-only").splitlines()
    if not staged or any(not path.startswith(relative_root + "/") for path in staged):
        raise ExportHold("STAGED_SCOPE_ESCAPE")
    for relative, content in selected.items():
        git_path = f"{relative_root}/{relative}"
        result = subprocess.run(
            ["git", "-C", str(destination), "show", f":{git_path}"],
            capture_output=True, check=False,
        )
        if result.returncode or hashlib.sha256(result.stdout).digest() != hashlib.sha256(content).digest():
            raise ExportHold(f"STAGED_BYTES_MISMATCH:{relative}")
    # This is an exact-byte source import, not a code edit. Existing trailing
    # whitespace in authenticated source files must not block publication;
    # staged SHA256 was verified above, with no formatting rewrite.
    _git(destination, "commit", "-m", "Import portable K1 V5 governance runtime sources (G1+G2)")
    _git(destination, "push", "origin", EXPECTED_DEST_BRANCH)
    return _git(destination, "rev-parse", "HEAD")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--push", action="store_true", help="Copy source files + commit + push (public repo)")
    args = parser.parse_args(argv)
    source = Path.home() / SOURCE_RELATIVE
    destination = Path(__file__).resolve().parents[3]
    try:
        source_head, _ = _verify_machine_and_repos(source, destination)
        selected, discovered = select_sources(source)
        manifest = _manifest(source, selected, discovered, source_head)
        print(f"MACHINE_VERIFIED={EXPECTED_MACHINE}")
        print(f"SOURCE_HEAD={source_head}")
        print(f"FILES_SELECTED={len(selected)}")
        print(f"CREATE_SOURCES_DISCOVERED={len(discovered)}")
        print(f"BYTES_SELECTED={sum(len(data) for data in selected.values())}")
        print(f"MODE={'PUBLIC_PUSH' if args.push else 'READ_ONLY_PREVIEW'}")
        for item in manifest["files"]:
            print(f"FILE={item['path']} SHA256={item['sha256']}")
        if args.push:
            commit = _push(destination, selected, manifest)
            print("PC1_K1_V5_GITHUB_PUSH_PASS=True")
            print(f"REMOTE_COMMIT={commit}")
            print(f"DESTINATION={IMPORT_SUBDIR.as_posix()}")
            print("SOURCE_WORKTREE_UNCHANGED=True")
        else:
            print("PREVIEW_PASS__NO_FILES_WRITTEN=True")
        return 0
    except (ExportHold, OSError) as exc:
        print(f"STOP={str(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
