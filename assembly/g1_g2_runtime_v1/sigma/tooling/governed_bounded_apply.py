"""
sigma/tooling/governed_bounded_apply.py
========================================
MODULE ISOLÉ D'APPLICATION BORNÉE GOUVERNÉE (PHASE 3B)

Implémente la séquence stricte de gouvernance sans inversion d'écriture :
  INTENTION
  → VALIDATION (Scope, Protected paths, HEAD)
  → DÉCISION KX108 (GuardX108)
  → AUTORISATION VÉRIFIÉE (SovereignTicket HMAC + Anti-rejeu)
  → MUTATION ATOMIQUE SOUS SCELLAGE ROLLBACK
  → PREUVE & POST-TESTS
  → COMMITTED (ou ROLLBACK IMMÉDIAT en cas d'échec)

Aucune écriture sur disque ne peut intervenir avant une décision KX108 valide (ALLOW).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from periphery.world_calls.sovereign_ticket import (
    SovereignTicket,
    issue_sovereign_ticket_from_decision_record,
    TICKET_VERSION_V1,
)
from periphery.world_calls.ticket_store import (
    verify_and_consume_sovereign_ticket,
    fail_ticket_nonce,
)
from sigma.contracts import (
    Domain,
    DomainAggregate,
    AgentVote,
    Severity,
    AuthorityLevel,
)
from sigma.guard import GuardX108


@dataclass
class ToolingBuildState:
    session_id: str
    objective: str
    base_sha: str
    manifest_hash: str
    diff_hash: str
    approved_scope: List[str]
    actual_touched_files: List[str]
    protected_scope_status: str
    human_approval_status: str
    obsidure_status: str
    worktree_isolated: bool
    branch_isolated: bool
    auto_commit_disabled: bool
    auto_push_disabled: bool
    auto_merge_disabled: bool
    tests_results: str
    gates_results: str
    unknowns: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    risk_flags: List[str] = field(default_factory=list)
    decision_authority: str = "KX108_ONLY"

# Fichiers protégés canoniques — aucune écriture permise
PROTECTED_PATHS = (
    "server.kernel.sealed.cjs",
    "proofs/",
    "formal/",
    "merkle_seal.json",
    "merkle_root.json",
    "audit_merkle.py",
)


@dataclass
class PatchOperation:
    path: str
    content: str
    op_type: str = "WRITE"  # "WRITE" | "DELETE"


@dataclass
class PatchProposal:
    proposal_id: str
    base_sha: str
    target_worktree: str
    approved_scope: List[str]
    operations: List[PatchOperation]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def raw_payload(self) -> List[dict]:
        return [
            {"path": op.path.replace("\\", "/"), "content": op.content, "type": op.op_type}
            for op in sorted(self.operations, key=lambda x: x.path)
        ]

    @property
    def patch_hash(self) -> str:
        """Empreinte canonique déterministe du patch."""
        serialized = json.dumps(self.raw_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    @property
    def touched_files(self) -> List[str]:
        return sorted({op.path.replace("\\", "/") for op in self.operations})




def _k1_attest_existing_write_target(worktree, relative_path):
    """Fail closed on target redirection, recreation or preimage drift.

    This is a re-attestation, NOT an atomic stable-handle write.
    Concurrency between last check and write remains an explicit limit.
    """
    root = Path(worktree).resolve(strict=True)
    if not root.is_dir() or not isinstance(relative_path, str):
        raise PermissionError("K1_TARGET_ROOT_INVALID")
    if "\\" in relative_path or ":" in relative_path:
        raise PermissionError("K1_TARGET_PATH_NONCANONICAL")
    parts = relative_path.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise PermissionError("K1_TARGET_PATH_TRAVERSAL")
    cursor = root
    for index, part in enumerate(parts):
        cursor = cursor / part
        if cursor.is_symlink() or getattr(cursor, "is_junction", lambda: False)():
            raise PermissionError("K1_TARGET_REDIRECTED")
        metadata = os.lstat(cursor)
        if getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise PermissionError("K1_TARGET_REPARSE_POINT_REFUSED")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise PermissionError("K1_TARGET_PARENT_NOT_DIRECTORY")
    resolved = cursor.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise PermissionError("K1_TARGET_OUTSIDE_WORKTREE")
    first = os.lstat(cursor)
    if not stat.S_ISREG(first.st_mode):
        raise PermissionError("K1_TARGET_NOT_REGULAR_FILE")
    if first.st_nlink != 1:
        raise PermissionError("K1_TARGET_HARDLINK_REFUSED")
    digest = hashlib.sha256(cursor.read_bytes()).hexdigest()
    last = os.lstat(cursor)
    attributes = ("st_dev", "st_ino", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    before = tuple(getattr(first, name) for name in attributes)
    after = tuple(getattr(last, name) for name in attributes)
    if before != after or not stat.S_ISREG(last.st_mode):
        raise PermissionError("K1_TARGET_CHANGED_DURING_READ")
    return (digest,) + after


from sigma.tooling.k1_windows_stable_write import (
    StableHandleRefused,
    pin_verified_windows_postimage,
    write_existing_windows_target,
)


def _k1_physical_write_bytes(target, payload, expected_attestation, worktree):
    """K1 pinned Windows WRITE boundary; testable crash-injection seam."""
    return write_existing_windows_target(
        target, payload, expected_attestation,
        worktree, _k1_attest_existing_write_target,
    )

def _validated_rollback_targets(worktree, original_files):
    """Validate every rollback target before any physical effect."""
    root = Path(worktree).resolve(strict=True)

    if not root.is_dir():
        raise PermissionError("ROLLBACK_ROOT_NOT_DIRECTORY")
    if not isinstance(original_files, dict):
        raise ValueError("ROLLBACK_FILES_NOT_MAPPING")

    validated = {}

    for raw_path in original_files:
        if not isinstance(raw_path, str) or not raw_path:
            raise PermissionError("ROLLBACK_PATH_INVALID")

        normalized = raw_path.replace("\\", "/")
        parts = normalized.split("/")

        if any(
            not part or part in (".", "..") or ":" in part
            for part in parts
        ):
            raise PermissionError("ROLLBACK_PATH_TRAVERSAL")

        if parts[0].lower() in (".git", ".obsidia_wal"):
            raise PermissionError("ROLLBACK_PROTECTED_PATH")

        relative = Path(*parts)

        if relative.is_absolute() or relative.drive or relative.root:
            raise PermissionError("ROLLBACK_ABSOLUTE_PATH")

        cursor = root
        for part in parts:
            cursor = cursor / part

            if cursor.is_symlink():
                raise PermissionError("ROLLBACK_SYMLINK_REFUSED")

            is_junction = getattr(cursor, "is_junction", None)
            if is_junction is not None and is_junction():
                raise PermissionError("ROLLBACK_JUNCTION_REFUSED")

            try:
                metadata = os.lstat(cursor)
            except FileNotFoundError:
                continue

            attributes = getattr(
                metadata, "st_file_attributes", 0
            )
            if attributes & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
            ):
                raise PermissionError("ROLLBACK_REPARSE_REFUSED")

        target = cursor.resolve(strict=False)

        try:
            target.relative_to(root)
        except ValueError:
            raise PermissionError(
                "ROLLBACK_TARGET_OUTSIDE_WORKTREE"
            )

        validated[raw_path] = target

    return validated





def _k1_wal_finality_receipt_path(data):
    terminal = _k1_wal_terminal_receipt_path(data)
    directory = terminal.parent.with_name(
        terminal.parent.name + ".finality_v1"
    )
    return directory / terminal.name


def _k1_wal_finality_check_path(path):
    for item in (path.parent.parent, path.parent, path):
        if item.is_symlink() or getattr(
            item, "is_junction", lambda: False
        )():
            raise PermissionError("WAL_FINALITY_REDIRECTED")

    if path.parent.exists() and not path.parent.is_dir():
        raise PermissionError("WAL_FINALITY_DIRECTORY_INVALID")

    if path.exists() and not path.is_file():
        raise PermissionError("WAL_FINALITY_NOT_FILE")


def _k1_wal_finality_payload(data):
    return {
        "schema": "K1_WAL_FINALITY_V1",
        "identity": _k1_wal_lifecycle_identity(data),
        "state": "COMMITTED",
    }


def _k1_wal_finality_auth(body):
    from periphery.world_calls.sovereign_ticket import (
        compute_authenticator,
    )

    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return compute_authenticator(
        b"OBSIDIA_K1_WAL_FINALITY_V1|" + canonical
    )


def _k1_wal_finality_receipt_present(data):
    import hmac

    path = _k1_wal_finality_receipt_path(data)
    _k1_wal_finality_check_path(path)

    if not path.exists():
        return False

    if path.stat().st_size > 1048576:
        raise PermissionError("WAL_FINALITY_OVERSIZED")

    receipt = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(receipt, dict) or set(receipt) != {
        "schema", "identity", "state", "authenticator"
    }:
        raise PermissionError("WAL_FINALITY_INVALID")

    supplied = receipt["authenticator"]

    if not isinstance(supplied, str):
        raise PermissionError("WAL_FINALITY_AUTH_MISSING")

    payload = {
        k: v for k, v in receipt.items()
        if k != "authenticator"
    }

    if payload != _k1_wal_finality_payload(data):
        raise PermissionError("WAL_FINALITY_IDENTITY_MISMATCH")

    if not hmac.compare_digest(
        supplied, _k1_wal_finality_auth(payload)
    ):
        raise PermissionError("WAL_FINALITY_AUTH_INVALID")

    return True


def _k1_wal_write_finality_receipt(data):
    path = _k1_wal_finality_receipt_path(data)
    _k1_wal_finality_check_path(path)

    path.parent.mkdir(parents=True, exist_ok=True)
    _k1_wal_finality_check_path(path)

    payload = _k1_wal_finality_payload(data)
    receipt = dict(payload)
    receipt["authenticator"] = _k1_wal_finality_auth(payload)

    encoded = (
        json.dumps(
            receipt,
            sort_keys=True,
            ensure_ascii=False,
        ) + "\n"
    ).encode("utf-8")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)

    fd = os.open(str(path), flags, 0o600)

    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def _k1_wal_terminal_receipt_path(data):
    ledger = _k1_wal_lifecycle_path()
    terminal_dir = ledger.with_name(
        ledger.name + ".terminals_v2"
    )

    identity = _k1_wal_lifecycle_identity(data)
    canonical = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    name = hashlib.sha256(canonical).hexdigest() + ".json"
    return terminal_dir / name


def _k1_wal_terminal_payload(data):
    return {
        "schema": "K1_WAL_TERMINAL_V2",
        "identity": _k1_wal_lifecycle_identity(data),
        "state": "COMMITTED",
    }


def _k1_wal_terminal_auth(payload):
    from periphery.world_calls.sovereign_ticket import (
        compute_authenticator,
    )

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return compute_authenticator(
        b"OBSIDIA_K1_WAL_TERMINAL_V2\x00" + canonical
    )


def _k1_wal_terminal_check_path(path):
    directory = path.parent

    if (
        directory.is_symlink()
        or getattr(directory, "is_junction", lambda: False)()
    ):
        raise PermissionError("WAL_TERMINAL_DIR_REDIRECTED")

    if (
        path.is_symlink()
        or getattr(path, "is_junction", lambda: False)()
    ):
        raise PermissionError("WAL_TERMINAL_FILE_REDIRECTED")


def _k1_wal_terminal_receipt_present(data):
    import hmac

    path = _k1_wal_terminal_receipt_path(data)
    _k1_wal_terminal_check_path(path)

    if not path.exists():
        return False

    if not path.is_file():
        raise PermissionError("WAL_TERMINAL_NOT_FILE")

    receipt = json.loads(path.read_text(encoding="utf-8"))
    expected_payload = _k1_wal_terminal_payload(data)

    if not isinstance(receipt, dict):
        raise PermissionError("WAL_TERMINAL_INVALID")

    authenticator = receipt.get("authenticator")

    if not isinstance(authenticator, str):
        raise PermissionError("WAL_TERMINAL_AUTH_MISSING")

    body = {
        k: v for k, v in receipt.items()
        if k != "authenticator"
    }

    if body != expected_payload:
        raise PermissionError("WAL_TERMINAL_IDENTITY_MISMATCH")

    if not hmac.compare_digest(
        authenticator,
        _k1_wal_terminal_auth(body),
    ):
        raise PermissionError("WAL_TERMINAL_AUTH_INVALID")

    return True


def _k1_wal_write_terminal_receipt(data):
    path = _k1_wal_terminal_receipt_path(data)
    _k1_wal_terminal_check_path(path)

    path.parent.mkdir(parents=True, exist_ok=True)
    _k1_wal_terminal_check_path(path)

    if path.exists():
        raise PermissionError("WAL_TERMINAL_ALREADY_EXISTS")

    body = _k1_wal_terminal_payload(data)
    receipt = dict(body)
    receipt["authenticator"] = _k1_wal_terminal_auth(body)

    encoded = (
        json.dumps(
            receipt,
            sort_keys=True,
            ensure_ascii=False,
        ) + "\n"
    ).encode("utf-8")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)

    fd = os.open(str(path), flags, 0o600)

    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def _k1_wal_flush_metadata_parents(wal_file):
    """
    Flush the WAL directory, then its parent, after rename.
    Failure forbids PREPARED and any physical ACT.
    """
    directory = Path(wal_file).parent
    directories = (directory, directory.parent)

    for current in directories:
        if current.is_symlink() or getattr(
            current, "is_junction", lambda: False
        )():
            raise PermissionError("WAL_DIRECTORY_REDIRECTED")

        if not current.is_dir():
            raise PermissionError("WAL_DIRECTORY_NOT_FOUND")

        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            k32 = ctypes.WinDLL(
                "kernel32", use_last_error=True
            )

            create = k32.CreateFileW
            create.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create.restype = wintypes.HANDLE

            flush = k32.FlushFileBuffers
            flush.argtypes = [wintypes.HANDLE]
            flush.restype = wintypes.BOOL

            close = k32.CloseHandle
            close.argtypes = [wintypes.HANDLE]
            close.restype = wintypes.BOOL

            handle = create(
                str(current),
                0x40000000,  # GENERIC_WRITE
                0x00000007,  # FILE_SHARE_ALL
                None,
                3,           # OPEN_EXISTING
                0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
                None,
            )

            invalid = ctypes.c_void_p(-1).value

            if handle is None or handle == invalid:
                raise OSError(
                    "WAL_DIRECTORY_OPEN_FAILED:"
                    + str(ctypes.get_last_error())
                )

            try:
                ok = flush(handle)
                error = ctypes.get_last_error() if not ok else 0
            finally:
                closed = close(handle)

            if not ok:
                raise OSError(
                    "WAL_DIRECTORY_FLUSH_FAILED:"
                    + str(error)
                )

            if not closed:
                raise OSError(
                    "WAL_DIRECTORY_CLOSE_FAILED"
                )

        else:
            if not hasattr(os, "O_DIRECTORY"):
                raise OSError("WAL_DIRECTORY_SYNC_UNSUPPORTED")

            fd = os.open(
                str(current),
                os.O_RDONLY | os.O_DIRECTORY,
            )
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


def _k1_wal_lifecycle_path():
    from periphery.world_calls import ticket_store as ts

    base = Path(str(ts._DEFAULT_CONSUMED_STORE)).resolve()
    return base.with_name(base.name + ".wal_lifecycle_v2.jsonl")


def _k1_wal_lifecycle_identity(data):
    return {
        "wal_digest": hashlib.sha256(
            _k1_wal_v2_bytes(data)
        ).hexdigest(),
        "ticket_id": data["ticket_id"],
        "decision_record_id": data["decision_record_id"],
        "worktree": data["worktree"],
    }


def _k1_wal_identity_key(identity):
    fields = (
        "wal_digest", "ticket_id",
        "decision_record_id", "worktree",
    )
    return tuple(identity[k] for k in fields)


def _k1_wal_event_authenticator(event):
    from periphery.world_calls.sovereign_ticket import (
        compute_authenticator,
    )

    body = {
        k: v for k, v in event.items()
        if k != "authenticator"
    }

    raw = (
        b"OBSIDIA_K1_WAL_LIFECYCLE_V2\x00"
        + json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )

    return compute_authenticator(raw)


def _k1_wal_load_states(path):
    import hmac

    states = {}

    if path.is_symlink() or getattr(
        path, "is_junction", lambda: False
    )():
        raise PermissionError("WAL_LIFECYCLE_REDIRECTED")

    if not path.exists():
        return states

    if not path.is_file():
        raise PermissionError("WAL_LIFECYCLE_NOT_FILE")

    allowed = {
        None: {"PREPARED"},
        "PREPARED": {
            "COMMITTED", "FINALIZING", "ROLLED_BACK", "RECOVERING"
        },
        "FINALIZING": {"COMMITTED"},
        "RECOVERING": {"RECOVERED"},
        "COMMITTED": set(),
        "ROLLED_BACK": set(),
        "RECOVERED": set(),
    }

    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)

            if not isinstance(event, dict) or set(event) != {
                "schema", "identity", "state", "authenticator"
            }:
                raise ValueError("WAL_LIFECYCLE_EVENT_INVALID")

            if event["schema"] != "K1_WAL_LIFECYCLE_V2":
                raise ValueError("WAL_LIFECYCLE_SCHEMA_INVALID")

            if not isinstance(event["identity"], dict):
                raise ValueError("WAL_LIFECYCLE_IDENTITY_INVALID")

            supplied = event["authenticator"]
            if not isinstance(supplied, str):
                raise ValueError("WAL_LIFECYCLE_AUTH_MISSING")

            if not hmac.compare_digest(
                supplied,
                _k1_wal_event_authenticator(event),
            ):
                raise PermissionError(
                    "WAL_LIFECYCLE_AUTH_INVALID"
                )

            identity = _k1_wal_identity_key(event["identity"])
            previous = states.get(identity)
            state = event["state"]

            if state not in allowed.get(previous, set()):
                raise PermissionError(
                    "WAL_LIFECYCLE_TRANSITION_INVALID"
                )

            states[identity] = state

    return states


def _k1_wal_current_state(data):
    path = _k1_wal_lifecycle_path()
    identity = _k1_wal_lifecycle_identity(data)
    return _k1_wal_load_states(path).get(
        _k1_wal_identity_key(identity)
    )


def _k1_wal_record_state(data, state):
    from periphery.world_calls.ticket_store import FileLock

    path = _k1_wal_lifecycle_path()

    if path.is_symlink() or getattr(
        path, "is_junction", lambda: False
    )():
        raise PermissionError("WAL_LIFECYCLE_REDIRECTED")

    path.parent.mkdir(parents=True, exist_ok=True)

    identity = _k1_wal_lifecycle_identity(data)
    event = {
        "schema": "K1_WAL_LIFECYCLE_V2",
        "identity": identity,
        "state": state,
    }

    expected = {
        "PREPARED": None,
        "FINALIZING": "PREPARED",
        "COMMITTED": "FINALIZING",
        "ROLLED_BACK": "PREPARED",
        "RECOVERING": "PREPARED",
        "RECOVERED": "RECOVERING",
    }

    if state not in expected:
        raise ValueError("WAL_LIFECYCLE_UNKNOWN_STATE")

    with FileLock(str(path) + ".lock"):
        states = _k1_wal_load_states(path)
        previous = states.get(
            _k1_wal_identity_key(identity)
        )

        if previous != expected[state]:
            raise PermissionError(
                "WAL_LIFECYCLE_TRANSITION_REFUSED"
            )

        event["authenticator"] = (
            _k1_wal_event_authenticator(event)
        )

        with path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    event,
                    sort_keys=True,
                    ensure_ascii=False,
                ) + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        if state == "PREPARED":
            # K1: the Lifecycle directory entry must
            # be flushed before physical ACT.
            _k1_wal_flush_metadata_parents(
                _k1_wal_lifecycle_path()
            )


def _k1_wal_v2_bytes(data):
    body = {k: v for k, v in data.items() if k != "authenticator"}
    return b"OBSIDIA_K1_WAL_V2\\x00" + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _k1_wal_recovery_known_target_state(data, targets):
    """Allow physical recovery only from an authenticated, known byte state.

    Unknown/partially written bytes remain unresolved for manual review.
    A legacy WAL without postimage hashes also remains unresolved.
    """
    # K1_WAL_POSTIMAGE_FINGERPRINT_V1
    post_hashes = data.get("post_state_hashes")
    pre_hashes = data.get("pre_state_hashes")
    if not isinstance(post_hashes, dict) or not isinstance(pre_hashes, dict):
        return False
    if set(post_hashes) != set(targets) or set(pre_hashes) != set(targets):
        return False
    for relative, target in targets.items():
        post_hash = post_hashes[relative]
        pre_hash = pre_hashes[relative]
        if (not isinstance(post_hash, str) or len(post_hash) != 64
                or any(c not in "0123456789abcdef" for c in post_hash)):
            return False
        if (not isinstance(pre_hash, str) or len(pre_hash) != 64
                or any(c not in "0123456789abcdef" for c in pre_hash)):
            return False
        if not target.is_file() or target.is_symlink():
            return False
        observed = hashlib.sha256(target.read_bytes()).hexdigest()
        if observed not in (pre_hash, post_hash):
            return False
    return True


def _k1_wal_check_preimages(original_files, pre_state_hashes):
    if not isinstance(original_files, dict) or len(original_files) != 1:
        raise ValueError("WAL_V2_SINGLE_TARGET_REQUIRED")
    if not isinstance(pre_state_hashes, dict) or set(original_files) != set(pre_state_hashes):
        raise ValueError("WAL_V2_PREIMAGE_KEYS_MISMATCH")
    for path, original in original_files.items():
        if not isinstance(path, str) or not path:
            raise ValueError("WAL_V2_PATH_INVALID")
        if original is not None and not isinstance(original, str):
            raise ValueError("WAL_V2_PREIMAGE_TYPE_INVALID")
        digest = None if original is None else hashlib.sha256(
            original.encode("utf-8")
        ).hexdigest()
        if pre_state_hashes[path] != digest:
            raise ValueError("WAL_V2_PREIMAGE_HASH_MISMATCH")


@dataclass
class SealedRollbackEvidence:
    """Instantané pré-mutation scellé en mémoire et persisté en journal WAL avant toute écriture disque."""
    evidence_id: str
    proposal_id: str
    created_at: str
    original_files: Dict[str, Optional[str]]  # path -> content (None si le fichier n'existait pas)
    pre_state_hashes: Dict[str, Optional[str]]

    def execute_rollback(self, target_worktree: str) -> None:
        worktree = Path(target_worktree)
        targets = _validated_rollback_targets(
            worktree, self.original_files
        )
        for path_str, orig_content in self.original_files.items():
            restored_file = targets[path_str]
            if orig_content is None:
                raise PermissionError("K1_ROLLBACK_WRITE_ONLY_TARGET_REQUIRED")
            else:
                # K1_V5_IMMEDIATE_ROLLBACK_PINNED_COMPARE_AND_WRITE
                # Rollback uses the same native compare/write/fdatasync
                # boundary as ACT and RECOVERY. A third-party edit never
                # becomes an implicit authority for restoring an old file.
                wal = getattr(self, "_k1_wal_v2_data", None)
                if not isinstance(wal, dict):
                    raise PermissionError("K1_ROLLBACK_AUTHENTICATED_WAL_REQUIRED")
                attestation = _k1_attest_existing_write_target(
                    worktree, path_str,
                )
                authorized = (
                    wal["pre_state_hashes"][path_str],
                    wal["post_state_hashes"][path_str],
                )
                if attestation[0] not in authorized:
                    raise StableHandleRefused("K1_ROLLBACK_FOREIGN_BYTES_HOLD")
                if attestation[0] != authorized[0]:
                    _k1_physical_write_bytes(
                        restored_file, orig_content.encode("utf-8"),
                        attestation, worktree,
                    )

    def persist_wal(
        self, target_worktree: str, *, verified_ticket,
        decision_store_dir, base_sha: str, patch_hash: str, approved_scope,
        post_state_hashes,
    ) -> Path:
        """Persist WAL V2 for a verified KX108 PRE transaction."""
        import re
        import tempfile
        from periphery.world_calls.sovereign_ticket import (
            compute_authenticator, verify_authenticator,
        )
        from scripts import obsidia_kx108_decision_store as ds

        if not isinstance(self.proposal_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,128}", self.proposal_id
        ) or self.proposal_id in (".", ".."):
            raise PermissionError("WAL_V2_PROPOSAL_ID_INVALID")

        root = Path(target_worktree).resolve(strict=True)
        targets = _validated_rollback_targets(root, self.original_files)
        _k1_wal_check_preimages(self.original_files, self.pre_state_hashes)
        if (not isinstance(post_state_hashes, dict)
                or set(post_state_hashes) != set(self.original_files)
                or any(not isinstance(v, str) or len(v) != 64
                       or any(c not in "0123456789abcdef" for c in v)
                       for v in post_state_hashes.values())):
            raise PermissionError("K1_WAL_POSTIMAGE_HASHES_INVALID")

        if set(targets) != set(approved_scope):
            raise PermissionError("WAL_V2_APPROVED_SCOPE_MISMATCH")
        if not verify_authenticator(verified_ticket):
            raise PermissionError("WAL_V2_TICKET_HMAC_INVALID")
        if (
            verified_ticket.x108_gate != "ALLOW"
            or verified_ticket.scope != "bounded_apply"
            or verified_ticket.action_id != self.proposal_id
            or verified_ticket.input_hash != patch_hash
            or verified_ticket.action_hash != hashlib.sha256(
                f"{target_worktree}:{base_sha}".encode("utf-8")
            ).hexdigest()
        ):
            raise PermissionError("WAL_V2_TICKET_BINDING_MISMATCH")

        dc = str(Path(decision_store_dir).resolve()) if decision_store_dir is not None else None
        record = ds.load_kx108_decision_record(
            verified_ticket.decision_record_id,
            Path(dc) if dc else None,
        )
        ok, reason = ds.verify_kx108_decision_record_authenticity(record)
        if not ok:
            raise PermissionError(f"WAL_V2_DECISION_AUTH_INVALID:{reason}")
        if (
            record.get("decision_record_hash") != verified_ticket.decision_record_hash
            or record.get("decision_phase") != "PRE_EXECUTION"
            or record.get("decision_record_producer")
                != "run_and_persist_kx108_pre_execution_decision"
            or record.get("x108_gate") != "ALLOW"
        ):
            raise PermissionError("WAL_V2_DECISION_BINDING_MISMATCH")

        wal_dir = root / ".obsidia_wal"
        if wal_dir.is_symlink() or getattr(
            wal_dir, "is_junction", lambda: False
        )():
            raise PermissionError("WAL_V2_DIRECTORY_REDIRECTED")
        wal_dir.mkdir(parents=True, exist_ok=True)
        if any(wal_dir.iterdir()):
            raise PermissionError("WAL_V2_UNRESOLVED_JOURNAL")

        data = {
            "wal_version": "K1_WAL_V2",
            "evidence_id": self.evidence_id,
            "proposal_id": self.proposal_id,
            "created_at": self.created_at,
            "original_files": self.original_files,
            "pre_state_hashes": self.pre_state_hashes,
            "post_state_hashes": post_state_hashes,
            "state": "MUTATION_IN_PROGRESS",
            "worktree": str(root),
            "base_sha": base_sha,
            "patch_hash": patch_hash,
            "approved_scope": sorted(set(approved_scope)),
            "decision_store_dir": dc,
            "decision_record_id": verified_ticket.decision_record_id,
            "decision_record_hash": verified_ticket.decision_record_hash,
            "ticket_id": verified_ticket.ticket_id,
            "action_id": verified_ticket.action_id,
            "ticket_action_hash": verified_ticket.action_hash,
        }
        data["authenticator"] = compute_authenticator(
            _k1_wal_v2_bytes(data)
        )

        wal_file = wal_dir / f"wal_{self.proposal_id}.json"
        fd, tmp = tempfile.mkstemp(
            prefix=".wal_v2_", suffix=".tmp", dir=str(wal_dir)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
                json.dump(data, out, sort_keys=True, ensure_ascii=False)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, wal_file)
            # Synchronize both the WAL entry and its parent
            # directory entry before publishing PREPARED.
            _k1_wal_flush_metadata_parents(wal_file)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        _k1_wal_record_state(data, "PREPARED")
        self._k1_wal_v2_data = data
        return wal_file

    def clear_wal(self, target_worktree: str) -> None:
        """Nettoie le journal WAL une fois la transaction validée ou annulée."""
        wal_file = Path(target_worktree) / ".obsidia_wal" / f"wal_{self.proposal_id}.json"
        if wal_file.exists():
            wal_file.unlink()
            # K1_WAL_CLEANUP_METADATA_BARRIER
            _k1_wal_flush_metadata_parents(wal_file)

    @staticmethod
    def recover_dangling_wal(target_worktree: str) -> List[str]:
        """Recover authenticated K1 WAL V2; otherwise preserve WAL and HOLD."""
        import hmac
        import tempfile
        from periphery.world_calls.sovereign_ticket import compute_authenticator
        from scripts import obsidia_kx108_decision_store as ds

        try:
            root = Path(target_worktree).resolve(strict=True)
            wal_dir = root / ".obsidia_wal"
            if wal_dir.is_symlink() or getattr(
                wal_dir, "is_junction", lambda: False
            )():
                return []
            if not wal_dir.is_dir():
                return []

            entries = list(wal_dir.iterdir())
            if len(entries) != 1:
                return []

            wal_file = entries[0]
            if (
                wal_file.is_symlink()
                or getattr(wal_file, "is_junction", lambda: False)()
                or not wal_file.is_file()
                or not wal_file.name.startswith("wal_")
                or not wal_file.name.endswith(".json")
            ):
                return []

            data = json.loads(wal_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("wal_version") != "K1_WAL_V2":
                return []

            authenticator = data.get("authenticator")
            if not isinstance(authenticator, str) or not hmac.compare_digest(
                authenticator, compute_authenticator(_k1_wal_v2_bytes(data))
            ):
                return []

            if (
                data.get("state") != "MUTATION_IN_PROGRESS"
                or data.get("worktree") != str(root)
                or data.get("action_id") != data.get("proposal_id")
                or data.get("approved_scope") != sorted(
                    data.get("original_files", {})
                )
                or wal_file.name != f"wal_{data.get('proposal_id')}.json"
            ):
                return []

            _k1_wal_check_preimages(
                data.get("original_files"),
                data.get("pre_state_hashes"),
            )
            targets = _validated_rollback_targets(
                root, data["original_files"]
            )

            dc = data.get("decision_store_dir")
            record = ds.load_kx108_decision_record(
                data.get("decision_record_id"),
                Path(dc) if dc else None,
            )
            ok, _ = ds.verify_kx108_decision_record_authenticity(record)
            if not ok or (
                record.get("decision_record_hash")
                    != data.get("decision_record_hash")
                or record.get("decision_phase") != "PRE_EXECUTION"
                or record.get("decision_record_producer")
                    != "run_and_persist_kx108_pre_execution_decision"
                or record.get("x108_gate") != "ALLOW"
            ):
                return []

            # All verification precedes the physical restoration.
            # Finalized WALs cannot restore an old preimage,
            # even when Lifecycle and terminal receipt are lost.
            if _k1_wal_finality_receipt_present(data):
                return []

            lifecycle_state = _k1_wal_current_state(data)

            # A durable post-test finalization intent is not a
            # recoverable interrupted mutation. Preserve the WAL.
            if lifecycle_state == "FINALIZING":
                return []

            if lifecycle_state not in ("PREPARED", "RECOVERING", "RECOVERED"):
                return []

            if _k1_wal_terminal_receipt_present(data):
                return []

            # K1: RECOVERED means physical restoration was already
            # verified and its lifecycle finalization persisted.
            # Only WAL cleanup is permitted; never restore again.
            if lifecycle_state == "RECOVERED":
                targets = _validated_rollback_targets(
                    target_worktree,
                    data["original_files"],
                )

                for path_str, original in data["original_files"].items():
                    target = targets[path_str]
                    if original is None:
                        return []  # K1 WRITE-only: never delete an alien target.
                    with pin_verified_windows_postimage(
                        target, root, data["pre_state_hashes"][path_str]
                    ):
                        # Do not release the native fence before cleanup.
                        wal_file.unlink()
                        _k1_wal_flush_metadata_parents(wal_file)
                        return [data["proposal_id"]]

            # K1_RECOVERY_POSTIMAGE_GATE_V1
            # Unknown current bytes must never be overwritten by recovery.
            if not _k1_wal_recovery_known_target_state(data, targets):
                return []

            # Resume an already authenticated recovery without
            # recording PREPARED -> RECOVERING a second time.
            if lifecycle_state == "PREPARED":
                _k1_wal_record_state(data, "RECOVERING")

            # K1_V5_RECOVERY_PINNED_COMPARE_AND_WRITE
            # Authenticated WAL requires one existing WRITE target. Fresh
            # attestation must still equal an authenticated pre/post state,
            # then the SAME stable native handle checks it again before ACT.
            # This removes the check -> os.replace foreign-clobber race.
            for path_str, original in data["original_files"].items():
                if original is None:
                    return []
                target = targets[path_str]
                attestation = _k1_attest_existing_write_target(root, path_str)
                expected_pre = data["pre_state_hashes"][path_str]
                expected_post = data["post_state_hashes"][path_str]
                if attestation[0] not in (expected_pre, expected_post):
                    return []

                if attestation[0] != expected_pre:
                    _k1_physical_write_bytes(
                        target, original.encode("utf-8"), attestation, root,
                    )

                # The preimage must stay pinned from the verification
                # through RECOVERED publication and WAL cleanup.
                with pin_verified_windows_postimage(
                    target, root, expected_pre, attestation[1:3]
                ):
                    _k1_wal_flush_metadata_parents(target)
                    _k1_wal_record_state(data, "RECOVERED")
                    wal_file.unlink()
                    _k1_wal_flush_metadata_parents(wal_file)
                    return [data["proposal_id"]]

            return []
        except Exception:
            # No recovery claim. Unresolved WAL is retained.
            return []


@dataclass
class GovernedApplyResult:
    status: str  # "COMMITTED" | "REFUSED_PRE_DECISION" | "ROLLED_BACK" | "ERROR"
    proposal_id: str
    kx108_pre_gate: str
    kx108_reason: str
    ticket_id: Optional[str]
    disk_written: bool
    rolled_back: bool
    modified_files: List[str]
    receipt_path: Optional[str] = None
    error_detail: str = ""


class GovernedBoundedApply:
    """Moteur d'application bornée gouvernée."""

    def __init__(self, worktree_head_provider: Optional[Callable[[str], str]] = None):
        # Fournisseur de HEAD pour validation de dérive (mockable pour tests isolés)
        self.head_provider = worktree_head_provider or self._default_head_provider

    @staticmethod
    def _default_head_provider(worktree_path: str) -> str:
        head_file = Path(worktree_path) / ".git" / "HEAD"
        if head_file.exists():
            return head_file.read_text(encoding="utf-8").strip()
        return "HEAD_STUB_SHA"

    def pre_check(self, proposal: PatchProposal) -> Tuple[bool, str, ToolingBuildState]:
        """
        Vérification statique et préparation du ToolingBuildState SANS toucher au disque.
        """
        worktree = Path(proposal.target_worktree)
        if not worktree.exists():
            return False, f"WORKTREE_NOT_FOUND:{proposal.target_worktree}", None

        # 1. Vérification du HEAD attendu
        current_head = self.head_provider(proposal.target_worktree)
        if current_head != proposal.base_sha:
            return False, f"WORKTREE_HEAD_DRIFT:{current_head}!={proposal.base_sha}", None

        # 2. Vérification de périmètre (Approved Scope)
        drift = sorted(set(proposal.touched_files) - set(proposal.approved_scope))
        if drift:
            return False, f"SCOPE_DRIFT_UNAPPROVED_FILES:{drift}", None

        # 3. Vérification des fichiers protégés
        for f in proposal.touched_files:
            f_norm = f.replace("\\", "/")
            if any(f_norm == p or f_norm.startswith(p) for p in PROTECTED_PATHS):
                return False, f"PROTECTED_SCOPE_VIOLATION:{f_norm}", None

        # 4. Construction de l'état ToolingBuildState pour évaluation prévisionnelle
        state = ToolingBuildState(
            session_id=proposal.proposal_id,
            objective=f"Apply proposal {proposal.proposal_id}",
            base_sha=proposal.base_sha,
            manifest_hash=proposal.patch_hash,
            diff_hash=proposal.patch_hash,
            approved_scope=proposal.approved_scope,
            actual_touched_files=proposal.touched_files,
            protected_scope_status="CLEAN",
            human_approval_status="APPROVED",
            obsidure_status="CLEAN",
            worktree_isolated=True,
            branch_isolated=True,
            auto_commit_disabled=True,
            auto_push_disabled=True,
            auto_merge_disabled=True,
            tests_results="PASS",
            gates_results="PASS",
            unknowns=[],
            contradictions=[],
            risk_flags=["GOVERNED_PROPOSAL_INTENT"],
            decision_authority="KX108_ONLY",
        )
        return True, "PRE_CHECK_OK", state

    def apply_proposal_governed(
        self,
        proposal: PatchProposal,
        post_test_runner: Optional[Callable[[str], bool]] = None,
        injected_ticket: Optional[SovereignTicket] = None,
        simulate_crash_after_auth: bool = False,
        simulate_crash_during_mutation: bool = False,
        decision_record_id: Optional[str] = None,
        decision_store_dir: Optional[Any] = None,
        execution_dir: Optional[Any] = None,
        pre_execution_context_dir: Optional[Any] = None,
        repo_root: Optional[Any] = None,
        derived_authority_context: Optional[Any] = None,
    ) -> GovernedApplyResult:
        """
        Exécute la chaîne transactionnelle gouvernée complète.

        KX108-K1 : l'autorisation d'écrire ne provient que d'une décision KX108 vérifiée
        (decision_record_id du magasin canonique), jamais d'un ALLOW émis ici ni de la
        porte revendiquée par un ticket injecté. Sans décision vérifiée : refus, zéro écriture.
        """
        worktree = Path(proposal.target_worktree)

        # ── 1. INTENTION & VALIDATION PRÉALABLE (ZÉRO ÉCRITURE) ──
        valid, reason, state = self.pre_check(proposal)
        if not valid:
            return GovernedApplyResult(
                status="REFUSED_PRE_DECISION",
                proposal_id=proposal.proposal_id,
                kx108_pre_gate="BLOCK",
                kx108_reason=reason,
                ticket_id=None,
                disk_written=False,
                rolled_back=False,
                modified_files=[],
                error_detail=reason,
            )

        # ── 2. DÉCISION SOUVERAINE KX108 (ZÉRO ÉCRITURE) ──
        # K1: mandatory cryptographic provenance before ticket
        # issuance, nonce consumption, WAL creation or physical ACT.
        try:
            from periphery.world_calls.sovereign_ticket import (
                _DEFAULT_KEY_ID,
                require_persistent_kernel_keys,
            )
            from scripts.obsidia_kx108_decision_store import (
                DECISION_RECORD_KEY_ID,
            )

            require_persistent_kernel_keys((
                _DEFAULT_KEY_ID,
                DECISION_RECORD_KEY_ID,
            ))
        except Exception as exc:
            known_reasons = {
                "K1_PERSISTENT_KEY_REQUIRED",
                "K1_PERSISTENT_KEY_INVALID",
                "K1_KEY_PROVENANCE_MISMATCH",
            }
            detail = str(exc)
            refusal = (
                detail if detail in known_reasons
                else "K1_PERSISTENT_KEY_UNAVAILABLE"
            )

            return GovernedApplyResult(
                status="REFUSED_PRE_DECISION",
                proposal_id=proposal.proposal_id,
                kx108_pre_gate="NO_VERIFIED_DECISION",
                kx108_reason=refusal,
                ticket_id=None,
                disk_written=False,
                rolled_back=False,
                modified_files=[],
                error_detail=refusal,
            )

        # KX108-K1: no synthetic authorization.
        # A decision record and ticket must pass canonical verification.
        # PENDING is never an authorization to mutate.
        kx108_gate = "PENDING_DECISION_RECORD_VERIFICATION"
        kx108_reason = "AWAITING_VERIFIED_KX108_DECISION"

        # 3. Verify the recorded decision and sovereign ticket
        if injected_ticket is not None:
            ticket = injected_ticket
        else:
            # K1 : aucun ALLOW émis ici ; le ticket est dérivé d'une décision KX108 vérifiée ou refusé.
            refusal = None
            if not decision_record_id:
                refusal = "NO_VERIFIED_DECISION_RECORD"
            else:
                try:
                    ticket = issue_sovereign_ticket_from_decision_record(
                        decision_record_id,
                        action_id=proposal.proposal_id,
                        scope="bounded_apply",
                        input_hash=proposal.patch_hash,
                        decision_store_dir=decision_store_dir,
                        action_payload=proposal.raw_payload,
                        target_worktree=proposal.target_worktree,
                        base_sha=proposal.base_sha,
                        approved_scope=proposal.approved_scope,
                        execution_dir=execution_dir,
                        pre_execution_context_dir=pre_execution_context_dir,
                        repo_root=repo_root,
                        derived_authority_context=derived_authority_context,
                        autonomy_level=1,
                        world_call_class="GOVERNED_WRITE",
                        action_hash=hashlib.sha256(
                            f"{proposal.target_worktree}:{proposal.base_sha}".encode()).hexdigest(),
                        ttl_seconds=120,
                    )
                except AssertionError as exc:
                    refusal = f"TICKET_ISSUANCE_REFUSED:{exc}"
            if refusal is not None:
                # aucune décision KX108 vérifiée : aucune porte n'est attribuée au noyau (ni HOLD ni BLOCK inventés)
                return GovernedApplyResult(
                    status="REFUSED_PRE_DECISION",
                    proposal_id=proposal.proposal_id,
                    kx108_pre_gate="NO_VERIFIED_DECISION",
                    kx108_reason=refusal,
                    ticket_id=None,
                    disk_written=False,
                    rolled_back=False,
                    modified_files=[],
                    error_detail=refusal,
                )

        # Simulation de crash immédiatement après autorisation
        if simulate_crash_after_auth:
            raise RuntimeError("CRASH_AFTER_AUTHORIZATION_BEFORE_MUTATION")

        # ── 4. CONTRÔLE AVANT CONSOMMATION DU TICKET (ANTI-REJEU & BINDING) ──
        try:
            verified_ticket = verify_and_consume_sovereign_ticket(
                ticket,
                required_scope="bounded_apply",
                expected_action_id=proposal.proposal_id,
                action_payload=proposal.raw_payload,
                decision_store_dir=decision_store_dir,
                target_worktree=proposal.target_worktree,
                base_sha=proposal.base_sha,
                approved_scope=proposal.approved_scope,
                execution_dir=execution_dir,
                pre_execution_context_dir=pre_execution_context_dir,
                repo_root=repo_root,
                derived_authority_context=derived_authority_context,
            )
            kx108_gate = verified_ticket.x108_gate
            kx108_reason = f"VERIFIED_DECISION_RECORD:{verified_ticket.decision_record_id}"
        except Exception as exc:
            return GovernedApplyResult(
                status="REFUSED_PRE_DECISION",
                proposal_id=proposal.proposal_id,
                kx108_pre_gate=kx108_gate,
                kx108_reason=f"TICKET_VERIFICATION_FAILED:{exc}",
                ticket_id=getattr(ticket, "ticket_id", None),
                disk_written=False,
                rolled_back=False,
                modified_files=[],
                error_detail=str(exc),
            )

        # ── 5. VÉRIFICATION TOCTOU (TIME-OF-CHECK TO TIME-OF-USE) ──
        # Re-vérification que le worktree n'a pas bougé entre décision et écriture
        fresh_head = self.head_provider(proposal.target_worktree)
        if fresh_head != proposal.base_sha:
            fail_ticket_nonce(verified_ticket.nonce, verified_ticket.ticket_id, reason="TOCTOU_HEAD_DRIFT")
            return GovernedApplyResult(
                status="REFUSED_PRE_DECISION",
                proposal_id=proposal.proposal_id,
                kx108_pre_gate=kx108_gate,
                kx108_reason=f"TOCTOU_HEAD_DRIFT_DETECTED:{fresh_head}!={proposal.base_sha}",
                ticket_id=verified_ticket.ticket_id,
                disk_written=False,
                rolled_back=False,
                modified_files=[],
            )

        # ── 6. SCELLAGE DU ROLLBACK EN MÉMOIRE & SUR DISQUE (WAL) ──
        # Réconciliation préalable si un crash antérieur a laissé des traces orphelines
        # K1: unresolved WAL blocks new physical mutation.
        wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
        wal_junction = getattr(
            wal_dir, "is_junction", lambda: False
        )()

        if (
            wal_dir.is_symlink()
            or wal_junction
            or (
                wal_dir.exists()
                and (
                    not wal_dir.is_dir()
                    or any(wal_dir.iterdir())
                )
            )
        ):
            fail_ticket_nonce(
                verified_ticket.nonce,
                verified_ticket.ticket_id,
                reason="WAL_UNRESOLVED_FAIL_CLOSED",
            )
            return GovernedApplyResult(
                status="REFUSED_PRE_DECISION",
                proposal_id=proposal.proposal_id,
                kx108_pre_gate=kx108_gate,
                kx108_reason="WAL_UNRESOLVED_FAIL_CLOSED",
                ticket_id=verified_ticket.ticket_id,
                disk_written=False,
                rolled_back=False,
                modified_files=[],
                error_detail="WAL_UNRESOLVED_FAIL_CLOSED",
            )

        SealedRollbackEvidence.recover_dangling_wal(
            proposal.target_worktree
        )

        # K1_PRE_ACT_REATTESTATION_V1
        # Revalidate the canonical signed PRE binding after nonce consumption.
        # Do not use a new local snapshot as an implicit authorization.
        from periphery.world_calls.sovereign_ticket import (
            verify_ticket_decision_binding as _k1_verify_pre_binding,
        )
        _k1_pre_kwargs = dict(
            decision_store_dir=decision_store_dir,
            action_payload=proposal.raw_payload,
            target_worktree=proposal.target_worktree,
            base_sha=proposal.base_sha,
            approved_scope=proposal.approved_scope,
            execution_dir=execution_dir,
            pre_execution_context_dir=pre_execution_context_dir,
            repo_root=repo_root,
            derived_authority_context=derived_authority_context,
        )
        snapshot_original: Dict[str, Optional[str]] = {}
        pre_hashes: Dict[str, Optional[str]] = {}
        _k1_attested_targets = {}
        try:
            _k1_verify_pre_binding(verified_ticket, **_k1_pre_kwargs)
            for op in proposal.operations:
                if op.op_type != "WRITE":
                    raise PermissionError("K1_WRITE_ONLY_ATTESTATION")
                attestation = _k1_attest_existing_write_target(worktree, op.path)
                content = (worktree / op.path).read_bytes()
                if hashlib.sha256(content).hexdigest() != attestation[0]:
                    raise PermissionError("K1_TARGET_SNAPSHOT_CHANGED")
                snapshot_original[op.path] = content.decode("utf-8")
                pre_hashes[op.path] = attestation[0]
                _k1_attested_targets[op.path] = attestation
        except Exception as exc:
            fail_ticket_nonce(
                verified_ticket.nonce, verified_ticket.ticket_id,
                reason="TOCTOU_PRE_WAL_REFUSED",
            )
            return GovernedApplyResult(
                status="REFUSED_PRE_DECISION",
                proposal_id=proposal.proposal_id,
                kx108_pre_gate=kx108_gate,
                kx108_reason="TOCTOU_PRE_WAL_REFUSED",
                ticket_id=verified_ticket.ticket_id,
                disk_written=False,
                rolled_back=False,
                modified_files=[],
                error_detail=str(exc),
            )

        rollback_evidence = SealedRollbackEvidence(
            evidence_id=f"rollback-{uuid.uuid4().hex[:12]}",
            proposal_id=proposal.proposal_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            original_files=snapshot_original,
            pre_state_hashes=pre_hashes,
        )
        # Écriture persistante et fsync du journal WAL avant le moindre octet de mutation
        rollback_evidence.persist_wal(
            proposal.target_worktree,
            verified_ticket=verified_ticket,
            decision_store_dir=decision_store_dir,
            base_sha=proposal.base_sha,
            patch_hash=proposal.patch_hash,
            approved_scope=proposal.approved_scope,
            post_state_hashes={
                op.path: hashlib.sha256(op.content.encode("utf-8")).hexdigest()
                for op in proposal.operations if op.op_type == "WRITE"
            },
        )

        # ── 7. APPLICATION DES MUTATIONS SUR DISQUE ──
        disk_written = False
        written_files = []
        _k1_commit_finality_started = False
        try:
            for op in proposal.operations:
                target_file = worktree / op.path
                # Fail closed AFTER WAL persistence, before any physical ACT.
                # A third-party mutation must not be silently rolled back here.
                try:
                    _k1_verify_pre_binding(verified_ticket, **_k1_pre_kwargs)
                    if (_k1_attest_existing_write_target(worktree, op.path)
                            != _k1_attested_targets[op.path]):
                        raise PermissionError("K1_TARGET_CHANGED_AFTER_WAL")
                except Exception as exc:
                    fail_ticket_nonce(
                        verified_ticket.nonce, verified_ticket.ticket_id,
                        reason="TOCTOU_TARGET_CHANGED_AFTER_WAL",
                    )
                    return GovernedApplyResult(
                        status="ERROR",
                        proposal_id=proposal.proposal_id,
                        kx108_pre_gate=kx108_gate,
                        kx108_reason="TOCTOU_TARGET_CHANGED_AFTER_WAL",
                        ticket_id=verified_ticket.ticket_id,
                        disk_written=False,
                        rolled_back=False,
                        modified_files=[],
                        error_detail=str(exc),
                    )
                target_file.parent.mkdir(parents=True, exist_ok=True)

                if simulate_crash_during_mutation and disk_written:
                    raise IOError("CRASH_DURING_MUTATION")

                if op.op_type == "WRITE":
                    # K1_WIN32_STABLE_HANDLE_ACT_V1
                    # File identity, preimage, physical WRITE and fsync
                    # all use the same pinned Windows file handle.
                    _k1_physical_write_bytes(
                        target_file, op.content.encode("utf-8"),
                        _k1_attested_targets[op.path], worktree,
                    )

                    disk_written = True
                    written_files.append(op.path)
                elif op.op_type == "DELETE":
                    if target_file.exists():
                        target_file.unlink()
                        disk_written = True
                        written_files.append(op.path)

            # ── 8. POST-TESTS & VALIDATION DE PREUVE ──
            tests_passed = True
            if post_test_runner is not None:
                tests_passed = post_test_runner(proposal.target_worktree)

            if not tests_passed:
                raise AssertionError("POST_APPLY_TESTS_FAILED")

            # K1_V5_POSTTEST_PINNED_COMMIT_FENCE
            # After post-tests, acquire an exclusive native read guard,
            # authenticate the expected WAL postimage and retain the guard
            # until both COMMITTED and WAL cleanup have completed. An edit
            # before this pin is detected; an edit after it is denied.
            _k1_final_op = proposal.operations[0]
            with pin_verified_windows_postimage(
                worktree / _k1_final_op.path,
                worktree,
                rollback_evidence._k1_wal_v2_data[
                    "post_state_hashes"
                ][_k1_final_op.path],
                _k1_attested_targets[_k1_final_op.path][1:3],
            ):
                # The finalization boundary begins only while protected.
                _k1_commit_finality_started = True

                _k1_wal_record_state(
                    rollback_evidence._k1_wal_v2_data,
                    "FINALIZING",
                )

                _k1_wal_write_finality_receipt(
                    rollback_evidence._k1_wal_v2_data
                )
                _k1_wal_flush_metadata_parents(
                    _k1_wal_finality_receipt_path(
                        rollback_evidence._k1_wal_v2_data
                    )
                )

                _k1_wal_write_terminal_receipt(
                    rollback_evidence._k1_wal_v2_data
                )
                _k1_wal_flush_metadata_parents(
                    _k1_wal_terminal_receipt_path(
                        rollback_evidence._k1_wal_v2_data
                    )
                )

                _k1_wal_record_state(
                    rollback_evidence._k1_wal_v2_data,
                    "COMMITTED",
                )
                rollback_evidence.clear_wal(proposal.target_worktree)

        except Exception as exc:
            if isinstance(exc, StableHandleRefused):
                # Either ACT was denied before writing or the post-test
                # pinned commit verification refused changed bytes.
                # Retain authenticated WAL and never clobber a third party.
                fail_ticket_nonce(
                    verified_ticket.nonce, verified_ticket.ticket_id,
                    reason="K1_STABLE_HANDLE_REFUSED",
                )
                return GovernedApplyResult(
                    status="ERROR",
                    proposal_id=proposal.proposal_id,
                    kx108_pre_gate=kx108_gate,
                    kx108_reason="K1_STABLE_HANDLE_REFUSED",
                    ticket_id=verified_ticket.ticket_id,
                    disk_written=disk_written,
                    rolled_back=False,
                    modified_files=written_files,
                    error_detail=str(exc),
                )
            # A post-finalization failure must retain the WAL
            # and must not physically restore the preimage.
            try:
                _k1_existing_finality = (
                    _k1_wal_finality_receipt_present(
                        rollback_evidence._k1_wal_v2_data
                    )
                    or _k1_wal_terminal_receipt_present(
                        rollback_evidence._k1_wal_v2_data
                    )
                )
            except Exception:
                _k1_existing_finality = True

            if _k1_commit_finality_started or _k1_existing_finality:
                return GovernedApplyResult(
                    status="ERROR",
                    proposal_id=proposal.proposal_id,
                    kx108_pre_gate=kx108_gate,
                    kx108_reason="K1_COMMIT_FINALIZATION_PENDING",
                    ticket_id=verified_ticket.ticket_id,
                    disk_written=disk_written,
                    rolled_back=False,
                    modified_files=written_files,
                    error_detail=str(exc),
                )

            # ── ROLLBACK AUTOMATIQUE IMMÉDIAT EN CAS D'ERREUR OU DE CRASH ──
            # K1: disk_written is not proof of physical state.
            # A write may reach disk and raise before returning.
            targets = _validated_rollback_targets(
                proposal.target_worktree,
                rollback_evidence.original_files,
            )
            rollback_needed = disk_written

            for path_str, original in rollback_evidence.original_files.items():
                target = targets[path_str]
                expected = (
                    None if original is None
                    else original.encode("utf-8")
                )

                if expected is None:
                    if target.exists() or target.is_symlink():
                        rollback_needed = True
                elif not target.is_file() or target.read_bytes() != expected:
                    rollback_needed = True

            if rollback_needed:
                rollback_evidence.execute_rollback(
                    proposal.target_worktree
                )

            targets = _validated_rollback_targets(
                proposal.target_worktree,
                rollback_evidence.original_files,
            )
            _k1_rollback_path = proposal.operations[0].path
            with pin_verified_windows_postimage(
                targets[_k1_rollback_path],
                worktree,
                rollback_evidence.pre_state_hashes[_k1_rollback_path],
            ):
                for path_str, original in rollback_evidence.original_files.items():
                    target = targets[path_str]
                    if original is None or (
                        not target.is_file()
                        or target.read_bytes() != original.encode("utf-8")
                    ):
                        raise PermissionError("WAL_ROLLBACK_UNVERIFIED")

                _k1_wal_record_state(
                    rollback_evidence._k1_wal_v2_data,
                    "ROLLED_BACK",
                )
                rollback_evidence.clear_wal(proposal.target_worktree)
            fail_ticket_nonce(verified_ticket.nonce, verified_ticket.ticket_id, reason=f"APPLY_ERROR:{exc}")
            return GovernedApplyResult(
                status="ROLLED_BACK",
                proposal_id=proposal.proposal_id,
                kx108_pre_gate=kx108_gate,
                kx108_reason=f"APPLY_FAILED_ROLLED_BACK:{exc}",
                ticket_id=verified_ticket.ticket_id,
                disk_written=False,
                rolled_back=True,
                modified_files=[],
                error_detail=str(exc),
            )

            return GovernedApplyResult(
                status="ROLLED_BACK",
                proposal_id=proposal.proposal_id,
                kx108_pre_gate=kx108_gate,
                kx108_reason=f"APPLY_FAILED_ROLLED_BACK:{exc}",
                ticket_id=verified_ticket.ticket_id,
                disk_written=False,
                rolled_back=True,
                modified_files=[],
                error_detail=str(exc),
            )

        # ── 9. COMMIT & RECEIPT ──
        return GovernedApplyResult(
            status="COMMITTED",
            proposal_id=proposal.proposal_id,
            kx108_pre_gate="ALLOW",
            kx108_reason="GOVERNED_APPLY_SUCCESSFUL",
            ticket_id=verified_ticket.ticket_id,
            disk_written=True,
            rolled_back=False,
            modified_files=written_files,
        )
