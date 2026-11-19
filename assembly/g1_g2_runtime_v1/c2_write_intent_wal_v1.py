"""G4G — journal d'intention C2 append-only, NON souverain.

Protocole autonome de développement. Il ne s'interpose PAS encore dans le
writer C2 canonique : aucune activation d'APPLY ni reprise automatique.
La durabilité testée couvre un arrêt de PROCESSUS après fsync/publication,
pas une perte d'alimentation ou de disque, surtout sous Windows.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

SCHEMA = "OBSIDIA_G4G_C2_WRITE_INTENT_WAL_V1"
RECORD_INTENT = "C2_INTENT"
RECORD_OUTCOME = "C2_OUTCOME"
STORED = "STORED"
IDEMPOTENT = "IDEMPOTENT_EXISTING_IDENTICAL"
IMMUTABILITY_VIOLATION = "IMMUTABILITY_VIOLATION"
STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
OUTCOME_STATUSES = frozenset({"REPORTED_KEEP", "REPORTED_ROLLBACK", "REPORTED_QUARANTINE"})
_ID = re.compile(r"^wi-[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")

_BOUND_INTENT = (
    "schema", "record_type", "intent_id", "batch_execution_id",
    "child_execution_id", "execution_authority_hash", "approval_id",
    "pre_decision_record_id", "pre_decision_record_hash",
    "sealed_rollback_evidence_id", "sealed_rollback_evidence_hash",
    "target_path", "target_pre_sha256", "target_post_sha256",
    "decision_authority", "producer_authenticated", "release_authorized",
    "record_hash",
)
_BOUND_OUTCOME = (
    "schema", "record_type", "intent_id", "intent_record_hash",
    "reported_status", "observed_sha256", "decision_authority",
    "producer_authenticated", "release_authorized", "record_hash",
)


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _digest(data: dict, *, omit: tuple[str, ...] = ("record_hash",)) -> str:
    return hashlib.sha256(_canonical({k: v for k, v in data.items()
                                      if k not in omit})).hexdigest()


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _is_id(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def build_intent(*, batch_execution_id: str, child_execution_id: str,
                 execution_authority_hash: str, approval_id: str,
                 pre_decision_record_id: str, pre_decision_record_hash: str,
                 sealed_rollback_evidence_id: str,
                 sealed_rollback_evidence_hash: str,
                 target_path: str, target_pre_sha256: str,
                 target_post_sha256: str) -> dict | None:
    """Construit un candidat non signé ; aucune autorité n'en découle."""
    strings = (batch_execution_id, child_execution_id, approval_id,
               pre_decision_record_id, sealed_rollback_evidence_id, target_path)
    hashes = (execution_authority_hash, pre_decision_record_hash,
              sealed_rollback_evidence_hash, target_pre_sha256, target_post_sha256)
    if any(not isinstance(x, str) or not x.strip() for x in strings):
        return None
    if any(not _is_sha(x) for x in hashes):
        return None
    norm = target_path.replace("\\", "/")
    if (norm.startswith("/") or re.match(r"^[a-zA-Z]:", norm)
            or any(piece in ("", ".", "..") for piece in norm.split("/"))):
        return None
    base = {
        "schema": SCHEMA, "record_type": RECORD_INTENT,
        "batch_execution_id": batch_execution_id,
        "child_execution_id": child_execution_id,
        "execution_authority_hash": execution_authority_hash,
        "approval_id": approval_id,
        "pre_decision_record_id": pre_decision_record_id,
        "pre_decision_record_hash": pre_decision_record_hash,
        "sealed_rollback_evidence_id": sealed_rollback_evidence_id,
        "sealed_rollback_evidence_hash": sealed_rollback_evidence_hash,
        "target_path": norm, "target_pre_sha256": target_pre_sha256,
        "target_post_sha256": target_post_sha256,
        "decision_authority": "KX108_ONLY",
        "producer_authenticated": False, "release_authorized": False,
    }
    record = {**base, "intent_id": "wi-" + _digest(base)}
    record["record_hash"] = _digest(record)
    return record


def verify_intent(record: Any) -> tuple[bool, str | None]:
    if not isinstance(record, dict) or set(record) != set(_BOUND_INTENT):
        return False, "INTENT_FIELDS_INVALID"
    if (record.get("schema") != SCHEMA or record.get("record_type") != RECORD_INTENT
            or record.get("decision_authority") != "KX108_ONLY"
            or record.get("producer_authenticated") is not False
            or record.get("release_authorized") is not False):
        return False, "INTENT_CONTRACT_INVALID"
    recalculated = build_intent(**{k: record[k] for k in (
        "batch_execution_id", "child_execution_id", "execution_authority_hash",
        "approval_id", "pre_decision_record_id", "pre_decision_record_hash",
        "sealed_rollback_evidence_id", "sealed_rollback_evidence_hash",
        "target_path", "target_pre_sha256", "target_post_sha256",
    )})
    if recalculated is None or recalculated != record:
        return False, "INTENT_ID_OR_HASH_MISMATCH"
    return True, None


def build_outcome(intent: dict, *, reported_status: str,
                  observed_sha256: str | None) -> dict | None:
    valid, _ = verify_intent(intent)
    if (not valid or not isinstance(reported_status, str)
            or reported_status not in OUTCOME_STATUSES
            or (observed_sha256 is not None and not _is_sha(observed_sha256))):
        return None
    record = {
        "schema": SCHEMA, "record_type": RECORD_OUTCOME,
        "intent_id": intent["intent_id"],
        "intent_record_hash": intent["record_hash"],
        "reported_status": reported_status, "observed_sha256": observed_sha256,
        "decision_authority": "KX108_ONLY",
        "producer_authenticated": False, "release_authorized": False,
    }
    record["record_hash"] = _digest(record)
    return record


def verify_outcome(record: Any, intent: dict) -> tuple[bool, str | None]:
    if not isinstance(record, dict) or set(record) != set(_BOUND_OUTCOME):
        return False, "OUTCOME_FIELDS_INVALID"
    rebuilt = build_outcome(intent, reported_status=record.get("reported_status"),
                            observed_sha256=record.get("observed_sha256"))
    if rebuilt is None or rebuilt != record:
        return False, "OUTCOME_LINK_OR_HASH_INVALID"
    return True, None


def _path(wal_dir: Path, intent_id: str, suffix: str) -> Path:
    if not isinstance(wal_dir, Path) or not _is_id(intent_id):
        raise ValueError("WAL_DIR_OR_INTENT_ID_INVALID")
    return wal_dir / f"{intent_id}.{suffix}.json"


def _store_path_safe(wal_dir: Path) -> bool:
    """Pas de chemin relatif ni de traversée d'alias/reparse du magasin."""
    if not isinstance(wal_dir, Path) or not wal_dir.is_absolute():
        return False
    for part in (wal_dir, *wal_dir.parents):
        try:
            if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                return False
        except OSError:
            return False
    return True


def _publish_exclusive(record: dict, wal_dir: Path, *, suffix: str) -> dict:
    intent_id = record.get("intent_id")
    try:
        dest = _path(wal_dir, intent_id, suffix)
        if not _store_path_safe(wal_dir):
            return {"status": STORE_UNAVAILABLE, "reason": "WAL_STORE_PATH_UNSAFE"}
        wal_dir.mkdir(parents=True, exist_ok=True)
        if not _store_path_safe(wal_dir):
            return {"status": STORE_UNAVAILABLE, "reason": "WAL_STORE_PATH_UNSAFE"}
        payload = _canonical(record)
        temp = wal_dir / f".{intent_id}.{uuid.uuid4().hex}.tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temp, dest)
                status = STORED
            except FileExistsError:
                if dest.is_symlink():
                    return {"status": IMMUTABILITY_VIOLATION, "reason": "WAL_DEST_IS_LINK"}
                try:
                    status = IDEMPOTENT if dest.read_bytes() == payload else IMMUTABILITY_VIOLATION
                except OSError:
                    status = STORE_UNAVAILABLE
            if status == STORED and os.name != "nt":
                try:
                    dir_fd = os.open(wal_dir, os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    return {"status": STORE_UNAVAILABLE, "reason": "DIR_FSYNC_FAILED"}
            return {"status": status, "intent_id": intent_id}
        finally:
            temp.unlink(missing_ok=True)
    except (OSError, ValueError, TypeError) as exc:
        return {"status": STORE_UNAVAILABLE, "reason": type(exc).__name__}


def store_intent(intent: dict, wal_dir: Path) -> dict:
    valid, why = verify_intent(intent)
    if not valid:
        return {"status": STORE_UNAVAILABLE, "reason": why}
    return _publish_exclusive(intent, wal_dir, suffix="intent")


def store_outcome(outcome: dict, intent: dict, wal_dir: Path) -> dict:
    valid, why = verify_outcome(outcome, intent)
    if not valid:
        return {"status": STORE_UNAVAILABLE, "reason": why}
    return _publish_exclusive(outcome, wal_dir, suffix="outcome")


def _read(path: Path) -> dict | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def inspect_intent(wal_dir: Path, intent_id: str) -> dict:
    """Inspection passive : aucun retour ne permet de reprendre ou libérer."""
    base = {
        "status": "HOLD", "decision_authority": "KX108_ONLY",
        "readonly": True, "release_authorized": False,
        "recovery_authorized": False, "producer_authenticated": False,
        "physical_mutation_attested": False,
        "quarantine_review_required": True,
        "target_mutated_by_inspector": False,
    }
    try:
        if not _store_path_safe(wal_dir):
            return {**base, "reason": "WAL_DIR_PATH_UNSAFE"}
        p = _path(wal_dir, intent_id, "intent")
        intent = _read(p)
        valid, why = verify_intent(intent)
        if not valid or intent.get("intent_id") != intent_id:
            return {**base, "reason": f"INTENT_UNTRUSTED:{why}"}
        outcome_path = _path(wal_dir, intent_id, "outcome")
        if not outcome_path.exists() and not outcome_path.is_symlink():
            return {**base, "reason": "UNRESOLVED_INTENT", "intent_verified_structurally": True}
        outcome = _read(outcome_path)
        verified, why = verify_outcome(outcome, intent)
        if not verified:
            return {**base, "reason": f"OUTCOME_UNTRUSTED:{why}",
                    "intent_verified_structurally": True}
        return {**base, "reason": "OUTCOME_REPORTED_NOT_ATTESTED",
                "intent_verified_structurally": True,
                "outcome_verified_structurally": True,
                "reported_status": outcome.get("reported_status")}
    except (OSError, TypeError, ValueError):
        return {**base, "reason": "WAL_INSPECT_UNAVAILABLE"}
