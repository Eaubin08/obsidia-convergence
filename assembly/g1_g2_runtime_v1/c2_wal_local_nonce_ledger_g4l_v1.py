"""G4L : registre LOCAL anti-doublon du scénario C2/WAL synthétique G4K.

Hors façade runtime. Un enregistrement local n'est NI une racine de confiance,
NI une preuve d'anti-rejeu distribuée, NI une autorisation KX108.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import c2_write_intent_wal_v1 as WAL
from c2_wal_runner_observation_g4k_v1 import inspect_c2_wal_synthetic_runner_observation

SCHEMA = "OBSIDIA_G4L_LOCAL_C2_NONCE_LEDGER_V1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = frozenset({
    "schema", "nonce_scope_hash", "machine_id", "public_certificate_sha256",
    "nonce", "intent_id", "outcome_record_hash", "runner_trace_sha256",
    "record_hash",
})


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _record_hash(record: dict) -> str:
    return hashlib.sha256(_canonical({k: v for k, v in record.items()
                                      if k != "record_hash"})).hexdigest()


def _hold(reason: str, **extra: Any) -> dict:
    return {
        "schema_version": SCHEMA, "status": "HOLD", "reason": reason,
        "decision_authority": "KX108_ONLY", "synthetic_test_only": True,
        "local_nonce_reserved": False, "local_duplicate_denied": False,
        "machine_signature_verified": False, "synthetic_trace_verified": False,
        "ledger_is_trusted": False, "replay_prevented": False,
        "producer_identity_attested": False, "process_execution_attested": False,
        "responsible_person_authenticated": False,
        "certificate_enrollment_approved": False,
        "human_approval_verified": False, "kx108_ticket_issued": False,
        "execution_authorized": False, "recovery_authorized": False,
        "release_authorized": False, "target_mutated": False,
        **extra,
    }


def _ledger_dir(repo_root: Path, wal_dir: Path) -> Path | None:
    if (type(repo_root) is not Path and not isinstance(repo_root, Path)) or not isinstance(wal_dir, Path):
        return None
    if (not WAL._store_path_safe(repo_root) or
            not WAL._store_path_safe(wal_dir) or
            wal_dir != repo_root / "wal"):
        return None
    return wal_dir / "g4l-local-testonly-ledger"


def _prepare(*, wal_dir: Path, intent_id: str, repo_root: Path,
             receipt: Any, public_certificate_der_base64: str,
             pinned_certificate_sha256: str, expected_machine_id: str) -> tuple[dict, Path | None, dict | None]:
    signed = inspect_c2_wal_synthetic_runner_observation(
        wal_dir=wal_dir, intent_id=intent_id, repo_root=repo_root,
        receipt=receipt, public_certificate_der_base64=public_certificate_der_base64,
        pinned_certificate_sha256=pinned_certificate_sha256,
        expected_machine_id=expected_machine_id)
    if (not signed.get("machine_signature_verified") or
            not signed.get("synthetic_runner_record_verified")):
        return _hold("G4L_G4K_SIGNED_TRACE_REQUIRED:" + str(signed.get("reason"))), None, None
    directory = _ledger_dir(repo_root, wal_dir)
    if directory is None:
        return _hold("G4L_LOCAL_ROOT_UNSAFE_OR_OUT_OF_SCOPE"), None, None
    payload = receipt["payload"]
    machine_id, pin, nonce = (payload["machine_id"], payload["public_certificate_sha256"],
                              payload["nonce"])
    scope = hashlib.sha256(_canonical({
        "domain": SCHEMA, "machine_id": machine_id,
        "public_certificate_sha256": pin, "nonce": nonce,
    })).hexdigest()
    intent = WAL.load_verified_intent(wal_dir, intent_id)
    outcome = WAL.load_verified_outcome(wal_dir, intent) if intent is not None else None
    if intent is None or outcome is None:
        return _hold("G4L_WAL_CHANGED"), None, None
    record = {
        "schema": SCHEMA, "nonce_scope_hash": scope,
        "machine_id": machine_id, "public_certificate_sha256": pin,
        "nonce": nonce, "intent_id": intent_id,
        "outcome_record_hash": outcome["record_hash"],
        "runner_trace_sha256": payload["tests_transcript_sha256"],
    }
    record["record_hash"] = _record_hash(record)
    return _hold("G4L_CLAIM_VERIFIED_LOCAL_ONLY", machine_signature_verified=True,
                 synthetic_trace_verified=True), directory / ("nonce-" + scope + ".json"), record


def _existing(path: Path, expected: dict) -> str:
    """Même un fichier partiel doit bloquer la réutilisation du nonce."""
    if path.is_symlink():
        return "G4L_NONCE_FILE_LINK_QUARANTINE"
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > 8192:
            return "G4L_NONCE_FILE_CORRUPT_QUARANTINE"
        def pairs_no_duplicates(pairs):
            d = {}
            for key, value in pairs:
                if key in d:
                    raise ValueError("DUPLICATE")
                d[key] = value
            return d
        stored = json.loads(raw, object_pairs_hook=pairs_no_duplicates)
        if (type(stored) is not dict or set(stored) != _FIELDS or
                raw != _canonical(stored) or
                type(stored.get("record_hash")) is not str or
                _SHA.fullmatch(stored["record_hash"]) is None or
                _record_hash(stored) != stored["record_hash"] or
                stored != expected):
            return "G4L_NONCE_FILE_CORRUPT_QUARANTINE"
    except (OSError, ValueError, TypeError, UnicodeError):
        return "G4L_NONCE_FILE_CORRUPT_QUARANTINE"
    return "G4L_LOCAL_REPLAY_DUPLICATE_DENIED"


def reserve_synthetic_nonce_testonly(
    *, wal_dir: Path, intent_id: str, repo_root: Path, receipt: Any,
    public_certificate_der_base64: str,
    pinned_certificate_sha256: str, expected_machine_id: str,
) -> dict:
    """Écrit UNE réservation locale exclusive, hors façade KX108.

    Un fichier existant (même corrompu) interdit toute réutilisation. Aucun
    traitement du véritable C2 APPLY ou du registre de production.
    """
    base, dest, record = _prepare(
        wal_dir=wal_dir, intent_id=intent_id, repo_root=repo_root,
        receipt=receipt, public_certificate_der_base64=public_certificate_der_base64,
        pinned_certificate_sha256=pinned_certificate_sha256,
        expected_machine_id=expected_machine_id)
    if dest is None or record is None:
        return base
    directory = dest.parent
    try:
        if not WAL._store_path_safe(directory):
            return {**base, "reason": "G4L_LEDGER_PATH_UNSAFE"}
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        if not WAL._store_path_safe(directory):
            return {**base, "reason": "G4L_LEDGER_PATH_UNSAFE"}
        raw = _canonical(record)
        try:
            fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return {**base, "reason": _existing(dest, record),
                    "local_duplicate_denied": True}
        # Si l'écriture s'interrompt, le fichier partiel reste présent et
        # bloque les prochaines tentatives. Aucune correction implicite.
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            fd_dir = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(fd_dir)
            finally:
                os.close(fd_dir)
        # Relecture avant d'annoncer la réservation locale.
        if _existing(dest, record) != "G4L_LOCAL_REPLAY_DUPLICATE_DENIED":
            return {**base, "reason": "G4L_LOCAL_LEDGER_RELOAD_HOLD"}
        return {**base, "reason": "G4L_NONCE_RESERVED_LOCAL_UNTRUSTED",
                "local_nonce_reserved": True}
    except (OSError, ValueError, TypeError):
        return {**base, "reason": "G4L_LOCAL_STORE_UNAVAILABLE_OR_PARTIAL"}
