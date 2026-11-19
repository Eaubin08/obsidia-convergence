"""G4F : observation conservatrice d'une fenêtre C2 interrompue.

Ne restaure, ne crée, ne modifie et ne signe aucun fichier. Les preuves de
préimage C2 sont scellées structurellement, PAS authentifiées par un runner.
L'inspection n'atteste ni qu'un crash a eu lieu ni qu'une écriture a eu lieu.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

from scripts import obsidia_content_apply as _C
from scripts import obsidia_governed_write_guard_v0 as _WG
from scripts import obsidia_kx108_decision_store as _DS
from scripts import obsidia_sealed_evidence_v0 as _SEV

SCHEMA = "OBSIDIA_G4F_C2_CRASH_WINDOW_READONLY_V1"


def _hold(reason: str, *, pre_hmac_verified: bool = False,
          preimage_structure_verified: bool = False,
          current_state: str = "NOT_OBSERVED",
          current_sha256: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "status": "HOLD", "reason": reason,
        "decision_authority": "KX108_ONLY",
        "readonly": True,
        "pre_hmac_verified": pre_hmac_verified,
        "preimage_structure_verified": preimage_structure_verified,
        "current_state": current_state,
        "observed_current_sha256": current_sha256,
        "recovery_review_required": True,
        "quarantine_recommended": current_state != "PREIMAGE_OBSERVED",
        "preimage_producer_authenticated": False,
        "target_state_live_attested": False,
        "crash_occurrence_attested": False,
        "automatic_restore_permitted": False,
        "execution_authorized": False,
        "release_authorized": False,
        "target_mutated_by_inspector": False,
        "global_write_closure_verified": False,
    }


def _safe_relative_target(raw: Any) -> tuple[str | None, str | None]:
    if not isinstance(raw, str) or not raw.strip():
        return None, "TARGET_PATH_REQUIRED"
    norm = raw.replace("\\", "/")
    if (norm.startswith("/") or re.match(r"^[a-zA-Z]:", norm)
            or any(segment in ("", ".", "..") for segment in norm.split("/"))):
        return None, "TARGET_PATH_NONCANONICAL"
    return norm, None


def _hash_file_once(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_c2_crash_window(*, pre_record_id: str,
                            sealed_rollback_evidence_id: str,
                            pre_store_dir: Path,
                            sealed_rollback_dir: Path,
                            repo_root: Path) -> dict[str, Any]:
    """Observe une cible liée à un PRE + une préimage C2 rechargés par ID.

    Aucun caller-supplied hash n'est une preuve ; toute conclusion est HOLD.
    Les entrées doivent venir d'une revue contrôlée, pas d'une autorisation.
    """
    if (not isinstance(pre_record_id, str)
            or not isinstance(sealed_rollback_evidence_id, str)
            or any(not isinstance(p, Path)
                   for p in (pre_store_dir, sealed_rollback_dir, repo_root))):
        return _hold("G4F_CANONICAL_IDS_AND_STORES_REQUIRED")
    try:
        pre = _DS.load_kx108_decision_record(pre_record_id, pre_store_dir)
        if not isinstance(pre, dict) or pre.get("decision_record_id") != pre_record_id:
            return _hold("G4F_PRE_MISSING_OR_ID_MISMATCH")
        ok, r = _DS.verify_kx108_decision_record_authenticity(pre)
        if not ok:
            return _hold(f"G4F_PRE_HMAC_INVALID:{r}")
        if (_DS.decision_phase_of(pre) != _DS.PRE_DECISION_PHASE
                or pre.get("x108_gate") != "ALLOW"
                or pre.get("decision_authority") != "KX108_ONLY"):
            return _hold("G4F_PRE_NOT_AUTHORITATIVE_PRE_ALLOW", pre_hmac_verified=True)

        sre = _SEV.load_sealed_rollback_evidence(sealed_rollback_evidence_id,
                                                  sealed_rollback_dir)
        if (not isinstance(sre, dict) or
                sre.get("sealed_rollback_evidence_id") != sealed_rollback_evidence_id):
            return _hold("G4F_PREIMAGE_MISSING_OR_ID_MISMATCH", pre_hmac_verified=True)
        valid, r = _SEV.verify_sealed_rollback_evidence(sre)
        if not valid:
            return _hold(f"G4F_PREIMAGE_STRUCTURAL_INVALID:{r}", pre_hmac_verified=True)
        if _SEV._sre_identity(sre) != sealed_rollback_evidence_id:
            return _hold("G4F_PREIMAGE_IDENTITY_INVALID", pre_hmac_verified=True)
        for key, pre_key in (
            ("kx108_pre_decision_record_id", "decision_record_id"),
            ("kx108_pre_decision_record_hash", "decision_record_hash"),
            ("batch_execution_id", "batch_execution_id"),
            ("child_execution_id", "child_execution_id"),
            ("execution_authority_hash", "execution_authority_hash"),
            ("approval_id", "approval_id"),
        ):
            if not sre.get(key) or sre[key] != pre.get(pre_key):
                return _hold(f"G4F_PREIMAGE_PRE_BINDING_MISMATCH:{key}",
                             pre_hmac_verified=True,
                             preimage_structure_verified=True)

        rel, path_reason = _safe_relative_target(sre.get("target_path"))
        if path_reason:
            return _hold(f"G4F_{path_reason}", pre_hmac_verified=True,
                         preimage_structure_verified=True)
        root = repo_root.resolve(strict=True)
        candidate, reason = _C.canonicalize_write_target(rel, root)
        if reason or candidate is None:
            return _hold(f"G4F_TARGET_SCOPE_INVALID:{reason}", pre_hmac_verified=True,
                         preimage_structure_verified=True)
        literal = root / rel
        if candidate != literal.resolve():
            return _hold("G4F_TARGET_CANONICAL_DRIFT", pre_hmac_verified=True,
                         preimage_structure_verified=True)
        safe, why = _WG.verify_path_reparse_safe(root, literal, kind="TARGET")
        if not safe:
            return _hold(f"G4F_TARGET_REPARSE_UNSAFE:{why}", pre_hmac_verified=True,
                         preimage_structure_verified=True)
        if not literal.is_file():
            return _hold("G4F_TARGET_MISSING_OR_NONFILE", pre_hmac_verified=True,
                         preimage_structure_verified=True, current_state="UNKNOWN_CONTENT")

        # Une observation stable deux fois n'est PAS une attestation
        # transactionnelle du disque : TOCTOU externe toujours possible.
        stat1 = literal.stat()
        sha1 = _hash_file_once(literal)
        stat2 = literal.stat()
        sha2 = _hash_file_once(literal)
        stat3 = literal.stat()
        safe2, why2 = _WG.verify_path_reparse_safe(root, literal, kind="TARGET")
        fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if not safe2 or sha1 != sha2 or fingerprint(stat1) != fingerprint(stat2) or fingerprint(stat2) != fingerprint(stat3):
            return _hold(f"G4F_TARGET_DRIFT_DURING_OBSERVATION:{why2}",
                         pre_hmac_verified=True, preimage_structure_verified=True,
                         current_state="UNKNOWN_CONTENT")
        before = sre.get("pre_write_sha256")
        intended = sre.get("source_content_sha256")
        if sha2 == before and sha2 != intended:
            state = "PREIMAGE_OBSERVED"
            classification = "G4F_PREIMAGE_OBSERVED_NO_CRASH_CONCLUSION"
        elif sha2 == intended and sha2 != before:
            state = "SOURCE_IMAGE_OBSERVED"
            classification = "G4F_SOURCE_IMAGE_OBSERVED_NO_PRODUCER_ATTESTATION"
        else:
            state = "UNKNOWN_CONTENT"
            classification = "G4F_TARGET_UNKNOWN_OR_INDISTINGUISHABLE"
        return _hold(classification, pre_hmac_verified=True,
                     preimage_structure_verified=True, current_state=state,
                     current_sha256=sha2)
    except Exception as exc:  # lecture seule : toute indisponibilité -> HOLD
        return _hold(f"G4F_INSPECTION_UNAVAILABLE:{type(exc).__name__}")
