"""G4I — observation à froid et résultat déclaratif C2 : HOLD absolu.

Le reporter peut ajouter une seule déclaration WAL immuable. Il ne fait
aucun APPLY ni rollback. Mesurer les octets n'authentifie PAS le producteur,
ne prouve PAS l'historique de la mutation et n'autorise PAS de reprise.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import c2_write_intent_wal_v1 as WAL

SCHEMA = "OBSIDIA_G4I_C2_WAL_OUTCOME_OBSERVER_V1"
PREIMAGE = "PREIMAGE_OBSERVED"
POSTIMAGE = "POSTIMAGE_OBSERVED"
UNKNOWN = "UNKNOWN_CONTENT"
MISSING = "TARGET_MISSING"
AMBIGUOUS = "AMBIGUOUS_EQUAL_PRE_POST"


def _hold(reason: str, *, current_state: str = "NOT_OBSERVED",
          observed_sha256: str | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA, "status": "HOLD", "reason": reason,
        "decision_authority": "KX108_ONLY", "readonly": True,
        "current_state": current_state, "observed_sha256": observed_sha256,
        "wal_structurally_verified": False, "producer_authenticated": False,
        "physical_mutation_attested": False, "rollback_attested": False,
        "recovery_authorized": False, "execution_authorized": False,
        "release_authorized": False, "quarantine_review_required": True,
        "target_mutated_by_observer": False, **extra,
    }


def _reparse_or_junction(p: Path) -> bool:
    return p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())


def _file_sha(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            data = stream.read(1024 * 1024)
            if not data:
                break
            sha.update(data)
    return sha.hexdigest()


def _fingerprint(s: os.stat_result) -> tuple:
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def inspect_c2_wal_outcome_state(*, wal_dir: Path, intent_id: str,
                                 repo_root: Path) -> dict[str, Any]:
    """Réconcilie seulement les octets actuellement observés et les claims WAL."""
    if (not isinstance(repo_root, Path) or not repo_root.is_absolute()
            or not isinstance(wal_dir, Path) or not wal_dir.is_absolute()):
        return _hold("G4I_ABSOLUTE_STORES_REQUIRED")
    record = WAL.load_verified_intent(wal_dir, intent_id)
    if record is None:
        return _hold("G4I_INTENT_UNTRUSTED_OR_MISSING")

    # La validation structurelle de l'intent couvre déjà la cible relative.
    # Le chemin disque est relu littéralement ; jamais de suivi d'alias.
    try:
        if not repo_root.is_dir() or _reparse_or_junction(repo_root):
            return _hold("G4I_ROOT_UNSAFE")
        if repo_root.resolve(strict=True) != repo_root:
            return _hold("G4I_ROOT_CANONICAL_DRIFT")
        relative = Path(*record["target_path"].split("/"))
        target = repo_root
        for component in relative.parts:
            target = target / component
            if _reparse_or_junction(target):
                return _hold("G4I_TARGET_REPARSE_UNSAFE")
        if not target.exists():
            state = MISSING
            digest = None
        elif not target.is_file() or target.resolve(strict=True) != target:
            return _hold("G4I_TARGET_NOT_CANONICAL_FILE")
        else:
            before = target.stat()
            first = _file_sha(target)
            during = target.stat()
            second = _file_sha(target)
            after = target.stat()
            if (_reparse_or_junction(target) or first != second
                    or _fingerprint(before) != _fingerprint(during)
                    or _fingerprint(during) != _fingerprint(after)):
                return _hold("G4I_TARGET_DRIFT_DURING_INSPECTION")
            digest = second
            pre, post = record["target_pre_sha256"], record["target_post_sha256"]
            if digest == pre == post:
                state = AMBIGUOUS
            elif digest == pre:
                state = PREIMAGE
            elif digest == post:
                state = POSTIMAGE
            else:
                state = UNKNOWN

        wal_view = WAL.inspect_intent(wal_dir, intent_id)
        reason = wal_view.get("reason")
        base = {
            "current_state": state, "observed_sha256": digest,
            "wal_structurally_verified": reason in (
                "UNRESOLVED_INTENT", "OUTCOME_REPORTED_NOT_ATTESTED"),
        }
        if reason == "UNRESOLVED_INTENT":
            return _hold("UNRESOLVED_INTENT", **base)
        if reason != "OUTCOME_REPORTED_NOT_ATTESTED":
            return _hold("G4I_WAL_UNTRUSTED_OR_UNAVAILABLE", **base)
        outcome = WAL.load_verified_outcome(wal_dir, record)
        if outcome is None:
            return _hold("G4I_OUTCOME_UNTRUSTED", **base)
        reported = outcome["reported_status"]
        claimed_sha = outcome["observed_sha256"]
        if (claimed_sha != digest
                or (reported == "REPORTED_KEEP" and state != POSTIMAGE)
                or (reported == "REPORTED_ROLLBACK" and state != PREIMAGE)):
            return _hold("G4I_OUTCOME_VS_LIVE_MISMATCH", **base,
                         reported_status=reported)
        return _hold("OUTCOME_REPORTED_NOT_ATTESTED", **base,
                     reported_status=reported)
    except (OSError, TypeError, ValueError):
        return _hold("G4I_OBSERVATION_UNAVAILABLE")


def report_c2_wal_outcome_testonly(*, wal_dir: Path, intent_id: str,
                                    repo_root: Path,
                                    reported_status: str) -> dict[str, Any]:
    """Publie 1 résultat déclaratif à partir d'une double lecture NON signée.

    Surface expérimentale externe à la façade du runtime ; aucune autorité.
    """
    view = inspect_c2_wal_outcome_state(
        wal_dir=wal_dir, intent_id=intent_id, repo_root=repo_root)
    if view["reason"] != "UNRESOLVED_INTENT":
        return {**view, "wal_outcome_recorded": False,
                "reason": "G4I_REPORT_REQUIRES_UNRESOLVED_VERIFIED_INTENT"}
    state = view["current_state"]
    allowed = (reported_status == "REPORTED_KEEP" and state == POSTIMAGE
               or reported_status == "REPORTED_ROLLBACK" and state == PREIMAGE
               or reported_status == "REPORTED_QUARANTINE"
               and state in (PREIMAGE, POSTIMAGE, MISSING, UNKNOWN, AMBIGUOUS))
    if not allowed:
        return {**view, "wal_outcome_recorded": False,
                "reason": "G4I_REPORT_INCONSISTENT_WITH_OBSERVATION"}
    record = WAL.load_verified_intent(wal_dir, intent_id)
    if record is None:
        return {**view, "wal_outcome_recorded": False,
                "reason": "G4I_INTENT_DRIFT_BEFORE_REPORT"}
    outcome = WAL.build_outcome(
        record, reported_status=reported_status,
        observed_sha256=view["observed_sha256"])
    if outcome is None:
        return {**view, "wal_outcome_recorded": False,
                "reason": "G4I_OUTCOME_BUILD_HOLD"}
    stored = WAL.store_outcome(outcome, record, wal_dir)
    if stored.get("status") != WAL.STORED:
        return {**view, "wal_outcome_recorded": False,
                "reason": "G4I_OUTCOME_STORE_NOT_NEW_OR_UNAVAILABLE"}
    final = inspect_c2_wal_outcome_state(
        wal_dir=wal_dir, intent_id=intent_id, repo_root=repo_root)
    # Ce reporter a écrit un METADATA WAL, jamais la cible métier.
    return {**final, "readonly": False, "wal_outcome_recorded": True,
            "wal_metadata_written": True}
