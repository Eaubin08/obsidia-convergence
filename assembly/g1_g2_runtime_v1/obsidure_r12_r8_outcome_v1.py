"""Obsidure F7/R12 -> preuves R8 canoniques, lecture seule et non souveraine.

Ce rail reprend uniquement l'ingestion historique R10-B3/R12 : il appelle les
quatre fonctions R8 réelles, sans réessayer une action ni exécuter Obsidure.
Les entrées R10/R9 restent des déclarations non attestées par cette frontière.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import obsidia_canonical_receipt_envelope_v1 as _CRE
import obsidia_canonical_receipt_replay_v1 as _R8_INTEGRITY
import obsidia_governance_decision_replay_v1 as _R8_DECISION
import obsidia_realized_state_reconciliation_v1 as _R8_REALIZED

_ACTION_ID = re.compile(r"aev-[0-9a-f]{32}\Z")
_REPAIR_KEYS = ("repair_request_id", "repair_proposal_id", "repair_verdict_id")
_BUILDER_KEYS = (
    "builder_proposal_id", "builder_manifest_id", "builder_validation_id",
    "builder_handoff_id", "v2_exec_id",
)
_STORE_DIRS = ("v2exec", "approval", "kxpre", "receipts")


def _answer(reason: str | None, classification: str, recommendation: str, **extra: Any) -> dict:
    return {
        "schema_version": "OBSIDURE_R12_R8_HISTORICAL_FEEDBACK_V1",
        "status": "R12_R8_OUTCOME_HELD" if reason is not None else "R12_R8_OUTCOME_INSPECTED",
        "reason": reason,
        "derived_outcome_classification": classification,
        "recommendation": recommendation,
        "readonly": True,
        "advisory_only": True,
        "authority": "NON_SOVEREIGN",
        "decision_authority": "KX108_ONLY",
        "human_approval_verified": False,
        "execution_authorized": False,
        "action_ticket_issued": False,
        "kx108_pre_invoked": False,
        "executor_invoked": False,
        "target_mutated": False,
        "memory_promotion": False,
        "canonical_receipt_mutation": False,
        "automatic_retry": False,
        **extra,
    }


def _hold(reason: str, **extra: Any) -> dict:
    return _answer(reason, "EVIDENCE_INCOMPLETE", "ESCALATE", **extra)


def _identity(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= 160 and value == value.strip()


def _lineage(value: Any, keys: tuple[str, ...]) -> dict[str, str] | None:
    if type(value) is not dict:
        return None
    if not all(_identity(value.get(key)) for key in keys):
        return None
    return {key: value[key] for key in keys}


def _safe_stores(base: Any) -> Path | None:
    """Refus des alias de répertoires susceptibles de sortir des stores R8."""
    try:
        if not isinstance(base, (str, Path)) or not str(base):
            return None
        root = Path(base)
        if not root.is_dir() or root.is_symlink() or root.is_junction():
            return None
        if any(parent.is_symlink() or parent.is_junction() for parent in root.parents):
            return None
        resolved = root.resolve(strict=True)
        for name in _STORE_DIRS:
            child = root / name
            if child.is_symlink() or child.is_junction():
                return None
            if child.exists() and (not child.is_dir() or child.resolve() != resolved / name):
                return None
        return resolved
    except (OSError, ValueError, TypeError, RuntimeError):
        return None


def inspect_obsidure_r12_r8_outcome(
    *, action_evidence_id: str, stores_base_dir: Path,
    r10_inspection: dict[str, Any], prepared_repair: dict[str, Any],
) -> dict[str, Any]:
    """Confronte une réparation R10 préparée à des preuves R8 déjà persistées.

    Aucune promesse d'approbation, de provenance sandbox ou d'APPLY n'est
    inférée d'une sortie de replay : c'est un avis sur l'historique seulement.
    """
    if type(action_evidence_id) is not str or _ACTION_ID.fullmatch(action_evidence_id) is None:
        return _hold("R8_ACTION_EVIDENCE_ID_INVALID")
    stores = _safe_stores(stores_base_dir)
    if stores is None:
        return _hold("R8_STORES_UNVERIFIED")
    if type(r10_inspection) is not dict or r10_inspection.get("status") != "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY":
        return _hold("R10_INSPECTION_REQUIRED")
    repair_lineage = _lineage(r10_inspection, _REPAIR_KEYS)
    if repair_lineage is None:
        return _hold("R10_REPAIR_LINEAGE_INCOMPLETE")
    if type(prepared_repair) is not dict:
        return _hold("R9_PREPARED_CONTEXT_REQUIRED")
    prepared_lineage = _lineage(prepared_repair.get("repair_lineage"), _REPAIR_KEYS)
    if prepared_lineage is None or prepared_lineage != repair_lineage:
        return _answer("R9_REPAIR_LINEAGE_MISMATCH", "GOVERNANCE_MISMATCH", "STOP_BLOCKED")

    action = prepared_repair.get("prepared_action")
    if type(action) is not dict:
        return _hold("R9_PREPARED_ACTION_REQUIRED")
    builder = _lineage(action.get("builder_lineage"), _BUILDER_KEYS[:4])
    v2_exec_id = action.get("v2_exec_id")
    if builder is None or not _identity(v2_exec_id):
        return _hold("R9_BUILDER_LINEAGE_INCOMPLETE")
    expected = {**builder, "v2_exec_id": v2_exec_id}

    try:
        receipt_file = stores / "receipts" / (action_evidence_id + ".json")
        if receipt_file.is_symlink() or receipt_file.is_junction():
            return _hold("R8_RECEIPT_REPARSE_UNSAFE")
        receipt_bytes_before = receipt_file.read_bytes() if receipt_file.is_file() else None
        receipt = _CRE.load_canonical_receipt_envelope(action_evidence_id, stores / "receipts")
    except (OSError, ValueError, UnicodeError, TypeError):
        return _hold("R8_RECEIPT_UNREADABLE")
    if type(receipt) is not dict:
        return _hold("R8_CANONICAL_RECEIPT_MISSING_OR_INVALID")
    try:
        valid, invalid_reason = _CRE.verify_canonical_receipt_envelope(receipt)
    except (OSError, TypeError, ValueError, KeyError, AttributeError, UnicodeError):
        return _answer("R8_RECEIPT_STRUCTURE_TAMPERED", "EVIDENCE_TAMPERED", "STOP_BLOCKED")
    if not valid:
        return _answer("R8_RECEIPT_INTEGRITY_INVALID:" + str(invalid_reason), "EVIDENCE_TAMPERED", "STOP_BLOCKED")
    ref = receipt.get("request_ref") or {}
    prepare = receipt.get("prepare") or {}
    session = receipt.get("session_ref") or {}
    if not all(type(x) is dict for x in (ref, prepare, session)):
        return _hold("R8_CANONICAL_RECEIPT_STRUCTURE_INVALID")
    observed = ref.get("builder_lineage") or prepare.get("builder_lineage") or {}
    if type(observed) is not dict or any(observed.get(key) != value for key, value in builder.items()):
        return _answer("R8_BUILDER_LINEAGE_MISMATCH", "GOVERNANCE_MISMATCH", "STOP_BLOCKED")
    if session.get("v2_exec_id") != v2_exec_id:
        return _answer("R8_V2_EXEC_LINEAGE_MISMATCH", "GOVERNANCE_MISMATCH", "STOP_BLOCKED")

    try:
        integrity = _R8_INTEGRITY.replay_action_evidence(action_evidence_id, stores_base_dir=stores)
        decision = _R8_DECISION.replay_governance_decision(action_evidence_id, stores_base_dir=stores)
        reconciliation = _R8_REALIZED.reconcile_action_evidence(action_evidence_id, stores_base_dir=stores)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        return _hold("R8_REPLAY_UNAVAILABLE:" + type(exc).__name__)
    try:
        if (receipt_file.is_symlink() or receipt_file.is_junction()
                or receipt_bytes_before is None
                or hashlib.sha256(receipt_file.read_bytes()).digest()
                != hashlib.sha256(receipt_bytes_before).digest()):
            return _answer("R8_RECEIPT_CHANGED_DURING_REPLAY", "EVIDENCE_TAMPERED", "STOP_BLOCKED")
    except (OSError, ValueError):
        return _answer("R8_RECEIPT_UNREADABLE_AFTER_REPLAY", "EVIDENCE_TAMPERED", "STOP_BLOCKED")
    if not all(type(item) is dict for item in (integrity, decision, reconciliation)):
        return _hold("R8_CANONICAL_REPLAY_RESULT_INVALID")
    replay_verdict = integrity.get("replay_verdict")
    decision_verdict = decision.get("replay_verdict")
    realization = reconciliation.get("reconciliation_status")
    realized = receipt.get("realized_state") or {}
    authorization = receipt.get("authorization") or {}
    if not all(type(item) is dict for item in (realized, authorization)):
        return _hold("R8_CANONICAL_OUTCOME_STRUCTURE_INVALID")
    outcome = realized.get("outcome", integrity.get("outcome", "UNKNOWN"))
    limits = tuple(str(v) for field in (
        integrity.get("evidence_missing"), decision.get("evidence_limits"),
        reconciliation.get("evidence_limits"),
    ) for v in (field if type(field) is list else ()))
    summary = {
        "action_evidence_id": action_evidence_id,
        "repair_lineage": repair_lineage,
        "builder_lineage": expected,
        "r8_integrity_verdict": replay_verdict,
        "r8_decision_verdict": decision_verdict,
        "r8_reconciliation_status": realization,
        "r8_outcome": outcome,
        "evidence_limits": list(limits)[:128],
        "evidence_provenance_verified": False,
    }
    if replay_verdict in {"TAMPERED", "CONFLICTING"} or realization == "TAMPERED":
        return _answer(None, "EVIDENCE_TAMPERED", "STOP_BLOCKED", **summary)
    if decision_verdict in {"TAMPERED", "MISMATCH"}:
        return _answer(None, "GOVERNANCE_MISMATCH", "STOP_BLOCKED", **summary)
    if outcome in {"KX108_HOLD", "KX108_BLOCK"} or authorization.get("kx108_verdict") in {"HOLD", "BLOCK"}:
        return _answer(None, "PRE_DISPATCH_FAILURE", "STOP_BLOCKED", **summary)
    if realization == "UNCERTAIN" or outcome == "DISPATCHED_OUTCOME_UNCERTAIN" or realized.get("dispatch_boundary") == "POST_DISPATCH_UNCERTAINTY":
        return _answer(None, "DISPATCHED_OUTCOME_UNCERTAIN", "ESCALATE", **summary)
    if realization == "MISMATCH" or outcome == "REALIZED_STATE_MISMATCH":
        return _answer(None, "EXECUTED_NOT_REALIZED", "ESCALATE", **summary)
    if (replay_verdict != "VERIFIED" or decision_verdict != "MATCH"
            or realization not in {"MATCH", "NOOP_CONFIRMED"} or limits):
        return _answer(None, "EVIDENCE_INCOMPLETE", "ESCALATE", **summary)
    if outcome not in {"SUCCESS", "NOOP"}:
        return _answer(None, "HISTORICAL_OUTCOME_NOT_SUCCESS", "ESCALATE", **summary)
    return _answer(None, "HISTORICAL_EXECUTION_EVIDENCE_MATCHED", "STOP_SUCCESS", **summary)
