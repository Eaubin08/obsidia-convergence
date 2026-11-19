"""G4 : inspection KX108 PRE/POST et liens C2, sans aucune autorite d'APPLY.

Le POST canonique est actuellement protege par son hash structurel, mais
pas authentifie par HMAC K1. Les liens de preuves C2 ne sont pas des preuves
verifiees de l'ecriture/du rollback. Aucune conclusion de release n'en suit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scripts import obsidia_kx108_decision_store as _DS

SCHEMA = "OBSIDIA_KX108_G4_PRE_POST_CLOSURE_INSPECTION_V1"
_ANCHORS = (
    "batch_execution_id", "child_execution_id", "execution_authority_hash",
    "approval_id", "test_contract_hash",
)
_SEALED_LINKS = (
    "sealed_apply_receipt_id", "sealed_apply_receipt_hash",
    "sealed_rollback_evidence_id", "sealed_rollback_evidence_hash",
)
_HASH = re.compile(r"[0-9a-fA-F]{64}\Z")


def _hold(reason: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "status": "HOLD", "reason": reason,
        "decision_authority": "KX108_ONLY", "readonly": True,
        "pre_hmac_verified": False, "post_authenticated": False,
        "sealed_evidence_verified": False, "write_closure_verified": False,
        "human_approval_verified": False, "execution_authorized": False,
        "release_authorized": False, "target_mutated": False,
    }


def inspect_pre_post_write_closure(
    *, pre_record_id: str, post_record_id: str,
    pre_store_dir: Path, post_store_dir: Path,
    expected_anchors: dict[str, str],
) -> dict[str, Any]:
    """Relit les vrais records canoniques, compare les liens et reste HOLD.

    expected_anchors sont des valeurs attendues fournies par l'appelant :
    leur provenance est INCONNUE ici, elles ne prouvent ni HumanApproval ni
    l'identite du producteur des artefacts C2.
    """
    if (not isinstance(expected_anchors, dict)
            or set(expected_anchors) != set(_ANCHORS)
            or any(not isinstance(expected_anchors[k], str) or not expected_anchors[k].strip()
                   for k in _ANCHORS)):
        return _hold("G4_TRUSTED_ANCHORS_REQUIRED_EXACT")
    if (not _HASH.fullmatch(expected_anchors["execution_authority_hash"])
            or not _HASH.fullmatch(expected_anchors["test_contract_hash"])):
        return _hold("G4_ANCHOR_HASH_INVALID")
    if (not isinstance(pre_record_id, str) or not isinstance(post_record_id, str)
            or not isinstance(pre_store_dir, Path) or not isinstance(post_store_dir, Path)):
        return _hold("G4_STORE_OR_ID_INVALID")

    pre = _DS.load_kx108_decision_record(pre_record_id, pre_store_dir)
    if not isinstance(pre, dict) or pre.get("decision_record_id") != pre_record_id:
        return _hold("G4_PRE_RECORD_NOT_FOUND_OR_ID_MISMATCH")
    try:
        pre_valid, pre_reason = _DS.verify_kx108_decision_record_authenticity(pre)
    except Exception:
        return _hold("G4_PRE_AUTH_VERIFIER_UNAVAILABLE")
    if not pre_valid:
        return _hold(f"G4_PRE_AUTH_INVALID:{pre_reason}")
    if _DS.decision_phase_of(pre) != _DS.PRE_DECISION_PHASE:
        return _hold("G4_PRE_PHASE_INVALID")
    if pre.get("x108_gate") != "ALLOW":
        return _hold("G4_PRE_NOT_ALLOW")

    post = _DS.load_kx108_decision_record(post_record_id, post_store_dir)
    if not isinstance(post, dict) or post.get("decision_record_id") != post_record_id:
        return _hold("G4_POST_RECORD_NOT_FOUND_OR_ID_MISMATCH")
    post_valid, post_reason = _DS.verify_kx108_decision_record(post)
    if not post_valid:
        return _hold(f"G4_POST_STRUCTURAL_INVALID:{post_reason}")
    if _DS.decision_phase_of(post) != _DS.POST_DECISION_PHASE:
        return _hold("G4_POST_PHASE_INVALID")
    if (post.get("kx108_pre_decision_record_id") != pre_record_id
            or post.get("kx108_pre_decision_record_hash") != pre["decision_record_hash"]):
        return _hold("G4_POST_PRE_EXACT_RECORD_BINDING_MISMATCH")
    for key in _ANCHORS:
        if pre.get(key) != expected_anchors[key] or post.get(key) != expected_anchors[key]:
            return _hold(f"G4_ANCHOR_MISMATCH:{key}")
    if not all(isinstance(post.get(key), str) and post[key].strip() for key in _SEALED_LINKS):
        return _hold("G4_C2_SEALED_EVIDENCE_LINK_INCOMPLETE")
    if any(not _HASH.fullmatch(post[key]) for key in
           ("sealed_apply_receipt_hash", "sealed_rollback_evidence_hash")):
        return _hold("G4_C2_SEALED_EVIDENCE_HASH_INVALID")

    return {
        **_hold("G4_RECORDS_BOUND_C2_RECEIPTS_AND_POST_ORIGIN_NOT_ATTESTED"),
        "pre_hmac_verified": True,
        "pre_post_record_link_verified": True,
        "post_structural_hash_verified": True,
        "post_authenticated": False,
        "sealed_evidence_links_present": True,
        "sealed_evidence_verified": False,
        "expected_anchors_source_attested": False,
        "observed_pre_gate": pre["x108_gate"],
        "observed_post_gate": post["x108_gate"],
    }
