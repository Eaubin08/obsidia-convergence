"""G4D : HMAC canonique POST + reçus C2 cohérents, sans preuve d'APPLY.

Ce contrôle ne signe rien, n'exécute rien et ne transforme jamais des reçus
structurels en autorisation. Le certificat du producteur/runner C2 est absent.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from kx108_c2_receipts_readonly_v1 import inspect_c2_actual_receipts
from scripts import obsidia_kx108_decision_store as _DS

SCHEMA = "OBSIDIA_G4D_C2_SIGNED_POST_READONLY_V1"
_POST_PRODUCER = "run_and_persist_kx108_post_execution_decision"


def _hold(reason: str, *, hmac_verified: bool = False,
          receipt_structure_verified: bool = False) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "status": "HOLD", "reason": reason,
        "decision_authority": "KX108_ONLY", "readonly": True,
        "post_hmac_verified": hmac_verified,
        "post_producer_claim_hmac_bound": hmac_verified,
        "post_producer_process_attested": False,
        "c2_receipts_structurally_verified": receipt_structure_verified,
        "receipt_producer_authenticated": False,
        "real_apply_attested": False,
        "target_state_live_verified": False,
        "human_approval_verified": False,
        "global_write_closure_verified": False,
        "execution_authorized": False,
        "release_authorized": False,
        "target_mutated": False,
    }


def inspect_c2_signed_post_receipts(*, pre_record_id: str, post_record_id: str,
                                    pre_store_dir: Any, post_store_dir: Any,
                                    sealed_receipt_dir: Any,
                                    sealed_rollback_dir: Any,
                                    expected_anchors: Any,
                                    expected_target_path: Any,
                                    expected_pre_sha256: Any,
                                    expected_post_sha256: Any) -> dict[str, Any]:
    """Vérification conservatrice, de provenance incomplète, sur magasins réels.

    Les références `expected_*` appartiennent toujours au demandeur ; elles
    ne prouvent pas leur propre origine. Les résultats sont uniquement HOLD.
    """
    if (not isinstance(pre_record_id, str) or not isinstance(post_record_id, str)
            or any(not isinstance(p, Path) for p in (
                pre_store_dir, post_store_dir,
                sealed_receipt_dir, sealed_rollback_dir))):
        return _hold("G4D_CANONICAL_IDS_OR_STORES_REQUIRED")
    # Les contraintes de forme/chemin/liaison sont vérifiées par G4B après
    # cette première barrière d'authenticité POST.
    post = _DS.load_kx108_decision_record(post_record_id, post_store_dir)
    if not isinstance(post, dict) or post.get("decision_record_id") != post_record_id:
        return _hold("G4D_POST_NOT_FOUND_OR_ID_MISMATCH")
    try:
        valid, reason = _DS.verify_kx108_decision_record_authenticity(post)
    except Exception:
        return _hold("G4D_POST_AUTH_VERIFIER_UNAVAILABLE")
    if not valid:
        return _hold(f"G4D_POST_HMAC_INVALID:{reason}")
    if _DS.decision_phase_of(post) != _DS.POST_DECISION_PHASE:
        return _hold("G4D_POST_PHASE_INVALID")
    if post.get("decision_record_producer") != _POST_PRODUCER:
        return _hold("G4D_POST_PRODUCER_NOT_CANONICAL")

    signed_hash = post["decision_record_hash"]
    signed_authenticator = post["decision_record_authenticator"]

    # G4B relit PRE et deux reçus C2 depuis les stockages canoniques.
    # Il vérifie les bytes de préimage et les liaisons, pas le producteur.
    try:
        base = inspect_c2_actual_receipts(
            pre_record_id=pre_record_id, post_record_id=post_record_id,
            pre_store_dir=pre_store_dir, post_store_dir=post_store_dir,
            sealed_receipt_dir=sealed_receipt_dir,
            sealed_rollback_dir=sealed_rollback_dir,
            expected_anchors=expected_anchors,
            expected_target_path=expected_target_path,
            expected_pre_sha256=expected_pre_sha256,
            expected_post_sha256=expected_post_sha256,
        )
    except (KeyError, TypeError, ValueError, OSError):
        return _hold("G4D_C2_INSPECTOR_INVALID_INPUT_OR_UNAVAILABLE")
    if base.get("c2_receipts_structurally_verified") is not True:
        return _hold(f"G4D_C2_CHAIN_HOLD:{base.get('reason')}", hmac_verified=True)

    # Dernière relecture : un POST différent ne peut pas profiter d'un
    # contrôle G4B réalisé sur une autre version du record.
    final_post = _DS.load_kx108_decision_record(post_record_id, post_store_dir)
    if (not isinstance(final_post, dict)
            or final_post.get("decision_record_hash") != signed_hash
            or final_post.get("decision_record_authenticator") != signed_authenticator):
        return _hold("G4D_POST_CHANGED_DURING_INSPECTION")
    try:
        final_valid, final_reason = _DS.verify_kx108_decision_record_authenticity(final_post)
    except Exception:
        return _hold("G4D_POST_FINAL_AUTH_VERIFIER_UNAVAILABLE")
    if not final_valid:
        return _hold(f"G4D_POST_FINAL_AUTH_INVALID:{final_reason}")

    return {
        **_hold(
            "G4D_POST_HMAC_AND_C2_STRUCTURE_VALID_PRODUCER_AND_WRITE_UNATTESTED",
            hmac_verified=True, receipt_structure_verified=True,
        ),
        "post_producer_claim": _POST_PRODUCER,
        "post_record_hash": signed_hash,
        "post_record_key_id": post.get("decision_record_key_id"),
    }
