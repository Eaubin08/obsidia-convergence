"""G4B : relecture des vrais contrats C2, sans effet ni autorite d'ecriture.

Les receipts C2 actuels ont un hash structurel, PAS un MAC de producteur.
Verifier les champs et leur liaison ne prouve pas une mutation historique.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from kx108_pre_post_closure_readonly_v1 import inspect_pre_post_write_closure
from scripts import obsidia_kx108_decision_store as _DS
from scripts import obsidia_sealed_evidence_v0 as _SEV

SCHEMA = "OBSIDIA_G4B_C2_ACTUAL_RECEIPTS_READONLY_V1"
_HASH = re.compile(r"[0-9a-fA-F]{64}\Z")
_BINDING_FIELDS = (
    "batch_execution_id", "child_execution_id",
    "execution_authority_hash", "approval_id",
)


def _hold(reason: str, *, structurally_linked: bool = False) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "status": "HOLD", "reason": reason,
        "decision_authority": "KX108_ONLY",
        "readonly": True,
        "c2_receipts_structurally_verified": structurally_linked,
        "receipt_producer_authenticated": False,
        "post_producer_authenticated": False,
        "actual_write_attested": False,
        "target_state_live_verified": False,
        "human_approval_verified": False,
        "global_write_closure_verified": False,
        "execution_authorized": False, "release_authorized": False,
        "target_mutated": False,
    }


def inspect_c2_actual_receipts(
    *, pre_record_id: str, post_record_id: str,
    pre_store_dir: Path, post_store_dir: Path,
    sealed_receipt_dir: Path, sealed_rollback_dir: Path,
    expected_anchors: dict[str, str], expected_target_path: str,
    expected_pre_sha256: str, expected_post_sha256: str,
) -> dict[str, Any]:
    """Compare les reçus C2 réellement relus, sans construire ces reçus.

    Les expected_* sont fournis par le demandeur : leurs origines ne sont
    pas prouvées ici. AUCUNE mutation ou release n'est possible dans l'API.
    """
    if (any(not isinstance(v, Path) for v in
            (pre_store_dir, post_store_dir, sealed_receipt_dir, sealed_rollback_dir))
            or not isinstance(expected_target_path, str) or not expected_target_path
            or not isinstance(expected_pre_sha256, str) or not _HASH.fullmatch(expected_pre_sha256)
            or not isinstance(expected_post_sha256, str) or not _HASH.fullmatch(expected_post_sha256)):
        return _hold("G4B_EXPECTED_TARGET_OR_STORES_INVALID")

    g4 = inspect_pre_post_write_closure(
        pre_record_id=pre_record_id, post_record_id=post_record_id,
        pre_store_dir=pre_store_dir, post_store_dir=post_store_dir,
        expected_anchors=expected_anchors,
    )
    if (not g4.get("pre_hmac_verified") or not g4.get("pre_post_record_link_verified")
            or not g4.get("sealed_evidence_links_present")):
        return _hold(f"G4B_PRE_POST_CHAIN_HOLD:{g4['reason']}")
    post = _DS.load_kx108_decision_record(post_record_id, post_store_dir)
    if (not isinstance(post, dict) or post.get("decision_record_id") != post_record_id
            or post.get("decision_record_hash") != g4["observed_post_record_hash"]):
        return _hold("G4B_POST_CHANGED_DURING_INSPECTION")

    apply_id = post["sealed_apply_receipt_id"]
    rollback_id = post["sealed_rollback_evidence_id"]
    apply_receipt = _SEV.load_sealed_apply_receipt(apply_id, sealed_receipt_dir)
    rollback = _SEV.load_sealed_rollback_evidence(rollback_id, sealed_rollback_dir)
    apply_ok, apply_reason = _SEV.verify_sealed_apply_receipt(apply_receipt)
    rollback_ok, rollback_reason = _SEV.verify_sealed_rollback_evidence(rollback)
    if not apply_ok:
        return _hold(f"G4B_APPLY_RECEIPT_INVALID:{apply_reason}")
    if not rollback_ok:
        return _hold(f"G4B_ROLLBACK_EVIDENCE_INVALID:{rollback_reason}")
    if not isinstance(apply_receipt, dict) or not isinstance(rollback, dict):
        return _hold("G4B_CANONICAL_VERIFIER_RETURN_TYPE_INVALID")
    if (apply_receipt.get("sealed_apply_receipt_id") != apply_id
            or rollback.get("sealed_rollback_evidence_id") != rollback_id):
        return _hold("G4B_RECEIPT_FILENAME_ID_MISMATCH")
    if (apply_receipt["sealed_apply_receipt_hash"] != post["sealed_apply_receipt_hash"]
            or rollback["sealed_rollback_evidence_hash"] != post["sealed_rollback_evidence_hash"]):
        return _hold("G4B_POST_C2_EXACT_HASH_MISMATCH")
    if (apply_receipt["sealed_rollback_evidence_id"] != rollback_id
            or apply_receipt["sealed_rollback_evidence_hash"] != rollback["sealed_rollback_evidence_hash"]):
        return _hold("G4B_APPLY_ROLLBACK_CROSS_LINK_MISMATCH")
    for record in (apply_receipt, rollback):
        for field in _BINDING_FIELDS:
            if record.get(field) != expected_anchors[field]:
                return _hold(f"G4B_RECEIPT_ANCHOR_MISMATCH:{field}")
        if (record.get("kx108_pre_decision_record_id") != pre_record_id
                or record.get("kx108_pre_decision_record_hash") != g4["observed_pre_record_hash"]):
            return _hold("G4B_RECEIPT_PRE_BINDING_MISMATCH")
        if record.get("target_path") != expected_target_path:
            return _hold("G4B_TARGET_PATH_MISMATCH")
        if record.get("source_content_sha256") != expected_post_sha256:
            return _hold("G4B_SOURCE_SHA_MISMATCH")
    if (rollback["pre_write_sha256"] != expected_pre_sha256
            or apply_receipt["target_pre_sha256"] != expected_pre_sha256
            or apply_receipt["target_post_sha256"] != expected_post_sha256):
        return _hold("G4B_TARGET_PRE_POST_SHA_MISMATCH")
    if (apply_receipt.get("source_kind") != rollback.get("source_kind")
            or apply_receipt.get("source_identity") != rollback.get("source_identity")):
        return _hold("G4B_SOURCE_PROVENANCE_MISMATCH")
    if (type(apply_receipt.get("bytes_written")) is not int
            or apply_receipt["bytes_written"] < 0):
        return _hold("G4B_BYTES_WRITTEN_INVALID")

    return {
        **_hold("G4B_C2_STRUCTURAL_BINDING_VALID_ORIGIN_AND_WRITE_UNATTESTED",
                structurally_linked=True),
        "pre_hmac_verified": True,
        "post_structural_hash_verified": True,
        "apply_receipt_structural_hash_verified": True,
        "rollback_evidence_structural_hash_verified": True,
        "preimage_bytes_hash_verified": True,
        "receipt_cross_links_verified": True,
        "source_provenance_fields_match": True,
        "expected_target_source_attested": False,
    }
