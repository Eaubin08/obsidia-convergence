"""G4M : cohérence d'une proposition de rôle par PC avec un WAL RSA G4K.

Une proposition Git/publique, même correctement épinglée, n'est pas une
attestation d'enrôlement ni une délégation d'autorité souveraine.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from obsidure_machine_identity_registry_v1 import inspect_machine_identity_registry
from c2_wal_runner_observation_g4k_v1 import inspect_c2_wal_synthetic_runner_observation

SCHEMA = "OBSIDIA_G4M_MACHINE_ROLE_PROPOSAL_BOUNDARY_V1"
REQUIRED_ROLE = "OBSIDURE_TEST_EVIDENCE_PRODUCER"


def _hold(reason: str, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA, "status": "HOLD", "reason": reason,
        "readonly": True, "decision_authority": "KX108_ONLY",
        "machine_registry_structure_valid": False,
        "proposal_machine_pin_consistent": False,
        "synthetic_machine_signature_verified": False,
        "synthetic_runner_trace_verified": False,
        "proposed_role": REQUIRED_ROLE,
        "proposed_role_is_active": False,
        "machine_identity_attested": False,
        "certificate_enrollment_approved": False,
        "registry_approval_verified": False,
        "responsible_person_authenticated": False,
        "producer_identity_attested": False,
        "real_c278_runner_attested": False,
        "replay_prevented": False,
        "human_approval_verified": False,
        "kx108_ticket_issued": False,
        "execution_authorized": False,
        "recovery_authorized": False,
        "release_authorized": False,
        "target_mutated": False,
        **extra,
    }


def inspect_obsidure_machine_role_proposal(
    *, registry: Any, expected_machine_id: str,
    expected_public_certificate_sha256: str,
    public_certificate_der_base64: str, wal_dir: Path,
    repo_root: Path, intent_id: str, receipt: Any,
) -> dict[str, Any]:
    """Un seul point d'entrée vérificateur sans API d'approbation ni writer."""
    structure = inspect_machine_identity_registry(registry)
    if structure.get("status") != "MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED":
        return _hold("G4M_MACHINE_REGISTRY_INVALID:" + str(structure.get("reason")))
    entries = [e for e in registry["machine_identities"] if e["machine_id"] == expected_machine_id]
    if len(entries) != 1:
        return _hold("G4M_MACHINE_NOT_REGISTERED", machine_registry_structure_valid=True)
    entry = entries[0]
    if entry["enrollment_state"] == "REVOKED":
        return _hold("G4M_MACHINE_REVOKED", machine_registry_structure_valid=True)
    if entry["enrollment_state"] != "ENROLLED_AWAITING_REVIEW":
        return _hold("G4M_MACHINE_NOT_ENROLLED", machine_registry_structure_valid=True)
    if (entry["public_certificate_sha256"] != expected_public_certificate_sha256
            or entry["public_certificate_der_base64"] != public_certificate_der_base64):
        return _hold("G4M_PUBLIC_CERTIFICATE_REGISTRY_MISMATCH",
                     machine_registry_structure_valid=True)
    signed = inspect_c2_wal_synthetic_runner_observation(
        wal_dir=wal_dir, intent_id=intent_id, repo_root=repo_root,
        receipt=receipt, public_certificate_der_base64=public_certificate_der_base64,
        pinned_certificate_sha256=expected_public_certificate_sha256,
        expected_machine_id=expected_machine_id)
    if (not signed.get("machine_signature_verified")
            or not signed.get("synthetic_runner_record_verified")):
        return _hold("G4M_SIGNED_SYNTHETIC_RUNNER_REQUIRED:" + str(signed.get("reason")),
                     machine_registry_structure_valid=True,
                     proposal_machine_pin_consistent=True)
    return _hold(
        "G4M_MACHINE_ROLE_PROPOSED_CRYPTO_BOUND_NOT_APPROVED",
        machine_registry_structure_valid=True,
        proposal_machine_pin_consistent=True,
        synthetic_machine_signature_verified=True,
        synthetic_runner_trace_verified=True,
        machine_id=expected_machine_id,
        responsible_refs_declared=list(entry["responsible_refs"]),
        review_reference_declared=entry["enrollment_review_ref"],
        enrollment_state=entry["enrollment_state"],
        limits=[
            "PUBLIC_GIT_REGISTRY_AND_CALLER_PIN_ARE_NOT_INDEPENDENT_APPROVAL",
            "RESPONSIBLE_REFS_AND_REVIEW_REFS_ARE_UNVERIFIED_DECLARATIONS",
            "G4K_SYNTHETIC_SIGNATURE_NOT_REAL_C278_PRODUCER_IDENTITY",
            "REVOKED_OR_UNREGISTERED_MACHINE_MUST_NOT_BE_ADMITTED",
            "NO_NEW_KX108_PERMISSION_OR_RELEASE",
        ],
    )
