"""Inventaire de confiance Obsidure par PC, sans émission d'autorité.

Le registre versionné est un PROJET d'attribution des rôles. Son contenu
seul ne prouve ni l'identité de la machine, ni celle d'un responsable :
l'ancrage indépendant et le contrôle de signatures restent obligatoires.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any

_SCHEMA = "OBSIDIA_OBSIDURE_MACHINE_IDENTITY_REGISTRY_V1"
_ROOT_FIELDS = frozenset({"schema", "decision_authority", "trust_model", "machine_identities"})
_MACHINE_FIELDS = frozenset({
    "machine_id", "enrollment_state", "public_certificate_der_base64",
    "public_certificate_sha256", "responsible_refs", "proposed_roles",
    "enrollment_review_ref", "revocation_ref",
})
_STATES = frozenset({"PLANNED", "ENROLLED_AWAITING_REVIEW", "REVOKED"})
_MACHINE = re.compile(r"[A-Z0-9][A-Z0-9-]{2,63}\Z")
_REF = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _result(status: str, reason: str | None, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "OBSIDIA_OBSIDURE_MACHINE_IDENTITY_INSPECTION_V1",
        "status": status, "reason": reason,
        "readonly": True, "authority": "NON_SOVEREIGN",
        "decision_authority": "KX108_ONLY",
        "machine_identity_attested": False,
        "responsible_person_authenticated": False,
        "trusted_machines_count": 0,
        "registry_approval_verified": False,
        "machine_signature_verified": False,
        "sandbox_origin_attested": False,
        "human_approval_verified": False,
        "action_ticket_issued": False,
        "execution_authorized": False,
        "release_authorized": False,
        "target_mutated": False,
        **extra,
    }


def _hold(reason: str) -> dict[str, Any]:
    return _result("HOLD", reason)


def inspect_machine_identity_registry(registry: Any) -> dict[str, Any]:
    """Contrôle structurel strict : jamais un registre d'autorisation actif."""
    if type(registry) is not dict or set(registry) != _ROOT_FIELDS:
        return _hold("MACHINE_REGISTRY_FIELDS_INVALID")
    if (registry.get("schema") != _SCHEMA
            or registry.get("decision_authority") != "KX108_ONLY"
            or registry.get("trust_model") != "PER_MACHINE_INDEPENDENT_ASYMMETRIC"):
        return _hold("MACHINE_REGISTRY_AUTHORITY_OR_SCHEMA_INVALID")
    identities = registry.get("machine_identities")
    if type(identities) is not list or not 1 <= len(identities) <= 256:
        return _hold("MACHINE_REGISTRY_SIZE_INVALID")

    machine_ids: set[str] = set()
    fingerprints: set[str] = set()
    pending = 0
    revoked = 0
    for entry in identities:
        if type(entry) is not dict or set(entry) != _MACHINE_FIELDS:
            return _hold("MACHINE_IDENTITY_FIELDS_INVALID")
        machine_id = entry["machine_id"]
        if (type(machine_id) is not str or _MACHINE.fullmatch(machine_id) is None
                or machine_id in machine_ids):
            return _hold("MACHINE_IDENTITY_DUPLICATE_OR_INVALID")
        machine_ids.add(machine_id)
        state = entry["enrollment_state"]
        if type(state) is not str or state not in _STATES:
            return _hold("MACHINE_ENROLLMENT_STATE_INVALID")
        roles = entry["proposed_roles"]
        if type(roles) is not list or roles != ["OBSIDURE_TEST_EVIDENCE_PRODUCER"]:
            return _hold("MACHINE_ROLE_CANNOT_GRANT_KX108_AUTHORITY")
        operators = entry["responsible_refs"]
        if (type(operators) is not list or len(operators) > 16
                or any(type(x) is not str or _REF.fullmatch(x) is None for x in operators)
                or len(operators) != len(set(operators))):
            return _hold("MACHINE_RESPONSIBLE_REFS_INVALID")
        public = entry["public_certificate_der_base64"]
        digest = entry["public_certificate_sha256"]
        if state == "PLANNED":
            if (public is not None or digest is not None
                    or entry["enrollment_review_ref"] is not None
                    or entry["revocation_ref"] is not None):
                return _hold("MACHINE_PLANNED_WITH_FORGED_ENROLLMENT")
            pending += 1
            continue
        if (type(public) is not str or not 0 < len(public) <= 16384
                or type(digest) is not str or _HEX64.fullmatch(digest) is None):
            return _hold("MACHINE_PUBLIC_CERTIFICATE_MISSING")
        try:
            raw = base64.b64decode(public, validate=True)
        except (ValueError, binascii.Error):
            return _hold("MACHINE_PUBLIC_CERTIFICATE_INVALID_BASE64")
        if (len(raw) < 200 or len(raw) > 12288
                or base64.b64encode(raw).decode("ascii") != public
                or hashlib.sha256(raw).hexdigest() != digest):
            return _hold("MACHINE_PUBLIC_CERTIFICATE_HASH_MISMATCH")
        if digest in fingerprints:
            return _hold("MACHINE_PUBLIC_CERTIFICATE_REUSED_ACROSS_MACHINES")
        fingerprints.add(digest)
        if state == "ENROLLED_AWAITING_REVIEW":
            if entry["revocation_ref"] is not None:
                return _hold("MACHINE_PENDING_ENROLLMENT_REVOCATION_CONFLICT")
            pending += 1
        else:
            ref = entry["revocation_ref"]
            if type(ref) is not str or _REF.fullmatch(ref) is None:
                return _hold("MACHINE_REVOCATION_EVIDENCE_REQUIRED")
            revoked += 1
        review = entry["enrollment_review_ref"]
        if review is not None and (type(review) is not str or _REF.fullmatch(review) is None):
            return _hold("MACHINE_REVIEW_REFERENCE_INVALID")
    return _result(
        "MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED", None,
        machine_ids=sorted(machine_ids), certificate_records_count=len(fingerprints),
        pending_count=pending, revoked_count=revoked,
        limits=[
            "THE_PUBLIC_GIT_REGISTRY_IS_NOT_A_TRUST_ROOT",
            "MACHINE_ID_IS_A_DECLARED_IDENTIFIER_NOT_HARDWARE_ATTESTATION",
            "RESPONSIBLE_REFS_ARE_NOT_HUMAN_APPROVAL",
            "ENROLLMENT_REQUIRES_OUT_OF_BAND_REVIEW_AND_PUBLIC_KEY_PINNING",
            "NO_C278_RUNNER_OR_TEST_PROVENANCE_SIGNED_YET",
        ],
    )
