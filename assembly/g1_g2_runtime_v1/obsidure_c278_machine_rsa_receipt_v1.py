"""Vérification RSA d'un reçu C278 par machine, sans délégation souveraine.

Une signature valide démontre la possession de la clé correspondant au
certificat épinglé. Elle ne prouve ni qui a lancé le test, ni qu'il a eu lieu.
Ce module ne signe rien, ne gère aucune clé privée et n'écrit aucun fichier.

La bibliothèque facultative ``cryptography`` n'est importée qu'au contrôle
cryptographique : son absence produit HOLD, jamais un contournement.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from obsidure_c278_sandbox_observation_v1 import (
    inspect_obsidure_c278_sandbox_observation,
)

_SCHEMA = "OBSIDURE_C278_MACHINE_RSA_RECEIPT_V1"
_DOMAIN = b"OBSIDIA_OBSIDURE_C278_MACHINE_RSA_V1\x00"
_FIELDS = frozenset({
    "schema", "machine_id", "public_certificate_sha256", "receipt_id",
    "nonce", "request_id", "proposal_id", "verdict_id",
    "repair_request_sha256", "repair_proposal_sha256", "c278_evidence_sha256",
    "repair_verdict_sha256", "candidate_artifact_sha256", "source_git_head",
    "runner_code_sha256", "tests_transcript_sha256",
})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_MACHINE = re.compile(r"[A-Z0-9][A-Z0-9-]{2,63}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def _canonical(value: Any) -> bytes | None:
    try:
        data = json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        return None
    return data if len(data) <= 2_000_000 else None


def _digest(value: Any) -> str | None:
    raw = _canonical(value)
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def _result(status: str, reason: str | None, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "OBSIDURE_C278_MACHINE_RSA_INSPECTION_V1",
        "status": status, "reason": reason, "readonly": True,
        "authority": "NON_SOVEREIGN", "decision_authority": "KX108_ONLY",
        "machine_signature_verified": False,
        "machine_identity_attested": False,
        "certificate_enrollment_approved": False,
        "producer_identity_attested": False,
        "responsible_person_authenticated": False,
        "sandbox_bytes_observed": False,
        "sandbox_origin_attested": False,
        "test_process_attested": False,
        "test_isolation_certified": False,
        "live_git_head_verified": False,
        "replay_prevented": False,
        "provenance_verified": False,
        "human_approval_verified": False,
        "execution_authorized": False,
        "release_authorized": False,
        "action_ticket_issued": False,
        "kx108_pre_invoked": False,
        "executor_invoked": False,
        "target_mutated": False,
        "automatic_retry": False,
        **extra,
    }


def _hold(reason: str) -> dict[str, Any]:
    return _result("HOLD", reason)


def inspect_c278_machine_rsa_receipt(
    *, r10_inspection: dict[str, Any], repair_request: dict[str, Any],
    repair_proposal: dict[str, Any], c278_evidence: dict[str, Any],
    repair_verdict: dict[str, Any], repo_root: Path,
    receipt: dict[str, Any], public_certificate_der_base64: str | None,
    pinned_certificate_sha256: str, expected_machine_id: str,
) -> dict[str, Any]:
    """Vérifie C278, les bytes observables et RSA-PKCS1v15/SHA256.

    Le pin et la machine attendue doivent provenir d'une politique distincte
    du reçu : un argument fourni par l'appelant ne vaut pas approbation.
    Le certificat public n'est jamais ajouté automatiquement à un registre.
    """
    if (type(expected_machine_id) is not str
            or _MACHINE.fullmatch(expected_machine_id) is None
            or type(pinned_certificate_sha256) is not str
            or _HEX64.fullmatch(pinned_certificate_sha256) is None):
        return _hold("C278_MACHINE_EXPECTED_IDENTITY_INVALID")
    if type(public_certificate_der_base64) is not str or not 0 < len(public_certificate_der_base64) <= 16384:
        return _hold("C278_MACHINE_PUBLIC_CERTIFICATE_REQUIRED")
    try:
        cert_bytes = base64.b64decode(public_certificate_der_base64, validate=True)
    except (binascii.Error, ValueError):
        return _hold("C278_MACHINE_PUBLIC_CERTIFICATE_BASE64_INVALID")
    if (not 200 <= len(cert_bytes) <= 12288
            or base64.b64encode(cert_bytes).decode("ascii") != public_certificate_der_base64
            or hashlib.sha256(cert_bytes).hexdigest() != pinned_certificate_sha256):
        return _hold("C278_MACHINE_PUBLIC_CERTIFICATE_PIN_MISMATCH")

    if type(receipt) is not dict or set(receipt) != {"payload", "signature_base64"}:
        return _hold("C278_MACHINE_RECEIPT_ENVELOPE_INVALID")
    payload, signature64 = receipt["payload"], receipt["signature_base64"]
    if type(payload) is not dict or set(payload) != _FIELDS:
        return _hold("C278_MACHINE_RECEIPT_FIELDS_INVALID")
    if (payload.get("schema") != _SCHEMA
            or payload.get("machine_id") != expected_machine_id
            or payload.get("public_certificate_sha256") != pinned_certificate_sha256):
        return _hold("C278_MACHINE_RECEIPT_IDENTITY_MISMATCH")
    if any(type(payload.get(k)) is not str or _ID.fullmatch(payload[k]) is None
           for k in ("receipt_id", "request_id", "proposal_id", "verdict_id")):
        return _hold("C278_MACHINE_RECEIPT_LINEAGE_INVALID")
    if (any(type(payload.get(k)) is not str or _HEX64.fullmatch(payload[k]) is None
            for k in (
                "nonce", "repair_request_sha256", "repair_proposal_sha256",
                "c278_evidence_sha256", "repair_verdict_sha256",
                "runner_code_sha256", "tests_transcript_sha256",
            ))
            or type(payload.get("source_git_head")) is not str
            or _HEX40.fullmatch(payload["source_git_head"]) is None):
        return _hold("C278_MACHINE_RECEIPT_DIGESTS_INVALID")
    if type(signature64) is not str or not 0 < len(signature64) <= 4096:
        return _hold("C278_MACHINE_SIGNATURE_FORMAT_INVALID")
    try:
        signature = base64.b64decode(signature64, validate=True)
    except (binascii.Error, ValueError):
        return _hold("C278_MACHINE_SIGNATURE_FORMAT_INVALID")
    if base64.b64encode(signature).decode("ascii") != signature64:
        return _hold("C278_MACHINE_SIGNATURE_FORMAT_INVALID")

    # Le contrôle d'origine observable se fait AVANT la vérification de signature.
    observation = inspect_obsidure_c278_sandbox_observation(
        r10_inspection=r10_inspection, repair_request=repair_request,
        repair_proposal=repair_proposal, c278_evidence=c278_evidence,
        repair_verdict=repair_verdict, repo_root=repo_root,
    )
    if observation["status"] != "C278_SANDBOX_BYTES_MATCH_UNATTESTED":
        return _hold("C278_MACHINE_SANDBOX_OBSERVATION_REQUIRED:" + str(observation["reason"]))
    lineage = observation["repair_lineage"]
    if (payload["request_id"] != lineage["repair_request_id"]
            or payload["proposal_id"] != lineage["repair_proposal_id"]
            or payload["verdict_id"] != lineage["repair_verdict_id"]):
        return _hold("C278_MACHINE_RECEIPT_LINEAGE_MISMATCH")
    for field, source in (
        ("repair_request_sha256", repair_request),
        ("repair_proposal_sha256", repair_proposal),
        ("c278_evidence_sha256", c278_evidence),
        ("repair_verdict_sha256", repair_verdict),
    ):
        if _digest(source) != payload[field]:
            return _hold("C278_MACHINE_RECEIPT_SOURCE_DIGEST_MISMATCH")
    if (type(payload["candidate_artifact_sha256"]) is not dict
            or payload["candidate_artifact_sha256"] != observation["candidate_artifact_sha256"]):
        return _hold("C278_MACHINE_RECEIPT_SANDBOX_ARTIFACT_MISMATCH")
    canonical = _canonical(payload)
    if canonical is None:
        return _hold("C278_MACHINE_RECEIPT_SERIALIZATION_INVALID")

    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return _hold("C278_MACHINE_RSA_VERIFIER_DEPENDENCY_MISSING")
    try:
        cert = x509.load_der_x509_certificate(cert_bytes)
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        key = cert.public_key()
        now = datetime.now(timezone.utc)
        if (len(names) != 1 or names[0].value != "OBSIDIA-OBSIDURE-" + expected_machine_id
                or not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072
                or not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            return _hold("C278_MACHINE_CERTIFICATE_CONTRACT_INVALID")
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return _hold("C278_MACHINE_CERTIFICATE_DIGITAL_SIGNATURE_REQUIRED")
        if not usage.digital_signature:
            return _hold("C278_MACHINE_CERTIFICATE_DIGITAL_SIGNATURE_REQUIRED")
        key.verify(signature, _DOMAIN + canonical, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return _hold("C278_MACHINE_RSA_SIGNATURE_MISMATCH")
    except (ValueError, TypeError, AttributeError):
        return _hold("C278_MACHINE_CERTIFICATE_OR_SIGNATURE_INVALID")

    return _result(
        "C278_MACHINE_RSA_SIGNATURE_MATCH_ORIGIN_UNATTESTED", None,
        machine_signature_verified=True, sandbox_bytes_observed=True,
        receipt_id=payload["receipt_id"], machine_id=expected_machine_id,
        public_certificate_sha256=pinned_certificate_sha256,
        lineage_verified=True,
        limits=[
            "PUBLIC_CERTIFICATE_PIN_IS_CALLER_SUPPLIED_NOT_APPROVED_ENROLLMENT",
            "CERTIFICATE_IS_SELF_SIGNED_NO_HARDWARE_ATTESTATION",
            "SIGNATURE_PROVES_KEY_POSSESSION_NOT_HISTORICAL_RUNNER_OR_TEST",
            "GIT_HEAD_RUNNER_AND_TRANSCRIPT_DIGESTS_ARE_SIGNED_CLAIMS_ONLY",
            "NO_PERSISTENT_REPLAY_LEDGER_OR_INDEPENDENT_REVOCATION_POLICY",
            "NO_HUMAN_APPROVAL_NO_KX108_TICKET_NO_RELEASE",
        ],
    )
