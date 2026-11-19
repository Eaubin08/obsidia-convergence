"""G4J — vérification RSA d'une déclaration WAL par identité de machine.

Signature = possession d'une clé, PAS preuve d'exécution historique, de
responsable humain ou d'approbation KX108. Ne lit aucune clé privée.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import c2_write_intent_wal_v1 as WAL
from c2_wal_outcome_observer_v1 import inspect_c2_wal_outcome_state
from obsidure_c278_machine_rsa_receipt_v1 import _verify_machine_rsa_signature_bytes

SCHEMA = "OBSIDIA_G4J_C2_WAL_MACHINE_RSA_RECEIPT_V1"
DOMAIN = b"OBSIDIA_G4J_C2_WAL_MACHINE_RSA_V1\x00"
_MACHINE = re.compile(r"[A-Z0-9][A-Z0-9-]{2,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HEAD = re.compile(r"[0-9a-f]{40}\Z")
_FIELDS = frozenset({
    "schema", "machine_id", "public_certificate_sha256", "intent_id",
    "intent_record_hash", "outcome_record_hash", "reported_status",
    "observed_sha256", "nonce", "source_git_head",
    "runner_code_sha256", "tests_transcript_sha256", "decision_authority",
    "receipt_kind",
})


def canonical_payload(payload: Any) -> bytes | None:
    if type(payload) is not dict or set(payload) != _FIELDS:
        return None
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        return None
    return encoded if len(encoded) <= 16384 else None


def _decode_base64(value: Any, *, minimum: int, maximum: int) -> bytes | None:
    if type(value) is not str or not 0 < len(value) <= maximum * 2:
        return None
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if (not minimum <= len(data) <= maximum
            or base64.b64encode(data).decode("ascii") != value):
        return None
    return data


def _hold(reason: str, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA, "status": "HOLD", "reason": reason,
        "readonly": True, "decision_authority": "KX108_ONLY",
        "machine_signature_verified": False,
        "machine_identity_attested": False,
        "certificate_enrollment_approved": False,
        "producer_identity_attested": False,
        "responsible_person_authenticated": False,
        "process_execution_attested": False,
        "test_transcript_attested": False,
        "source_git_head_attested": False,
        "replay_prevented": False,
        "physical_mutation_attested": False,
        "rollback_attested": False,
        "kx108_ticket_issued": False,
        "human_approval_verified": False,
        "execution_authorized": False,
        "release_authorized": False,
        "recovery_authorized": False,
        "target_mutated": False,
        **extra,
    }


def build_claim_payload(*, machine_id: str, public_certificate_sha256: str,
                        intent: dict, outcome: dict, nonce: str,
                        source_git_head: str, runner_code_sha256: str,
                        tests_transcript_sha256: str) -> dict | None:
    """Matériel signé déclaratif, à préparer hors de la façade runtime."""
    valid_i, _ = WAL.verify_intent(intent)
    valid_o, _ = WAL.verify_outcome(outcome, intent)
    if not valid_i or not valid_o:
        return None
    if (type(machine_id) is not str or _MACHINE.fullmatch(machine_id) is None
            or any(type(x) is not str or _SHA.fullmatch(x) is None
                   for x in (public_certificate_sha256, nonce,
                             runner_code_sha256, tests_transcript_sha256))
            or type(source_git_head) is not str
            or _HEAD.fullmatch(source_git_head) is None):
        return None
    payload = {
        "schema": SCHEMA,
        "machine_id": machine_id,
        "public_certificate_sha256": public_certificate_sha256,
        "intent_id": intent["intent_id"],
        "intent_record_hash": intent["record_hash"],
        "outcome_record_hash": outcome["record_hash"],
        "reported_status": outcome["reported_status"],
        "observed_sha256": outcome["observed_sha256"],
        "nonce": nonce,
        "source_git_head": source_git_head,
        "runner_code_sha256": runner_code_sha256,
        "tests_transcript_sha256": tests_transcript_sha256,
        "decision_authority": "KX108_ONLY",
        "receipt_kind": "OBSERVATION_NOT_RELEASE",
    }
    return payload if canonical_payload(payload) is not None else None


def inspect_wal_machine_rsa_receipt(
    *, wal_dir: Path, intent_id: str, repo_root: Path, receipt: Any,
    public_certificate_der_base64: str,
    pinned_certificate_sha256: str, expected_machine_id: str,
) -> dict[str, Any]:
    """Vérifie WAL courant + signature sans donner confiance à un producteur."""
    if (type(expected_machine_id) is not str
            or _MACHINE.fullmatch(expected_machine_id) is None
            or type(pinned_certificate_sha256) is not str
            or _SHA.fullmatch(pinned_certificate_sha256) is None):
        return _hold("G4J_EXPECTED_IDENTITY_INVALID")
    cert_bytes = _decode_base64(public_certificate_der_base64,
                                minimum=200, maximum=12288)
    if (cert_bytes is None
            or hashlib.sha256(cert_bytes).hexdigest() != pinned_certificate_sha256):
        return _hold("G4J_PUBLIC_CERTIFICATE_PIN_MISMATCH")
    if type(receipt) is not dict or set(receipt) != {"payload", "signature_base64"}:
        return _hold("G4J_RECEIPT_ENVELOPE_INVALID")
    payload, raw_signature = receipt["payload"], receipt["signature_base64"]
    canonical = canonical_payload(payload)
    if canonical is None:
        return _hold("G4J_RECEIPT_FIELDS_INVALID")
    if (payload.get("schema") != SCHEMA
            or payload.get("decision_authority") != "KX108_ONLY"
            or payload.get("receipt_kind") != "OBSERVATION_NOT_RELEASE"
            or payload.get("machine_id") != expected_machine_id
            or payload.get("public_certificate_sha256") != pinned_certificate_sha256):
        return _hold("G4J_RECEIPT_SCOPE_OR_IDENTITY_INVALID")
    if (type(payload.get("nonce")) is not str
            or _SHA.fullmatch(payload["nonce"]) is None
            or type(payload.get("source_git_head")) is not str
            or _HEAD.fullmatch(payload["source_git_head"]) is None
            or any(type(payload.get(f)) is not str
                   or _SHA.fullmatch(payload[f]) is None
                   for f in ("runner_code_sha256", "tests_transcript_sha256"))):
        return _hold("G4J_SIGNED_CLAIMS_INVALID")
    signature = _decode_base64(raw_signature, minimum=256, maximum=1024)
    if signature is None:
        return _hold("G4J_SIGNATURE_FORMAT_INVALID")

    observed = inspect_c2_wal_outcome_state(
        wal_dir=wal_dir, intent_id=intent_id, repo_root=repo_root)
    if observed.get("reason") != "OUTCOME_REPORTED_NOT_ATTESTED":
        return _hold("G4J_WAL_LIVE_OBSERVATION_REQUIRED:" + str(observed.get("reason")))
    intent = WAL.load_verified_intent(wal_dir, intent_id)
    outcome = WAL.load_verified_outcome(wal_dir, intent) if intent is not None else None
    if intent is None or outcome is None:
        return _hold("G4J_WAL_RECORDS_CHANGED")
    if (payload.get("intent_id") != intent_id
            or payload.get("intent_record_hash") != intent["record_hash"]
            or payload.get("outcome_record_hash") != outcome["record_hash"]
            or payload.get("reported_status") != outcome["reported_status"]
            or payload.get("observed_sha256") != outcome["observed_sha256"]
            or payload["observed_sha256"] != observed["observed_sha256"]):
        return _hold("G4J_WAL_RECEIPT_BINDING_MISMATCH")

    error = _verify_machine_rsa_signature_bytes(
        cert_bytes=cert_bytes, expected_machine_id=expected_machine_id,
        signature=signature, message=DOMAIN + canonical)
    if error is not None:
        return _hold("G4J_RSA:" + error)
    return _hold(
        "G4J_RSA_SIGNATURE_MATCH_ORIGIN_UNATTESTED",
        machine_signature_verified=True,
        machine_id=expected_machine_id,
        public_certificate_sha256=pinned_certificate_sha256,
        intent_id=intent_id,
        limits=[
            "PIN_SUPPLIED_BY_CALLER_NOT_INDEPENDENTLY_APPROVED",
            "MACHINE_KEY_POSSESSION_NOT_HISTORICAL_PRODUCER_PROOF",
            "SOURCE_RUNNER_TRANSCRIPT_DIGESTS_ARE_SIGNED_CLAIMS",
            "NO_TRUSTED_REPLAY_LEDGER_OR_MACHINE_REVOCATION",
            "NO_KX108_PERMISSION_NO_RESTORE_NO_RELEASE",
        ],
    )
