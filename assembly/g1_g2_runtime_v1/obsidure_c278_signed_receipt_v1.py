"""Contrat de vérification d'un reçu C278, indépendant du secret KX108.

Ce module ne produit PAS de reçus : le runner historique F7 n'en signe aucun.
Un HMAC valide prouve seulement la possession d'une clé fournie par l'appelant.
Sans ancrage indépendant du runner, du test et du temps, la provenance reste
NON ATTESTÉE. Aucune décision ni écriture n'est autorisée par ce module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

from obsidure_c278_sandbox_observation_v1 import (
    inspect_obsidure_c278_sandbox_observation,
)

_SCHEMA = "OBSIDURE_C278_DETACHED_HMAC_RECEIPT_V1"
_DOMAIN = b"OBSIDIA_OBSIDURE_C278_RECEIPT_V1\x00"
_EXPECTED_FIELDS = frozenset({
    "schema", "issuer_id", "key_id", "receipt_id", "nonce",
    "request_id", "proposal_id", "verdict_id", "repair_request_sha256",
    "repair_proposal_sha256", "c278_evidence_sha256", "repair_verdict_sha256",
    "candidate_artifact_sha256", "source_git_head", "runner_code_sha256",
    "tests_transcript_sha256",
})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_JSON_BYTES = 2_000_000


def _json_bytes(value: Any) -> bytes | None:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeError):
        return None
    return raw if len(raw) <= _MAX_JSON_BYTES else None


def _sha(value: Any) -> str | None:
    raw = _json_bytes(value)
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def _result(status: str, reason: str | None, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "OBSIDURE_C278_SIGNED_RECEIPT_INSPECTION_V1",
        "status": status, "reason": reason,
        "readonly": True, "authority": "NON_SOVEREIGN",
        "decision_authority": "KX108_ONLY",
        "receipt_hmac_verified": False,
        "producer_identity_attested": False,
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


def inspect_c278_detached_hmac_receipt(
    *, r10_inspection: dict[str, Any], repair_request: dict[str, Any],
    repair_proposal: dict[str, Any], c278_evidence: dict[str, Any],
    repair_verdict: dict[str, Any], repo_root: Path,
    receipt: dict[str, Any], trusted_issuer_id: str,
    trusted_key_id: str, verifier_key: bytes | None,
) -> dict[str, Any]:
    """Compare le reçu à un NOUVEAU replay C278/sandbox, puis vérifie le MAC.

    `verifier_key` doit venir d'un canal de confiance Obsidure distinct de
    KX108. Aucun magasin de clés ni registre anti-rejeu n'est créé ici.
    Le reçu ne saurait affirmer l'exécution réelle du test historique.
    """
    if (type(verifier_key) is not bytes or len(verifier_key) < 32
            or len(verifier_key) > 128):
        return _hold("C278_INDEPENDENT_TRUST_KEY_MISSING")
    if (type(trusted_issuer_id) is not str
            or _IDENTIFIER.fullmatch(trusted_issuer_id) is None
            or type(trusted_key_id) is not str
            or _IDENTIFIER.fullmatch(trusted_key_id) is None
            or trusted_key_id.upper().startswith(("KX108", "K1_KERNEL"))):
        return _hold("C278_OBSIDURE_TRUST_IDENTITY_INVALID")
    if type(receipt) is not dict or set(receipt) != {"payload", "hmac_sha256"}:
        return _hold("C278_RECEIPT_ENVELOPE_INVALID")
    payload = receipt.get("payload")
    signature = receipt.get("hmac_sha256")
    if (type(payload) is not dict or set(payload) != _EXPECTED_FIELDS
            or type(signature) is not str or _HEX64.fullmatch(signature) is None):
        return _hold("C278_RECEIPT_FIELDS_INVALID")
    if (payload.get("schema") != _SCHEMA
            or payload.get("issuer_id") != trusted_issuer_id
            or payload.get("key_id") != trusted_key_id):
        return _hold("C278_RECEIPT_ISSUER_OR_SCHEMA_MISMATCH")
    if any(type(payload.get(k)) is not str or _IDENTIFIER.fullmatch(payload[k]) is None
           for k in ("receipt_id", "request_id", "proposal_id", "verdict_id")):
        return _hold("C278_RECEIPT_LINEAGE_INVALID")
    if (any(type(payload.get(k)) is not str or _HEX64.fullmatch(payload[k]) is None
            for k in (
                "nonce", "repair_request_sha256", "repair_proposal_sha256",
                "c278_evidence_sha256", "repair_verdict_sha256",
                "runner_code_sha256", "tests_transcript_sha256",
            ))
            or type(payload.get("source_git_head")) is not str
            or _HEX40.fullmatch(payload["source_git_head"]) is None):
        return _hold("C278_RECEIPT_DIGESTS_INVALID")
    observation = inspect_obsidure_c278_sandbox_observation(
        r10_inspection=r10_inspection, repair_request=repair_request,
        repair_proposal=repair_proposal, c278_evidence=c278_evidence,
        repair_verdict=repair_verdict, repo_root=repo_root,
    )
    if observation["status"] != "C278_SANDBOX_BYTES_MATCH_UNATTESTED":
        return _hold("C278_SANDBOX_OBSERVATION_REQUIRED:" + observation["reason"])
    lineage = observation["repair_lineage"]
    if (payload["request_id"] != lineage["repair_request_id"]
            or payload["proposal_id"] != lineage["repair_proposal_id"]
            or payload["verdict_id"] != lineage["repair_verdict_id"]):
        return _hold("C278_RECEIPT_LINEAGE_MISMATCH")
    for field, source in (
        ("repair_request_sha256", repair_request),
        ("repair_proposal_sha256", repair_proposal),
        ("c278_evidence_sha256", c278_evidence),
        ("repair_verdict_sha256", repair_verdict),
    ):
        if _sha(source) != payload[field]:
            return _hold("C278_RECEIPT_SOURCE_DIGEST_MISMATCH")
    if (type(payload["candidate_artifact_sha256"]) is not dict
            or payload["candidate_artifact_sha256"] != observation["candidate_artifact_sha256"]):
        return _hold("C278_RECEIPT_SANDBOX_ARTIFACT_MISMATCH")
    canonical = _json_bytes(payload)
    if canonical is None:
        return _hold("C278_RECEIPT_SERIALIZATION_INVALID")
    calculated = hmac.new(verifier_key, _DOMAIN + canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated, signature):
        return _hold("C278_RECEIPT_MAC_MISMATCH")
    return _result(
        "C278_RECEIPT_HMAC_MATCH_ORIGIN_UNATTESTED", None,
        receipt_hmac_verified=True, receipt_id=payload["receipt_id"],
        lineage_verified=True, sandbox_bytes_observed=True,
        limits=[
            "KEY_PROVISIONING_AND_RUNNER_IDENTITY_NOT_ATTESTED",
            "SOURCE_GIT_HEAD_AND_RUNNER_DIGEST_ARE_SIGNED_CLAIMS_ONLY",
            "TEST_TRANSCRIPT_DIGEST_HAS_NO_INDEPENDENT_WITNESS",
            "NONCE_IS_NOT_CHECKED_AGAINST_A_PERSISTENT_REPLAY_LEDGER",
            "HMAC_ONLY_PROVES_POSSESSION_OF_CALLER_TRUST_KEY",
        ],
    )
