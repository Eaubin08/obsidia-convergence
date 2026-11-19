"""Preuve RSA d'empreintes de sources C278 *observées*, jamais d'un test.

Ce contrat est volontairement distinct d'un reçu C278 de test. La lecture du
FIX et la possession de la clé Windows ne certifient ni le runner, ni l'origine
des imports, ni une approbation de l'enrôlement, ni une action KX108.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any

from obsidure_c278_machine_rsa_receipt_v1 import (
    _verify_machine_rsa_signature_bytes,
)

SCHEMA = "OBSIDIA_C278_PORTABLE_SOURCE_SNAPSHOT_RSA_V1"
DOMAIN = b"OBSIDIA_C278_SOURCE_SNAPSHOT_ONLY_V1\x00"
MACHINE = "DESKTOP-Q5MD7J7"
PUBLIC_SHA256 = "5bb3f8688930de497254185292a49b46c2f88b0bb23cf259711e86981932c398"
OBSERVED_HEAD = "c9612ae922f5302a8bd012800d368973d0241d4d"
EXPECTED_SOURCES = {
    "periphery/agents/agent_obsidure.py": "fbf8f84de0f21e74f2b5faa55a6e6cef38b2a3fc812e26a6636935da06030d25",
    "periphery/agents/obsidure_repair_bridge.py": "fdfbc9b7c10a3039d31d72a871d0473b87b46cbf922918f669f07e2d10fb72a8",
    "periphery/agents/obsidure_repair_contract.py": "1dbb49eea44d8b02e5c7a5ee988a232fcd43fd461f65c0a0a711b24b9e129ba3",
}
_FIELDS = frozenset({
    "schema", "machine_id", "public_certificate_sha256", "source_git_head",
    "source_git_branch", "observed_baseline_git_head", "source_sha256",
    "nonce", "attestation_scope", "test_process_attested", "test_isolation_certified",
    "execution_authorized", "release_authorized", "kx108_authority",
})
_ENVELOPE = frozenset({"payload", "message_base64", "signature_base64", "public_certificate_der_base64"})
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _hold(reason: str) -> dict[str, Any]:
    return {
        "status": "HOLD", "reason": reason,
        "test_process_attested": False, "test_isolation_certified": False,
        "enrollment_approved": False, "execution_authorized": False,
        "release_authorized": False, "kx108_authority": "UNCHANGED",
    }


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _source_match(observed: dict[str, Any]) -> bool:
    if (type(observed) is not dict or observed.get("status") != "C278_STATIC_SOURCE_PROFILE_ONLY"
            or observed.get("machine") != MACHINE or observed.get("required_symbols_present") is not True
            or type(observed.get("files")) is not dict
            or set(observed["files"]) != set(EXPECTED_SOURCES)):
        return False
    return all(type(observed["files"][p]) is dict
               and observed["files"][p].get("sha256") == sha
               for p, sha in EXPECTED_SOURCES.items())


def prepare_snapshot(observed: dict[str, Any], *, nonce: str) -> dict[str, Any]:
    """Produit des octets bornés à signer avec la clé locale existante."""
    if not _source_match(observed):
        return _hold("C278_SOURCE_BYTES_DIFFER_FROM_REVIEWED_SNAPSHOT")
    head, branch = observed.get("git_head"), observed.get("git_branch")
    if (type(head) is not str or _HEX40.fullmatch(head) is None
            or type(branch) is not str or not 1 <= len(branch) <= 128
            or type(nonce) is not str or _HEX32.fullmatch(nonce) is None):
        return _hold("C278_SOURCE_PROVENANCE_FIELDS_INVALID")
    payload = {
        "schema": SCHEMA,
        "machine_id": MACHINE,
        "public_certificate_sha256": PUBLIC_SHA256,
        "source_git_head": head,
        "source_git_branch": branch,
        "observed_baseline_git_head": OBSERVED_HEAD,
        "source_sha256": dict(EXPECTED_SOURCES),
        "nonce": nonce,
        "attestation_scope": "SOURCE_HASHES_ONLY_NOT_C278_RUNNER_OR_TEST",
        "test_process_attested": False,
        "test_isolation_certified": False,
        "execution_authorized": False,
        "release_authorized": False,
        "kx108_authority": "UNCHANGED",
    }
    return {
        "status": "READY_FOR_LOCAL_KEY_SIGNING",
        "payload": payload,
        "message_base64": base64.b64encode(DOMAIN + _canonical(payload)).decode("ascii"),
    }


def verify_snapshot(envelope: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """Revérifie source courante, domaine, certificat épinglé et signature."""
    if type(envelope) is not dict or set(envelope) != _ENVELOPE:
        return _hold("C278_SNAPSHOT_ENVELOPE_FIELDS_INVALID")
    payload = envelope["payload"]
    if type(payload) is not dict or set(payload) != _FIELDS:
        return _hold("C278_SNAPSHOT_PAYLOAD_FIELDS_INVALID")
    if (payload.get("schema") != SCHEMA or payload.get("machine_id") != MACHINE
            or payload.get("public_certificate_sha256") != PUBLIC_SHA256
            or payload.get("observed_baseline_git_head") != OBSERVED_HEAD
            or payload.get("attestation_scope") != "SOURCE_HASHES_ONLY_NOT_C278_RUNNER_OR_TEST"
            or payload.get("source_sha256") != EXPECTED_SOURCES
            or any(payload.get(k) is not False for k in (
                "test_process_attested", "test_isolation_certified", "execution_authorized", "release_authorized"))
            or payload.get("kx108_authority") != "UNCHANGED"
            or type(payload.get("nonce")) is not str or _HEX32.fullmatch(payload["nonce"]) is None):
        return _hold("C278_SNAPSHOT_SCOPE_OR_SOURCE_INVALID")
    if not _source_match(observed):
        return _hold("C278_SOURCE_CHANGED_SINCE_SNAPSHOT")
    if (payload.get("source_git_head") != observed.get("git_head")
            or payload.get("source_git_branch") != observed.get("git_branch")):
        return _hold("C278_GIT_PROVENANCE_CHANGED_SINCE_SNAPSHOT")
    try:
        message = base64.b64decode(envelope["message_base64"], validate=True)
        signature = base64.b64decode(envelope["signature_base64"], validate=True)
        cert = base64.b64decode(envelope["public_certificate_der_base64"], validate=True)
    except (TypeError, ValueError, binascii.Error):
        return _hold("C278_SNAPSHOT_BASE64_INVALID")
    if (len(message) > 8192 or not 300 <= len(signature) <= 1024
            or not 500 <= len(cert) <= 12000
            or message != DOMAIN + _canonical(payload)
            or hashlib.sha256(cert).hexdigest() != PUBLIC_SHA256):
        return _hold("C278_SNAPSHOT_SIGNED_DATA_OR_PUBLIC_PIN_MISMATCH")
    error = _verify_machine_rsa_signature_bytes(
        cert_bytes=cert, expected_machine_id=MACHINE,
        signature=signature, message=message,
    )
    if error:
        return _hold(error)
    return {
        "status": "C278_SOURCE_SNAPSHOT_RSA_MATCH_NO_TEST_PROVENANCE",
        "reason": None, "machine_id": MACHINE,
        "machine_signature_verified": True,
        "source_hashes_match": True,
        "source_git_head": payload["source_git_head"],
        "test_process_attested": False, "test_isolation_certified": False,
        "enrollment_approved": False, "replay_prevented": False,
        "execution_authorized": False, "release_authorized": False,
        "kx108_authority": "UNCHANGED",
    }
