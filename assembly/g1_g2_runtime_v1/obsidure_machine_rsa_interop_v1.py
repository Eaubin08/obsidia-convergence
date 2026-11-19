"""Contrôle purement cryptographique d'un challenge Windows Obsidure.

Le challenge est créé et signé par Windows en mémoire. Ce module vérifie sa
signature avec le même validateur de certificat que les reçus C278.
Il ne représente aucun test C278, aucune approbation ou exécution autorisée.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any

from obsidure_c278_machine_rsa_receipt_v1 import (
    _HEX64, _MACHINE, _result, _verify_machine_rsa_signature_bytes,
)

_SCHEMA = "OBSIDURE_WINDOWS_RSA_INTEROP_CHALLENGE_V1"
_DOMAIN = b"OBSIDIA_OBSIDURE_MACHINE_INTEROP_V1\x00"
_FIELDS = frozenset({
    "schema", "expected_machine_id", "public_certificate_der_base64",
    "pinned_certificate_sha256", "challenge_base64", "signature_base64",
})


def _hold(reason: str) -> dict[str, Any]:
    return _result("HOLD", reason)


def _decode(value: Any, maximum: int) -> bytes | None:
    if type(value) is not str or not 0 < len(value) <= maximum:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    if base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def inspect_machine_rsa_interop_challenge(envelope: Any) -> dict[str, Any]:
    """Proof-of-possession locale, jamais origine runner ou identité approuvée."""
    if type(envelope) is not dict or set(envelope) != _FIELDS:
        return _hold("MACHINE_RSA_INTEROP_ENVELOPE_INVALID")
    machine, pin = envelope["expected_machine_id"], envelope["pinned_certificate_sha256"]
    if (envelope["schema"] != _SCHEMA or type(machine) is not str
            or _MACHINE.fullmatch(machine) is None or type(pin) is not str
            or _HEX64.fullmatch(pin) is None):
        return _hold("MACHINE_RSA_INTEROP_IDENTITY_INVALID")
    cert = _decode(envelope["public_certificate_der_base64"], 16384)
    challenge = _decode(envelope["challenge_base64"], 2048)
    signature = _decode(envelope["signature_base64"], 4096)
    if cert is None or not 200 <= len(cert) <= 12288:
        return _hold("MACHINE_RSA_INTEROP_CERTIFICATE_INVALID")
    if hashlib.sha256(cert).hexdigest() != pin:
        return _hold("MACHINE_RSA_INTEROP_CERTIFICATE_PIN_MISMATCH")
    if challenge is None or signature is None:
        return _hold("MACHINE_RSA_INTEROP_CHALLENGE_OR_SIGNATURE_INVALID")
    # Le nom du PC et le nonce font partie des bytes réellement signés.
    expected_prefix = _DOMAIN + machine.encode("ascii") + b"|"
    if (not challenge.startswith(expected_prefix)
            or re.fullmatch(rb"[0-9a-f]{32}", challenge[len(expected_prefix):]) is None):
        return _hold("MACHINE_RSA_INTEROP_CHALLENGE_DOMAIN_INVALID")
    reason = _verify_machine_rsa_signature_bytes(
        cert_bytes=cert, expected_machine_id=machine,
        signature=signature, message=challenge,
    )
    if reason is not None:
        return _hold("MACHINE_RSA_INTEROP:" + reason)
    # Vérifie explicitement qu'un octet de message modifié n'est pas accepté.
    tampered = bytes([challenge[0] ^ 1]) + challenge[1:]
    tamper_reason = _verify_machine_rsa_signature_bytes(
        cert_bytes=cert, expected_machine_id=machine,
        signature=signature, message=tampered,
    )
    if tamper_reason != "C278_MACHINE_RSA_SIGNATURE_MISMATCH":
        return _hold("MACHINE_RSA_INTEROP_TAMPER_DENIAL_UNPROVEN")
    return _result(
        "MACHINE_RSA_INTEROP_VERIFIED_NOT_C278_PROVENANCE", None,
        machine_signature_verified=True,
        machine_id=machine,
        public_certificate_sha256=pin,
        tampered_challenge_rejected=True,
        limits=[
            "CHALLENGE_ONLY_NOT_A_SIGNED_C278_RECEIPT",
            "CERTIFICATE_PUBLIC_PIN_DOES_NOT_APPROVE_ENROLLMENT",
            "SIGNER_ONLY_KEY_POSSESSION_NO_TEST_PROCESS_ATTESTATION",
            "NO_HUMAN_APPROVAL_NO_KX108_TICKET_NO_RELEASE",
        ],
    )
