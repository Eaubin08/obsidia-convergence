"""G4N — un fondateur, une équipe préparée, aucune autorité auto-attribuée.

Le fondateur peut signer une *proposition* d'activation du mode équipe.
Une signature liée à une clé déclarée dans le plan ne constitue pas un
enrôlement approuvé : la racine de confiance indépendante manque encore.
Ce module est purement consultatif : aucune écriture, signature ou APPLY.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from obsidure_machine_identity_registry_v1 import inspect_machine_identity_registry

SCHEMA = "OBSIDIA_G4N_FOUNDER_TEAM_ADMIN_PLAN_V1"
ACTIVATION_SCHEMA = "OBSIDIA_G4N_TEAM_ACTIVATION_PROPOSAL_V1"
DOMAIN = b"OBSIDIA_G4N_FOUNDER_TEAM_ACTIVATION_V1\x00"
ADMIN_SCOPE = "OBSIDURE_MACHINE_ENROLLMENT_REVIEW_ONLY"
FOUNDER_ID = "FOUNDER-ETIENNE"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Z0-9][A-Z0-9-]{2,63}\Z")
_PLAN_FIELDS = frozenset({"schema", "decision_authority", "admin_scope",
                          "startup_mode", "founder", "team"})
_FOUNDER_FIELDS = frozenset({"admin_id", "enrollment_state",
                             "public_certificate_der_base64", "public_certificate_sha256"})
_TEAM_FIELDS = frozenset({"state", "administrators"})
_MEMBER_FIELDS = frozenset({"admin_id", "enrollment_state", "public_certificate_sha256"})
_ACTIVATION_FIELDS = frozenset({"schema", "event", "founder_admin_id",
                                "founder_certificate_sha256", "plan_sha256",
                                "team_sha256", "activation_id", "nonce"})


def canonical(value: Any) -> bytes | None:
    try:
        result = json.dumps(value, sort_keys=True, ensure_ascii=False,
                            allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeError):
        return None
    return result if len(result) <= 128_000 else None


def digest(value: Any) -> str | None:
    raw = canonical(value)
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def _hold(reason: str, **fields: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA, "status": "HOLD", "reason": reason,
        "readonly": True, "administrative_scope": ADMIN_SCOPE,
        "decision_authority": "KX108_ONLY", "startup_mode": "FOUNDER_ONLY",
        "founder_only_plan_valid": False, "team_plan_prepared": False,
        "founder_key_separate_from_pc": False,
        "founder_key_registry_conflict_absent": False,
        "founder_activation_proposal_signature_verified": False,
        "founder_independently_enrolled": False,
        "founder_trust_anchor_verified": False,
        "founder_human_identity_authenticated": False,
        "team_mode_activated": False, "team_members_approved": False,
        "machine_enrollment_approved": False, "responsible_person_authenticated": False,
        "human_approval_verified": False, "replay_prevented": False,
        "kx108_ticket_issued": False, "execution_authorized": False,
        "release_authorized": False, "target_mutated": False,
        **fields,
    }


def _verify_founder_certificate(cert64: str, pin: str) -> tuple[bytes | None, str | None]:
    if (type(cert64) is not str or not 0 < len(cert64) <= 16384
            or type(pin) is not str or _HEX.fullmatch(pin) is None):
        return None, "G4N_FOUNDER_CERTIFICATE_MISSING"
    try:
        raw = base64.b64decode(cert64, validate=True)
    except (binascii.Error, ValueError):
        return None, "G4N_FOUNDER_CERTIFICATE_BASE64_INVALID"
    if (not 200 <= len(raw) <= 12288
            or base64.b64encode(raw).decode("ascii") != cert64
            or hashlib.sha256(raw).hexdigest() != pin):
        return None, "G4N_FOUNDER_CERTIFICATE_PIN_MISMATCH"
    return raw, None


def _rsa_public_material_digest(cert_bytes: bytes) -> tuple[str | None, str | None]:
    """Empreinte du RSA SPKI, stable même en cas de réémission du certificat.

    Comparer les seuls SHA256 du certificat DER ne détecte pas deux
    certificats différents construits avec la même clé privée RSA.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        cert = x509.load_der_x509_certificate(cert_bytes)
        key = cert.public_key()
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
            return None, "G4O_PUBLIC_KEY_NOT_RSA3072"
        raw = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(raw).hexdigest(), None
    except ImportError:
        return None, "G4O_CRYPTOGRAPHY_DEPENDENCY_MISSING"
    except (ValueError, TypeError, AttributeError):
        return None, "G4O_PUBLIC_CERTIFICATE_UNPARSABLE"


def _verify_founder_signature(cert_bytes: bytes, signature: bytes, payload: bytes) -> str | None:
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return "G4N_CRYPTOGRAPHY_DEPENDENCY_MISSING"
    try:
        cert = x509.load_der_x509_certificate(cert_bytes)
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        key = cert.public_key()
        now = datetime.now(timezone.utc)
        if (len(names) != 1 or names[0].value != "OBSIDIA-ADMIN-" + FOUNDER_ID
                or not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072
                or not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            return "G4N_FOUNDER_CERTIFICATE_CONTRACT_INVALID"
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return "G4N_FOUNDER_CERTIFICATE_DIGITAL_SIGNATURE_REQUIRED"
        if not usage.digital_signature:
            return "G4N_FOUNDER_CERTIFICATE_DIGITAL_SIGNATURE_REQUIRED"
        key.verify(signature, DOMAIN + payload, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return "G4N_FOUNDER_ACTIVATION_SIGNATURE_INVALID"
    except (ValueError, TypeError, AttributeError, UnsupportedAlgorithm):
        return "G4N_FOUNDER_CERTIFICATE_OR_SIGNATURE_INVALID"
    return None


def inspect_obsidure_admin_bootstrap(
    *, plan: Any, machine_registry: Any, activation_receipt: Any = None,
) -> dict[str, Any]:
    """Inspecte les deux modes sans pouvoir les activer.

    Un éventuel certificat fondateur vient du plan PUBLIC. Il ne faut
    jamais confondre sa vérification crypto avec une racine indépendante.
    """
    machines = inspect_machine_identity_registry(machine_registry)
    if machines.get("status") != "MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED":
        return _hold("G4N_MACHINE_REGISTRY_INVALID:" + str(machines.get("reason")))
    if (type(plan) is not dict or set(plan) != _PLAN_FIELDS
            or plan.get("schema") != SCHEMA
            or plan.get("decision_authority") != "KX108_ONLY"
            or plan.get("admin_scope") != ADMIN_SCOPE
            or plan.get("startup_mode") != "FOUNDER_ONLY"):
        return _hold("G4N_PLAN_FIELDS_OR_AUTHORITY_INVALID")
    founder, team = plan["founder"], plan["team"]
    if (type(founder) is not dict or set(founder) != _FOUNDER_FIELDS
            or founder.get("admin_id") != FOUNDER_ID
            or type(founder.get("enrollment_state")) is not str
            or founder.get("enrollment_state") not in {
                "PLANNED", "KEY_PROPOSED_AWAITING_INDEPENDENT_REVIEW"}):
        return _hold("G4N_FOUNDER_PROPOSAL_INVALID")
    if (type(team) is not dict or set(team) != _TEAM_FIELDS
            or team.get("state") != "PREPARED"
            or type(team.get("administrators")) is not list
            or len(team["administrators"]) > 16):
        return _hold("G4N_TEAM_MUST_REMAIN_PREPARED")

    founder_bytes = None
    if founder["enrollment_state"] == "PLANNED":
        if (founder["public_certificate_der_base64"] is not None
                or founder["public_certificate_sha256"] is not None):
            return _hold("G4N_PLANNED_FOUNDER_CANNOT_HOLD_KEY")
    else:
        founder_bytes, error = _verify_founder_certificate(
            founder["public_certificate_der_base64"], founder["public_certificate_sha256"])
        if error is not None:
            return _hold(error)

    ids = {FOUNDER_ID}
    pins = set()
    machine_spkis = set()
    for entry in machine_registry["machine_identities"]:
        if entry["public_certificate_sha256"] is not None:
            pins.add(entry["public_certificate_sha256"])
            try:
                machine_bytes = base64.b64decode(entry["public_certificate_der_base64"], validate=True)
            except (ValueError, binascii.Error):
                return _hold("G4O_MACHINE_CERTIFICATE_INVALID")
            machine_spki, err = _rsa_public_material_digest(machine_bytes)
            if err is not None:
                return _hold("G4O_MACHINE_CERTIFICATE_NOT_CRYPTO_VERIFIABLE:" + err)
            machine_spkis.add(machine_spki)
    if founder["public_certificate_sha256"] is not None:
        if founder["public_certificate_sha256"] in pins:
            return _hold("G4N_FOUNDER_KEY_MUST_BE_DISTINCT_FROM_PC")
        founder_spki, err = _rsa_public_material_digest(founder_bytes)
        if err is not None:
            return _hold("G4O_FOUNDER_CERTIFICATE_NOT_CRYPTO_VERIFIABLE:" + err)
        if founder_spki in machine_spkis:
            return _hold("G4O_FOUNDER_REISSUED_CERTIFICATE_SAME_PC_KEY_DENIED")
        pins.add(founder["public_certificate_sha256"])

    for member in team["administrators"]:
        if (type(member) is not dict or set(member) != _MEMBER_FIELDS
                or type(member.get("admin_id")) is not str
                or _ID.fullmatch(member["admin_id"]) is None
                or member["admin_id"] in ids
                or member["admin_id"].startswith("KX108")):
            return _hold("G4N_TEAM_ADMIN_ID_INVALID_OR_DUPLICATE")
        ids.add(member["admin_id"])
        if (type(member.get("enrollment_state")) is not str
                or member.get("enrollment_state") not in {"PLANNED", "KEY_PROPOSED_AWAITING_REVIEW"}):
            return _hold("G4N_TEAM_ADMIN_CANNOT_SELF_APPROVE")
        pin = member["public_certificate_sha256"]
        if member["enrollment_state"] == "PLANNED":
            if pin is not None:
                return _hold("G4N_PLANNED_TEAM_ADMIN_CANNOT_HOLD_KEY")
        elif type(pin) is not str or _HEX.fullmatch(pin) is None:
            return _hold("G4N_TEAM_ADMIN_PIN_REQUIRED")
        if pin is not None:
            if pin in pins:
                return _hold("G4N_ADMIN_KEY_CROSS_ROLE_OR_PC_REUSE")
            pins.add(pin)

    ready = {
        "founder_only_plan_valid": True, "team_plan_prepared": True,
        # Le registre public ne couvre pas forcément toutes les clés PC
        # installées : l'indépendance réelle sera prouvée sur Windows.
        "founder_key_separate_from_pc": False,
        "founder_key_registry_conflict_absent": founder_bytes is not None,
        "founder_admin_id": FOUNDER_ID,
        "proposed_team_count": len(team["administrators"]),
    }
    if activation_receipt is None:
        return _hold("G4N_FOUNDER_ONLY_TEAM_STAGED_NOT_ACTIVE", **ready)
    if (founder_bytes is None or len(team["administrators"]) == 0
            or any(m["enrollment_state"] != "KEY_PROPOSED_AWAITING_REVIEW"
                   for m in team["administrators"])):
        return _hold("G4N_ACTIVATION_PROPOSAL_REQUIRES_SEPARATE_KEYS", **ready)
    if (type(activation_receipt) is not dict
            or set(activation_receipt) != {"payload", "signature_base64"}):
        return _hold("G4N_ACTIVATION_ENVELOPE_INVALID", **ready)
    payload, signature64 = (activation_receipt["payload"],
                            activation_receipt["signature_base64"])
    if (type(payload) is not dict or set(payload) != _ACTIVATION_FIELDS
            or payload.get("schema") != ACTIVATION_SCHEMA
            or payload.get("event") != "PROPOSE_ENABLE_TEAM_REVIEW"
            or payload.get("founder_admin_id") != FOUNDER_ID
            or payload.get("founder_certificate_sha256") != founder["public_certificate_sha256"]
            or payload.get("plan_sha256") != digest(plan)
            or payload.get("team_sha256") != digest(team["administrators"])
            or type(payload.get("nonce")) is not str or _HEX.fullmatch(payload["nonce"]) is None
            or type(payload.get("activation_id")) is not str
            or _ID.fullmatch(payload["activation_id"]) is None):
        return _hold("G4N_ACTIVATION_PAYLOAD_NOT_BOUND_TO_PLAN", **ready)
    if type(signature64) is not str or not 0 < len(signature64) <= 4096:
        return _hold("G4N_ACTIVATION_SIGNATURE_INVALID", **ready)
    try:
        signature = base64.b64decode(signature64, validate=True)
    except (binascii.Error, ValueError):
        return _hold("G4N_ACTIVATION_SIGNATURE_INVALID", **ready)
    if base64.b64encode(signature).decode("ascii") != signature64:
        return _hold("G4N_ACTIVATION_SIGNATURE_INVALID", **ready)
    raw = canonical(payload)
    if raw is None:
        return _hold("G4N_ACTIVATION_CANONICAL_INVALID", **ready)
    error = _verify_founder_signature(founder_bytes, signature, raw)
    if error is not None:
        return _hold(error, **ready)
    return _hold(
        "G4N_FOUNDER_SIGNED_TEAM_SWITCH_PROPOSAL_NOT_TRUSTED_OR_ACTIVE",
        **ready,
        founder_activation_proposal_signature_verified=True,
        limits=[
            "FOUNDER_CERTIFICATE_FROM_PUBLIC_PLAN_IS_NOT_AN_INDEPENDENT_TRUST_ROOT",
            "FOUNDER_HUMAN_IDENTITY_NOT_AUTHENTICATED",
            "TEAM_ADMIN_PINS_ARE_UNVERIFIED_PUBLIC_PROPOSALS",
            "SIGNED_ACTIVATION_CANNOT_ENABLE_TEAM_WITHOUT_TRUSTED_ENROLLMENT_AND_REPLAY_PROTECTION",
            "SCOPE_IS_MACHINE_ENROLLMENT_ONLY_KX108_AUTHORITY_UNCHANGED",
        ],
    )
