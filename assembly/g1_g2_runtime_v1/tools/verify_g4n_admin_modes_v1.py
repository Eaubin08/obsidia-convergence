"""Test G4N — certificat fondateur et demande de bascule entièrement synthétiques.

Aucune clé réelle, aucun certificat Windows et aucune racine de confiance ne
sont créés, importés ou modifiés. La clé temporaire reste en mémoire.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obsidure_admin_bootstrap_g4n_v1 import (
    ACTIVATION_SCHEMA, DOMAIN, FOUNDER_ID, canonical, digest,
)
from obsidia_governance_runtime_v1 import get_runtime


def synthetic_founder(*, expired: bool = False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, "OBSIDIA-ADMIN-" + FOUNDER_ID)])
    now = datetime.now(timezone.utc)
    before = now - timedelta(days=20 if expired else 1)
    after = now - timedelta(days=1) if expired else now + timedelta(days=10)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(before).not_valid_after(after)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    return key, base64.b64encode(der).decode("ascii"), hashlib.sha256(der).hexdigest()


def build_fixture(*, members: int = 1, expired: bool = False):
    key, cert64, pin = synthetic_founder(expired=expired)
    plan = json.loads((ROOT / "OBSIDURE_ADMIN_BOOTSTRAP_PLAN_G4N_V1.json").read_text(encoding="utf-8"))
    registry = json.loads((ROOT / "OBSIDURE_MACHINE_IDENTITY_PLAN_V1.json").read_text(encoding="utf-8"))
    plan["founder"].update({
        "enrollment_state": "KEY_PROPOSED_AWAITING_INDEPENDENT_REVIEW",
        "public_certificate_der_base64": cert64,
        "public_certificate_sha256": pin,
    })
    for i in range(members):
        plan["team"]["administrators"].append({
            "admin_id": f"REVIEWER-{i + 1}",
            "enrollment_state": "KEY_PROPOSED_AWAITING_REVIEW",
            "public_certificate_sha256": hashlib.sha256(
                f"synthetic-reviewer-{i}".encode()).hexdigest(),
        })
    payload = {
        "schema": ACTIVATION_SCHEMA,
        "event": "PROPOSE_ENABLE_TEAM_REVIEW",
        "founder_admin_id": FOUNDER_ID,
        "founder_certificate_sha256": pin,
        "plan_sha256": digest(plan),
        "team_sha256": digest(plan["team"]["administrators"]),
        "activation_id": "ACTIVATION-SYNTHETIC-001",
        "nonce": hashlib.sha256(b"synthetic-g4n-nonce").hexdigest(),
    }
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    signature = key.sign(DOMAIN + canonical(payload), padding.PKCS1v15(), hashes.SHA256())
    receipt = {"payload": payload, "signature_base64": base64.b64encode(signature).decode("ascii")}
    return plan, registry, receipt


def main() -> int:
    runtime = get_runtime()
    plan = json.loads((ROOT / "OBSIDURE_ADMIN_BOOTSTRAP_PLAN_G4N_V1.json").read_text(encoding="utf-8"))
    registry = json.loads((ROOT / "OBSIDURE_MACHINE_IDENTITY_PLAN_V1.json").read_text(encoding="utf-8"))
    founder = runtime.inspect_obsidure_admin_bootstrap(plan=plan, machine_registry=registry)
    if (founder["reason"] != "G4N_FOUNDER_ONLY_TEAM_STAGED_NOT_ACTIVE"
            or not founder["founder_only_plan_valid"] or founder["team_mode_activated"]):
        print("G4N_FOUNDER_MODE_HOLD:" + str(founder["reason"]))
        return 2
    proposed, registry, activation = build_fixture()
    staged = runtime.inspect_obsidure_admin_bootstrap(plan=proposed, machine_registry=registry)
    if staged["reason"] != "G4N_FOUNDER_ONLY_TEAM_STAGED_NOT_ACTIVE":
        print("G4N_TEAM_STAGING_HOLD:" + str(staged["reason"]))
        return 2
    verified = runtime.inspect_obsidure_admin_bootstrap(
        plan=proposed, machine_registry=registry, activation_receipt=activation)
    if (verified["reason"] != "G4N_FOUNDER_SIGNED_TEAM_SWITCH_PROPOSAL_NOT_TRUSTED_OR_ACTIVE"
            or not verified["founder_activation_proposal_signature_verified"]):
        print("G4N_FOUNDER_ACTIVATION_PROPOSAL_HOLD:" + str(verified["reason"]))
        return 2
    forged = copy.deepcopy(activation)
    forged["payload"]["team_sha256"] = "0" * 64
    denied = runtime.inspect_obsidure_admin_bootstrap(
        plan=proposed, machine_registry=registry, activation_receipt=forged)
    if denied["founder_activation_proposal_signature_verified"]:
        print("G4N_TAMPER_REJECTION_FAILED")
        return 2
    if any(r["team_mode_activated"] or r["machine_enrollment_approved"]
           or r["kx108_ticket_issued"] or r["release_authorized"]
           for r in (founder, staged, verified, denied)):
        print("G4N_AUTHORITY_ESCALATION_HOLD")
        return 2
    print("OBSIDIA_G4N_ADMIN_BOOTSTRAP_CONTRACT_PASS=True")
    print("FOUNDER=ETIENNE")
    print("FOUNDER_ONLY_MODE_PREPARED=True")
    print("TEAM_MODE_PREPARED=True")
    print("SYNTHETIC_FOUNDER_SIGNED_SWITCH_PROPOSAL_VERIFIED=True")
    print("FOUNDER_REAL_IDENTITY_ENROLLED=False")
    print("TEAM_MODE_ACTIVATED=False")
    print("REAL_TEAM_ADMIN_AUTHENTICATED=False")
    print("REAL_C278_PRODUCER_ATTESTED=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
