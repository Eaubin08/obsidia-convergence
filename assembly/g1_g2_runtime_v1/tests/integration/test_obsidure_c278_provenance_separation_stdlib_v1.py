"""C278/F7 : Séparation stricte HMAC/RSA, registre machine, provenance et attestation réelle."""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
from obsidure_c278_machine_rsa_receipt_v1 import inspect_c278_machine_rsa_receipt
from obsidure_machine_identity_registry_v1 import inspect_machine_identity_registry
from obsidure_r10_repair_intake_v1 import _BOUNDARY
from scripts.proposal_meaning_validator import validate_proposal_meaning


def _sha(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def _canon(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


class C278F7ProvenanceSeparationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-c278-sep-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo_root = self.root / "repo"
        self.target = "scripts/tool.py"
        (self.repo_root / "scripts").mkdir(parents=True)
        (self.repo_root / self.target).write_bytes(b"old\n")
        self.sb = self.repo_root / "_EPHEMERAL_REPAIR_SANDBOX_C278"
        (self.sb / "scripts").mkdir(parents=True)
        (self.sb / self.target).write_bytes(b"new\n")
        self.runtime = ObsidiaGovernanceRuntime()

        self.ids = {
            "repair_request_id": "req-c278-sep-1",
            "repair_proposal_id": "prop-c278-sep-1",
            "repair_verdict_id": "verd-c278-sep-1",
        }
        self.request = {
            "request_id": self.ids["repair_request_id"],
            "repo_targets": [self.target],
            "objective": "Repair tool",
            "summary": "tool broken",
            "error_contexts": [
                {"target_path": self.target, "error_type": "TOOL", "raw_details": "broken"}
            ],
            "target_excerpts": {self.target: "old\n"},
            "tests_hint": ["tests/test_tool.py"],
            "boundary": dict(_BOUNDARY),
        }
        self.proposal = {
            "proposal_id": self.ids["repair_proposal_id"],
            "request_id": self.ids["repair_request_id"],
            "rationale": "Repair tool",
            "candidate_files": [
                {
                    "path": self.target,
                    "change_kind": "MODIFY",
                    "full_content": "new\n",
                    "base_sha256": _sha(b"old\n"),
                    "rationale": "Fix",
                }
            ],
            "tests_to_run": ["tests/test_tool.py"],
            "confidence": "HIGH",
            "boundary": dict(_BOUNDARY),
        }
        self.c278 = validate_proposal_meaning(request=self.request, proposal=self.proposal)
        self.verdict = {
            "verdict_id": self.ids["repair_verdict_id"],
            "request_id": self.ids["repair_request_id"],
            "proposal_id": self.ids["repair_proposal_id"],
            "status": "PASS",
            "compiled_files": [self.target],
            "sandbox_dir": str(self.sb),
            "errors": [],
            "boundary": dict(_BOUNDARY),
            "tested_artifacts": [{"path": self.target, "sha256": _sha(b"new\n")}],
            "tests_executed": [
                {"test": "tests/test_tool.py", "status": "PASS", "returncode": 0, "isolation": "FULL"}
            ],
        }
        self.r10 = self.runtime.inspect_obsidure_r10_repair(
            repair_request=self.request,
            repair_proposal=self.proposal,
            c278_evidence=self.c278,
            repair_verdict=self.verdict,
            worktree_root=self.repo_root,
            declared_targets=[self.target],
        )
        self.assertEqual(self.r10["status"], "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY")

    def _assert_no_attestation_or_authority(self, res: dict) -> None:
        self.assertEqual(res.get("decision_authority"), "KX108_ONLY")
        self.assertIs(res.get("sandbox_origin_attested"), False)
        self.assertIs(res.get("human_approval_verified"), False)
        self.assertIs(res.get("execution_authorized"), False)
        self.assertIs(res.get("release_authorized"), False)
        self.assertIs(res.get("target_mutated"), False)

    def test_machine_identity_registry_structure_never_grants_trust(self) -> None:
        fake_der = b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" + b"\x01" * 220
        fake_b64 = base64.b64encode(fake_der).decode("ascii")
        fake_sha = _sha(fake_der)
        registry = {
            "schema": "OBSIDIA_OBSIDURE_MACHINE_IDENTITY_REGISTRY_V1",
            "decision_authority": "KX108_ONLY",
            "trust_model": "PER_MACHINE_INDEPENDENT_ASYMMETRIC",
            "machine_identities": [
                {
                    "machine_id": "OBSIDIA-PC-01",
                    "enrollment_state": "PLANNED",
                    "public_certificate_der_base64": None,
                    "public_certificate_sha256": None,
                    "responsible_refs": ["operator/a"],
                    "proposed_roles": ["OBSIDURE_TEST_EVIDENCE_PRODUCER"],
                    "enrollment_review_ref": None,
                    "revocation_ref": None,
                },
                {
                    "machine_id": "OBSIDIA-PC-02",
                    "enrollment_state": "ENROLLED_AWAITING_REVIEW",
                    "public_certificate_der_base64": fake_b64,
                    "public_certificate_sha256": fake_sha,
                    "responsible_refs": ["operator/b"],
                    "proposed_roles": ["OBSIDURE_TEST_EVIDENCE_PRODUCER"],
                    "enrollment_review_ref": "review/2026-11-24",
                    "revocation_ref": None,
                },
            ],
        }
        res = inspect_machine_identity_registry(registry)
        self.assertEqual(res["status"], "MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED")
        self.assertIs(res["machine_identity_attested"], False)
        self.assertIs(res["responsible_person_authenticated"], False)
        self.assertIs(res["registry_approval_verified"], False)
        self.assertIs(res["machine_signature_verified"], False)
        self._assert_no_attestation_or_authority(res)

        # Rôle KX108 interdit dans le registre
        bad_role = {
            **registry,
            "machine_identities": [
                {**registry["machine_identities"][0], "proposed_roles": ["KX108_AUTHORITY"]}
            ],
        }
        self.assertEqual(
            inspect_machine_identity_registry(bad_role)["reason"],
            "MACHINE_ROLE_CANNOT_GRANT_KX108_AUTHORITY",
        )

        # PLANNED avec certificat forgé refusé
        bad_planned = {
            **registry,
            "machine_identities": [
                {
                    **registry["machine_identities"][0],
                    "public_certificate_der_base64": fake_b64,
                    "public_certificate_sha256": fake_sha,
                }
            ],
        }
        self.assertEqual(
            inspect_machine_identity_registry(bad_planned)["reason"],
            "MACHINE_PLANNED_WITH_FORGED_ENROLLMENT",
        )

    def test_machine_rsa_receipt_pin_mismatch_and_signature_without_origin_attestation(self) -> None:
        machine_id = "OBSIDIA-PC-TEST-1"
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
            from cryptography.x509.oid import NameOID
        except ImportError:
            self.skipTest("cryptography package not installed")

        priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "OBSIDIA-OBSIDURE-" + machine_id)]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(priv, hashes.SHA256())
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode("ascii")
        cert_sha = _sha(cert_der)

        payload = {
            "schema": "OBSIDURE_C278_MACHINE_RSA_RECEIPT_V1",
            "machine_id": machine_id,
            "public_certificate_sha256": cert_sha,
            "receipt_id": "rcpt-rsa-1",
            "nonce": "1" * 64,
            "request_id": self.ids["repair_request_id"],
            "proposal_id": self.ids["repair_proposal_id"],
            "verdict_id": self.ids["repair_verdict_id"],
            "repair_request_sha256": _sha(_canon(self.request)),
            "repair_proposal_sha256": _sha(_canon(self.proposal)),
            "c278_evidence_sha256": _sha(_canon(self.c278)),
            "repair_verdict_sha256": _sha(_canon(self.verdict)),
            "candidate_artifact_sha256": {self.target: _sha(b"new\n")},
            "source_git_head": "a" * 40,
            "runner_code_sha256": "2" * 64,
            "tests_transcript_sha256": "3" * 64,
        }
        sig = priv.sign(
            b"OBSIDIA_OBSIDURE_C278_MACHINE_RSA_V1\x00" + _canon(payload),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        receipt = {
            "payload": payload,
            "signature_base64": base64.b64encode(sig).decode("ascii"),
        }

        # 1. Signature RSA valide -> machine_signature_verified=True mais provenance/origine=False
        res = inspect_c278_machine_rsa_receipt(
            r10_inspection=self.r10,
            repair_request=self.request,
            repair_proposal=self.proposal,
            c278_evidence=self.c278,
            repair_verdict=self.verdict,
            repo_root=self.repo_root,
            receipt=receipt,
            public_certificate_der_base64=cert_b64,
            pinned_certificate_sha256=cert_sha,
            expected_machine_id=machine_id,
        )
        self.assertEqual(res["status"], "C278_MACHINE_RSA_SIGNATURE_MATCH_ORIGIN_UNATTESTED")
        self.assertIs(res["machine_signature_verified"], True)
        self.assertIs(res["machine_identity_attested"], False)
        self.assertIs(res["certificate_enrollment_approved"], False)
        self.assertIs(res["producer_identity_attested"], False)
        self.assertIs(res["test_process_attested"], False)
        self.assertIs(res["provenance_verified"], False)
        self._assert_no_attestation_or_authority(res)

        # 2. Pin mismatch -> HOLD
        bad_pin = inspect_c278_machine_rsa_receipt(
            r10_inspection=self.r10,
            repair_request=self.request,
            repair_proposal=self.proposal,
            c278_evidence=self.c278,
            repair_verdict=self.verdict,
            repo_root=self.repo_root,
            receipt=receipt,
            public_certificate_der_base64=cert_b64,
            pinned_certificate_sha256="0" * 64,
            expected_machine_id=machine_id,
        )
        self.assertEqual(bad_pin["status"], "HOLD")
        self.assertEqual(bad_pin["reason"], "C278_MACHINE_PUBLIC_CERTIFICATE_PIN_MISMATCH")


if __name__ == "__main__":
    unittest.main()
