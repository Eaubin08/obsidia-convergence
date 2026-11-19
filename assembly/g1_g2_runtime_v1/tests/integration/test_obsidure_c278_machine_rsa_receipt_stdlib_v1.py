"""Signature RSA synthétique indépendante ; pas de clé ni de test historique."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import obsidure_c278_machine_rsa_receipt_v1 as rsa_module
from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
import test_obsidure_c278_sandbox_observation_stdlib_v1 as _fixture_module

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None

MACHINE = "DESKTOP-Q5MD7J7"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


@unittest.skipUnless(x509 is not None, "optional cryptography missing on this host")
class MachineRsaReceiptContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, "OBSIDIA-OBSIDURE-" + MACHINE,
        )])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(subject)
                .public_key(cls.private.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ), critical=True)
                .sign(cls.private, hashes.SHA256()))
        cls.public_der = cert.public_bytes(serialization.Encoding.DER)
        cls.cert64 = base64.b64encode(cls.public_der).decode("ascii")
        cls.cert_sha = hashlib.sha256(cls.public_der).hexdigest()

    def setUp(self):
        self.fixture = _fixture_module.C278SandboxObservation(
            "test_c278_canonical_replay_and_sandbox_bytes_are_only_observed",
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.runtime = ObsidiaGovernanceRuntime()
        self.kwargs = dict(
            r10_inspection=f.r10, repair_request=f.request,
            repair_proposal=f.proposal, c278_evidence=f.c278,
            repair_verdict=f.verdict, repo_root=f.root,
            public_certificate_der_base64=self.cert64,
            pinned_certificate_sha256=self.cert_sha,
            expected_machine_id=MACHINE,
        )
        self.payload = dict(
            schema="OBSIDURE_C278_MACHINE_RSA_RECEIPT_V1", machine_id=MACHINE,
            public_certificate_sha256=self.cert_sha,
            receipt_id="synthetic-machine-receipt-001", nonce="a" * 64,
            request_id=f.request["request_id"],
            proposal_id=f.proposal["proposal_id"],
            verdict_id=f.verdict["verdict_id"],
            repair_request_sha256=digest(f.request),
            repair_proposal_sha256=digest(f.proposal),
            c278_evidence_sha256=digest(f.c278),
            repair_verdict_sha256=digest(f.verdict),
            candidate_artifact_sha256={f.target: hashlib.sha256(f.content.encode()).hexdigest()},
            source_git_head="1" * 40, runner_code_sha256="2" * 64,
            tests_transcript_sha256="3" * 64,
        )

    def verify(self, payload=None, signature=None, **kwargs):
        payload = self.payload if payload is None else payload
        if signature is None:
            signature = self.private.sign(
                rsa_module._DOMAIN + canonical(payload),
                padding.PKCS1v15(), hashes.SHA256(),
            )
        receipt = {
            "payload": payload,
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
        return self.runtime.inspect_obsidure_c278_machine_rsa_receipt(
            **{**self.kwargs, **kwargs}, receipt=receipt,
        )

    def test_matching_synthetic_rsa_signature_does_not_grant_origin_or_release(self):
        f = self.fixture
        paths = [f.root / f.target, f.sandbox / f.target]
        original = [p.read_bytes() for p in paths]
        result = self.verify()
        self.assertEqual(result["status"], "C278_MACHINE_RSA_SIGNATURE_MATCH_ORIGIN_UNATTESTED")
        self.assertTrue(result["machine_signature_verified"])
        self.assertTrue(result["sandbox_bytes_observed"])
        self.assertEqual(result["machine_id"], MACHINE)
        self.assertEqual(result["public_certificate_sha256"], self.cert_sha)
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        for field in (
            "machine_identity_attested", "certificate_enrollment_approved",
            "producer_identity_attested", "responsible_person_authenticated",
            "sandbox_origin_attested", "test_process_attested", "test_isolation_certified",
            "live_git_head_verified", "replay_prevented", "provenance_verified",
            "human_approval_verified", "execution_authorized", "release_authorized",
            "action_ticket_issued", "kx108_pre_invoked", "executor_invoked",
            "target_mutated", "automatic_retry",
        ):
            self.assertIs(result[field], False, field)
        self.assertEqual(original, [p.read_bytes() for p in paths])

    def test_missing_public_certificate_holds(self):
        result = self.verify(public_certificate_der_base64=None)
        self.assertEqual(result["reason"], "C278_MACHINE_PUBLIC_CERTIFICATE_REQUIRED")

    def test_public_certificate_hash_mismatch_holds(self):
        result = self.verify(pinned_certificate_sha256="0" * 64)
        self.assertEqual(result["reason"], "C278_MACHINE_PUBLIC_CERTIFICATE_PIN_MISMATCH")

    def test_different_certificate_key_is_rejected_even_with_new_pin(self):
        second = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                               "OBSIDIA-OBSIDURE-" + MACHINE)])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(second.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ), critical=True).sign(second, hashes.SHA256()))
        data = cert.public_bytes(serialization.Encoding.DER)
        forged = copy.deepcopy(self.payload)
        forged["public_certificate_sha256"] = hashlib.sha256(data).hexdigest()
        self.assertEqual(self.verify(
            payload=forged, public_certificate_der_base64=base64.b64encode(data).decode("ascii"),
            pinned_certificate_sha256=hashlib.sha256(data).hexdigest(),
        )["reason"], "C278_MACHINE_RSA_SIGNATURE_MISMATCH")

    def test_signature_mismatch_and_truncation_hold(self):
        self.assertEqual(self.verify(signature=b"0" * 384)["reason"],
                         "C278_MACHINE_RSA_SIGNATURE_MISMATCH")
        self.assertEqual(self.verify(signature=b"0" * 8)["reason"],
                         "C278_MACHINE_RSA_SIGNATURE_MISMATCH")

    def test_payload_mutation_after_signing_is_not_accepted(self):
        original_signature = self.private.sign(
            rsa_module._DOMAIN + canonical(self.payload),
            padding.PKCS1v15(), hashes.SHA256(),
        )
        changed = copy.deepcopy(self.payload)
        changed["runner_code_sha256"] = "d" * 64
        self.assertEqual(self.verify(changed, signature=original_signature)["reason"],
                         "C278_MACHINE_RSA_SIGNATURE_MISMATCH")

    def test_cross_machine_claim_rejected(self):
        changed = copy.deepcopy(self.payload)
        changed["machine_id"] = "DESKTOP-SDOG0EL"
        self.assertEqual(self.verify(changed)["reason"],
                         "C278_MACHINE_RECEIPT_IDENTITY_MISMATCH")

    def test_wrong_expected_machine_rejected(self):
        self.assertEqual(self.verify(expected_machine_id="DESKTOP-SDOG0EL")["reason"],
                         "C278_MACHINE_RECEIPT_IDENTITY_MISMATCH")

    def test_forged_authority_field_rejected_even_if_signed(self):
        changed = copy.deepcopy(self.payload)
        changed["execution_authorized"] = True
        self.assertEqual(self.verify(changed)["reason"],
                         "C278_MACHINE_RECEIPT_FIELDS_INVALID")

    def test_hmac_receipt_schema_cannot_substitute_rsa(self):
        changed = copy.deepcopy(self.payload)
        changed["schema"] = "OBSIDURE_C278_DETACHED_HMAC_RECEIPT_V1"
        self.assertEqual(self.verify(changed)["reason"],
                         "C278_MACHINE_RECEIPT_IDENTITY_MISMATCH")

    def test_c278_lineage_substitution_holds_even_with_valid_signature(self):
        changed = copy.deepcopy(self.payload)
        changed["proposal_id"] = "other-proposal"
        self.assertEqual(self.verify(changed)["reason"],
                         "C278_MACHINE_RECEIPT_LINEAGE_MISMATCH")

    def test_sandbox_artifact_digest_substitution_holds(self):
        changed = copy.deepcopy(self.payload)
        changed["candidate_artifact_sha256"][self.fixture.target] = "f" * 64
        self.assertEqual(self.verify(changed)["reason"],
                         "C278_MACHINE_RECEIPT_SANDBOX_ARTIFACT_MISMATCH")

    def test_sandbox_content_drift_holds(self):
        (self.fixture.sandbox / self.fixture.target).write_bytes(b"changed\n")
        self.assertEqual(self.verify()["reason"],
                         "C278_MACHINE_SANDBOX_OBSERVATION_REQUIRED:C278_SANDBOX_BYTES_DIFFER_FROM_VERDICT")

    def test_c278_evidence_drift_holds(self):
        changed = copy.deepcopy(self.payload)
        changed["c278_evidence_sha256"] = "f" * 64
        self.assertEqual(self.verify(changed)["reason"],
                         "C278_MACHINE_RECEIPT_SOURCE_DIGEST_MISMATCH")

    def test_nonce_reuse_does_not_pretend_to_be_replay_protected(self):
        self.assertTrue(self.verify()["machine_signature_verified"])
        second = self.verify()
        self.assertTrue(second["machine_signature_verified"])
        self.assertFalse(second["replay_prevented"])
        self.assertFalse(second["release_authorized"])

    def test_missing_crypto_dependency_holds_explicitly(self):
        # Induit exactement la branche ImportError du vérificateur.
        import builtins
        real_import = builtins.__import__

        def no_crypto(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise ImportError("synthetic unavailable")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=no_crypto):
            self.assertEqual(self.verify()["reason"],
                             "C278_MACHINE_RSA_VERIFIER_DEPENDENCY_MISSING")

    def test_capability_stays_readonly_and_single_runtime(self):
        capabilities = self.runtime.capabilities()
        self.assertEqual(capabilities["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertIn("VERIFICATION_ONLY", capabilities["obsidure_c278_machine_rsa_receipt"])
        self.assertEqual(capabilities["apply"], "HOLD")
        self.assertEqual(self.runtime.execute(operation_type="C278_RELEASE")["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
