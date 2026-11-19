"""G4J — signatures RSA synthétiques sur WAL, aucune clé réelle ni APPLY."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import c2_write_intent_wal_v1 as WAL
from c2_wal_outcome_observer_v1 import report_c2_wal_outcome_testonly
from c2_wal_machine_rsa_receipt_v1 import (
    DOMAIN, build_claim_payload, canonical_payload, inspect_wal_machine_rsa_receipt,
)
from obsidia_governance_runtime_v1 import get_runtime

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None


MACHINE = "DESKTOP-Q5MD7J7"


@unittest.skipUnless(x509 is not None, "optional cryptography unavailable")
class G4JWalMachineRsa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                             "OBSIDIA-OBSIDURE-" + MACHINE)])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(cls.private.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=2))
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ), critical=True).sign(cls.private, hashes.SHA256()))
        cls.cert_der = cert.public_bytes(serialization.Encoding.DER)
        cls.cert64 = base64.b64encode(cls.cert_der).decode("ascii")
        cls.pin = hashlib.sha256(cls.cert_der).hexdigest()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="obsidia-g4j-wal-rsa-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "targets").mkdir()
        self.target = self.root / "targets" / "synthetic.txt"
        self.old = b"g4j before"
        self.new = b"g4j after"
        self.target.write_bytes(self.new)
        self.wal = self.root / "wal"
        self.intent = WAL.build_intent(
            batch_execution_id="batch-g4j", child_execution_id="child-g4j",
            execution_authority_hash="a" * 64,
            approval_id="approval-synthetic", pre_decision_record_id="pre-g4j",
            pre_decision_record_hash="b" * 64,
            sealed_rollback_evidence_id="sre-g4j",
            sealed_rollback_evidence_hash="c" * 64,
            target_path="targets/synthetic.txt",
            target_pre_sha256=hashlib.sha256(self.old).hexdigest(),
            target_post_sha256=hashlib.sha256(self.new).hexdigest(),
        )
        self.assertEqual(WAL.store_intent(self.intent, self.wal)["status"], WAL.STORED)
        reported = report_c2_wal_outcome_testonly(
            wal_dir=self.wal, intent_id=self.intent["intent_id"],
            repo_root=self.root, reported_status="REPORTED_KEEP")
        self.assertTrue(reported["wal_outcome_recorded"])
        self.outcome = WAL.load_verified_outcome(self.wal, self.intent)
        self.payload = build_claim_payload(
            machine_id=MACHINE, public_certificate_sha256=self.pin,
            intent=self.intent, outcome=self.outcome, nonce="d" * 64,
            source_git_head="e" * 40, runner_code_sha256="f" * 64,
            tests_transcript_sha256="1" * 64,
        )
        self.assertIsNotNone(self.payload)

    def _signed(self, payload=None, *, signing_key=None):
        payload = self.payload if payload is None else payload
        private = signing_key or self.private
        signature = private.sign(DOMAIN + canonical_payload(payload),
                                 padding.PKCS1v15(), hashes.SHA256())
        return {"payload": payload,
                "signature_base64": base64.b64encode(signature).decode("ascii")}

    def _inspect(self, *, receipt=None, **kw):
        args = dict(wal_dir=self.wal, intent_id=self.intent["intent_id"],
                    repo_root=self.root, receipt=receipt or self._signed(),
                    public_certificate_der_base64=self.cert64,
                    pinned_certificate_sha256=self.pin,
                    expected_machine_id=MACHINE)
        return get_runtime().inspect_c2_wal_machine_rsa_receipt(**{**args, **kw})

    def _assert_no_authority(self, result):
        self.assertEqual(result["status"], "HOLD")
        for field in (
            "machine_identity_attested", "certificate_enrollment_approved",
            "producer_identity_attested", "responsible_person_authenticated",
            "process_execution_attested", "test_transcript_attested",
            "source_git_head_attested", "replay_prevented",
            "physical_mutation_attested", "rollback_attested", "kx108_ticket_issued",
            "human_approval_verified", "execution_authorized",
            "release_authorized", "recovery_authorized", "target_mutated",
        ):
            self.assertFalse(result[field], field)

    def test_valid_signature_is_key_possession_not_runner_identity(self):
        result = self._inspect()
        self._assert_no_authority(result)
        self.assertTrue(result["machine_signature_verified"])
        self.assertEqual(result["reason"], "G4J_RSA_SIGNATURE_MATCH_ORIGIN_UNATTESTED")
        self.assertEqual(self.target.read_bytes(), self.new)

    def test_signed_nonce_changed_after_signature_holds(self):
        receipt = self._signed()
        receipt["payload"] = {**receipt["payload"], "nonce": "0" * 64}
        self.assertIn("SIGNATURE_MISMATCH", self._inspect(receipt=receipt)["reason"])

    def test_extra_authorizing_field_rejected_even_if_resigned(self):
        forged = {**self.payload, "release_authorized": True}
        self.assertIsNone(canonical_payload(forged))
        receipt = {"payload": forged, "signature_base64": self._signed()["signature_base64"]}
        self.assertEqual(self._inspect(receipt=receipt)["reason"], "G4J_RECEIPT_FIELDS_INVALID")

    def test_machine_cross_claim_rejected_even_if_resigned(self):
        payload = {**self.payload, "machine_id": "DESKTOP-SDOG0EL"}
        result = self._inspect(receipt=self._signed(payload), expected_machine_id=MACHINE)
        self.assertEqual(result["reason"], "G4J_RECEIPT_SCOPE_OR_IDENTITY_INVALID")
        result2 = self._inspect(receipt=self._signed(payload), expected_machine_id="DESKTOP-SDOG0EL")
        self.assertIn("CERTIFICATE_CONTRACT_INVALID", result2["reason"])

    def test_certificate_pin_mismatch_holds(self):
        self.assertEqual(self._inspect(pinned_certificate_sha256="0" * 64)["reason"],
                         "G4J_PUBLIC_CERTIFICATE_PIN_MISMATCH")

    def test_second_private_key_not_accepted(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.assertIn("SIGNATURE_MISMATCH", self._inspect(
            receipt=self._signed(signing_key=other))["reason"])

    def test_outcome_claim_substitution_is_denied(self):
        payload = {**self.payload, "outcome_record_hash": "a" * 64}
        result = self._inspect(receipt=self._signed(payload))
        self.assertEqual(result["reason"], "G4J_WAL_RECEIPT_BINDING_MISMATCH")

    def test_current_target_drifts_after_signature(self):
        receipt = self._signed()
        self.target.write_bytes(self.old)
        result = self._inspect(receipt=receipt)
        self._assert_no_authority(result)
        self.assertIn("G4I_OUTCOME_VS_LIVE_MISMATCH", result["reason"])

    def test_tampered_outcome_disk_is_denied(self):
        path = self.wal / (self.intent["intent_id"] + ".outcome.json")
        bad = json.loads(path.read_text(encoding="utf-8"))
        bad["reported_status"] = "REPORTED_ROLLBACK"
        path.write_text(json.dumps(bad), encoding="utf-8")
        self.assertIn("G4J_WAL_LIVE_OBSERVATION_REQUIRED", self._inspect()["reason"])

    def test_two_checks_do_not_invent_replay_protection(self):
        one, two = self._inspect(), self._inspect()
        self.assertTrue(one["machine_signature_verified"])
        self.assertTrue(two["machine_signature_verified"])
        self.assertFalse(two["replay_prevented"])

    def test_wrong_domain_signed_message_is_rejected(self):
        bad_signature = self.private.sign(b"OTHER_DOMAIN\x00" + canonical_payload(self.payload),
                                          padding.PKCS1v15(), hashes.SHA256())
        bad = {"payload": self.payload,
               "signature_base64": base64.b64encode(bad_signature).decode("ascii")}
        self.assertIn("SIGNATURE_MISMATCH", self._inspect(receipt=bad)["reason"])

    def test_bad_nonce_and_git_head_cannot_be_signed_payload(self):
        self.assertIsNone(build_claim_payload(
            machine_id=MACHINE, public_certificate_sha256=self.pin,
            intent=self.intent, outcome=self.outcome, nonce="not-hex",
            source_git_head="e" * 40, runner_code_sha256="f" * 64,
            tests_transcript_sha256="1" * 64))


if __name__ == "__main__":
    unittest.main()
