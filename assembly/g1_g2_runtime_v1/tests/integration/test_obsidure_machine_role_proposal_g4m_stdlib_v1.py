"""G4M : rôle proposé par PC, jamais approbation ou provenance C278."""
from __future__ import annotations

import base64
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from c2_wal_machine_rsa_receipt_v1 import DOMAIN, canonical_payload
from prepare_g4k_synthetic_subprocess_v1 import build_subprocess_fixture
from obsidia_governance_runtime_v1 import get_runtime
from verify_g4m_machine_role_proposal_v1 import main as verify_cli
import test_c2_wal_machine_rsa_g4j_stdlib_v1 as _G4J

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:
    hashes = None


@unittest.skipUnless(hashes is not None, "optional cryptography unavailable")
class G4MMachineProposal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _G4J.G4JWalMachineRsa.setUpClass()
        cls.private = _G4J.G4JWalMachineRsa.private
        cls.cert64 = _G4J.G4JWalMachineRsa.cert64
        cls.pin = _G4J.G4JWalMachineRsa.pin

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="obsidia-g4m-proposal-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "new-root"
        fixture = build_subprocess_fixture(
            repo_root=root, machine_id="DESKTOP-Q5MD7J7",
            public_cert_pin=self.pin, source_git_head="f" * 40)
        signature = self.private.sign(
            DOMAIN + canonical_payload(fixture["payload"]),
            padding.PKCS1v15(), hashes.SHA256())
        self.registry = {
            "schema": "OBSIDIA_OBSIDURE_MACHINE_IDENTITY_REGISTRY_V1",
            "decision_authority": "KX108_ONLY",
            "trust_model": "PER_MACHINE_INDEPENDENT_ASYMMETRIC",
            "machine_identities": [
                {
                    "machine_id": "DESKTOP-Q5MD7J7",
                    "enrollment_state": "ENROLLED_AWAITING_REVIEW",
                    "public_certificate_der_base64": self.cert64,
                    "public_certificate_sha256": self.pin,
                    "responsible_refs": [],
                    "proposed_roles": ["OBSIDURE_TEST_EVIDENCE_PRODUCER"],
                    "enrollment_review_ref": None,
                    "revocation_ref": None,
                },
                {
                    "machine_id": "DESKTOP-SDOG0EL",
                    "enrollment_state": "PLANNED",
                    "public_certificate_der_base64": None,
                    "public_certificate_sha256": None,
                    "responsible_refs": [],
                    "proposed_roles": ["OBSIDURE_TEST_EVIDENCE_PRODUCER"],
                    "enrollment_review_ref": None,
                    "revocation_ref": None,
                },
            ],
        }
        self.data = {
            "registry": self.registry,
            "wal_dir": fixture["wal_dir"], "repo_root": str(root),
            "intent_id": fixture["intent_id"],
            "receipt": {"payload": fixture["payload"],
                        "signature_base64": base64.b64encode(signature).decode("ascii")},
            "public_certificate_der_base64": self.cert64,
            "expected_public_certificate_sha256": self.pin,
            "expected_machine_id": "DESKTOP-Q5MD7J7",
        }

    def _inspect(self, data=None):
        d = self.data if data is None else data
        return get_runtime().inspect_obsidure_machine_role_proposal(
            registry=d["registry"], wal_dir=Path(d["wal_dir"]),
            repo_root=Path(d["repo_root"]), intent_id=d["intent_id"],
            receipt=d["receipt"], expected_machine_id=d["expected_machine_id"],
            public_certificate_der_base64=d["public_certificate_der_base64"],
            expected_public_certificate_sha256=d["expected_public_certificate_sha256"],
        )

    def _no_authority(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        for k in (
            "proposed_role_is_active", "machine_identity_attested",
            "certificate_enrollment_approved", "registry_approval_verified",
            "responsible_person_authenticated", "producer_identity_attested",
            "real_c278_runner_attested", "replay_prevented",
            "human_approval_verified", "kx108_ticket_issued",
            "execution_authorized", "recovery_authorized",
            "release_authorized", "target_mutated",
        ):
            self.assertIs(result[k], False, k)

    def test_registry_and_rsa_proposal_match_without_approval(self):
        res = self._inspect()
        self._no_authority(res)
        self.assertTrue(res["machine_registry_structure_valid"])
        self.assertTrue(res["proposal_machine_pin_consistent"])
        self.assertTrue(res["synthetic_machine_signature_verified"])
        self.assertTrue(res["synthetic_runner_trace_verified"])
        self.assertEqual(res["enrollment_state"], "ENROLLED_AWAITING_REVIEW")
        self.assertEqual(res["reason"], "G4M_MACHINE_ROLE_PROPOSED_CRYPTO_BOUND_NOT_APPROVED")

    def test_cli_reports_not_approved(self):
        with patch("sys.stdin", io.StringIO(json.dumps(self.data))), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
            code = verify_cli()
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("CERTIFICATE_ENROLLMENT_APPROVED=False", out.getvalue())
        self.assertIn("REAL_C278_PRODUCER_ATTESTED=False", out.getvalue())

    def test_duplicate_json_keys_denied(self):
        raw = json.dumps(self.data).replace('"registry":', '"registry":null,"registry":', 1)
        with patch("sys.stdin", io.StringIO(raw)), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
            code = verify_cli()
        self.assertEqual(code, 2)
        self.assertIn("INPUT_JSON_INVALID", out.getvalue())

    def test_declared_human_reference_is_not_authenticated(self):
        d = copy.deepcopy(self.data)
        d["registry"]["machine_identities"][0]["responsible_refs"] = ["person:etienne"]
        res = self._inspect(d)
        self._no_authority(res)
        self.assertEqual(res["responsible_refs_declared"], ["person:etienne"])

    def test_declared_review_reference_is_not_approval(self):
        d = copy.deepcopy(self.data)
        d["registry"]["machine_identities"][0]["enrollment_review_ref"] = "review:unverified"
        res = self._inspect(d)
        self._no_authority(res)
        self.assertEqual(res["review_reference_declared"], "review:unverified")

    def test_planned_fixed_pc_not_admitted(self):
        d = copy.deepcopy(self.data)
        d["expected_machine_id"] = "DESKTOP-SDOG0EL"
        self.assertEqual(self._inspect(d)["reason"], "G4M_MACHINE_NOT_ENROLLED")

    def test_revoked_portable_rejected(self):
        d = copy.deepcopy(self.data)
        entry = d["registry"]["machine_identities"][0]
        entry["enrollment_state"] = "REVOKED"
        entry["revocation_ref"] = "revocation:synthetic"
        res = self._inspect(d)
        self._no_authority(res)
        self.assertEqual(res["reason"], "G4M_MACHINE_REVOKED")

    def test_active_state_forgery_denied(self):
        d = copy.deepcopy(self.data)
        d["registry"]["machine_identities"][0]["enrollment_state"] = "APPROVED"
        self.assertIn("G4M_MACHINE_REGISTRY_INVALID", self._inspect(d)["reason"])

    def test_role_escalation_denied(self):
        d = copy.deepcopy(self.data)
        d["registry"]["machine_identities"][0]["proposed_roles"] = ["KX108_SOVEREIGN"]
        self.assertIn("MACHINE_ROLE_CANNOT_GRANT_KX108_AUTHORITY", self._inspect(d)["reason"])

    def test_duplicate_machine_ids_denied(self):
        d = copy.deepcopy(self.data)
        d["registry"]["machine_identities"].append(copy.deepcopy(d["registry"]["machine_identities"][0]))
        self.assertIn("MACHINE_IDENTITY_DUPLICATE_OR_INVALID", self._inspect(d)["reason"])

    def test_cross_pc_certificate_reuse_denied(self):
        d = copy.deepcopy(self.data)
        entry = d["registry"]["machine_identities"][1]
        entry["enrollment_state"] = "ENROLLED_AWAITING_REVIEW"
        entry["public_certificate_der_base64"] = self.cert64
        entry["public_certificate_sha256"] = self.pin
        self.assertIn("MACHINE_PUBLIC_CERTIFICATE_REUSED_ACROSS_MACHINES",
                      self._inspect(d)["reason"])

    def test_unlisted_machine_denied(self):
        d = copy.deepcopy(self.data)
        d["expected_machine_id"] = "DESKTOP-OTHER001"
        self.assertEqual(self._inspect(d)["reason"], "G4M_MACHINE_NOT_REGISTERED")

    def test_pin_mismatch_denied(self):
        d = copy.deepcopy(self.data)
        d["expected_public_certificate_sha256"] = "0" * 64
        self.assertEqual(self._inspect(d)["reason"], "G4M_PUBLIC_CERTIFICATE_REGISTRY_MISMATCH")

    def test_registry_public_cert_mismatch_denied(self):
        d = copy.deepcopy(self.data)
        d["registry"]["machine_identities"][0]["public_certificate_der_base64"] = "x"
        self.assertIn("G4M_MACHINE_REGISTRY_INVALID", self._inspect(d)["reason"])

    def test_signed_transcript_modified_denied(self):
        d = copy.deepcopy(self.data)
        d["receipt"]["payload"]["runner_code_sha256"] = "a" * 64
        self.assertIn("G4M_SIGNED_SYNTHETIC_RUNNER_REQUIRED", self._inspect(d)["reason"])

    def test_no_runtime_role_activation_api(self):
        runtime = get_runtime()
        self.assertFalse(hasattr(runtime, "approve_machine_enrollment"))
        self.assertFalse(hasattr(runtime, "activate_machine_role"))
        self.assertEqual(runtime.capabilities()["apply"], "HOLD")


if __name__ == "__main__":
    unittest.main()
