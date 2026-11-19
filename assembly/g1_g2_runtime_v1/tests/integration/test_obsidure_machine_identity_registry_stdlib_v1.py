"""Identités distinctes portable/fixe, rôles non souverains, aucune clé réelle."""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime


class MachineIdentityRegistry(unittest.TestCase):
    def setUp(self):
        self.runtime = ObsidiaGovernanceRuntime()
        self.manifest = json.loads((ROOT / "OBSIDURE_MACHINE_IDENTITY_PLAN_V1.json").read_text(encoding="utf-8"))

    def inspect(self):
        return self.runtime.inspect_obsidure_machine_identity_registry(self.manifest)

    def enroll_fake_public_only(self, index: int, raw: bytes) -> None:
        entry = self.manifest["machine_identities"][index]
        entry["enrollment_state"] = "ENROLLED_AWAITING_REVIEW"
        entry["public_certificate_der_base64"] = base64.b64encode(raw).decode("ascii")
        entry["public_certificate_sha256"] = hashlib.sha256(raw).hexdigest()

    def test_two_known_pcs_are_distinct_and_not_enrolled(self):
        result = self.inspect()
        self.assertEqual(result["status"], "MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED")
        self.assertEqual(result["machine_ids"], ["DESKTOP-Q5MD7J7", "DESKTOP-SDOG0EL"])
        self.assertEqual(result["pending_count"], 2)
        self.assertEqual(result["trusted_machines_count"], 0)
        self.assertFalse(result["registry_approval_verified"])
        self.assertFalse(result["execution_authorized"])

    def test_duplicate_machine_id_refused(self):
        self.manifest["machine_identities"][1]["machine_id"] = "DESKTOP-Q5MD7J7"
        self.assertEqual(self.inspect()["reason"], "MACHINE_IDENTITY_DUPLICATE_OR_INVALID")

    def test_fake_sovereign_role_and_unknown_field_refused(self):
        entry = self.manifest["machine_identities"][0]
        entry["proposed_roles"] = ["KX108_DECISION_AUTHORITY"]
        self.assertEqual(self.inspect()["reason"], "MACHINE_ROLE_CANNOT_GRANT_KX108_AUTHORITY")
        entry["proposed_roles"] = ["OBSIDURE_TEST_EVIDENCE_PRODUCER"]
        entry["execution_authorized"] = True
        self.assertEqual(self.inspect()["reason"], "MACHINE_IDENTITY_FIELDS_INVALID")

    def test_planned_identity_cannot_claim_certificate(self):
        self.manifest["machine_identities"][0]["public_certificate_sha256"] = "a" * 64
        self.assertEqual(self.inspect()["reason"], "MACHINE_PLANNED_WITH_FORGED_ENROLLMENT")

    def test_matching_fake_certificate_is_still_untrusted(self):
        self.enroll_fake_public_only(0, b"not-a-certificate" * 32)
        self.manifest["machine_identities"][0]["responsible_refs"] = ["person:responsable-a"]
        result = self.inspect()
        self.assertEqual(result["status"], "MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED")
        self.assertEqual(result["certificate_records_count"], 1)
        self.assertFalse(result["machine_identity_attested"])
        self.assertFalse(result["responsible_person_authenticated"])
        self.assertFalse(result["human_approval_verified"])
        self.assertEqual(result["trusted_machines_count"], 0)

    def test_certificate_payload_or_hash_corruption_refused(self):
        self.enroll_fake_public_only(0, b"not-a-certificate" * 32)
        entry = self.manifest["machine_identities"][0]
        entry["public_certificate_sha256"] = "a" * 64
        self.assertEqual(self.inspect()["reason"], "MACHINE_PUBLIC_CERTIFICATE_HASH_MISMATCH")
        entry["public_certificate_der_base64"] = "!!!!"
        self.assertEqual(self.inspect()["reason"], "MACHINE_PUBLIC_CERTIFICATE_INVALID_BASE64")

    def test_same_public_key_reused_between_machines_refused(self):
        shared = b"not-a-certificate" * 32
        self.enroll_fake_public_only(0, shared)
        self.enroll_fake_public_only(1, shared)
        self.assertEqual(self.inspect()["reason"], "MACHINE_PUBLIC_CERTIFICATE_REUSED_ACROSS_MACHINES")

    def test_unknown_enrollment_state_and_unhashable_values_fail_closed(self):
        entry = self.manifest["machine_identities"][0]
        entry["enrollment_state"] = "TRUSTED_WITHOUT_REVIEW"
        self.assertEqual(self.inspect()["reason"], "MACHINE_ENROLLMENT_STATE_INVALID")
        entry["enrollment_state"] = []
        self.assertEqual(self.inspect()["reason"], "MACHINE_ENROLLMENT_STATE_INVALID")
        entry["enrollment_state"] = "PLANNED"
        entry["proposed_roles"] = [{"authority": "KX108"}]
        self.assertEqual(self.inspect()["reason"], "MACHINE_ROLE_CANNOT_GRANT_KX108_AUTHORITY")

    def test_responsible_refs_are_not_permissions(self):
        entry = self.manifest["machine_identities"][0]
        entry["responsible_refs"] = ["person:etienne", "person:reviewer"]
        result = self.inspect()
        self.assertEqual(result["status"], "MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED")
        self.assertFalse(result["human_approval_verified"])
        entry["responsible_refs"] = ["person:etienne", "person:etienne"]
        self.assertEqual(self.inspect()["reason"], "MACHINE_RESPONSIBLE_REFS_INVALID")

    def test_revocation_requires_reference_and_never_restores_authority(self):
        self.enroll_fake_public_only(0, b"not-a-certificate" * 32)
        entry = self.manifest["machine_identities"][0]
        entry["enrollment_state"] = "REVOKED"
        self.assertEqual(self.inspect()["reason"], "MACHINE_REVOCATION_EVIDENCE_REQUIRED")
        entry["revocation_ref"] = "revocation:001"
        result = self.inspect()
        self.assertEqual(result["status"], "MACHINE_REGISTRY_STRUCTURE_VALID_NOT_TRUSTED")
        self.assertEqual(result["revoked_count"], 1)
        self.assertFalse(result["machine_signature_verified"])

    def test_public_runtime_and_execution_gate_unchanged(self):
        caps = self.runtime.capabilities()
        self.assertEqual(caps["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertIn("obsidure_machine_identity", caps)
        self.assertEqual(self.runtime.execute(operation_type="ENROLL_AND_APPLY")["status"], "HOLD")
        self.assertEqual(self.inspect()["decision_authority"], "KX108_ONLY")

    def test_check_only_windows_script_does_not_enroll_implicitly(self):
        script = (ROOT / "tools" / "enroll_obsidure_machine_identity_windows_v1.ps1").read_text(encoding="utf-8")
        self.assertIn("param([switch]$Enroll)", script)
        self.assertIn("if (-not $Enroll)", script)
        self.assertIn("return", script)
        self.assertIn("New-SelfSignedCertificate @params", script)
        self.assertIn("KeyExportPolicy = 'NonExportable'", script)
        self.assertIn("EXPLICIT_ENROLL", script)


if __name__ == "__main__":
    unittest.main()
