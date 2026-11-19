"""G4N — fondateur seul au démarrage, équipe seulement préparée.

Les clés synthétiques ne représentent aucun administrateur réel enrôlé.
"""
from __future__ import annotations

import base64
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from obsidia_governance_runtime_v1 import get_runtime
from obsidure_admin_bootstrap_g4n_v1 import canonical, digest, DOMAIN
from verify_g4n_admin_modes_v1 import build_fixture, main as verify_main

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:
    hashes = None


@unittest.skipUnless(hashes is not None, "optional cryptography unavailable")
class FounderAndTeamBootstrapG4N(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = build_fixture(members=2)

    def setUp(self):
        self.plan, self.registry, self.activation = copy.deepcopy(self.source)
        self.runtime = get_runtime()

    def check(self, *, activation=False):
        return self.runtime.inspect_obsidure_admin_bootstrap(
            plan=self.plan, machine_registry=self.registry,
            activation_receipt=self.activation if activation else None)

    def assert_no_authority(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertTrue(result["readonly"])
        for key in (
            "founder_independently_enrolled", "founder_trust_anchor_verified",
            "founder_human_identity_authenticated", "team_mode_activated",
            "team_members_approved", "machine_enrollment_approved",
            "responsible_person_authenticated", "human_approval_verified",
            "replay_prevented", "kx108_ticket_issued", "execution_authorized",
            "release_authorized", "target_mutated",
        ):
            self.assertIs(result[key], False, key)

    def test_repository_plan_starts_founder_only_without_keys(self):
        initial = json.loads((ROOT / "OBSIDURE_ADMIN_BOOTSTRAP_PLAN_G4N_V1.json").read_text(encoding="utf-8"))
        result = self.runtime.inspect_obsidure_admin_bootstrap(
            plan=initial, machine_registry=self.registry)
        self.assert_no_authority(result)
        self.assertEqual(result["reason"], "G4N_FOUNDER_ONLY_TEAM_STAGED_NOT_ACTIVE")
        self.assertTrue(result["founder_only_plan_valid"])
        self.assertEqual(result["proposed_team_count"], 0)

    def test_two_proposed_reviewers_no_approval(self):
        result = self.check()
        self.assert_no_authority(result)
        self.assertTrue(result["team_plan_prepared"])
        self.assertEqual(result["proposed_team_count"], 2)

    def test_founder_signed_team_switch_remains_untrusted(self):
        result = self.check(activation=True)
        self.assert_no_authority(result)
        self.assertTrue(result["founder_activation_proposal_signature_verified"])
        self.assertTrue(result["founder_key_separate_from_pc"])
        self.assertEqual(result["reason"],
                         "G4N_FOUNDER_SIGNED_TEAM_SWITCH_PROPOSAL_NOT_TRUSTED_OR_ACTIVE")

    def test_tampered_team_roster_denied(self):
        self.plan["team"]["administrators"][0]["admin_id"] = "REVIEWER-CHANGED"
        result = self.check(activation=True)
        self.assert_no_authority(result)
        self.assertFalse(result["founder_activation_proposal_signature_verified"])
        self.assertEqual(result["reason"], "G4N_ACTIVATION_PAYLOAD_NOT_BOUND_TO_PLAN")

    def test_changed_nonce_signature_denied(self):
        self.activation["payload"]["nonce"] = "1" * 64
        result = self.check(activation=True)
        self.assert_no_authority(result)
        self.assertEqual(result["reason"], "G4N_FOUNDER_ACTIVATION_SIGNATURE_INVALID")

    def test_changed_signature_denied(self):
        self.activation["signature_base64"] = base64.b64encode(b"signature-forged").decode("ascii")
        result = self.check(activation=True)
        self.assert_no_authority(result)
        self.assertEqual(result["reason"], "G4N_FOUNDER_ACTIVATION_SIGNATURE_INVALID")

    def test_team_cannot_self_activate(self):
        self.plan["team"]["state"] = "ACTIVE"
        result = self.check()
        self.assert_no_authority(result)
        self.assertEqual(result["reason"], "G4N_TEAM_MUST_REMAIN_PREPARED")

    def test_team_admin_cannot_self_approve(self):
        self.plan["team"]["administrators"][0]["enrollment_state"] = "APPROVED"
        self.assertEqual(self.check()["reason"], "G4N_TEAM_ADMIN_CANNOT_SELF_APPROVE")

    def test_admin_cannot_impersonate_kx108(self):
        self.plan["team"]["administrators"][0]["admin_id"] = "KX108-SOVEREIGN"
        self.assertEqual(self.check()["reason"], "G4N_TEAM_ADMIN_ID_INVALID_OR_DUPLICATE")
        self.plan["team"]["administrators"][0]["admin_id"] = "REVIEWER-1"
        self.plan["admin_scope"] = "KX108_SOVEREIGN"
        self.assertEqual(self.check()["reason"], "G4N_PLAN_FIELDS_OR_AUTHORITY_INVALID")

    def test_duplicate_admin_identity_denied(self):
        self.plan["team"]["administrators"][1]["admin_id"] = "REVIEWER-1"
        self.assertEqual(self.check()["reason"], "G4N_TEAM_ADMIN_ID_INVALID_OR_DUPLICATE")

    def test_same_key_across_team_members_denied(self):
        self.plan["team"]["administrators"][1]["public_certificate_sha256"] = (
            self.plan["team"]["administrators"][0]["public_certificate_sha256"])
        self.assertEqual(self.check()["reason"], "G4N_ADMIN_KEY_CROSS_ROLE_OR_PC_REUSE")

    def test_founder_key_reused_from_machine_denied(self):
        machine = self.registry["machine_identities"][0]
        machine["enrollment_state"] = "ENROLLED_AWAITING_REVIEW"
        machine["public_certificate_der_base64"] = self.plan["founder"]["public_certificate_der_base64"]
        machine["public_certificate_sha256"] = self.plan["founder"]["public_certificate_sha256"]
        self.assertEqual(self.check()["reason"], "G4N_FOUNDER_KEY_MUST_BE_DISTINCT_FROM_PC")

    def test_founder_pin_mismatch_denied(self):
        self.plan["founder"]["public_certificate_sha256"] = "f" * 64
        self.assertEqual(self.check()["reason"], "G4N_FOUNDER_CERTIFICATE_PIN_MISMATCH")

    def test_unsigned_activation_is_not_approval(self):
        self.activation["signature_base64"] = ""
        self.assertEqual(self.check(activation=True)["reason"], "G4N_ACTIVATION_SIGNATURE_INVALID")

    def test_activation_cannot_bind_unpinned_member(self):
        member = self.plan["team"]["administrators"][0]
        member["enrollment_state"] = "PLANNED"
        member["public_certificate_sha256"] = None
        self.assertEqual(self.check(activation=True)["reason"],
                         "G4N_ACTIVATION_PROPOSAL_REQUIRES_SEPARATE_KEYS")

    def test_no_team_activation_with_empty_roster(self):
        self.plan["team"]["administrators"] = []
        self.assertEqual(self.check(activation=True)["reason"],
                         "G4N_ACTIVATION_PROPOSAL_REQUIRES_SEPARATE_KEYS")

    def test_fake_admin_approved_flag_rejected(self):
        self.plan["founder"]["approved"] = True
        self.assertEqual(self.check()["reason"], "G4N_FOUNDER_PROPOSAL_INVALID")

    def test_activation_unknown_field_rejected(self):
        self.activation["payload"]["approved"] = True
        self.assertEqual(self.check(activation=True)["reason"],
                         "G4N_ACTIVATION_PAYLOAD_NOT_BOUND_TO_PLAN")

    def test_unhashable_enrollment_state_fails_closed(self):
        self.plan["founder"]["enrollment_state"] = []
        self.assertEqual(self.check()["reason"], "G4N_FOUNDER_PROPOSAL_INVALID")
        self.plan["founder"]["enrollment_state"] = "KEY_PROPOSED_AWAITING_INDEPENDENT_REVIEW"
        self.plan["team"]["administrators"][0]["enrollment_state"] = []
        self.assertEqual(self.check()["reason"], "G4N_TEAM_ADMIN_CANNOT_SELF_APPROVE")

    def test_not_trusted_before_real_founder_certificate(self):
        initial = json.loads((ROOT / "OBSIDURE_ADMIN_BOOTSTRAP_PLAN_G4N_V1.json").read_text(encoding="utf-8"))
        initial["team"] = copy.deepcopy(self.plan["team"])
        result = self.runtime.inspect_obsidure_admin_bootstrap(
            plan=initial, machine_registry=self.registry,
            activation_receipt=self.activation)
        self.assert_no_authority(result)
        self.assertFalse(result["founder_activation_proposal_signature_verified"])

    def test_verifier_synthetic_one_pass(self):
        from contextlib import redirect_stdout
        from io import StringIO
        out = StringIO()
        with redirect_stdout(out):
            code = verify_main()
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("TEAM_MODE_ACTIVATED=False", out.getvalue())

    def test_runtime_never_exposes_admin_activation_api(self):
        self.assertFalse(hasattr(self.runtime, "approve_machine_enrollment"))
        self.assertFalse(hasattr(self.runtime, "activate_team_mode"))
        self.assertFalse(hasattr(self.runtime, "sign_founder_team_activation"))
        self.assertEqual(self.runtime.capabilities()["apply"], "HOLD")
        self.assertIn("FOUNDER_ONLY_TEAM_PREPARED", self.runtime.capabilities()["obsidure_admin_bootstrap"])


if __name__ == "__main__":
    unittest.main()
