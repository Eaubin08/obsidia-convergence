"""G4D : POST HMAC canonique et reçus C2 synthétiques, sans APPLY réel."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import test_kx108_g4b_c2_receipts_stdlib_v1 as _G4B
import kx108_c2_signed_post_readonly_v1 as _G4D
from scripts import obsidia_kx108_decision_store as DS
from scripts import obsidia_sealed_evidence_v0 as SEV
from obsidia_governance_runtime_v1 import get_runtime


class G4DSignedPostC2ReadOnly(unittest.TestCase):
    def setUp(self):
        self.base_case = _G4B.G4BCanonicalSealedReceiptInspection(
            "test_canonical_receipts_match_structurally_but_release_holds"
        )
        self.base_case.setUp()
        self.addCleanup(self.base_case.doCleanups)
        self.f = self.base_case.fixture

    def _sign_post(self, producer="run_and_persist_kx108_post_execution_decision"):
        # Clé de test en mémoire uniquement, utilisée par la fixture G4.
        DS._authenticate_decision_record(self.f.post, producer)
        self.f._save_records()

    def _inspect(self, **changes):
        arguments = {
            "pre_record_id": self.f.pre["decision_record_id"],
            "post_record_id": self.f.post["decision_record_id"],
            "pre_store_dir": self.f.pre_dir,
            "post_store_dir": self.f.post_dir,
            "sealed_receipt_dir": self.base_case.sar_dir,
            "sealed_rollback_dir": self.base_case.sre_dir,
            "expected_anchors": self.f.anchors,
            "expected_target_path": self.base_case.target_path,
            "expected_pre_sha256": self.base_case.pre_sha,
            "expected_post_sha256": self.base_case.post_sha,
        }
        arguments.update(changes)
        return get_runtime().inspect_kx108_c2_signed_post_receipts(**arguments)

    def test_signed_post_plus_canonical_receipts_remains_hold(self):
        self._sign_post()
        before = {p.relative_to(self.f.base): p.read_bytes()
                  for p in self.f.base.rglob("*.json")}
        result = self._inspect()
        after = {p.relative_to(self.f.base): p.read_bytes()
                 for p in self.f.base.rglob("*.json")}
        self.assertEqual(before, after)
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(result["post_hmac_verified"])
        self.assertTrue(result["post_producer_claim_hmac_bound"])
        self.assertTrue(result["c2_receipts_structurally_verified"])
        for field in (
            "post_producer_process_attested", "receipt_producer_authenticated",
            "real_apply_attested", "target_state_live_verified",
            "human_approval_verified", "global_write_closure_verified",
            "execution_authorized", "release_authorized", "target_mutated",
        ):
            self.assertFalse(result[field], field)
        self.assertEqual(result["decision_authority"], "KX108_ONLY")

    def test_old_unsigned_post_stays_hold_even_if_receipts_match(self):
        # G4B continuera à constater la correspondance structurelle ;
        # G4D exige l'authentification cryptographique complémentaire.
        self.assertTrue(self.base_case._inspect()["c2_receipts_structurally_verified"])
        result = self._inspect()
        self.assertEqual(result["status"], "HOLD")
        self.assertIn("DECISION_RECORD_NOT_AUTHENTICATED", result["reason"])
        self.assertFalse(result["c2_receipts_structurally_verified"])

    def test_post_rehashed_to_allow_fails_hmac(self):
        self._sign_post()
        self.f.post["x108_gate"] = "ALLOW"
        self.f.post["canonical_envelope"]["x108_gate"] = "ALLOW"
        self.f.post["decision_record_hash"] = DS.compute_kx108_decision_record_hash(self.f.post)
        self.f._save_records()
        self.assertTrue(DS.verify_kx108_decision_record(self.f.post)[0])
        result = self._inspect()
        self.assertEqual(result["status"], "HOLD")
        self.assertIn("DECISION_RECORD_AUTHENTICATOR_INVALID", result["reason"])

    def test_post_hmac_tampering_fails(self):
        self._sign_post()
        self.f.post["decision_record_authenticator"] = "0" * 64
        self.f._save_records()
        self.assertIn("G4D_POST_HMAC_INVALID", self._inspect()["reason"])

    def test_missing_kernel_key_fails_closed(self):
        self._sign_post()
        with patch.object(DS, "_kernel_key", side_effect=RuntimeError("test key unavailable")):
            result = self._inspect()
        self.assertIn("DECISION_RECORD_KERNEL_KEY_UNAVAILABLE", result["reason"])

    def test_wrong_signed_producer_claim_not_accepted_as_post(self):
        self._sign_post(producer="run_and_persist_kx108_decision")
        self.assertTrue(DS.verify_kx108_decision_record_authenticity(self.f.post)[0])
        self.assertEqual(self._inspect()["reason"], "G4D_POST_PRODUCER_NOT_CANONICAL")

    def test_receipt_rehash_does_not_bypass_post_binding(self):
        self._sign_post()
        self.base_case.sar["bytes_written"] = 999
        self.base_case.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(
            self.base_case.sar
        )
        self.base_case._save_receipts()
        result = self._inspect()
        self.assertTrue(result["post_hmac_verified"])
        self.assertFalse(result["c2_receipts_structurally_verified"])
        self.assertIn("G4B_POST_C2_EXACT_HASH_MISMATCH", result["reason"])

    def test_rebound_receipt_with_test_key_is_not_real_write_attestation(self):
        self.base_case.sar["bytes_written"] = 999
        self.base_case.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(
            self.base_case.sar
        )
        self.base_case._rebind_post_hashes()
        self.base_case._save_receipts()
        self._sign_post()
        result = self._inspect()
        self.assertTrue(result["post_hmac_verified"])
        self.assertTrue(result["c2_receipts_structurally_verified"])
        self.assertFalse(result["real_apply_attested"])
        self.assertFalse(result["receipt_producer_authenticated"])

    def test_pre_hmac_tampering_stops_chain(self):
        self._sign_post()
        self.f.pre["decision_record_authenticator"] = "0" * 64
        self.f._save_records()
        result = self._inspect()
        self.assertTrue(result["post_hmac_verified"])
        self.assertFalse(result["c2_receipts_structurally_verified"])
        self.assertIn("G4_PRE_AUTH_INVALID", result["reason"])

    def test_caller_anchor_mismatch_fails(self):
        self._sign_post()
        changed = dict(self.f.anchors, approval_id="forged")
        self.assertIn("G4_ANCHOR_MISMATCH", self._inspect(expected_anchors=changed)["reason"])

    def test_post_swap_during_inspection_fails(self):
        self._sign_post()
        second = copy.deepcopy(self.f.post)
        second["decision_record_hash"] = "0" * 64
        with patch.object(_G4D._DS, "load_kx108_decision_record", side_effect=[self.f.post, second]), \
             patch.object(_G4D, "inspect_c2_actual_receipts", return_value={
                 "c2_receipts_structurally_verified": True,
             }):
            result = self._inspect()
        self.assertEqual(result["reason"], "G4D_POST_CHANGED_DURING_INSPECTION")

    def test_store_paths_mandatory_and_no_default_store_fallback(self):
        self._sign_post()
        with patch.object(_G4D._DS, "load_kx108_decision_record", side_effect=AssertionError("UNBOUNDED_READ")) as load:
            result = self._inspect(post_store_dir=None)
        self.assertEqual(result["reason"], "G4D_CANONICAL_IDS_OR_STORES_REQUIRED")
        load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
