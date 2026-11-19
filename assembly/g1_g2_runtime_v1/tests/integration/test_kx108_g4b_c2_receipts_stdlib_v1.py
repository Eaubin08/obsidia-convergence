"""G4B : vrais builders et validateurs C2 dans un répertoire jetable uniquement."""
from __future__ import annotations

import hashlib
import json
import unittest

import test_kx108_g4_pre_post_closure_stdlib_v1 as _G4_TEST_FIXTURE
from scripts import obsidia_sealed_evidence_v0 as SEV
from obsidia_governance_runtime_v1 import get_runtime


class G4BCanonicalSealedReceiptInspection(unittest.TestCase):
    def setUp(self):
        self.fixture = _G4_TEST_FIXTURE.Kx108G4ReadOnlyClosure(
            "test_valid_synthetic_chain_is_still_hold"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.sar_dir = f.base / "sealed-apply"
        self.sre_dir = f.base / "sealed-rollback"
        self.sar_dir.mkdir()
        self.sre_dir.mkdir()
        self.preimage = b"synthetic old content\n"
        self.afterimage = b"synthetic new content\n"
        self.pre_sha = hashlib.sha256(self.preimage).hexdigest()
        self.post_sha = hashlib.sha256(self.afterimage).hexdigest()
        self.target_path = "targets/test-only.txt"
        self.child = {
            "child_execution_id": f.anchors["child_execution_id"],
            "target_path": self.target_path,
            "target_pre_sha256": self.pre_sha,
            "source_content_sha256": self.post_sha,
            "operation_type": "UPDATE_TARGET_FROM_SOURCE",
            "source_kind": "SOURCE_CONTENT_TEST_ONLY",
            "source_path": "test-only/source.txt",
            "source_git_commit_sha": None,
            "source_git_blob_sha": None,
            "source_git_historical_path": None,
        }
        self.sre, reason = SEV.build_sealed_rollback_evidence(
            batch_execution_id=f.anchors["batch_execution_id"], child=self.child,
            execution_authority_hash=f.anchors["execution_authority_hash"],
            approval_id=f.anchors["approval_id"],
            kx108_pre_decision_record_id=f.pre["decision_record_id"],
            kx108_pre_decision_record_hash=f.pre["decision_record_hash"],
            preimage_bytes=self.preimage,
        )
        self.assertIsNone(reason)
        self.sar, reason = SEV.build_sealed_apply_receipt(
            batch_execution_id=f.anchors["batch_execution_id"], child=self.child,
            execution_authority_hash=f.anchors["execution_authority_hash"],
            approval_id=f.anchors["approval_id"],
            kx108_pre_decision_record_id=f.pre["decision_record_id"],
            kx108_pre_decision_record_hash=f.pre["decision_record_hash"],
            sealed_rollback_evidence_id=self.sre["sealed_rollback_evidence_id"],
            sealed_rollback_evidence_hash=self.sre["sealed_rollback_evidence_hash"],
            target_pre_sha256=self.pre_sha,
            target_post_sha256=self.post_sha,
            bytes_written=len(self.afterimage),
        )
        self.assertIsNone(reason)
        f.post.update({
            "sealed_apply_receipt_id": self.sar["sealed_apply_receipt_id"],
            "sealed_apply_receipt_hash": self.sar["sealed_apply_receipt_hash"],
            "sealed_rollback_evidence_id": self.sre["sealed_rollback_evidence_id"],
            "sealed_rollback_evidence_hash": self.sre["sealed_rollback_evidence_hash"],
        })
        f._seal_post()
        f._save_records()
        self._save_receipts()

    def _save_receipts(self):
        (self.sar_dir / f"{self.sar['sealed_apply_receipt_id']}.json").write_text(
            json.dumps(self.sar), encoding="utf-8"
        )
        (self.sre_dir / f"{self.sre['sealed_rollback_evidence_id']}.json").write_text(
            json.dumps(self.sre), encoding="utf-8"
        )

    def _rebind_post_hashes(self):
        f = self.fixture
        f.post["sealed_apply_receipt_hash"] = self.sar["sealed_apply_receipt_hash"]
        f.post["sealed_rollback_evidence_hash"] = self.sre["sealed_rollback_evidence_hash"]
        f._seal_post()
        f._save_records()

    def _inspect(self, **changes):
        f = self.fixture
        params = dict(
            pre_record_id=f.pre["decision_record_id"],
            post_record_id=f.post["decision_record_id"],
            pre_store_dir=f.pre_dir, post_store_dir=f.post_dir,
            sealed_receipt_dir=self.sar_dir,
            sealed_rollback_dir=self.sre_dir,
            expected_anchors=f.anchors,
            expected_target_path=self.target_path,
            expected_pre_sha256=self.pre_sha,
            expected_post_sha256=self.post_sha,
        )
        params.update(changes)
        return get_runtime().inspect_kx108_c2_actual_receipts(**params)

    def test_canonical_receipts_match_structurally_but_release_holds(self):
        filenames_before = sorted(p.name for p in self.fixture.base.rglob("*.json"))
        result = self._inspect()
        self.assertEqual(sorted(p.name for p in self.fixture.base.rglob("*.json")), filenames_before)
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(result["c2_receipts_structurally_verified"])
        self.assertTrue(result["pre_hmac_verified"])
        self.assertTrue(result["preimage_bytes_hash_verified"])
        for field in (
            "receipt_producer_authenticated", "post_producer_authenticated",
            "actual_write_attested", "target_state_live_verified",
            "human_approval_verified", "global_write_closure_verified",
            "execution_authorized", "release_authorized", "target_mutated",
        ):
            self.assertFalse(result[field], field)

    def test_kernel_key_missing_blocks_receipt_inspection(self):
        from unittest.mock import patch
        from scripts import obsidia_kx108_decision_store as DS
        with patch.object(DS, "_kernel_key", side_effect=RuntimeError("no key")):
            self.assertIn("G4B_PRE_POST_CHAIN_HOLD", self._inspect()["reason"])

    def test_missing_apply_receipt_holds(self):
        (self.sar_dir / f"{self.sar['sealed_apply_receipt_id']}.json").unlink()
        self.assertIn("APPLY_RECEIPT_INVALID", self._inspect()["reason"])

    def test_missing_rollback_evidence_holds(self):
        (self.sre_dir / f"{self.sre['sealed_rollback_evidence_id']}.json").unlink()
        self.assertIn("ROLLBACK_EVIDENCE_INVALID", self._inspect()["reason"])

    def test_tampered_apply_bytes_holds(self):
        self.sar["source_content_sha256"] = "1" * 64
        self._save_receipts()
        self.assertIn("APPLY_RECEIPT_INVALID", self._inspect()["reason"])

    def test_tampered_rollback_preimage_holds(self):
        self.sre["pre_write_bytes_b64"] = "AQID"
        self._save_receipts()
        self.assertIn("ROLLBACK_EVIDENCE_INVALID", self._inspect()["reason"])

    def test_self_consistent_receipt_rehash_still_cannot_authorize(self):
        self.sar["bytes_written"] = 6000
        self.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(self.sar)
        self._rebind_post_hashes()
        self._save_receipts()
        result = self._inspect()
        self.assertTrue(result["c2_receipts_structurally_verified"])
        self.assertFalse(result["receipt_producer_authenticated"])
        self.assertFalse(result["actual_write_attested"])

    def test_apply_rollback_crosslink_mismatch_holds(self):
        self.sar["sealed_rollback_evidence_hash"] = "5" * 64
        self.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(self.sar)
        self._rebind_post_hashes()
        self._save_receipts()
        self.assertEqual(self._inspect()["reason"], "G4B_APPLY_ROLLBACK_CROSS_LINK_MISMATCH")

    def test_post_to_receipt_hash_mismatch_holds(self):
        self.sar["bytes_written"] = 999
        self.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(self.sar)
        self._save_receipts()
        self.assertEqual(self._inspect()["reason"], "G4B_POST_C2_EXACT_HASH_MISMATCH")

    def test_pre_receipt_binding_mismatch_holds(self):
        self.sre["kx108_pre_decision_record_hash"] = "6" * 64
        self.sre["sealed_rollback_evidence_hash"] = SEV.compute_sealed_rollback_evidence_hash(self.sre)
        self.sar["sealed_rollback_evidence_hash"] = self.sre["sealed_rollback_evidence_hash"]
        self.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(self.sar)
        self._rebind_post_hashes()
        self._save_receipts()
        self.assertEqual(self._inspect()["reason"], "G4B_RECEIPT_PRE_BINDING_MISMATCH")

    def test_source_provenance_drift_holds(self):
        self.sre["source_kind"] = "SYNTHETIC_DRIFT"
        self.sre["sealed_rollback_evidence_hash"] = SEV.compute_sealed_rollback_evidence_hash(self.sre)
        self.sar["sealed_rollback_evidence_hash"] = self.sre["sealed_rollback_evidence_hash"]
        self.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(self.sar)
        self._rebind_post_hashes()
        self._save_receipts()
        self.assertEqual(self._inspect()["reason"], "G4B_SOURCE_PROVENANCE_MISMATCH")

    def test_target_path_mismatch_holds(self):
        self.assertEqual(self._inspect(expected_target_path="other/path.txt")["reason"], "G4B_TARGET_PATH_MISMATCH")

    def test_expected_pre_sha_mismatch_holds(self):
        self.assertEqual(self._inspect(expected_pre_sha256="0" * 64)["reason"], "G4B_TARGET_PRE_POST_SHA_MISMATCH")

    def test_expected_post_sha_mismatch_holds(self):
        self.assertEqual(self._inspect(expected_post_sha256="0" * 64)["reason"], "G4B_SOURCE_SHA_MISMATCH")

    def test_noncanonical_target_operation_holds(self):
        self.sar["operation_type"] = "CREATE_TARGET_FROM_SOURCE"
        self.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(self.sar)
        self._rebind_post_hashes()
        self._save_receipts()
        self.assertIn("APPLY_RECEIPT_INVALID", self._inspect()["reason"])

    def test_invalid_bytes_written_type_holds(self):
        self.sar["bytes_written"] = True
        self.sar["sealed_apply_receipt_hash"] = SEV.compute_sealed_apply_receipt_hash(self.sar)
        self._rebind_post_hashes()
        self._save_receipts()
        self.assertEqual(self._inspect()["reason"], "G4B_BYTES_WRITTEN_INVALID")

    def test_post_downgrade_without_sealed_link_holds(self):
        del self.fixture.post["sealed_apply_receipt_id"]
        self.fixture._seal_post()
        self.fixture._save_records()
        self.assertIn("G4B_PRE_POST_CHAIN_HOLD", self._inspect()["reason"])


if __name__ == "__main__":
    unittest.main()
