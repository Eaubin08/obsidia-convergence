"""G4F : observation sans mutation de crash windows C2 synthétiques."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_kx108_g4_pre_post_closure_stdlib_v1 as _G4
from obsidia_governance_runtime_v1 import get_runtime
from scripts import obsidia_kx108_decision_store as DS
from scripts import obsidia_sealed_evidence_v0 as SEV


class G4FCrashWindowReadOnly(unittest.TestCase):
    def setUp(self):
        self.g4 = _G4.Kx108G4ReadOnlyClosure("test_valid_synthetic_chain_is_still_hold")
        self.g4.setUp()
        self.addCleanup(self.g4.doCleanups)
        self.temp = tempfile.TemporaryDirectory(prefix="obsidia-g4f-crash-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "targets").mkdir()
        self.target = self.root / "targets" / "item.txt"
        self.before = b"original C2 synthetic bytes"
        self.after = b"proposed C2 synthetic bytes"
        self.target.write_bytes(self.before)
        self.sealed_dir = self.root / "sealed"
        child = {
            "child_execution_id": self.g4.anchors["child_execution_id"],
            "target_path": "targets/item.txt",
            "target_pre_sha256": SEV._sha256_hex(self.before),
            "source_content_sha256": SEV._sha256_hex(self.after),
            "source_kind": "SYNTHETIC_TEST_ONLY",
            "source_path": "not-used-by-inspector",
            "operation_type": SEV.OPERATION_TYPE,
        }
        pre = self.g4.pre
        self.sre, reason = SEV.build_sealed_rollback_evidence(
            batch_execution_id=pre["batch_execution_id"], child=child,
            execution_authority_hash=pre["execution_authority_hash"],
            approval_id=pre["approval_id"],
            kx108_pre_decision_record_id=pre["decision_record_id"],
            kx108_pre_decision_record_hash=pre["decision_record_hash"],
            preimage_bytes=self.before,
        )
        self.assertIsNone(reason)
        stored = SEV.store_sealed_rollback_evidence(self.sre, self.sealed_dir)
        self.assertEqual(stored["status"], SEV.STATUS_STORED)

    def _save_sre(self):
        filename = self.sealed_dir / (self.sre["sealed_rollback_evidence_id"] + ".json")
        filename.write_text(json.dumps(self.sre), encoding="utf-8")

    def _inspect(self, **overrides):
        args = {
            "pre_record_id": self.g4.pre["decision_record_id"],
            "sealed_rollback_evidence_id": self.sre["sealed_rollback_evidence_id"],
            "pre_store_dir": self.g4.pre_dir,
            "sealed_rollback_dir": self.sealed_dir,
            "repo_root": self.root,
        }
        args.update(overrides)
        return get_runtime().inspect_kx108_c2_crash_window(**args)

    def _assert_holding(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertTrue(result["readonly"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_restore_permitted"])
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["target_mutated_by_inspector"])
        self.assertFalse(result["crash_occurrence_attested"])

    def test_preimage_observed_is_not_crash_clearance(self):
        result = self._inspect()
        self._assert_holding(result)
        self.assertEqual(result["current_state"], "PREIMAGE_OBSERVED")
        self.assertFalse(result["quarantine_recommended"])
        self.assertTrue(result["recovery_review_required"])
        self.assertTrue(result["pre_hmac_verified"])
        self.assertTrue(result["preimage_structure_verified"])

    def test_source_image_observed_is_quarantined_not_approved(self):
        self.target.write_bytes(self.after)
        result = self._inspect()
        self._assert_holding(result)
        self.assertEqual(result["current_state"], "SOURCE_IMAGE_OBSERVED")
        self.assertTrue(result["quarantine_recommended"])
        self.assertFalse(result["target_state_live_attested"])

    def test_unknown_disk_bytes_require_review(self):
        self.target.write_bytes(b"third state")
        result = self._inspect()
        self._assert_holding(result)
        self.assertEqual(result["current_state"], "UNKNOWN_CONTENT")
        self.assertTrue(result["quarantine_recommended"])

    def test_missing_target_remains_unknown(self):
        self.target.unlink()
        result = self._inspect()
        self._assert_holding(result)
        self.assertEqual(result["current_state"], "UNKNOWN_CONTENT")

    def test_forged_pre_hash_cannot_repair_hmac(self):
        pre = dict(self.g4.pre)
        pre["approval_id"] = "forged"
        pre["decision_record_hash"] = DS.compute_kx108_decision_record_hash(pre)
        (self.g4.pre_dir / "pre-synthetic.json").write_text(json.dumps(pre), encoding="utf-8")
        result = self._inspect()
        self._assert_holding(result)
        self.assertIn("PRE_HMAC_INVALID", result["reason"])

    def test_missing_kernel_key_fails_closed(self):
        with patch.object(DS, "_kernel_key", side_effect=RuntimeError("no key")):
            result = self._inspect()
        self._assert_holding(result)
        self.assertIn("PRE_HMAC_INVALID", result["reason"])

    def test_corrupted_sealed_preimage_rejected(self):
        self.sre["pre_write_bytes_b64"] = "AAAA"
        self._save_sre()
        result = self._inspect()
        self._assert_holding(result)
        self.assertIn("PREIMAGE_STRUCTURAL_INVALID", result["reason"])

    def test_structurally_rehashed_forgery_fails_identity_or_binding(self):
        self.sre["approval_id"] = "synthetic-forgery"
        self.sre["sealed_rollback_evidence_hash"] = SEV.compute_sealed_rollback_evidence_hash(self.sre)
        self._save_sre()
        result = self._inspect()
        self._assert_holding(result)
        self.assertIn("PREIMAGE_IDENTITY_INVALID", result["reason"])

    def test_sre_other_pre_binding_rejected(self):
        self.sre["kx108_pre_decision_record_hash"] = "f" * 64
        self.sre["sealed_rollback_evidence_id"] = SEV._sre_identity(self.sre)
        self.sre["sealed_rollback_evidence_hash"] = SEV.compute_sealed_rollback_evidence_hash(self.sre)
        self._save_sre()
        result = self._inspect()
        self._assert_holding(result)
        self.assertIn("PREIMAGE_PRE_BINDING_MISMATCH", result["reason"])

    def test_traversal_target_rejected_even_when_structurally_sealed(self):
        self.sre["target_path"] = "../outside.txt"
        self.sre["sealed_rollback_evidence_id"] = SEV._sre_identity(self.sre)
        self.sre["sealed_rollback_evidence_hash"] = SEV.compute_sealed_rollback_evidence_hash(self.sre)
        self._save_sre()
        result = self._inspect()
        self._assert_holding(result)
        self.assertIn("TARGET_PATH_NONCANONICAL", result["reason"])

    def test_symlink_target_never_read(self):
        linked = self.root / "targets" / "link.txt"
        try:
            linked.symlink_to(self.target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink indisponible sous Windows: {exc}")
        self.sre["target_path"] = "targets/link.txt"
        self.sre["sealed_rollback_evidence_id"] = SEV._sre_identity(self.sre)
        self.sre["sealed_rollback_evidence_hash"] = SEV.compute_sealed_rollback_evidence_hash(self.sre)
        self._save_sre()
        result = self._inspect()
        self._assert_holding(result)
        self.assertIn("TARGET_REPARSE_UNSAFE", result["reason"])

    def test_missing_or_invalid_ids_hold(self):
        for overrides in (
            {"pre_record_id": "../outside"},
            {"sealed_rollback_evidence_id": "../../outside"},
            {"pre_store_dir": "not-a-path"},
        ):
            result = self._inspect(**overrides)
            self._assert_holding(result)

    def test_inspection_does_not_write_any_source_or_record(self):
        watched = [self.target, self.g4.pre_dir / "pre-synthetic.json",
                   self.sealed_dir / (self.sre["sealed_rollback_evidence_id"] + ".json")]
        before = [p.read_bytes() for p in watched]
        result = self._inspect()
        self._assert_holding(result)
        self.assertEqual([p.read_bytes() for p in watched], before)


if __name__ == "__main__":
    unittest.main()
