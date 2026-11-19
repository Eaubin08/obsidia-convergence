"""G4I — lien WAL / octets observés sans signature, sans mutation métier."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import test_kx108_g4e_post_mutation_exception_stdlib_v1 as _G4E
import c2_write_intent_wal_v1 as WAL
from c2_wal_outcome_observer_v1 import (
    AMBIGUOUS, MISSING, POSTIMAGE, PREIMAGE, UNKNOWN,
    inspect_c2_wal_outcome_state, report_c2_wal_outcome_testonly,
)
from obsidia_governance_runtime_v1 import get_runtime


class G4IOutcomeObserver(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="obsidia-g4i-outcome-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "targets").mkdir()
        self.target = self.root / "targets" / "synthetic.txt"
        self.old = b"G4I-before\n"
        self.new = b"G4I-after\n"
        self.target.write_bytes(self.old)
        self.wal = self.root / "wal"
        self.intent = self._intent()
        self.assertEqual(WAL.store_intent(self.intent, self.wal)["status"], WAL.STORED)

    def _intent(self, *, target="targets/synthetic.txt", pre=None, post=None):
        return WAL.build_intent(
            batch_execution_id="batch-test-g4i", child_execution_id="child-test-g4i",
            execution_authority_hash="a" * 64, approval_id="approval-test-g4i",
            pre_decision_record_id="pre-test-g4i", pre_decision_record_hash="b" * 64,
            sealed_rollback_evidence_id="sre-test-g4i",
            sealed_rollback_evidence_hash="c" * 64,
            target_path=target,
            target_pre_sha256=pre or hashlib.sha256(self.old).hexdigest(),
            target_post_sha256=post or hashlib.sha256(self.new).hexdigest(),
        )

    def _inspect(self):
        return get_runtime().inspect_c2_wal_outcome_state(
            wal_dir=self.wal, intent_id=self.intent["intent_id"], repo_root=self.root)

    def _report(self, status):
        return report_c2_wal_outcome_testonly(
            wal_dir=self.wal, intent_id=self.intent["intent_id"],
            repo_root=self.root, reported_status=status)

    def _hold(self, record):
        self.assertEqual(record["status"], "HOLD")
        for field in ("producer_authenticated", "physical_mutation_attested",
                      "rollback_attested", "execution_authorized", "release_authorized",
                      "recovery_authorized", "target_mutated_by_observer"):
            self.assertFalse(record[field], field)

    def test_unresolved_preimage_is_only_observation(self):
        report = self._inspect()
        self._hold(report)
        self.assertEqual(report["current_state"], PREIMAGE)
        self.assertEqual(report["reason"], "UNRESOLVED_INTENT")
        self.assertFalse(self.wal.joinpath(self.intent["intent_id"] + ".outcome.json").exists())

    def test_report_rollback_preimage_never_attests_rollback(self):
        report = self._report("REPORTED_ROLLBACK")
        self._hold(report)
        self.assertTrue(report["wal_outcome_recorded"])
        self.assertEqual(report["reason"], "OUTCOME_REPORTED_NOT_ATTESTED")
        self.assertEqual(report["reported_status"], "REPORTED_ROLLBACK")
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_report_keep_postimage_never_authorizes_release(self):
        self.target.write_bytes(self.new)  # source synthétique, pas le writer
        report = self._report("REPORTED_KEEP")
        self._hold(report)
        self.assertTrue(report["wal_outcome_recorded"])
        self.assertEqual(report["current_state"], POSTIMAGE)
        self.assertEqual(report["reason"], "OUTCOME_REPORTED_NOT_ATTESTED")
        self.assertFalse(report["readonly"])  # émission de métadonnée WAL
        self.assertTrue(report["wal_metadata_written"])

    def test_keep_and_rollback_claims_cannot_contradict_live_bytes(self):
        self.assertEqual(self._report("REPORTED_KEEP")["reason"],
                         "G4I_REPORT_INCONSISTENT_WITH_OBSERVATION")
        self.target.write_bytes(self.new)
        self.assertEqual(self._report("REPORTED_ROLLBACK")["reason"],
                         "G4I_REPORT_INCONSISTENT_WITH_OBSERVATION")
        self.assertEqual(self._inspect()["reason"], "UNRESOLVED_INTENT")

    def test_unknown_content_only_quarantine_report(self):
        self.target.write_bytes(b"unknown-unexpected")
        self.assertEqual(self._inspect()["current_state"], UNKNOWN)
        self.assertEqual(self._report("REPORTED_KEEP")["reason"],
                         "G4I_REPORT_INCONSISTENT_WITH_OBSERVATION")
        result = self._report("REPORTED_QUARANTINE")
        self._hold(result)
        self.assertTrue(result["wal_outcome_recorded"])
        self.assertEqual(result["current_state"], UNKNOWN)

    def test_missing_target_only_quarantine_report(self):
        self.target.unlink()
        result = self._report("REPORTED_QUARANTINE")
        self._hold(result)
        self.assertTrue(result["wal_outcome_recorded"])
        self.assertEqual(result["current_state"], MISSING)
        self.assertIsNone(result["observed_sha256"])

    def test_equal_pre_post_is_ambiguous_not_keep_or_rollback(self):
        same = self._intent(post=hashlib.sha256(self.old).hexdigest())
        self.assertEqual(WAL.store_intent(same, self.wal)["status"], WAL.STORED)
        base = dict(wal_dir=self.wal, intent_id=same["intent_id"], repo_root=self.root)
        self.assertEqual(inspect_c2_wal_outcome_state(**base)["current_state"], AMBIGUOUS)
        for claim in ("REPORTED_KEEP", "REPORTED_ROLLBACK"):
            self.assertEqual(report_c2_wal_outcome_testonly(**base, reported_status=claim)["reason"],
                             "G4I_REPORT_INCONSISTENT_WITH_OBSERVATION")

    def test_immutable_outcome_replay_is_not_new_report(self):
        self.assertTrue(self._report("REPORTED_ROLLBACK")["wal_outcome_recorded"])
        second = self._report("REPORTED_ROLLBACK")
        self._hold(second)
        self.assertFalse(second["wal_outcome_recorded"])
        self.assertEqual(second["reason"],
                         "G4I_REPORT_REQUIRES_UNRESOLVED_VERIFIED_INTENT")

    def test_outcome_becomes_stale_if_target_changes_later(self):
        self.target.write_bytes(self.new)
        self.assertTrue(self._report("REPORTED_KEEP")["wal_outcome_recorded"])
        self.target.write_bytes(self.old)
        status = self._inspect()
        self._hold(status)
        self.assertEqual(status["reason"], "G4I_OUTCOME_VS_LIVE_MISMATCH")

    def test_corrupt_intent_never_passes_verification(self):
        intent_path = self.wal / (self.intent["intent_id"] + ".intent.json")
        tampered = json.loads(intent_path.read_text(encoding="utf-8"))
        tampered["target_path"] = "targets/evil.txt"
        intent_path.write_text(json.dumps(tampered), encoding="utf-8")
        result = self._inspect()
        self._hold(result)
        self.assertEqual(result["reason"], "G4I_INTENT_UNTRUSTED_OR_MISSING")

    def test_corrupt_outcome_never_passes_verification(self):
        self.assertTrue(self._report("REPORTED_ROLLBACK")["wal_outcome_recorded"])
        outcome_path = self.wal / (self.intent["intent_id"] + ".outcome.json")
        tampered = json.loads(outcome_path.read_text(encoding="utf-8"))
        tampered["reported_status"] = "REPORTED_KEEP"
        outcome_path.write_text(json.dumps(tampered), encoding="utf-8")
        result = self._inspect()
        self._hold(result)
        self.assertEqual(result["reason"], "G4I_WAL_UNTRUSTED_OR_UNAVAILABLE")

    def test_wal_store_error_never_becomes_success(self):
        from unittest.mock import patch
        with patch.object(WAL, "store_outcome", return_value={"status": WAL.STORE_UNAVAILABLE}):
            result = self._report("REPORTED_ROLLBACK")
        self._hold(result)
        self.assertFalse(result["wal_outcome_recorded"])
        self.assertEqual(result["reason"], "G4I_OUTCOME_STORE_NOT_NEW_OR_UNAVAILABLE")
        self.assertEqual(self._inspect()["reason"], "UNRESOLVED_INTENT")

    def test_target_symlink_and_non_absolute_root_are_refused(self):
        self.assertEqual(inspect_c2_wal_outcome_state(
            wal_dir=self.wal, intent_id=self.intent["intent_id"],
            repo_root=Path("relative"))["reason"], "G4I_ABSOLUTE_STORES_REQUIRED")
        self.target.unlink()
        other = self.root / "other.txt"
        other.write_bytes(self.old)
        try:
            self.target.symlink_to(other)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink unavailable on Windows: {exc}")
        status = self._inspect()
        self._hold(status)
        self.assertEqual(status["reason"], "G4I_TARGET_REPARSE_UNSAFE")

    def test_runtime_cannot_emit_an_outcome(self):
        self.assertFalse(hasattr(get_runtime(), "report_c2_wal_outcome_testonly"))

    def test_g4h_synthetic_rollback_can_be_reported_without_authority(self):
        fixture = _G4E.G4EPostMutationExceptions("test_receipt_builder_exception_routes_rollback")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.adp.translate_evidence_to_tooling_build_state.side_effect = RuntimeError("simulated")
        result = fixture._invoke(c2_write_intent_dir=self.wal)
        fixture._assert_safe_rollback(result)
        intent_ids = [p.name.removesuffix(".intent.json") for p in self.wal.glob("*.intent.json")]
        self.assertEqual(len(intent_ids), 2)  # l'intention G4I + celle du writer G4H
        second = next(identifier for identifier in intent_ids if identifier != self.intent["intent_id"])
        observed = report_c2_wal_outcome_testonly(
            wal_dir=self.wal, intent_id=second, repo_root=fixture.root,
            reported_status="REPORTED_ROLLBACK")
        self._hold(observed)
        self.assertTrue(observed["wal_outcome_recorded"])
        self.assertEqual(observed["reason"], "OUTCOME_REPORTED_NOT_ATTESTED")


if __name__ == "__main__":
    unittest.main()
