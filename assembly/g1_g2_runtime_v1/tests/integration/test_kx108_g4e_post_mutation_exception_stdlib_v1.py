"""G4E : les exceptions POST après une mutation synthétique appellent D2.

La cible vit exclusivement dans TemporaryDirectory. Le remplacement et le
rollback sont DOUBLES de test ; aucune autorité de production n'est invoquée.
"""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import test_kx108_g4_pre_post_closure_stdlib_v1 as _G4
from scripts import obsidia_governed_apply_v0 as APPLY
from scripts import obsidia_sealed_evidence_v0 as SEV


class G4EPostMutationExceptions(unittest.TestCase):
    def setUp(self):
        self.g4 = _G4.Kx108G4ReadOnlyClosure("test_valid_synthetic_chain_is_still_hold")
        self.g4.setUp()
        self.addCleanup(self.g4.doCleanups)
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-g4e-post-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "targets").mkdir()
        (self.root / "sources").mkdir()
        self.target = self.root / "targets" / "item.txt"
        self.source = self.root / "sources" / "source.txt"
        self.old = b"before G4E synthetic\n"
        self.new = b"after G4E synthetic\n"
        self.target.write_bytes(self.old)
        self.source.write_bytes(self.new)
        self.child = {
            "child_execution_id": "child-synth",
            "execution_status": APPLY._E.PLANNED,
            "operation_type": APPLY.OPERATION_TYPE,
            "source_kind": "FILE_SYSTEM_TEST_ONLY",
            "source_path": "sources/source.txt",
            "source_git_commit_sha": None,
            "source_git_blob_sha": None,
            "source_git_historical_path": None,
            "source_content_sha256": hashlib.sha256(self.new).hexdigest(),
            "target_path": "targets/item.txt",
            "target_pre_sha256": hashlib.sha256(self.old).hexdigest(),
        }
        self.envelope = {
            "integrity_verified": True,
            "decision_authority": "KX108_ONLY",
            "execution_authority_hash": "a" * 64,
            "pre_execution_context_id": "pc-synth",
            "pre_execution_context_record_hash": "pc-hash-synth",
            "children": [self.child],
            "test_contract": {"synthetic": True},
            "test_contract_hash": "b" * 64,
        }
        self.approval = {"approved_by": "HUMAN", "execution_authority_hash": "a" * 64}
        self.pctx = {
            "context_record_hash": "pc-hash-synth",
            "worktree_isolated": True, "branch_isolated": True,
            "protected_scope_status": "CLEAN",
        }
        self.mutations = 0
        self.rollback_calls = 0
        self.tc = SimpleNamespace(run_and_persist_test_contract=Mock(return_value={
            "verify_ok": True, "result_id": "tcr-synth",
            "record": {"result_record_hash": "e" * 64},
        }))
        self.adp = SimpleNamespace(
            READY_FOR_KX108_SUBMISSION="READY_FOR_KX108_SUBMISSION",
            translate_evidence_to_tooling_build_state=Mock(return_value={
                "status": "READY_FOR_KX108_SUBMISSION",
                "tooling_build_state_kwargs": {"synthetic": "tooling"},
                "translation_report": {"kx108_input_translation_hash": "f" * 64},
            }),
        )
        self.disp = SimpleNamespace(
            DISPOSITION_CLASSIFIED="DISPOSITION_CLASSIFIED",
            KEEP_ELIGIBLE_FOR_HUMAN_COMMIT_REVIEW="KEEP_ELIGIBLE_FOR_HUMAN_COMMIT_REVIEW",
            classify_post_execution_disposition=Mock(return_value={
                "status": "DISPOSITION_CLASSIFIED", "disposition": "MUST_ROLLBACK",
            }),
        )
        self.rb = SimpleNamespace(
            ROLLBACK_SUCCEEDED="ROLLBACK_SUCCEEDED",
            ALREADY_ROLLED_BACK="ALREADY_ROLLED_BACK",
            ROLLBACK_SUCCEEDED_RESULT_UNPERSISTED="ROLLBACK_SUCCEEDED_RESULT_UNPERSISTED",
            run_governed_rollback=self._rollback,
        )
        self.wg = SimpleNamespace(verify_path_reparse_safe=Mock(return_value=(True, None)))

    def _mutate(self, target, data, expected_hash):
        self.assertEqual(Path(target), self.target)
        self.assertEqual(data, self.new)
        self.assertEqual(hashlib.sha256(self.target.read_bytes()).hexdigest(), expected_hash)
        self.target.write_bytes(data)
        self.mutations += 1
        return {"status": APPLY._C.CONTENT_APPLIED, "bytes_written": len(data)}

    def _rollback(self, **kw):
        self.assertEqual(kw["child_execution_id"], "child-synth")
        self.rollback_trigger = kw
        self.assertEqual(self.target.read_bytes(), self.new)
        self.target.write_bytes(self.old)
        self.rollback_calls += 1
        return {"status": "ROLLBACK_SUCCEEDED", "quarantine_required": False,
                "kx108_invocations_during_rollback": 0}

    def _invoke(self, *, sealed_module=SEV):
        with ExitStack() as stack:
            stack.enter_context(patch.object(APPLY, "_c2_mod", return_value=(
                sealed_module, self.tc, self.adp, self.disp, self.rb, self.wg,
            )))
            stack.enter_context(patch.object(APPLY, "validate_governed_apply_preflight", return_value={
                "status": APPLY.STATUS_PASS,
            }))
            stack.enter_context(patch.object(APPLY._E, "_load_execution", return_value=self.envelope))
            stack.enter_context(patch.object(APPLY._E, "compute_execution_authority_hash", return_value="a" * 64))
            stack.enter_context(patch.object(APPLY._E, "load_approval_artifact", return_value=self.approval))
            stack.enter_context(patch.object(APPLY._E, "verify_approval_artifact", return_value=(True, None)))
            stack.enter_context(patch.object(APPLY._E, "_validate_approval", return_value=(True, None)))
            stack.enter_context(patch.object(APPLY._DS, "load_kx108_decision_record", return_value=self.g4.pre))
            stack.enter_context(patch.object(APPLY._DS, "_kernel_key", return_value=self.g4._test_key))
            stack.enter_context(patch.object(APPLY._PEC, "load_pre_execution_context_record", return_value=self.pctx))
            stack.enter_context(patch.object(APPLY._PEC, "verify_pre_execution_context_record", return_value=(True, None)))
            stack.enter_context(patch.object(APPLY._C, "resolve_source_bytes", return_value=(self.new, None)))
            stack.enter_context(patch.object(APPLY._C, "atomic_replace_with_bytes", side_effect=self._mutate))
            return APPLY.run_governed_content_apply(
                "batch-synth", "child-synth", "approval-synth-not-real", "pre-synthetic",
                repo_root=self.root,
                sealed_rollback_evidence_dir=self.root / "sealed-rollback",
                sealed_receipt_dir=self.root / "sealed-apply",
                rollback_result_dir=self.root / "rollback",
                test_contract_results_dir=self.root / "tests",
                post_decision_store_dir=self.root / "post",
            )

    def _assert_safe_rollback(self, result):
        self.assertEqual(self.mutations, 1)
        self.assertEqual(self.rollback_calls, 1)
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(result["status"], APPLY.GOVERNED_REMEDIATION_REJECTED_ROLLED_BACK)
        self.assertFalse(result["commit_review_eligible"])
        self.assertEqual(result["decision_authority"], "KX108_ONLY")

    def test_receipt_builder_exception_routes_rollback(self):
        with patch.object(SEV, "build_sealed_apply_receipt", side_effect=RuntimeError("test")):
            result = self._invoke()
        self.assertIn("SEALED_APPLY_RECEIPT_SEAL_FAILED:EXCEPTION:RuntimeError", result["reason"])
        self._assert_safe_rollback(result)

    def test_receipt_store_exception_routes_rollback(self):
        with patch.object(SEV, "store_sealed_apply_receipt", side_effect=OSError("test")):
            result = self._invoke()
        self.assertIn("SEALED_APPLY_RECEIPT_SEAL_FAILED:EXCEPTION:OSError", result["reason"])
        self._assert_safe_rollback(result)

    def test_translation_exception_routes_rollback(self):
        self.adp.translate_evidence_to_tooling_build_state.side_effect = RuntimeError("test")
        result = self._invoke()
        self.assertIn("POST_EVIDENCE_TRANSLATION_FAILED:RuntimeError", result["reason"])
        self._assert_safe_rollback(result)

    def test_translation_incomplete_result_routes_rollback(self):
        self.adp.translate_evidence_to_tooling_build_state.return_value = {
            "status": "READY_FOR_KX108_SUBMISSION", "translation_report": {},
        }
        result = self._invoke()
        self.assertIn("POST_EVIDENCE_TRANSLATION_FAILED", result["reason"])
        self._assert_safe_rollback(result)

    def test_post_kernel_exception_routes_rollback(self):
        with patch.object(APPLY._DS, "run_and_persist_kx108_post_execution_decision",
                          side_effect=RuntimeError("test kernel failure")):
            result = self._invoke()
        self.assertIn("KX108_POST_STORE_OR_VERIFY_FAILED:RuntimeError", result["reason"])
        self._assert_safe_rollback(result)

    def test_post_missing_record_id_routes_rollback(self):
        with patch.object(APPLY._DS, "run_and_persist_kx108_post_execution_decision",
                          return_value={"status": "STORED", "verify_ok": True}):
            result = self._invoke()
        self.assertIn("KX108_POST_STORE_OR_VERIFY_FAILED", result["reason"])
        self._assert_safe_rollback(result)

    def test_disposition_exception_routes_rollback(self):
        self.disp.classify_post_execution_disposition.side_effect = RuntimeError("test")
        with patch.object(APPLY._DS, "run_and_persist_kx108_post_execution_decision",
                          return_value={"status": "STORED", "verify_ok": True,
                                        "decision_record_id": "post-synth", "x108_gate": "ALLOW"}):
            result = self._invoke()
        self.assertIn("KX108_POST_DISPOSITION_None", result["reason"])
        self.assertEqual(self.rollback_trigger.get("rollback_trigger_code"), "POST_EVIDENCE_UNAVAILABLE")
        self.assertNotIn("kx108_post_decision_record_id", self.rollback_trigger)
        self._assert_safe_rollback(result)

    def test_disposition_malformed_return_routes_rollback(self):
        self.disp.classify_post_execution_disposition.return_value = None
        with patch.object(APPLY._DS, "run_and_persist_kx108_post_execution_decision",
                          return_value={"status": "STORED", "verify_ok": True,
                                        "decision_record_id": "post-synth", "x108_gate": "ALLOW"}):
            result = self._invoke()
        self.assertEqual(self.rollback_trigger.get("rollback_trigger_code"), "POST_EVIDENCE_UNAVAILABLE")
        self._assert_safe_rollback(result)

    def test_rollback_exception_quarantines_unknown_target(self):
        self.adp.translate_evidence_to_tooling_build_state.side_effect = RuntimeError("test")
        self.rb.run_governed_rollback = Mock(side_effect=RuntimeError("simulated failed restore"))
        result = self._invoke()
        self.assertEqual(self.mutations, 1)
        self.assertEqual(self.target.read_bytes(), self.new)
        self.assertEqual(result["status"], APPLY.GOVERNED_REMEDIATION_ROLLBACK_FAILED_QUARANTINE)
        self.assertTrue(result["quarantine_required"])
        self.assertFalse(result["target_state_live_verified"])
        self.assertFalse(result["commit_review_eligible"])
        self.assertIn("ROLLBACK_EXCEPTION:RuntimeError", result["reason"])
        self.assertEqual(result["decision_authority"], "KX108_ONLY")

    def test_rollback_invalid_result_forces_quarantine(self):
        self.adp.translate_evidence_to_tooling_build_state.side_effect = RuntimeError("test")
        self.rb.run_governed_rollback = Mock(return_value={
            "status": "INVALID_RESTORE_STATUS", "quarantine_required": False,
        })
        result = self._invoke()
        self.assertEqual(self.mutations, 1)
        self.assertEqual(self.target.read_bytes(), self.new)
        self.assertEqual(result["status"], APPLY.GOVERNED_REMEDIATION_ROLLBACK_FAILED_QUARANTINE)
        self.assertTrue(result["quarantine_required"])
        self.assertFalse(result["target_state_live_verified"])
        self.assertFalse(result["commit_review_eligible"])


if __name__ == "__main__":
    unittest.main()
