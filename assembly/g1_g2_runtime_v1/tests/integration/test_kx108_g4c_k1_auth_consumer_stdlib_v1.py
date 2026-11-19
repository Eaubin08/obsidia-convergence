"""G4C : une preuve cohérente mais non authentifiée n'autorise aucun rail C2.

Tests synthétiques avec une clé HMAC de TEST ; seuls les magasins temporaires
sont écrits. Aucune invocation du vrai noyau ou d'un APPLY de production.
"""
from __future__ import annotations

import copy
import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_kx108_g4_pre_post_closure_stdlib_v1 as _G4
from scripts import obsidia_governed_apply_v0 as APPLY
from scripts import obsidia_kx108_decision_store as DS
from scripts import obsidia_post_execution_disposition_v0 as DISP
from scripts import obsidia_governed_rollback_v0 as ROLLBACK


@dataclasses.dataclass
class _SyntheticDecision:
    decision_id: str = "kernel-synthetic-g4c"
    trace_id: str = "trace-synthetic-g4c"
    domain: str = "tooling_build"
    x108_gate: str = "HOLD"
    reason_code: str = "TEST_ONLY"
    severity: str = "S2"
    market_verdict: str = "BUILD_HOLD"
    contradictions: tuple = ()
    unknowns: tuple = ()
    risk_flags: tuple = ()


class G4CK1ConsumerClosure(unittest.TestCase):
    def setUp(self):
        self.fixture = _G4.Kx108G4ReadOnlyClosure("test_valid_synthetic_chain_is_still_hold")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.pre = copy.deepcopy(self.fixture.pre)
        self.forged = copy.deepcopy(self.pre)
        self.forged.pop("decision_record_authenticator", None)
        self.assertTrue(DS.verify_kx108_decision_record(self.forged)[0])
        self.assertEqual(
            DS.verify_kx108_decision_record_authenticity(self.forged),
            (False, "DECISION_RECORD_NOT_AUTHENTICATED"),
        )

    def _envelope(self):
        return {
            "integrity_verified": True, "decision_authority": "KX108_ONLY",
            "execution_authority_hash": "a" * 64,
            "children": [{
                "child_execution_id": "child-synth",
                "execution_status": APPLY._E.PLANNED,
                "operation_type": APPLY.OPERATION_TYPE,
                "source_content_sha256": "b" * 64,
                "target_pre_sha256": "c" * 64,
            }],
        }

    def _approval(self):
        return {"execution_authority_hash": "a" * 64, "approved_by": "HUMAN"}

    def test_preflight_rejects_rehashed_pre_without_hmac_before_source_read(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.object(APPLY._E, "_load_execution", return_value=self._envelope()))
            stack.enter_context(patch.object(APPLY._E, "compute_execution_authority_hash", return_value="a" * 64))
            stack.enter_context(patch.object(APPLY._E, "load_approval_artifact", return_value=self._approval()))
            stack.enter_context(patch.object(APPLY._E, "verify_approval_artifact", return_value=(True, None)))
            stack.enter_context(patch.object(APPLY._E, "_validate_approval", return_value=(True, None)))
            stack.enter_context(patch.object(APPLY._DS, "load_kx108_decision_record", return_value=self.forged))
            read_source = stack.enter_context(patch.object(APPLY._C, "resolve_source_bytes", side_effect=AssertionError("SOURCE_READ")))
            result = APPLY.validate_governed_apply_preflight(
                "batch-synth", "child-synth", "approval-synth-not-real", "pre-synthetic",
                repo_root=self.fixture.base,
            )
        self.assertEqual(result["status"], APPLY.STATUS_HOLD)
        self.assertIn("DECISION_RECORD_NOT_AUTHENTICATED", result["reason"])
        read_source.assert_not_called()

    def test_write_boundary_reloads_hmac_even_if_preflight_claims_pass(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.object(APPLY, "_c2_mod", return_value=(None,) * 6))
            stack.enter_context(patch.object(APPLY, "validate_governed_apply_preflight", return_value={"status": APPLY.STATUS_PASS}))
            stack.enter_context(patch.object(APPLY._E, "_load_execution", return_value=self._envelope()))
            stack.enter_context(patch.object(APPLY._E, "compute_execution_authority_hash", return_value="a" * 64))
            stack.enter_context(patch.object(APPLY._E, "load_approval_artifact", return_value=self._approval()))
            stack.enter_context(patch.object(APPLY._E, "verify_approval_artifact", return_value=(True, None)))
            stack.enter_context(patch.object(APPLY._E, "_validate_approval", return_value=(True, None)))
            stack.enter_context(patch.object(APPLY._DS, "load_kx108_decision_record", return_value=self.forged))
            read_source = stack.enter_context(patch.object(APPLY._C, "resolve_source_bytes", side_effect=AssertionError("SOURCE_READ")))
            result = APPLY.run_governed_content_apply(
                "batch-synth", "child-synth", "approval-synth-not-real", "pre-synthetic",
                repo_root=self.fixture.base,
            )
        self.assertNotEqual(result["status"], "APPLY_PASS")
        self.assertIn("DECISION_RECORD_NOT_AUTHENTICATED", result["reason"])
        read_source.assert_not_called()

    def test_unsigned_post_cannot_be_promoted_to_commit_review(self):
        post = copy.deepcopy(self.fixture.post)
        post["x108_gate"] = "ALLOW"
        post["canonical_envelope"] = _G4._envelope("ALLOW")
        post["decision_record_hash"] = DS.compute_kx108_decision_record_hash(post)
        self.assertTrue(DS.verify_kx108_decision_record(post)[0])
        with patch.object(DISP._DS, "load_kx108_decision_record", return_value=post):
            result = DISP.classify_post_execution_disposition(post_decision_record_id="post-synthetic")
        self.assertEqual(result["disposition"], DISP.MUST_ROLLBACK)
        self.assertFalse(result["commit_review_eligible"])
        self.assertIn("DECISION_RECORD_NOT_AUTHENTICATED", result["reason"])
        self.assertFalse(result["write_capability"])

    def test_signed_post_can_be_classified_but_never_executes(self):
        post = copy.deepcopy(self.fixture.post)
        post["x108_gate"] = "ALLOW"
        post["canonical_envelope"] = _G4._envelope("ALLOW")
        post["decision_record_hash"] = DS.compute_kx108_decision_record_hash(post)
        DS._authenticate_decision_record(post, "run_and_persist_kx108_post_execution_decision")
        self.assertTrue(DS.verify_kx108_decision_record_authenticity(post)[0])
        self.assertNotIn(post["decision_record_producer"], DS.TICKET_ELIGIBLE_PRODUCERS)
        with patch.object(DISP._DS, "load_kx108_decision_record", return_value=post), \
             patch.object(DISP._DS, "_kernel_key", return_value=self.fixture._test_key):
            result = DISP.classify_post_execution_disposition(post_decision_record_id="post-synthetic")
        self.assertEqual(result["disposition"], DISP.KEEP_ELIGIBLE_FOR_HUMAN_COMMIT_REVIEW)
        self.assertFalse(result["write_capability"])

    def test_post_producer_denies_unsigned_pre_before_kernel(self):
        from sigma import protocols, contracts
        called = []
        with tempfile.TemporaryDirectory(prefix="obsidia-g4c-post-") as tmp:
            out = Path(tmp) / "post"
            with patch.object(DS, "load_kx108_decision_record", return_value=self.forged), \
                 patch.object(contracts, "ToolingBuildState", return_value=object()), \
                 patch.object(protocols, "run_tooling_build_pipeline", side_effect=lambda _: called.append(True)):
                result = DS.run_and_persist_kx108_post_execution_decision(
                    {}, {k: "synthetic" for k in DS._BINDING_CONTEXT_FIELDS},
                    "pre-synthetic", post_decision_store_dir=out,
                )
            self.assertEqual(result["status"], "REJECTED")
            self.assertEqual(result["kx108_kernel_call_count"], 0)
            self.assertIn("DECISION_RECORD_NOT_AUTHENTICATED", result["reason"])
            self.assertEqual(called, [])
            self.assertFalse(out.exists())

    def test_rollback_rejects_unsigned_pre_before_target_access(self):
        with patch.object(ROLLBACK._DS, "load_kx108_decision_record", return_value=self.forged), \
             patch.object(ROLLBACK, "_finalize", side_effect=lambda **kw: kw) as finalize, \
             patch.object(ROLLBACK, "_read_target_sha256", side_effect=AssertionError("TARGET_ACCESS")) as read_target:
            result = ROLLBACK.run_governed_rollback(
                "child-synth", "pre-synthetic",
                rollback_trigger_code="TEST_INFRA_FAILURE", repo_root=self.fixture.base,
                rollback_result_dir=self.fixture.base / "not-created",
            )
        self.assertEqual(result["status"], ROLLBACK.ROLLBACK_REFUSED_PRE_DECISION_INVALID)
        self.assertIn("DECISION_RECORD_NOT_AUTHENTICATED", result["reason"])
        finalize.assert_called_once()
        read_target.assert_not_called()
        self.assertFalse((self.fixture.base / "not-created").exists())

    def test_consistent_rehash_after_hmac_is_rejected(self):
        tampered = copy.deepcopy(self.pre)
        tampered["approval_id"] = "forged-approval"
        tampered["decision_record_hash"] = DS.compute_kx108_decision_record_hash(tampered)
        self.assertTrue(DS.verify_kx108_decision_record(tampered)[0])
        self.assertEqual(
            DS.verify_kx108_decision_record_authenticity(tampered),
            (False, "DECISION_RECORD_AUTHENTICATOR_INVALID"),
        )
        with patch.object(DISP._DS, "load_kx108_decision_record", return_value=tampered), \
             patch.object(DISP._DS, "_kernel_key", return_value=self.fixture._test_key):
            result = DISP.classify_post_execution_disposition(post_decision_record_id="pre-synthetic")
        self.assertEqual(result["disposition"], DISP.MUST_ROLLBACK)

    def test_absent_kernel_key_fails_closed_in_post_disposition(self):
        post = copy.deepcopy(self.fixture.post)
        post["decision_record_hash"] = DS.compute_kx108_decision_record_hash(post)
        DS._authenticate_decision_record(post, "run_and_persist_kx108_post_execution_decision")
        with patch.object(DISP._DS, "load_kx108_decision_record", return_value=post), \
             patch.object(DISP._DS, "_kernel_key", side_effect=RuntimeError("test key unavailable")):
            result = DISP.classify_post_execution_disposition(post_decision_record_id="post-synthetic")
        self.assertEqual(result["disposition"], DISP.MUST_ROLLBACK)
        self.assertFalse(result["commit_review_eligible"])
        self.assertIn("DECISION_RECORD_KERNEL_KEY_UNAVAILABLE", result["reason"])

    def test_post_producer_signs_after_one_synthetic_kernel_call(self):
        from sigma import protocols, contracts
        called = []
        binding = {k: "synthetic" for k in DS._BINDING_CONTEXT_FIELDS}
        binding.update({
            "batch_execution_id": "batch-synth",
            "child_execution_id": "child-synth",
            "approval_id": "approval-synth-not-real",
            "execution_authority_hash": "a" * 64,
        })
        with tempfile.TemporaryDirectory(prefix="obsidia-g4c-post-") as tmp:
            out = Path(tmp) / "post"
            with patch.object(DS, "load_kx108_decision_record", wraps=DS.load_kx108_decision_record) as load_mock, \
                 patch.object(DS, "_batch_execution_module") as batch_mod, \
                 patch.object(contracts, "ToolingBuildState", return_value=object()), \
                 patch.object(protocols, "run_tooling_build_pipeline", side_effect=lambda _: called.append(True) or _SyntheticDecision()):
                real_load = load_mock._mock_wraps
                load_mock.side_effect = lambda record_id, store_dir=None: (
                    self.pre if record_id == "pre-synthetic" else real_load(record_id, store_dir)
                )
                batch_mod.return_value._load_execution.return_value = self._envelope()
                batch_mod.return_value.compute_execution_authority_hash.return_value = "a" * 64
                result = DS.run_and_persist_kx108_post_execution_decision(
                    {}, binding, "pre-synthetic", post_decision_store_dir=out,
                )
            self.assertEqual(result["status"], "STORED")
            self.assertEqual(result["kx108_kernel_call_count"], 1)
            self.assertEqual(len(called), 1)
            record = result["record"]
            self.assertEqual(record["decision_record_producer"], "run_and_persist_kx108_post_execution_decision")
            self.assertTrue(DS.verify_kx108_decision_record_authenticity(record)[0])
            self.assertNotIn(record["decision_record_producer"], DS.TICKET_ELIGIBLE_PRODUCERS)


if __name__ == "__main__":
    unittest.main()
