"""Tests locaux sans dépendance pytest : contrat du runtime unifié G1/G2.

Les créations/écritures de test ont lieu exclusivement sous TemporaryDirectory.
"""
from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from obsidia_governance_runtime_v1 import get_runtime
from scripts import obsidia_kx108_decision_store as DS
from sigma.contracts import DomainAggregate


@dataclasses.dataclass
class CallerForgedWorldDecision:
    decision_id: str = "forged-decision"
    trace_id: str = "forged-trace"
    domain: str = "tooling_build"
    x108_gate: str = "ALLOW"
    reason_code: str = "FORGED"
    severity: str = "S0"
    market_verdict: str = "ACT"
    contradictions: tuple = ()
    unknowns: tuple = ()
    risk_flags: tuple = ()


class UnifiedRuntimeContract(unittest.TestCase):
    def setUp(self):
        self.runtime = get_runtime()
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-g1g2-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def prepare(self, path="subdir/new.txt", operation="CREATE_TARGET_FROM_SOURCE"):
        return self.runtime.prepare_create(
            worktree_root=self.root,
            operation_type=operation,
            target_path=path,
            source_content_sha256="a" * 64,
        )

    def test_one_runtime_and_kx108_only(self):
        info = self.runtime.capabilities()
        self.assertEqual(info["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertEqual(info["decision_authority"], "KX108_ONLY")
        self.assertEqual(info["apply"], "HOLD")

    def test_zero_vote_cannot_authorize_action(self):
        result = self.runtime.evaluate(
            DomainAggregate(domain="tooling_build", market_verdict="ACT",
                            confidence=0.98, agent_votes=[])
        )
        self.assertFalse(result["execution_authorized"])
        self.assertNotEqual(result["envelope"]["x108_gate"], "ALLOW")

    def test_create_preflight_is_not_execution(self):
        result = self.prepare()
        self.assertEqual(result["status"], "READY_FOR_CANONICAL_PRE_EVIDENCE")
        self.assertEqual(result["pc2_adapter_operation_type"], "CREATE")
        self.assertIsNone(result["target_pre_sha256"])
        self.assertFalse(result["authorized"])
        self.assertFalse((self.root / "subdir/new.txt").exists())

    def test_create_cannot_reuse_update_operation(self):
        result = self.prepare(operation="UPDATE_TARGET_FROM_SOURCE")
        self.assertEqual(result["status"], "HOLD_CREATE_PRE")

    def test_k1_prepare_existing_rejects_invalid_commit_before_any_apply(self):
        dirs = {key: self.root / key for key in (
            "ledger_dir", "selector_dir", "execution_dir",
            "pre_execution_context_dir",
        )}
        result = self.runtime.prepare_existing_update(
            source_git_commit="invalid", source_historical_path="a.py",
            target_path="a.py", test_contract={"checks": []},
            execution_worktree_path=self.root, main_worktree_path=self.root,
            branch_name="test", base_sha="invalid", **dirs,
        )
        self.assertEqual(result["status"], "PREPARE_REJECTED")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["target_mutated"])

    def test_create_rejects_target_existing(self):
        (self.root / "already.txt").write_text("old", encoding="utf-8")
        result = self.prepare(path="already.txt")
        self.assertEqual(result["reason"], "CREATE_TARGET_ALREADY_EXISTS")
        self.assertEqual((self.root / "already.txt").read_text(), "old")

    def test_create_rejects_traversal(self):
        result = self.prepare(path="../escape.txt")
        self.assertEqual(result["status"], "HOLD_CREATE_PRE")
        self.assertFalse((self.root.parent / "escape.txt").exists())

    def test_execute_always_holds(self):
        for operation in ("CREATE_TARGET_FROM_SOURCE", "UPDATE_TARGET_FROM_SOURCE", "WORLD_ACTION"):
            with self.subTest(operation=operation):
                result = self.runtime.execute(operation_type=operation, x108_gate="ALLOW")
                self.assertEqual(result["status"], "HOLD")
                self.assertFalse(result["execution_authorized"])

    def test_forged_world_allow_is_evidence_only(self):
        ctx = {field: "fixed-" + field for field in DS._WORLD_ACTION_PRE_BINDING_CONTEXT_FIELDS}
        result = self.runtime.record_world_action_evidence(
            decision_envelope=CallerForgedWorldDecision(),
            binding_context=ctx,
            store_dir=self.root / "world_evidence",
        )
        self.assertEqual(result["status"], "EVIDENCE_ONLY")
        self.assertFalse(result["execution_authorized"])
        valid, reason = DS.verify_kx108_decision_record_authenticity(result["record"])
        self.assertFalse(valid)
        self.assertEqual(reason, "DECISION_RECORD_NOT_AUTHENTICATED")

    def test_merkle_4a1_is_readonly(self):
        result = self.runtime.compute_proof_root(["a" * 64, "b" * 64])
        self.assertEqual(result["status"], "MERKLE_ROOT_COMPUTED_READ_ONLY")
        self.assertEqual(len(result["root"]), 64)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse((self.root / "merkle_seal.json").exists())

    def test_world_requires_complete_binding(self):
        ctx = {field: "fixed-" + field for field in DS._WORLD_ACTION_PRE_BINDING_CONTEXT_FIELDS}
        ctx.pop("human_approval_hash")
        result = self.runtime.record_world_action_evidence(
            decision_envelope=CallerForgedWorldDecision(),
            binding_context=ctx,
            store_dir=self.root / "world_evidence",
        )
        self.assertEqual(result["status"], "REJECTED")
        self.assertFalse((self.root / "world_evidence").exists())


if __name__ == "__main__":
    unittest.main()
