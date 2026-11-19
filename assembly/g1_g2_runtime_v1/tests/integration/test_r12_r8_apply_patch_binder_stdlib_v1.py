"""R8 D3 / R12: Binder V2_APPLY_PATCH reel, preuves 100% synthetiques.

Les identifiants, approbations et constats d'execution sont fabriques dans
un TemporaryDirectory de test. Ils n'attestent AUCUNE action physique.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts", ROOT / "tests"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import obsidia_canonical_receipt_envelope_v1 as CRE
import obsidia_canonical_receipt_replay_v1 as R8
import obsidia_governance_decision_replay_v1 as DECISION
import obsidia_realized_state_reconciliation_v1 as REALIZED
import obsidia_kx108_decision_store as DS
import obsidia_kx108_policy_identity_v1 as POLICY
import r8_b3_fixture_upstream as FIXTURE
from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
from sigma.contracts import ToolingBuildState
from sigma.protocols import run_tooling_build_pipeline


REPAIR = {
    "repair_request_id": "r10-synthetic-request",
    "repair_proposal_id": "r10-synthetic-proposal",
    "repair_verdict_id": "r10-synthetic-verdict",
}
BUILDER = {
    "builder_proposal_id": "r9-synthetic-proposal",
    "builder_manifest_id": "r9-synthetic-manifest",
    "builder_validation_id": "r9-synthetic-validation",
    "builder_handoff_id": "r9-synthetic-handoff",
}
PATCH = "V2_APPLY_PATCH"
TARGET = "sandbox/result.txt"


def _synthetic_patch_evidence(base: Path):
    stores = FIXTURE._stores(base)
    descriptor = {
        "operation_type": PATCH,
        "public_action": "APPLY_PATCH",
        "base_sha": "a" * 40,
        "patch_sha256": "b" * 64,
        "target_paths": [TARGET],
        "before_digests": {TARGET: "c" * 64},
        "physical_state_anchor": "d" * 64,
        "semantic_intent": "SYNTHETIC_REPLAY_TEST_ONLY",
    }
    v2id, eah, descriptor_hash, _ = FIXTURE._persist_descriptor(
        stores, op=PATCH, descriptor=descriptor,
    )
    child = "chd-synthetic-r8-apply"
    manifest_hash = FIXTURE._sha("synthetic-manifest")
    approval = FIXTURE._store_approval(stores, v2id=v2id, child=child, eah=eah)

    # Reconstruction independante du resultat KX108 a partir du contrat canonique.
    state = ToolingBuildState(
        session_id=child, objective="V2 governed V2_APPLY_PATCH",
        base_sha=descriptor["base_sha"], manifest_hash=manifest_hash,
        diff_hash="", physical_state_anchor=descriptor["physical_state_anchor"],
        state_anchor_kind="GIT_HEAD", approved_scope=[TARGET],
        actual_touched_files=[], new_files=[], deleted_files=[],
        protected_scope_status="CLEAN", human_approval_status="APPROVED",
        obsidure_status="UNKNOWN", worktree_isolated=True, branch_isolated=True,
        auto_commit_disabled=True, auto_push_disabled=True,
        auto_merge_disabled=True, tests_results="UNKNOWN", gates_results="UNKNOWN",
        first_failure="", commit_status="NOT_COMMITTED", push_status="NOT_PUSHED",
        merge_status="NOT_MERGED", unknowns=[], contradictions=[], risk_flags=[],
        decision_authority="KX108_ONLY",
    )
    actual_decision = run_tooling_build_pipeline(state)
    kx = FIXTURE._store_kx(
        stores, v2id=v2id, child=child, eah=eah,
        approval_id=approval["approval_id"], dh=descriptor_hash,
        mh=manifest_hash, gate=actual_decision.x108_gate,
    )
    for key in ("x108_gate", "reason_code", "severity", "market_verdict"):
        kx[key] = getattr(actual_decision, key)
    for key in ("contradictions", "unknowns", "risk_flags"):
        kx[key] = list(getattr(actual_decision, key) or [])
    kx["canonical_envelope"] = {
        "synthetic_fixture": True,
        "x108_gate": actual_decision.x108_gate,
        "policy_identity": POLICY.build_tooling_build_policy_identity(),
    }
    kx["decision_record_hash"] = DS.compute_kx108_decision_record_hash(kx)
    kxfile = stores["kxpre"] / (kx["decision_record_id"] + ".json")
    kxfile.write_text(json.dumps(kx, sort_keys=True), encoding="utf-8")

    request = {"public_action": "APPLY_PATCH", "builder_lineage": dict(BUILDER),
               "synthetic_fixture": True}
    session = {"session_id": "session-synthetic", "child_id": child,
               "v2_exec_id": v2id}
    exec_ref = {"public_action": "APPLY_PATCH", "target_paths": [TARGET],
                "patch_sha256": descriptor["patch_sha256"]}
    post = {"target_paths": [TARGET], "after_digests": {TARGET: "e" * 64},
            "sealed_apply_receipt_id": "synthetic-no-physical-receipt",
            "sealed_rollback_evidence_ids": []}
    auth = {
        "execution_authority_hash": eah,
        "approval_id": approval["approval_id"],
        "approval_status": approval["approval_status"],
        "approved_by": approval["approved_by"],
        "approval_record_hash": approval["approval_record_hash"],
        "kx108_pre_decision_record_id": kx["decision_record_id"],
        "kx108_pre_decision_record_hash": kx["decision_record_hash"],
        "kx108_verdict": actual_decision.x108_gate,
        "binder_verdict_status": "OBSERVED_INLINE_NOT_SEPARATELY_PERSISTED",
        "binder_verdict_ref": "NOT_SEPARATELY_PERSISTED",
    }
    env = CRE.build_canonical_receipt_envelope(
        capability="TEST_SYNTHETIC_PATCH_REPLAY", operation_type=PATCH,
        request_ref=request, session_ref=session,
        prepare={"descriptor_ref": v2id, "descriptor_hash": descriptor_hash,
                 "physical_state_anchor": descriptor["physical_state_anchor"],
                 "state_anchor_kind": "GIT_HEAD", "manifest_hash": manifest_hash,
                 "target_paths": [TARGET], "builder_lineage": dict(BUILDER)},
        authorization=auth,
        execution={"executor_kind": "SYNTHETIC_FIXTURE_NO_REAL_EXECUTOR",
                   "executor_operation": "apply.patch", "executor_status": "INVOKED",
                   "executor_input_ref": exec_ref,
                   "executor_input_hash": CRE.compute_ref_hash(exec_ref),
                   "physical_effect_dispatched": True,
                   "mutation_performed": True, "execution_state": "POSTCONDITION_CONFIRMED"},
        realized_state={"outcome": CRE.OUTCOME_SUCCESS,
                        "dispatch_boundary": CRE.DISPATCH_POST_CONFIRMED,
                        "physical_effect_dispatched": True, "mutation_performed": True,
                        "realized_state_verified": True, "proof_strength": "STRONG",
                        "execution_state": "POSTCONDITION_CONFIRMED",
                        "uncertainty_state": "NONE", "uncertainty_reason": "",
                        "post_state_ref": post,
                        "post_state_hash": CRE.compute_ref_hash(post)},
        receipt={"status": "SYNTHETIC_TEST_ONLY", "existing_receipt_ref": "NO_PHYSICAL_ACTION"},
        replay={"physical_replay_allowed": False, "evidence_replay_allowed": True,
                "automatic_retry": False},
        privacy={"redaction_policy": "HASHES_AND_REFS_ONLY",
                 "plaintext_sensitive_data_present": False},
    )
    stored = CRE.store_canonical_receipt_envelope(env, stores["receipts"])
    assert stored["status"] == CRE.STATUS_STORED
    return env, stores, kx


class R12R8ApplyPatchBinderTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="obsidia-r8-patch-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env, self.stores, self.kx = _synthetic_patch_evidence(self.base)
        self.runtime = ObsidiaGovernanceRuntime()

    def _replay_r12(self):
        return self.runtime.inspect_obsidure_r12_r8_outcome(
            action_evidence_id=self.env["action_evidence_id"],
            stores_base_dir=self.base,
            r10_inspection={"status": "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY", **REPAIR},
            prepared_repair={"repair_lineage": dict(REPAIR),
                             "prepared_action": {"builder_lineage": dict(BUILDER),
                                                 "v2_exec_id": self.env["session_ref"]["v2_exec_id"]}},
        )

    def _assert_no_authority(self, result):
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertEqual(result["authority"], "NON_SOVEREIGN")
        for key in ("execution_authorized", "human_approval_verified", "executor_invoked",
                    "target_mutated", "action_ticket_issued", "automatic_retry",
                    "canonical_receipt_mutation", "memory_promotion"):
            self.assertIs(result[key], False, key)

    def test_real_binder_reconstructs_but_policy_coverage_stays_limited(self):
        receipt = self.stores["receipts"] / (self.env["action_evidence_id"] + ".json")
        before = receipt.read_bytes()
        integrity = R8.replay_action_evidence(self.env["action_evidence_id"], stores_base_dir=self.base)
        decision = DECISION.replay_governance_decision(self.env["action_evidence_id"], stores_base_dir=self.base)
        realized = REALIZED.reconcile_action_evidence(self.env["action_evidence_id"], stores_base_dir=self.base)
        result = self._replay_r12()

        self.assertEqual(integrity["binder_replay_status"], "RECONSTRUCTED_MATCH")
        self.assertEqual(integrity["replay_verdict"], "VERIFIED")
        self.assertEqual(decision["binder_match"], "YES")
        self.assertEqual(decision["replay_verdict"], "MATCH")
        self.assertEqual(decision["policy_identity_status"], "MATCH")
        self.assertIn("KX108_POLICY_FINGERPRINT_BOUNDED_COVERAGE", decision["evidence_limits"])
        self.assertEqual(realized["reconciliation_status"], "MATCH")
        self.assertEqual(result["derived_outcome_classification"], "EVIDENCE_INCOMPLETE")
        self.assertEqual(result["recommendation"], "ESCALATE")
        self.assertFalse(result["evidence_provenance_verified"])
        self.assertEqual(receipt.read_bytes(), before)
        self._assert_no_authority(result)

    def test_simulated_binder_policy_drift_is_conflicting(self):
        drifted = SimpleNamespace(**{
            **{key: self.kx[key] for key in (
                "x108_gate", "reason_code", "severity", "market_verdict",
                "contradictions", "unknowns", "risk_flags",
            )},
            "reason_code": "SYNTHETIC_POLICY_DRIFT",
        })
        # Simulation d'une politique en derive, jamais manipulation de KX108.
        with patch("sigma.protocols.run_tooling_build_pipeline", return_value=drifted):
            integrity = R8.replay_action_evidence(
                self.env["action_evidence_id"], stores_base_dir=self.base,
            )
            result = self._replay_r12()
        self.assertEqual(integrity["binder_replay_status"], "RECONSTRUCTION_MISMATCH")
        self.assertIn("BINDER_RECONSTRUCTION_MISMATCH", integrity["evidence_conflicts"])
        self.assertEqual(integrity["replay_verdict"], "CONFLICTING")
        self.assertEqual(result["derived_outcome_classification"], "EVIDENCE_TAMPERED")
        self._assert_no_authority(result)

    def test_k1_protected_kx108_record_tamper_is_rejected(self):
        kxfile = self.stores["kxpre"] / (self.kx["decision_record_id"] + ".json")
        changed = json.loads(kxfile.read_text(encoding="utf-8"))
        changed["reason_code"] = "SYNTHETIC_FORGED_REASON"
        changed["decision_record_hash"] = DS.compute_kx108_decision_record_hash(changed)
        kxfile.write_text(json.dumps(changed, sort_keys=True), encoding="utf-8")
        integrity = R8.replay_action_evidence(self.env["action_evidence_id"], stores_base_dir=self.base)
        self.assertEqual(integrity["KX108_ref_valid"], "NO")
        self.assertIn(integrity["replay_verdict"], {"TAMPERED", "CONFLICTING"})
        result = self._replay_r12()
        self.assertEqual(result["derived_outcome_classification"], "EVIDENCE_TAMPERED")
        self._assert_no_authority(result)

    def test_r9_builder_lineage_mismatch_stays_blocked(self):
        result = self.runtime.inspect_obsidure_r12_r8_outcome(
            action_evidence_id=self.env["action_evidence_id"],
            stores_base_dir=self.base,
            r10_inspection={"status": "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY", **REPAIR},
            prepared_repair={"repair_lineage": dict(REPAIR),
                             "prepared_action": {"builder_lineage": {**BUILDER, "builder_handoff_id": "forged"},
                                                 "v2_exec_id": self.env["session_ref"]["v2_exec_id"]}},
        )
        self.assertEqual(result["derived_outcome_classification"], "GOVERNANCE_MISMATCH")
        self._assert_no_authority(result)


if __name__ == "__main__":
    unittest.main()
