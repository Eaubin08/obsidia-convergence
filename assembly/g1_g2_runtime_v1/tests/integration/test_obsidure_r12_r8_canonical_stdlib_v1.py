"""R12/R8 : vraies APIs historiques, aucune mutation ni autorisation."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
import obsidia_canonical_receipt_envelope_v1 as cre
import obsidure_r12_r8_outcome_v1 as gateway

REPAIR = {
    "repair_request_id": "r10-request-01",
    "repair_proposal_id": "r10-proposal-01",
    "repair_verdict_id": "r10-verdict-01",
}
BUILDER = {
    "builder_proposal_id": "r9-proposal-01",
    "builder_manifest_id": "r9-manifest-01",
    "builder_validation_id": "r9-validation-01",
    "builder_handoff_id": "r9-handoff-01",
}


class ObsidureR12R8ReadOnly(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-r12-r8-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ("v2exec", "approval", "kxpre", "receipts"):
            (self.root / name).mkdir()
        self.runtime = ObsidiaGovernanceRuntime()
        self.r10 = {
            "status": "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY",
            **REPAIR,
        }
        self.r9 = {
            "repair_lineage": dict(REPAIR),
            "prepared_action": {"builder_lineage": dict(BUILDER), "v2_exec_id": "v2-exec-01"},
        }

    def invoke(self, action_evidence_id, *, r10=None, r9=None, root=None):
        return self.runtime.inspect_obsidure_r12_r8_outcome(
            action_evidence_id=action_evidence_id,
            stores_base_dir=self.root if root is None else root,
            r10_inspection=self.r10 if r10 is None else r10,
            prepared_repair=self.r9 if r9 is None else r9,
        )

    def receipt(self, outcome="KX108_HOLD", **overrides):
        kwargs = dict(
            capability="TOOLING_BUILD", operation_type="UPDATE_TARGET_FROM_SOURCE",
            request_ref={"builder_lineage": dict(BUILDER)},
            session_ref={"v2_exec_id": "v2-exec-01"},
            prepare={"builder_lineage": dict(BUILDER)},
            authorization={"kx108_verdict": "HOLD"},
            execution={"executor_kind": "NOT_EXECUTED"},
            realized_state={"outcome": outcome, "physical_effect_dispatched": False},
            receipt={"status": "NO_ACTION"},
        )
        kwargs.update(overrides)
        envelope = cre.build_canonical_receipt_envelope(**kwargs)
        path = self.root / "receipts" / (envelope["action_evidence_id"] + ".json")
        path.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")
        return envelope, path

    def assert_non_authorizing(self, result):
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertEqual(result["authority"], "NON_SOVEREIGN")
        for field in (
            "human_approval_verified", "execution_authorized", "action_ticket_issued",
            "kx108_pre_invoked", "executor_invoked", "target_mutated",
            "memory_promotion", "canonical_receipt_mutation", "automatic_retry",
        ):
            self.assertIs(result[field], False, field)

    def test_one_runtime_exposes_historical_only(self):
        cap = self.runtime.capabilities()
        self.assertEqual(cap["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertEqual(cap["apply"], "HOLD")
        self.assertEqual(cap["obsidure_r12_r8_outcome"], "CANONICAL_HISTORICAL_REPLAY_READONLY_NO_RETRY")
        self.assert_non_authorizing(self.invoke("invalid"))

    def test_empty_or_path_traversal_action_id_holds(self):
        for value in ("", "../secret", "aev-" + "Z" * 32, "aev-" + "a" * 32 + "/other"):
            with self.subTest(value=value):
                r = self.invoke(value)
                self.assertEqual(r["reason"], "R8_ACTION_EVIDENCE_ID_INVALID")
                self.assert_non_authorizing(r)

    def test_r10_and_r9_lineage_required_before_read(self):
        action_id = "aev-" + "a" * 32
        self.assertEqual(self.invoke(action_id, r10={})["reason"], "R10_INSPECTION_REQUIRED")
        self.assertEqual(self.invoke(action_id, r9={})["reason"], "R9_REPAIR_LINEAGE_MISMATCH")
        self.assertEqual(self.invoke(action_id, r9={**self.r9, "repair_lineage": {**REPAIR, "repair_verdict_id": "forged"}})["derived_outcome_classification"], "GOVERNANCE_MISMATCH")

    def test_missing_receipt_holds(self):
        r = self.invoke("aev-" + "f" * 32)
        self.assertEqual(r["reason"], "R8_CANONICAL_RECEIPT_MISSING_OR_INVALID")
        self.assert_non_authorizing(r)

    def test_real_canonical_four_modules_no_mutation(self):
        envelope, path = self.receipt()
        before = path.read_bytes()
        # Les trois vrais replay R8 sont invoqués (pas un rapport fourni par l'appelant).
        orig_integrity = gateway._R8_INTEGRITY.replay_action_evidence
        orig_decision = gateway._R8_DECISION.replay_governance_decision
        orig_realized = gateway._R8_REALIZED.reconcile_action_evidence
        with (patch.object(gateway._R8_INTEGRITY, "replay_action_evidence", wraps=orig_integrity) as a,
              patch.object(gateway._R8_DECISION, "replay_governance_decision", wraps=orig_decision) as b,
              patch.object(gateway._R8_REALIZED, "reconcile_action_evidence", wraps=orig_realized) as c):
            result = self.invoke(envelope["action_evidence_id"])
            self.assertGreaterEqual(a.call_count, 1)
            self.assertEqual(b.call_count, 1)
            self.assertEqual(c.call_count, 1)
        self.assertEqual(path.read_bytes(), before)
        # Receipt structurellement valide, mais pièces R8 incomplètes et
        # contradictoires : les vrais vérificateurs doivent refuser ce cas.
        self.assertEqual(result["derived_outcome_classification"], "EVIDENCE_TAMPERED")
        self.assert_non_authorizing(result)

    def test_hash_tamper_blocks_before_replay(self):
        envelope, path = self.receipt()
        data = json.loads(path.read_text(encoding="utf-8"))
        data["authorization"]["kx108_verdict"] = "ALLOW"
        path.write_text(json.dumps(data), encoding="utf-8")
        r = self.invoke(envelope["action_evidence_id"])
        self.assertEqual(r["derived_outcome_classification"], "EVIDENCE_TAMPERED")
        self.assertEqual(r["recommendation"], "STOP_BLOCKED")
        self.assert_non_authorizing(r)

    def test_correctly_hashed_but_different_builder_blocks(self):
        envelope, _ = self.receipt()
        other = dict(self.r9)
        other["prepared_action"] = {**self.r9["prepared_action"], "builder_lineage": {**BUILDER, "builder_manifest_id": "other"}}
        r = self.invoke(envelope["action_evidence_id"], r9=other)
        self.assertEqual(r["derived_outcome_classification"], "GOVERNANCE_MISMATCH")
        self.assert_non_authorizing(r)

    def test_symlink_store_not_followed(self):
        with tempfile.TemporaryDirectory(prefix="obsidia-r8-symlink-") as temp:
            link = Path(temp) / "receipts"
            try:
                link.symlink_to(self.root / "receipts", target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            r = self.invoke("aev-" + "a" * 32, root=Path(temp))
            self.assertEqual(r["reason"], "R8_STORES_UNVERIFIED")
            self.assert_non_authorizing(r)

    def test_symlink_receipt_not_followed(self):
        envelope, real_path = self.receipt()
        real_path.rename(self.root / "outside.json")
        try:
            real_path.symlink_to(self.root / "outside.json")
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        r = self.invoke(envelope["action_evidence_id"])
        self.assertEqual(r["reason"], "R8_RECEIPT_REPARSE_UNSAFE")

    def test_limited_replay_never_promoted_to_verified(self):
        envelope, _ = self.receipt(outcome="SUCCESS", authorization={"kx108_verdict": "ALLOW"})
        with (patch.object(gateway._R8_INTEGRITY, "replay_action_evidence", return_value={"replay_verdict": "VERIFIED_WITH_LIMITS", "evidence_missing": ["SOME_REF"]}),
              patch.object(gateway._R8_DECISION, "replay_governance_decision", return_value={"replay_verdict": "MATCH", "evidence_limits": []}),
              patch.object(gateway._R8_REALIZED, "reconcile_action_evidence", return_value={"reconciliation_status": "MATCH", "evidence_limits": []})):
            r = self.invoke(envelope["action_evidence_id"])
        self.assertEqual(r["derived_outcome_classification"], "EVIDENCE_INCOMPLETE")
        self.assertEqual(r["recommendation"], "ESCALATE")
        self.assert_non_authorizing(r)

    def test_receipt_swapped_during_replay_is_not_accepted(self):
        envelope, path = self.receipt(outcome="SUCCESS", authorization={"kx108_verdict": "ALLOW"})
        def mutate_during_integrity(*_args, **_kwargs):
            path.write_text("{}", encoding="utf-8")
            return {"replay_verdict": "VERIFIED"}
        with (patch.object(gateway._R8_INTEGRITY, "replay_action_evidence", side_effect=mutate_during_integrity),
              patch.object(gateway._R8_DECISION, "replay_governance_decision", return_value={"replay_verdict": "MATCH"}),
              patch.object(gateway._R8_REALIZED, "reconcile_action_evidence", return_value={"reconciliation_status": "MATCH"})):
            r = self.invoke(envelope["action_evidence_id"])
        self.assertEqual(r["reason"], "R8_RECEIPT_CHANGED_DURING_REPLAY")
        self.assertEqual(r["recommendation"], "STOP_BLOCKED")
        self.assert_non_authorizing(r)

    def test_no_live_action_from_success_history(self):
        r = self.runtime.execute(operation_type="OBSIDURE_R12_RETRY")
        self.assertEqual(r["status"], "HOLD")
        self.assertFalse(r["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
