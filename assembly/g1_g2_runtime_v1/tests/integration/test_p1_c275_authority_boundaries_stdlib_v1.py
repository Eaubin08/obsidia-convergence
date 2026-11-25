"""C275 : frontières d'autorité Obsidure -> OS4/Sigma -> KX108 -> C2 -> R8/R12 -> D1.

Chaque étape est vérifiée séparément (proposition, observation, décision,
autorisation, exécution, reçu, disposition) et aucune promotion implicite
vers l'étape suivante n'est acceptée. Artefacts synthétiques uniquement.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _p in (str(HERE), str(ROOT / "scripts"), str(ROOT)):
    if _p in sys.path:
        sys.path.remove(_p)
    sys.path.insert(0, _p)

import obsidia_canonical_receipt_envelope_v1 as _CRE
import obsidia_post_execution_disposition_v0 as _DISP
import obsidia_realized_state_reconciliation_v1 as _R8_RECON
import obsidia_sealed_evidence_v0 as _SEV
import test_p1_c264_c268_c2_d1_adversarial_stdlib_v1 as _BASE
from obsidia_governance_runtime_v1 import get_runtime
from periphery.world_calls import sovereign_ticket as _ST
from sigma.contracts import AgentVote, AuthorityLevel

# Drapeaux dont aucune étape non souveraine ne peut afficher la valeur True.
_PROMOTION_FLAGS = (
    "execution_authorized", "action_ticket_issued", "human_approval_verified",
    "release_authorized", "target_mutated", "kx108_pre_invoked", "executor_invoked",
)


def assert_no_promotion(testcase: unittest.TestCase, result: dict, stage: str) -> None:
    for flag in _PROMOTION_FLAGS:
        if flag in result:
            testcase.assertIsNot(result[flag], True, f"{stage}: {flag} promu")
    testcase.assertNotIn("ticket_id", json.dumps(result, default=str), stage)
    if "decision_authority" in result:
        testcase.assertEqual(result["decision_authority"], "KX108_ONLY", stage)


def _votes(**overrides):
    return [
        AgentVote(agent_id=f"obs-{i}", domain="tooling_build", proposed_verdict="ACT",
                  claim="observation", confidence=0.99, **overrides)
        for i in range(4)
    ]


class AuthorityBoundaryChain(unittest.TestCase):
    def setUp(self) -> None:
        # Réutilise la fixture synthétique C264-C268 sans réexécuter ses tests.
        self.base = _BASE.P1C264ToC268ContinuityAndAdversarialTest(
            "test_c266_end_to_end_handoff_r9_c2_kx108_r8_reconcile_d1_replay"
        )
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.addCleanup(self.base.tmp.cleanup)
        self.rt = get_runtime()

    # -- 1. PROPOSITION ---------------------------------------------------
    def test_stage1_proposal_is_not_approval_or_authorization(self):
        b = self.base
        handoff = self.rt.inspect_obsidure_governance_handoff(
            proposal=b.proposal, manifest=b.manifest, validation=b.validation, handoff=b.handoff)
        self.assertEqual(handoff["status"], "OBSIDURE_HANDOFF_VERIFIED_READONLY")
        self.assertEqual(handoff["handoff_authority"], "NONE")
        assert_no_promotion(self, handoff, "handoff")
        r9 = self.rt.inspect_obsidure_r9_preparation(
            r10_inspection=b.r10, r9_result=b.r9, stores_base_dir=b.root,
            expected_repo_identity_ref=b.repo_ref)
        self.assertEqual(r9["status"], "R9_PREPARE_BINDING_MATCH_UNATTESTED")
        self.assertIs(r9["provenance_verified"], False)
        self.assertIs(r9["sandbox_origin_attested"], False)
        assert_no_promotion(self, r9, "r9")
        # Un R9 qui revendique une approbation/KX108 est refusé, pas promu.
        for claim in ("approval_created", "kx108_called", "executor_invoked", "physical_mutation"):
            with self.subTest(claim=claim):
                res = self.rt.inspect_obsidure_r9_preparation(
                    r10_inspection=b.r10, r9_result={**b.r9, claim: True},
                    stores_base_dir=b.root, expected_repo_identity_ref=b.repo_ref)
                self.assertEqual(res["reason"], "R9_RESULT_CLAIMS_EXECUTION_AUTHORITY")

    # -- 2. OBSERVATION (OS4/Sigma) ---------------------------------------
    def test_stage2_observation_never_becomes_decision(self):
        res = self.rt.evaluate_tooling_build_advisory(_votes())
        self.assertEqual(res["status"], "SIGMA_ADVISORY_ONLY")
        self.assertEqual(res["advisory"]["guard_gate_observed"], "HOLD")
        assert_no_promotion(self, res, "sigma")
        # Un vote qui usurpe une règle / une autorité impérative est refusé.
        usurper = _votes()
        usurper[0] = AgentVote(agent_id="obs-0", domain="tooling_build",
                               proposed_verdict="ACT", claim="x", confidence=0.99,
                               authority_level=AuthorityLevel.MANDATORY_VETO)
        self.assertEqual(self.rt.evaluate_tooling_build_advisory(usurper)["reason"],
                         "SIGMA_VOTE_AUTHORITY_NOT_ADVISORY")
        # Même un résultat Sigma fourni à execute() ne déclenche aucune exécution.
        executed = self.rt.execute(operation_type="WORLD_ACTION", sigma_result=res)
        self.assertEqual(executed["status"], "HOLD")
        assert_no_promotion(self, executed, "execute-with-sigma")

    # -- 3/4. DÉCISION puis AUTORISATION ----------------------------------
    def test_stage3_4_decision_and_authorization_are_distinct_and_unforgeable(self):
        _ST.reset_kernel_keys() if hasattr(_ST, "reset_kernel_keys") else None
        # Un ALLOW fourni par l'appelant n'est jamais accepté.
        with self.assertRaisesRegex(AssertionError, "ALLOW_REQUIRES_VERIFIED_DECISION_RECORD"):
            _ST.issue_sovereign_ticket(
                action_id="act-c275", os3_ticket_id="os3", x108_gate="ALLOW",
                scope="bounded_apply", autonomy_level=1, world_call_class="GOVERNED_WRITE",
                input_hash="0" * 64)
        # Une décision absente du magasin canonique ne produit aucun ticket.
        with self.assertRaises(AssertionError):
            _ST.issue_sovereign_ticket_from_decision_record(
                "kxdec-c275-missing", action_id="act-c275", scope="bounded_apply",
                input_hash="0" * 64, decision_store_dir=self.base.root / "kxpost")
        # Une décision POST simulée (non souveraine) n'est pas une autorisation :
        # D1 la classe seulement, avec write_capability False.
        self.base._write_simulated_kx108_post(record_id="kxpost-c275", gate="ALLOW")
        disp = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kxpost-c275",
            post_decision_store_dir=self.base.root / "kxpost")
        self.assertEqual(disp["authority"], "NON_SOVEREIGN")
        self.assertIs(disp["write_capability"], False)

    # -- 5. EXÉCUTION -----------------------------------------------------
    def test_stage5_execution_is_locked_for_every_operation(self):
        for op in ("V2_APPLY_PATCH", "UPDATE_TARGET_FROM_SOURCE", "WORLD_ACTION", "CREATE_TARGET_FROM_SOURCE"):
            with self.subTest(op=op):
                res = self.rt.execute(operation_type=op)
                self.assertEqual(res["status"], "HOLD")
                self.assertTrue(res["reason"].startswith("G1_G2_EXECUTION_NOT_RELEASED"))
                assert_no_promotion(self, res, f"execute:{op}")
        self.assertEqual(self.rt.capabilities()["apply"], "HOLD")

    # -- 6. REÇU ----------------------------------------------------------
    def test_stage6_receipt_success_never_promotes_to_authorization(self):
        b = self.base
        r9 = self.rt.inspect_obsidure_r9_preparation(
            r10_inspection=b.r10, r9_result=b.r9, stores_base_dir=b.root,
            expected_repo_identity_ref=b.repo_ref)
        import hashlib
        post = {"target_paths": [b.target], "after_digests": {b.target: hashlib.sha256(b.post_bytes).hexdigest()}}
        exec_in = {"v2_exec_id": b.v2id, "patch_sha256": b.patch_sha}
        env = _CRE.build_canonical_receipt_envelope(
            capability="G1_G2_PATCH", operation_type="V2_APPLY_PATCH",
            request_ref={"public_action": "APPLY_PATCH", "builder_lineage": r9["builder_lineage"]},
            session_ref={"v2_exec_id": b.v2id},
            prepare={"descriptor_ref": b.v2id, "descriptor_hash": b.desc_hash, "builder_lineage": r9["builder_lineage"]},
            authorization={"execution_authority_hash": b.eah, "approval_id": "NOT_REACHED",
                           "kx108_pre_decision_record_id": "NOT_REACHED", "kx108_verdict": "ALLOW",
                           "binder_verdict_status": "NOT_REACHED"},
            execution={"executor_kind": "GOVERNED_PATCH", "executor_operation": "V2_APPLY_PATCH",
                       "executor_status": "EXECUTED", "executor_input_ref": exec_in,
                       "executor_input_hash": _CRE.compute_ref_hash(exec_in),
                       "physical_effect_dispatched": True, "mutation_performed": True},
            realized_state={"outcome": _CRE.OUTCOME_SUCCESS, "physical_effect_dispatched": True,
                            "mutation_performed": True, "realized_state_verified": True,
                            "proof_strength": "STRONG", "post_state_ref": post,
                            "post_state_hash": _CRE.compute_ref_hash(post)},
            receipt={"source": "SYNTHETIC_C275_CLAIMS_SUCCESS"})
        _CRE.store_canonical_receipt_envelope(env, b.root / "receipts")
        aev = env["action_evidence_id"]
        join = self.rt.inspect_obsidure_r9_r12_outcome(
            action_evidence_id=aev, stores_base_dir=b.root, r10_inspection=b.r10,
            r9_result=b.r9, expected_repo_identity_ref=b.repo_ref)
        # Un SUCCESS historique plaidé par un reçu non attesté est rétrogradé.
        self.assertNotEqual(join["derived_outcome_classification"], "HISTORICAL_EXECUTION_EVIDENCE_MATCHED")
        # Le rejeu de décision est INCOMPLETE (aucun enregistrement KX108 réel) :
        # le SUCCESS plaidé par le reçu reste EVIDENCE_INCOMPLETE.
        self.assertEqual(join["derived_outcome_classification"], "EVIDENCE_INCOMPLETE", join)
        self.assertEqual(join["r8_decision_verdict"], "INCOMPLETE")
        self.assertEqual(join["recommendation"], "ESCALATE")
        self.assertIs(join["r9_provenance_verified"], False)
        assert_no_promotion(self, join, "r12-join")
        inspected = self.rt.inspect_r8_receipt(action_evidence_id=aev, stores_base_dir=b.root)
        assert_no_promotion(self, inspected, "r8-inspect")
        # La réconciliation constate l'état, elle ne l'autorise pas.
        recon = _R8_RECON.reconcile_action_evidence(aev, stores_base_dir=b.root)
        self.assertIn(recon["reconciliation_status"], {_R8_RECON.STATUS_MATCH, _R8_RECON.STATUS_MISMATCH,
                                                       _R8_RECON.STATUS_INCOMPLETE})
        assert_no_promotion(self, recon, "reconcile")

    # -- 7. DISPOSITION ---------------------------------------------------
    def test_stage7_keep_eligible_is_not_a_commit_authorization(self):
        b = self.base
        b._write_simulated_kx108_post(record_id="kxpost-c275-keep", gate="ALLOW")
        keep = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kxpost-c275-keep", post_decision_store_dir=b.root / "kxpost")
        self.assertEqual(keep["disposition"], _DISP.MUST_ROLLBACK)
        self.assertEqual(
            keep["reason"],
            "KX108_POST_RECORD_INVALID:DECISION_RECORD_NOT_AUTHENTICATED",
        )
        self.assertIs(keep["commit_review_eligible"], False)
        self.assertIs(keep["write_capability"], False)
        self.assertEqual(keep["authority"], "NON_SOVEREIGN")
        for flag in ("execution_authorized", "release_authorized", "commit_authorized", "ticket_id"):
            self.assertNotIn(flag, keep)
        # Le module ne contient aucune capacité git/commit/écriture de cible.
        src = Path(_DISP.__file__).read_text(encoding="utf-8")
        for needle in ("subprocess", "os.system", "git commit", "git push", "write_bytes", "os.replace"):
            self.assertNotIn(needle, src, needle)
        # Tout signal inconnu est refusé, pas interprété.
        self.assertEqual(_DISP.classify_post_execution_disposition(failure_signal="KEEP")["status"],
                         _DISP.DISPOSITION_HOLD)


if __name__ == "__main__":
    unittest.main()
