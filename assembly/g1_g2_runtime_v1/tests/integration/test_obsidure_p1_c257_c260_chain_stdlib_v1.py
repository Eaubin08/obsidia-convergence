"""C257-C260 : Continuité des preuves Obsidure Handoff -> R9 -> R12 -> R8.

Tests intégrés en lecture seule sur artefacts synthétiques isolés :
- C257 : Liaison Handoff -> R9, 4 identifiants de filiation, substitutions refusées.
- C258 : Séparation stricte intégrité structurelle vs provenance/authenticité/KX108.
- C259 : Continuité R9 -> R12, cohérence et refus des contradictions sans APPLY.
- C260 : Reçus canoniques, rejeu d'intégrité et réconciliation d'état réalisé.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import obsidia_canonical_receipt_envelope_v1 as _CRE
import obsidia_canonical_receipt_replay_v1 as _R8_REPLAY
import obsidia_realized_state_reconciliation_v1 as _R8_RECON
from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
from obsidure_builder_proposal_v1 import BuilderPatchRef, ObsidureBuilderProposalV1
from obsidure_governance_handoff_v1 import build_governance_handoff
from obsidure_proposal_manifest_v1 import (
    ArtifactRef,
    EvidenceRecord,
    build_proposal_manifest,
)
from obsidure_proposal_validation_v1 import (
    ValidationObligation,
    ValidationPolicy,
    validate_obsidure_proposal,
)


def _sha(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


class ObsidureP1ChainC257ToC260Test(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-p1-c257-c260-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for sub in ("v2exec", "approval", "kxpre", "receipts"):
            (self.root / sub).mkdir()
        self.runtime = ObsidiaGovernanceRuntime()
        self.target = "scripts/tool.py"
        self.repo_ref = "synthetic-isolated-repo"
        self.fixture = self._build_r9_fixture(
            suffix="1",
            patch_content="--- a/scripts/tool.py\n+++ b/scripts/tool.py\n@@ -1 +1 @@\n-old\n+new\n",
            persist=True,
        )

    def _build_r9_fixture(
        self, *, suffix: str, patch_content: str, persist: bool
    ) -> dict:
        patch_sha = _sha(patch_content)
        base_sha = ("a" if suffix == "1" else "b") * 40
        ids = {
            "repair_request_id": f"r10-synthetic-request-{suffix}",
            "repair_proposal_id": f"r10-synthetic-proposal-{suffix}",
            "repair_verdict_id": f"r10-synthetic-verdict-{suffix}",
        }
        r10 = {"status": "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY", **ids}
        proposal = ObsidureBuilderProposalV1(
            objective=f"Test synthetic R9 {suffix}",
            proposal_kind="REPAIR",
            base_commit_sha=base_sha,
            target_scope=(self.target,),
            files_touched=(self.target,),
            candidate_patch_ref=BuilderPatchRef("repair_candidate.patch", patch_sha),
            tests_proposed=("repair-sandbox-verdict",),
            source_context_refs=(ids["repair_request_id"],),
            declared_evidence={
                "c278_evidence": "CONTINUOUS",
                **ids,
                "tested_artifact_hashes": {self.target: _sha(b"new\n")},
            },
        )
        patch_artifact = ArtifactRef(
            artifact_kind="CANDIDATE_PATCH",
            logical_ref="repair_candidate.patch",
            content_sha256=patch_sha,
            artifact_format="REAL_UNIFIED_DIFF_V1",
        )
        test_artifact = ArtifactRef(
            artifact_kind="TEST_RESULT",
            logical_ref=ids["repair_verdict_id"],
            content_sha256=_sha(f"synthetic-verdict-{suffix}"),
        )
        evidence = EvidenceRecord(
            evidence_kind="TEST_RESULT_EVIDENCE",
            subject_ref=proposal.proposal_id,
            producer_ref="SYNTHETIC_TEST",
            verification_status="VERIFIED",
            artifact_ref=test_artifact,
            scope=(self.target,),
            result="VALIDATED_REPAIR_SANDBOX_PASS",
            provenance={"base_commit_sha": base_sha},
        )
        manifest = build_proposal_manifest(
            proposal,
            candidate_artifacts=(patch_artifact, test_artifact),
            evidence_records=(evidence,),
            verification_obligations=("repair-sandbox-verdict",),
            repo_identity_ref=self.repo_ref,
        )
        policy = ValidationPolicy(
            obligations=(
                ValidationObligation(
                    obligation_kind="UNIT_TEST",
                    target="repair-sandbox-verdict",
                    scope=(self.target,),
                    required=True,
                    expected_evidence_kind="TEST_RESULT_EVIDENCE",
                    allow_observed=False,
                ),
            )
        )
        validation = validate_obsidure_proposal(
            proposal, manifest, validation_policy=policy
        )
        self.assertEqual(validation.validation_verdict, "VALID")
        handoff = build_governance_handoff(
            proposal,
            manifest,
            validation,
            source_metadata={**ids, "c278_evidence": "CONTINUOUS"},
        )
        lineage = {
            "lineage_schema_version": "OBSIDURE_GOVERNED_PATCH_PREPARE_ADAPTER_V1",
            "builder_proposal_id": proposal.proposal_id,
            "builder_manifest_id": manifest.manifest_id,
            "builder_validation_id": validation.validation_id,
            "builder_handoff_id": handoff.handoff_id,
        }
        before_digests = {self.target: _sha(b"old\n")}
        desc = {
            "patch_sha256": patch_sha,
            "target_paths": [self.target],
            "before_digests": before_digests,
            "execution_worktree": str(self.root / "isolated"),
            "main_worktree": str(self.root / "main"),
            "branch_name": f"synthetic/r9-test-{suffix}",
            "base_sha": base_sha,
            "session_id": f"synthetic-r9-session-{suffix}",
            "operation_type": "V2_APPLY_PATCH",
            "descriptor_lineage": lineage,
        }
        eah = _sha(
            json.dumps(
                {
                    "v2_schema": "PC_CAPABILITIES_V2_EAH_V0",
                    "operation_type": "V2_APPLY_PATCH",
                    "action_descriptor": desc,
                },
                sort_keys=True,
            )
        )
        v2id = "v2x-" + _sha(eah + base_sha + desc["session_id"])[:32]
        child = "chd-" + _sha(eah + patch_sha)[:32]
        record = {
            "v2_exec_id": v2id,
            "operation_type": "V2_APPLY_PATCH",
            "eah": eah,
            "descriptor": desc,
            "decision_authority": "KX108_ONLY",
            "created_at": "2026-11-19T00:00:00+00:00",
        }
        raw_desc = json.dumps(record, sort_keys=True, ensure_ascii=False)
        if persist:
            (self.root / "v2exec" / f"{v2id}.json").write_text(
                raw_desc, encoding="utf-8"
            )
            (self.root / "v2exec" / f"{v2id}.patch").write_bytes(
                patch_content.encode("utf-8")
            )
        prepared = {
            "status": "PREPARED_AWAITING_HUMAN_APPROVAL",
            "j5_phase": "PREPARE",
            "operation_type": "V2_APPLY_PATCH",
            "decision_authority": "KX108_ONLY",
            "execution_authority_hash": eah,
            "patch_sha256": patch_sha,
            "target_paths": [self.target],
            "before_digests": before_digests,
            "v2_exec_id": v2id,
            "child_id": child,
            "manifest_hash": _sha(json.dumps(desc, sort_keys=True))[:16],
            "desc_hash": _sha(raw_desc),
            "builder_lineage": dict(lineage),
            "approval_created": False,
            "binder_runtime_called": False,
            "kx108_called": False,
            "executor_invoked": False,
            "physical_mutation": False,
            "action_evidence_id_created": False,
            "validation_equals_approval": False,
            "handoff_equals_authorization": False,
            "prepare_equals_authorization": False,
        }
        r9 = {
            "status": "R10_REPAIR_PREPARED",
            "r9_proposal": proposal,
            "r9_manifest": manifest,
            "r9_validation": validation,
            "r9_handoff": handoff,
            "prepared_action": prepared,
            "patch_content": patch_content,
            "tested_patch_hash": patch_sha,
            "repair_lineage": ids,
            "prepared": True,
            "approval_created": False,
            "kx108_called": False,
            "executor_invoked": False,
            "physical_mutation": False,
            "commit_created": False,
            "push_performed": False,
            "merge_performed": False,
        }
        return {
            "r10": r10,
            "r9": r9,
            "proposal": proposal,
            "manifest": manifest,
            "validation": validation,
            "handoff": handoff,
            "lineage": lineage,
            "v2id": v2id,
            "eah": eah,
            "desc_hash": _sha(raw_desc),
            "patch_sha": patch_sha,
        }

    def _assert_non_authorizing(self, result: dict) -> None:
        self.assertEqual(result.get("decision_authority"), "KX108_ONLY")
        self.assertIs(result.get("execution_authorized"), False)
        self.assertIs(result.get("action_ticket_issued"), False)
        self.assertIs(result.get("target_mutated"), False)
        self.assertNotIn("ticket_id", result)

    def _build_receipt_for_fixture(
        self,
        *,
        outcome: str,
        kx108_verdict: str,
        physical: bool,
        executor_status: str,
        after_digests: dict[str, str] | None = None,
        realized_verified: bool = False,
        builder_lineage_override: dict | None = None,
        v2_exec_id_override: str | None = None,
    ) -> dict:
        fx = self.fixture
        v2id = fx["v2id"]
        exec_input = {"v2_exec_id": v2id, "patch_sha256": fx["patch_sha"]}
        post_state = (
            {
                "target_paths": [self.target],
                "after_digests": after_digests or {self.target: _sha(b"new\n")},
            }
            if after_digests is not None
            else {"status": "NOT_REACHED"}
        )
        return _CRE.build_canonical_receipt_envelope(
            capability="G1_G2_PATCH",
            operation_type="V2_APPLY_PATCH",
            request_ref={
                "public_action": "APPLY_PATCH",
                "builder_lineage": (
                    builder_lineage_override
                    if builder_lineage_override is not None
                    else dict(fx["lineage"])
                ),
            },
            session_ref={"v2_exec_id": v2_exec_id_override or v2id},
            prepare={
                "descriptor_ref": v2id,
                "descriptor_hash": fx["desc_hash"],
                "builder_lineage": dict(fx["lineage"]),
            },
            authorization={
                "execution_authority_hash": fx["eah"],
                "approval_id": "NOT_REACHED",
                "kx108_pre_decision_record_id": "NOT_REACHED",
                "kx108_verdict": kx108_verdict,
                "binder_verdict_status": "NOT_REACHED",
            },
            execution={
                "executor_kind": "GOVERNED_PATCH",
                "executor_operation": "V2_APPLY_PATCH",
                "executor_status": executor_status,
                "executor_input_ref": exec_input,
                "executor_input_hash": _CRE.compute_ref_hash(exec_input),
                "physical_effect_dispatched": physical,
                "mutation_performed": physical,
            },
            realized_state={
                "outcome": outcome,
                "physical_effect_dispatched": physical,
                "mutation_performed": physical,
                "realized_state_verified": realized_verified,
                "proof_strength": "STRONG" if realized_verified else "NONE",
                "post_state_ref": post_state,
                "post_state_hash": _CRE.compute_ref_hash(post_state),
            },
            receipt={"source": "SYNTHETIC_TEST"},
        )

    # ------------------------------------------------------------------
    # C257 : Liaison Handoff -> R9
    # ------------------------------------------------------------------
    def test_c257_handoff_to_r9_lineage_and_substitutions(self) -> None:
        fx = self.fixture
        v2_dir = self.root / "v2exec"
        persisted_before = {p.name: p.read_bytes() for p in v2_dir.iterdir()}

        handoff_res = self.runtime.inspect_obsidure_governance_handoff(
            proposal=fx["proposal"],
            manifest=fx["manifest"],
            validation=fx["validation"],
            handoff=fx["handoff"],
        )
        self.assertEqual(handoff_res["status"], "OBSIDURE_HANDOFF_VERIFIED_READONLY")
        self._assert_non_authorizing(handoff_res)

        r9_res = self.runtime.inspect_obsidure_r9_preparation(
            r10_inspection=fx["r10"],
            r9_result=fx["r9"],
            stores_base_dir=self.root,
            expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(r9_res["status"], "R9_PREPARE_BINDING_MATCH_UNATTESTED")
        expected_builder_lineage = {
            k: v for k, v in fx["lineage"].items() if k != "lineage_schema_version"
        }
        self.assertEqual(r9_res["builder_lineage"], expected_builder_lineage)
        self.assertEqual(r9_res["descriptor_hash"], fx["desc_hash"])
        self.assertEqual(r9_res["patch_sha256"], fx["patch_sha"])
        self._assert_non_authorizing(r9_res)
        self.assertEqual(
            persisted_before, {p.name: p.read_bytes() for p in v2_dir.iterdir()}
        )

        # Falsification individuelle de chacun des 4 identifiants dans prepared_action
        lineage_keys = (
            "builder_proposal_id",
            "builder_manifest_id",
            "builder_validation_id",
            "builder_handoff_id",
        )
        for key in lineage_keys:
            with self.subTest(target="prepared_action", falsified_key=key):
                mutated_r9 = {
                    **fx["r9"],
                    "prepared_action": {
                        **fx["r9"]["prepared_action"],
                        "builder_lineage": {
                            **fx["lineage"],
                            key: fx["lineage"][key] + "-forged",
                        },
                    },
                }
                res = self.runtime.inspect_obsidure_r9_preparation(
                    r10_inspection=fx["r10"],
                    r9_result=mutated_r9,
                    stores_base_dir=self.root,
                    expected_repo_identity_ref=self.repo_ref,
                )
                self.assertEqual(res["status"], "HOLD")
                self.assertEqual(res["reason"], "R9_BUILDER_LINEAGE_OR_OPERATION_MISMATCH")
                self._assert_non_authorizing(res)

        # Falsification individuelle de chacun des 4 identifiants dans le descripteur persisté
        desc_path = v2_dir / f"{fx['v2id']}.json"
        original_desc_bytes = desc_path.read_bytes()
        try:
            for key in lineage_keys:
                with self.subTest(target="persisted_descriptor", falsified_key=key):
                    rec = json.loads(original_desc_bytes.decode("utf-8"))
                    rec["descriptor"]["descriptor_lineage"][key] += "-tampered"
                    desc_path.write_text(
                        json.dumps(rec, sort_keys=True, ensure_ascii=False),
                        encoding="utf-8",
                    )
                    res = self.runtime.inspect_obsidure_r9_preparation(
                        r10_inspection=fx["r10"],
                        r9_result=fx["r9"],
                        stores_base_dir=self.root,
                        expected_repo_identity_ref=self.repo_ref,
                    )
                    self.assertEqual(res["status"], "HOLD")
                    self.assertEqual(
                        res["reason"], "R9_PERSISTED_DESCRIPTOR_BINDING_MISMATCH"
                    )
                    self._assert_non_authorizing(res)
        finally:
            desc_path.write_bytes(original_desc_bytes)

        # Substitution d'un autre objet canonique valide (proposal, manifest, validation, handoff)
        fx2 = self._build_r9_fixture(
            suffix="2",
            patch_content="--- a/scripts/tool.py\n+++ b/scripts/tool.py\n@@ -1 +1 @@\n-old\n+other\n",
            persist=False,
        )
        for field in ("r9_proposal", "r9_manifest", "r9_validation", "r9_handoff"):
            with self.subTest(substituted_field=field):
                mutated_r9 = {**fx["r9"], field: fx2["r9"][field]}
                res = self.runtime.inspect_obsidure_r9_preparation(
                    r10_inspection=fx["r10"],
                    r9_result=mutated_r9,
                    stores_base_dir=self.root,
                    expected_repo_identity_ref=self.repo_ref,
                )
                self.assertEqual(res["status"], "HOLD")
                self._assert_non_authorizing(res)

    # ------------------------------------------------------------------
    # C258 : Provenance et authenticité strictement séparées
    # ------------------------------------------------------------------
    def test_c258_strict_separation_structural_vs_provenance_and_authority(self) -> None:
        fx = self.fixture
        r9_res = self.runtime.inspect_obsidure_r9_preparation(
            r10_inspection=fx["r10"],
            r9_result=fx["r9"],
            stores_base_dir=self.root,
            expected_repo_identity_ref=self.repo_ref,
        )
        # Intégrité structurelle et liaison vérifiées, mais provenance/sandbox/autorité = False
        self.assertIs(r9_res["artifact_binding_verified"], True)
        self.assertIs(r9_res["provenance_verified"], False)
        self.assertIs(r9_res["sandbox_origin_attested"], False)
        self.assertIs(r9_res["live_git_head_verified"], False)
        self.assertIs(r9_res["human_approval_verified"], False)
        self.assertIs(r9_res["kx108_pre_invoked"], False)
        self.assertIn("R9_SANDBOX_ORIGIN_NOT_AUTHENTICATED", r9_res["evidence_limits"])
        self.assertIn("PREPARE_IS_NOT_HUMAN_APPROVAL", r9_res["evidence_limits"])
        self._assert_non_authorizing(r9_res)

    # ------------------------------------------------------------------
    # C259 : Continuité R9 -> R12 et refus des contradictions
    # ------------------------------------------------------------------
    def test_c259_r9_to_r12_continuity_and_contradiction_refusal(self) -> None:
        fx = self.fixture

        # 1. Reçu historique KX108_HOLD cohérent avec R9
        hold_env = self._build_receipt_for_fixture(
            outcome=_CRE.OUTCOME_KX108_HOLD,
            kx108_verdict="HOLD",
            physical=False,
            executor_status="NOT_REACHED",
        )
        self.assertEqual(
            _CRE.store_canonical_receipt_envelope(hold_env, self.root / "receipts")[
                "status"
            ],
            _CRE.STATUS_STORED,
        )
        r12_hold = self.runtime.inspect_obsidure_r9_r12_outcome(
            action_evidence_id=hold_env["action_evidence_id"],
            stores_base_dir=self.root,
            r10_inspection=fx["r10"],
            r9_result=fx["r9"],
            expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(r12_hold["derived_outcome_classification"], "PRE_DISPATCH_FAILURE")
        self.assertEqual(r12_hold["recommendation"], "STOP_BLOCKED")
        self.assertIs(r12_hold["r9_artifact_binding_verified"], True)
        self.assertIs(r12_hold["r9_provenance_verified"], False)
        self.assertIs(r12_hold["release_authorized"], False)
        self._assert_non_authorizing(r12_hold)

        # 2. Contradiction : builder_lineage différent dans le reçu R8
        bad_lineage_env = self._build_receipt_for_fixture(
            outcome=_CRE.OUTCOME_KX108_HOLD,
            kx108_verdict="HOLD",
            physical=False,
            executor_status="NOT_REACHED",
            builder_lineage_override={
                **fx["lineage"],
                "builder_handoff_id": "obh-" + "0" * 64,
            },
        )
        _CRE.store_canonical_receipt_envelope(bad_lineage_env, self.root / "receipts")
        r12_bad_lin = self.runtime.inspect_obsidure_r9_r12_outcome(
            action_evidence_id=bad_lineage_env["action_evidence_id"],
            stores_base_dir=self.root,
            r10_inspection=fx["r10"],
            r9_result=fx["r9"],
            expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(r12_bad_lin["reason"], "R8_BUILDER_LINEAGE_MISMATCH")
        self.assertEqual(
            r12_bad_lin["derived_outcome_classification"], "GOVERNANCE_MISMATCH"
        )
        self._assert_non_authorizing(r12_bad_lin)

        # 3. Contradiction : v2_exec_id différent dans session_ref du reçu R8
        bad_v2_env = self._build_receipt_for_fixture(
            outcome=_CRE.OUTCOME_KX108_HOLD,
            kx108_verdict="HOLD",
            physical=False,
            executor_status="NOT_REACHED",
            v2_exec_id_override="v2x-" + "9" * 32,
        )
        _CRE.store_canonical_receipt_envelope(bad_v2_env, self.root / "receipts")
        r12_bad_v2 = self.runtime.inspect_obsidure_r9_r12_outcome(
            action_evidence_id=bad_v2_env["action_evidence_id"],
            stores_base_dir=self.root,
            r10_inspection=fx["r10"],
            r9_result=fx["r9"],
            expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(r12_bad_v2["reason"], "R8_V2_EXEC_LINEAGE_MISMATCH")
        self._assert_non_authorizing(r12_bad_v2)

        # 4. Reçu altéré (envelope_hash invalide) refusé
        tampered_path = (
            self.root / "receipts" / f"{hold_env['action_evidence_id']}.json"
        )
        tampered_data = json.loads(tampered_path.read_text(encoding="utf-8"))
        tampered_data["envelope_hash"] = "0" * 64
        tampered_path.write_text(json.dumps(tampered_data), encoding="utf-8")
        r12_tampered = self.runtime.inspect_obsidure_r9_r12_outcome(
            action_evidence_id=hold_env["action_evidence_id"],
            stores_base_dir=self.root,
            r10_inspection=fx["r10"],
            r9_result=fx["r9"],
            expected_repo_identity_ref=self.repo_ref,
        )
        self.assertIn("ENVELOPE_HASH_MISMATCH", r12_tampered["reason"])
        self.assertEqual(
            r12_tampered["derived_outcome_classification"], "EVIDENCE_TAMPERED"
        )
        self._assert_non_authorizing(r12_tampered)

    # ------------------------------------------------------------------
    # C260 : Reçus canoniques, rejeu d'intégrité et réconciliation
    # ------------------------------------------------------------------
    def test_c260_canonical_receipt_envelope_replay_and_reconciliation(self) -> None:
        receipts_dir = self.root / "receipts"
        hold_env = self._build_receipt_for_fixture(
            outcome=_CRE.OUTCOME_KX108_HOLD,
            kx108_verdict="HOLD",
            physical=False,
            executor_status="NOT_REACHED",
        )
        ok, reason = _CRE.verify_canonical_receipt_envelope(hold_env)
        self.assertTrue(ok, reason)

        # Immutabilité & idempotence du store
        self.assertEqual(
            _CRE.store_canonical_receipt_envelope(hold_env, receipts_dir)["status"],
            _CRE.STATUS_STORED,
        )
        self.assertEqual(
            _CRE.store_canonical_receipt_envelope(hold_env, receipts_dir)["status"],
            _CRE.STATUS_IDEMPOTENT,
        )
        mutated_same_id = {**hold_env, "created_at": "2026-11-20T00:00:00+00:00"}
        mutated_same_id["envelope_hash"] = _CRE.compute_envelope_hash(mutated_same_id)
        self.assertEqual(
            _CRE.store_canonical_receipt_envelope(mutated_same_id, receipts_dir)[
                "status"
            ],
            _CRE.STATUS_IMMUTABILITY_VIOLATION,
        )

        # Rejeu et réconciliation sur KX108_HOLD
        replay_hold = _R8_REPLAY.replay_action_evidence(
            hold_env["action_evidence_id"], stores_base_dir=self.root
        )
        self.assertEqual(replay_hold["replay_verdict"], _R8_REPLAY.VERDICT_VERIFIED)
        self.assertEqual(replay_hold["descriptor_ref_valid"], _R8_REPLAY.YES)
        self.assertEqual(replay_hold["EAH_binding_valid"], _R8_REPLAY.YES)
        self.assertEqual(replay_hold["outcome_consistency_valid"], _R8_REPLAY.YES)

        recon_hold = _R8_RECON.reconcile_action_evidence(
            hold_env["action_evidence_id"], stores_base_dir=self.root
        )
        self.assertEqual(recon_hold["reconciliation_status"], _R8_RECON.STATUS_NOT_REALIZED)

        # Réconciliation APPLY_PATCH : MATCH vs MISMATCH (after_digests == before_digests)
        success_env = self._build_receipt_for_fixture(
            outcome=_CRE.OUTCOME_SUCCESS,
            kx108_verdict="ALLOW",
            physical=True,
            executor_status="EXECUTED",
            after_digests={self.target: _sha(b"new\n")},
            realized_verified=True,
        )
        _CRE.store_canonical_receipt_envelope(success_env, receipts_dir)
        recon_match = _R8_RECON.reconcile_action_evidence(
            success_env["action_evidence_id"], stores_base_dir=self.root
        )
        self.assertEqual(recon_match["reconciliation_status"], _R8_RECON.STATUS_MATCH)

        # On utilise un action_evidence_id distinct (via executor_input_ref) pour tester MISMATCH
        unchanged_env = self._build_receipt_for_fixture(
            outcome=_CRE.OUTCOME_SUCCESS,
            kx108_verdict="ALLOW",
            physical=True,
            executor_status="EXECUTED",
            after_digests={self.target: _sha(b"old\n")},
            realized_verified=True,
        )
        unchanged_env["action_identity"] = {"case": "unchanged_after_digest"}
        unchanged_env["action_evidence_id"] = _CRE.compute_action_evidence_id(unchanged_env)
        unchanged_env["envelope_hash"] = _CRE.compute_envelope_hash(unchanged_env)
        self.assertEqual(
            _CRE.store_canonical_receipt_envelope(unchanged_env, receipts_dir)["status"],
            _CRE.STATUS_STORED,
        )
        recon_mismatch = _R8_RECON.reconcile_action_evidence(
            unchanged_env["action_evidence_id"], stores_base_dir=self.root
        )
        self.assertEqual(recon_mismatch["reconciliation_status"], _R8_RECON.STATUS_MISMATCH)

        # Reçu absent : NOT_FOUND (jamais de reçu fabriqué)
        missing_id = "aev-" + "0" * 32
        self.assertEqual(
            _R8_REPLAY.replay_action_evidence(missing_id, stores_base_dir=self.root)[
                "replay_verdict"
            ],
            _R8_REPLAY.VERDICT_NOT_FOUND,
        )
        self.assertEqual(
            _R8_RECON.reconcile_action_evidence(missing_id, stores_base_dir=self.root)[
                "reconciliation_status"
            ],
            _R8_RECON.STATUS_NOT_FOUND,
        )


if __name__ == "__main__":
    unittest.main()
