"""C264-C268 : Intégration C2/D1, continuité runtime P1 et tests adversariaux transversaux.

Tous les artefacts et magasins sont synthétiques et temporaires :
- KX108_AUTHORITY=UNCHANGED
- RELEASE=HOLD
- REAL_ACT=False
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT / "periphery" / "world_calls", ROOT / "scripts", ROOT):
    _s = str(folder)
    if _s in sys.path:
        sys.path.remove(_s)
    sys.path.insert(0, _s)

import obsidia_canonical_receipt_envelope_v1 as _CRE
import obsidia_canonical_receipt_replay_v1 as _R8_REPLAY
import obsidia_kx108_decision_store as _DS
import obsidia_post_execution_disposition_v0 as _DISP
import obsidia_realized_state_reconciliation_v1 as _R8_RECON
import obsidia_sealed_evidence_v0 as _SEV
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
from periphery.world_calls import ticket_store as _TS


def _sha(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


class P1C264ToC268ContinuityAndAdversarialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-c264-c268-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for sub in ("v2exec", "approval", "kxpre", "receipts", "sre", "sar", "kxpost"):
            (self.root / sub).mkdir()
        self.runtime = ObsidiaGovernanceRuntime()
        self.target = "scripts/tool.py"
        self.repo_ref = "synthetic-c264-c268-repo"
        self.pre_bytes = b"old\n"
        self.post_bytes = b"new\n"
        self.patch = "--- a/scripts/tool.py\n+++ b/scripts/tool.py\n@@ -1 +1 @@\n-old\n+new\n"
        self.patch_sha = _sha(self.patch)
        self.base_sha = "a" * 40
        self.ids = {
            "repair_request_id": "r10-c266-req",
            "repair_proposal_id": "r10-c266-prop",
            "repair_verdict_id": "r10-c266-verd",
        }
        self.r10 = {"status": "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY", **self.ids}
        self.proposal = ObsidureBuilderProposalV1(
            objective="C266 synthetic continuity",
            proposal_kind="REPAIR",
            base_commit_sha=self.base_sha,
            target_scope=(self.target,),
            files_touched=(self.target,),
            candidate_patch_ref=BuilderPatchRef("repair.patch", self.patch_sha),
            tests_proposed=("repair-sandbox-verdict",),
            source_context_refs=(self.ids["repair_request_id"],),
            declared_evidence={"c278_evidence": "CONTINUOUS", **self.ids},
        )
        patch_art = ArtifactRef(
            artifact_kind="CANDIDATE_PATCH",
            logical_ref="repair.patch",
            content_sha256=self.patch_sha,
            artifact_format="REAL_UNIFIED_DIFF_V1",
        )
        test_art = ArtifactRef(
            artifact_kind="TEST_RESULT",
            logical_ref=self.ids["repair_verdict_id"],
            content_sha256=_sha("c266-verdict"),
        )
        ev = EvidenceRecord(
            evidence_kind="TEST_RESULT_EVIDENCE",
            subject_ref=self.proposal.proposal_id,
            producer_ref="SYNTHETIC_TEST",
            verification_status="VERIFIED",
            artifact_ref=test_art,
            scope=(self.target,),
            result="PASS",
            provenance={"base_commit_sha": self.base_sha},
        )
        self.manifest = build_proposal_manifest(
            self.proposal,
            candidate_artifacts=(patch_art, test_art),
            evidence_records=(ev,),
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
        self.validation = validate_obsidure_proposal(
            self.proposal, self.manifest, validation_policy=policy
        )
        self.handoff = build_governance_handoff(
            self.proposal,
            self.manifest,
            self.validation,
            source_metadata={**self.ids, "c278_evidence": "CONTINUOUS"},
        )
        self.lineage = {
            "lineage_schema_version": "OBSIDURE_GOVERNED_PATCH_PREPARE_ADAPTER_V1",
            "builder_proposal_id": self.proposal.proposal_id,
            "builder_manifest_id": self.manifest.manifest_id,
            "builder_validation_id": self.validation.validation_id,
            "builder_handoff_id": self.handoff.handoff_id,
        }
        before = {self.target: _sha(self.pre_bytes)}
        desc = {
            "patch_sha256": self.patch_sha,
            "target_paths": [self.target],
            "before_digests": before,
            "execution_worktree": str(self.root / "iso"),
            "main_worktree": str(self.root / "main"),
            "branch_name": "synthetic/c266",
            "base_sha": self.base_sha,
            "session_id": "c266-sess",
            "operation_type": "V2_APPLY_PATCH",
            "descriptor_lineage": self.lineage,
        }
        self.eah = _sha(
            json.dumps(
                {
                    "v2_schema": "PC_CAPABILITIES_V2_EAH_V0",
                    "operation_type": "V2_APPLY_PATCH",
                    "action_descriptor": desc,
                },
                sort_keys=True,
            )
        )
        self.v2id = "v2x-" + _sha(self.eah + self.base_sha + desc["session_id"])[:32]
        self.child_id = "chd-" + _sha(self.eah + self.patch_sha)[:32]
        record = {
            "v2_exec_id": self.v2id,
            "operation_type": "V2_APPLY_PATCH",
            "eah": self.eah,
            "descriptor": desc,
            "decision_authority": "KX108_ONLY",
        }
        raw_desc = json.dumps(record, sort_keys=True, ensure_ascii=False)
        (self.root / "v2exec" / f"{self.v2id}.json").write_text(raw_desc, encoding="utf-8")
        (self.root / "v2exec" / f"{self.v2id}.patch").write_bytes(self.patch.encode("utf-8"))
        self.desc_hash = _sha(raw_desc)
        self.r9 = {
            "status": "R10_REPAIR_PREPARED",
            "r9_proposal": self.proposal,
            "r9_manifest": self.manifest,
            "r9_validation": self.validation,
            "r9_handoff": self.handoff,
            "prepared_action": {
                "status": "PREPARED_AWAITING_HUMAN_APPROVAL",
                "j5_phase": "PREPARE",
                "operation_type": "V2_APPLY_PATCH",
                "decision_authority": "KX108_ONLY",
                "execution_authority_hash": self.eah,
                "patch_sha256": self.patch_sha,
                "target_paths": [self.target],
                "before_digests": before,
                "v2_exec_id": self.v2id,
                "child_id": self.child_id,
                "manifest_hash": _sha(json.dumps(desc, sort_keys=True))[:16],
                "desc_hash": self.desc_hash,
                "builder_lineage": dict(self.lineage),
                "approval_created": False,
                "binder_runtime_called": False,
                "kx108_called": False,
                "executor_invoked": False,
                "physical_mutation": False,
                "action_evidence_id_created": False,
                "validation_equals_approval": False,
                "handoff_equals_authorization": False,
                "prepare_equals_authorization": False,
            },
            "patch_content": self.patch,
            "tested_patch_hash": self.patch_sha,
            "repair_lineage": self.ids,
            "prepared": True,
            "approval_created": False,
            "kx108_called": False,
            "executor_invoked": False,
            "physical_mutation": False,
            "commit_created": False,
            "push_performed": False,
            "merge_performed": False,
        }
        self.c2_child = {
            "child_execution_id": self.child_id,
            "target_path": self.target,
            "target_pre_sha256": _sha(self.pre_bytes),
            "source_content_sha256": _sha(self.post_bytes),
            "operation_type": _SEV.OPERATION_TYPE,
            "source_kind": "GIT_BLOB",
            "source_path": self.target,
            "source_git_commit_sha": self.base_sha,
            "source_git_blob_sha": "b" * 40,
            "source_git_historical_path": self.target,
        }

    def _write_simulated_kx108_post(
        self,
        *,
        record_id: str,
        gate: str,
        phase: str = _DS.POST_DECISION_PHASE,
        linked_pre: bool = True,
    ) -> dict:
        # Fixture explicitement non souveraine pour rejeu D1 uniquement
        rec = {
            "decision_record_schema_version": 1,
            "decision_record_id": record_id,
            "created_at": "2026-11-24T00:00:00+00:00",
            "decision_phase": phase,
            "batch_execution_id": self.v2id,
            "child_execution_id": self.child_id,
            "execution_authority_hash": self.eah,
            "approval_id": "apr-synthetic",
            "test_contract_hash": "c" * 64,
            "test_result_id": "tcr-synthetic",
            "test_result_record_hash": "d" * 64,
            "kx108_input_translation_hash": "1" * 64,
            "decision_id": "dec-sim-1",
            "trace_id": "trc-sim-1",
            "domain": "tooling_build",
            "x108_gate": gate,
            "reason_code": "OK" if gate == "ALLOW" else "HOLD_GATE",
            "severity": "S0" if gate == "ALLOW" else "S2",
            "market_verdict": "ACT" if gate == "ALLOW" else gate,
            "contradictions": [],
            "unknowns": [],
            "risk_flags": [],
            "decision_authority": "KX108_ONLY",
            "canonical_envelope": {"x108_gate": gate},
        }
        if phase == _DS.PRE_DECISION_PHASE:
            rec.pop("test_result_id")
            rec.pop("test_result_record_hash")
            rec["pre_execution_context_id"] = "pec-sim"
            rec["pre_execution_context_record_hash"] = "2" * 64
        if linked_pre:
            rec["kx108_pre_decision_record_id"] = "kxpre-sim-1"
            rec["kx108_pre_decision_record_hash"] = "f" * 64
        rec["decision_record_hash"] = _DS.compute_kx108_decision_record_hash(rec)
        (self.root / "kxpost" / f"{record_id}.json").write_text(
            json.dumps(rec, sort_keys=True), encoding="utf-8"
        )
        return rec

    # ------------------------------------------------------------------
    # C264 : Intégration et falsification des preuves scellées C2
    # ------------------------------------------------------------------
    def test_c264_sealed_evidence_c2_contracts_and_substitutions(self) -> None:
        sre, err = _SEV.build_sealed_rollback_evidence(
            batch_execution_id=self.v2id,
            child=self.c2_child,
            execution_authority_hash=self.eah,
            approval_id="apr-1",
            kx108_pre_decision_record_id="kxpre-1",
            kx108_pre_decision_record_hash="f" * 64,
            preimage_bytes=self.pre_bytes,
        )
        self.assertIsNone(err)
        self.assertEqual(_SEV.verify_sealed_rollback_evidence(sre), (True, None))

        sar, err = _SEV.build_sealed_apply_receipt(
            batch_execution_id=self.v2id,
            child=self.c2_child,
            execution_authority_hash=self.eah,
            approval_id="apr-1",
            kx108_pre_decision_record_id="kxpre-1",
            kx108_pre_decision_record_hash="f" * 64,
            sealed_rollback_evidence_id=sre["sealed_rollback_evidence_id"],
            sealed_rollback_evidence_hash=sre["sealed_rollback_evidence_hash"],
            target_pre_sha256=_sha(self.pre_bytes),
            target_post_sha256=_sha(self.post_bytes),
            bytes_written=len(self.post_bytes),
        )
        self.assertIsNone(err)
        self.assertEqual(_SEV.verify_sealed_apply_receipt(sar), (True, None))
        legacy = _SEV.as_legacy_receipt_dict(sar)
        self.assertEqual(legacy["sealed_apply_receipt_id"], sar["sealed_apply_receipt_id"])
        self.assertEqual(legacy["sealed_apply_receipt_hash"], sar["sealed_apply_receipt_hash"])

        # Falsifications SRE/SAR
        bad_preimage = {**sre, "pre_write_bytes_b64": base64.b64encode(b"tampered").decode("ascii")}
        self.assertEqual(_SEV.verify_sealed_rollback_evidence(bad_preimage), (False, "PREIMAGE_SHA256_MISMATCH"))
        bad_sre_hash = {**sre, "sealed_rollback_evidence_hash": "0" * 64}
        self.assertEqual(_SEV.verify_sealed_rollback_evidence(bad_sre_hash), (False, "SEALED_ROLLBACK_EVIDENCE_HASH_MISMATCH"))
        bad_sar_hash = {**sar, "sealed_apply_receipt_hash": "0" * 64}
        self.assertEqual(_SEV.verify_sealed_apply_receipt(bad_sar_hash), (False, "SEALED_APPLY_RECEIPT_HASH_MISMATCH"))
        self.assertEqual(_SEV.verify_sealed_apply_receipt({**sar, "sealed": False}), (False, "NOT_SEALED"))
        self.assertEqual(_SEV.verify_sealed_apply_receipt({**sar, "decision_authority": "LOCAL"}), (False, "DECISION_AUTHORITY_NOT_KX108_ONLY"))

    # ------------------------------------------------------------------
    # C265 : Intégration de la disposition D1
    # ------------------------------------------------------------------
    def test_c265_disposition_d1_and_non_authorization(self) -> None:
        # 1. Preuve absente -> MUST_ROLLBACK
        self.assertEqual(
            _DISP.classify_post_execution_disposition(
                post_decision_record_id="kxpost-missing", post_decision_store_dir=self.root / "kxpost"
            )["disposition"],
            _DISP.MUST_ROLLBACK,
        )
        # 2. POST HOLD lié -> MUST_ROLLBACK
        self._write_simulated_kx108_post(record_id="kxpost-hold", gate="HOLD", linked_pre=True)
        hold_d = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kxpost-hold", post_decision_store_dir=self.root / "kxpost"
        )
        self.assertEqual(hold_d["disposition"], _DISP.MUST_ROLLBACK)
        self.assertIs(hold_d["commit_review_eligible"], False)
        self.assertIs(hold_d["write_capability"], False)

        # 3. Échec d'exécution -> MUST_ROLLBACK
        fail_d = _DISP.classify_post_execution_disposition(failure_signal="KX108_POST_INVOCATION_FAILURE")
        self.assertEqual(fail_d["disposition"], _DISP.MUST_ROLLBACK)

        # 4. POST ALLOW lié -> KEEP_ELIGIBLE_FOR_HUMAN_COMMIT_REVIEW (jamais auto-commit)
        self._write_simulated_kx108_post(record_id="kxpost-allow", gate="ALLOW", linked_pre=True)
        allow_d = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kxpost-allow", post_decision_store_dir=self.root / "kxpost"
        )
        self.assertEqual(allow_d["disposition"], _DISP.MUST_ROLLBACK)
        self.assertIs(allow_d["write_capability"], False)
        self.assertEqual(allow_d["authority"], "NON_SOVEREIGN")

        # 5. POST contradictoire (phase PRE ou non lié) -> DISPOSITION_HOLD
        self._write_simulated_kx108_post(
            record_id="kxpost-pre-phase", gate="ALLOW", phase=_DS.PRE_DECISION_PHASE, linked_pre=False
        )
        self.assertEqual(
            _DISP.classify_post_execution_disposition(
                post_decision_record_id="kxpost-pre-phase", post_decision_store_dir=self.root / "kxpost"
            )["disposition"],
            _DISP.MUST_ROLLBACK,
        )
        self._write_simulated_kx108_post(record_id="kxpost-unlinked", gate="ALLOW", linked_pre=False)
        self.assertEqual(
            _DISP.classify_post_execution_disposition(
                post_decision_record_id="kxpost-unlinked", post_decision_store_dir=self.root / "kxpost"
            )["disposition"],
            _DISP.MUST_ROLLBACK,
        )

        # 6. Reçu/record POST falsifié -> MUST_ROLLBACK
        rec_tampered = self._write_simulated_kx108_post(record_id="kxpost-tampered", gate="ALLOW", linked_pre=True)
        rec_tampered["decision_record_hash"] = "0" * 64
        (self.root / "kxpost" / "kxpost-tampered.json").write_text(json.dumps(rec_tampered), encoding="utf-8")
        tampered_d = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kxpost-tampered", post_decision_store_dir=self.root / "kxpost"
        )
        self.assertEqual(tampered_d["disposition"], _DISP.MUST_ROLLBACK)
        self.assertIn("DECISION_RECORD_HASH_MISMATCH", tampered_d["reason"])

    # ------------------------------------------------------------------
    # C266 : Continuité C2/D1 avec le runtime P1 (sans APPLY réel)
    # ------------------------------------------------------------------
    def test_c266_end_to_end_handoff_r9_c2_kx108_r8_reconcile_d1_replay(self) -> None:
        # 1. Handoff Obsidure
        h = self.runtime.inspect_obsidure_governance_handoff(
            proposal=self.proposal, manifest=self.manifest, validation=self.validation, handoff=self.handoff
        )
        self.assertEqual(h["status"], "OBSIDURE_HANDOFF_VERIFIED_READONLY")

        # 2. Préparation R9
        r9 = self.runtime.inspect_obsidure_r9_preparation(
            r10_inspection=self.r10, r9_result=self.r9,
            stores_base_dir=self.root, expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(r9["status"], "R9_PREPARE_BINDING_MATCH_UNATTESTED")

        # 3. Évidence C2 (liée au v2_exec_id / EAH / child_id de R9)
        sre, err = _SEV.build_sealed_rollback_evidence(
            batch_execution_id=r9["v2_exec_id"], child=self.c2_child,
            execution_authority_hash=self.eah, approval_id="apr-sim",
            kx108_pre_decision_record_id="kxpre-sim-1", kx108_pre_decision_record_hash="f" * 64,
            preimage_bytes=self.pre_bytes,
        )
        self.assertIsNone(err)
        _SEV.store_sealed_rollback_evidence(sre, self.root / "sre")
        sar, err = _SEV.build_sealed_apply_receipt(
            batch_execution_id=r9["v2_exec_id"], child=self.c2_child,
            execution_authority_hash=self.eah, approval_id="apr-sim",
            kx108_pre_decision_record_id="kxpre-sim-1", kx108_pre_decision_record_hash="f" * 64,
            sealed_rollback_evidence_id=sre["sealed_rollback_evidence_id"],
            sealed_rollback_evidence_hash=sre["sealed_rollback_evidence_hash"],
            target_pre_sha256=_sha(self.pre_bytes), target_post_sha256=_sha(self.post_bytes),
            bytes_written=len(self.post_bytes),
        )
        self.assertIsNone(err)
        _SEV.store_sealed_apply_receipt(sar, self.root / "sar")

        # 4. Décision KX108 simulée non souveraine (HOLD)
        self._write_simulated_kx108_post(record_id="kxpost-c266-hold", gate="HOLD", linked_pre=True)

        # 5. Reçu canonique R8 + R12
        exec_in = {"v2_exec_id": r9["v2_exec_id"], "patch_sha256": r9["patch_sha256"]}
        env = _CRE.build_canonical_receipt_envelope(
            capability="G1_G2_PATCH", operation_type="V2_APPLY_PATCH",
            request_ref={"public_action": "APPLY_PATCH", "builder_lineage": r9["builder_lineage"]},
            session_ref={"v2_exec_id": r9["v2_exec_id"]},
            prepare={"descriptor_ref": r9["v2_exec_id"], "descriptor_hash": r9["descriptor_hash"], "builder_lineage": r9["builder_lineage"]},
            authorization={"execution_authority_hash": self.eah, "approval_id": "NOT_REACHED", "kx108_pre_decision_record_id": "NOT_REACHED", "kx108_verdict": "HOLD", "binder_verdict_status": "NOT_REACHED"},
            execution={"executor_kind": "GOVERNED_PATCH", "executor_operation": "V2_APPLY_PATCH", "executor_status": "NOT_REACHED", "executor_input_ref": exec_in, "executor_input_hash": _CRE.compute_ref_hash(exec_in), "physical_effect_dispatched": False, "mutation_performed": False},
            realized_state={"outcome": _CRE.OUTCOME_KX108_HOLD, "physical_effect_dispatched": False, "mutation_performed": False, "realized_state_verified": False, "proof_strength": "NONE", "post_state_ref": {"status": "NOT_REACHED"}, "post_state_hash": _CRE.compute_ref_hash({"status": "NOT_REACHED"})},
            receipt={"source": "SYNTHETIC_C266"},
        )
        _CRE.store_canonical_receipt_envelope(env, self.root / "receipts")
        aev = env["action_evidence_id"]

        r12 = self.runtime.inspect_obsidure_r9_r12_outcome(
            action_evidence_id=aev, stores_base_dir=self.root,
            r10_inspection=self.r10, r9_result=self.r9, expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(r12["derived_outcome_classification"], "PRE_DISPATCH_FAILURE")
        self.assertIs(r12["release_authorized"], False)
        self.assertIs(r12["execution_authorized"], False)

        # 6. Réconciliation R8
        recon = _R8_RECON.reconcile_action_evidence(aev, stores_base_dir=self.root)
        self.assertEqual(recon["reconciliation_status"], _R8_RECON.STATUS_NOT_REALIZED)

        # 7. Disposition D1
        disp = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kxpost-c266-hold", post_decision_store_dir=self.root / "kxpost"
        )
        self.assertEqual(disp["disposition"], _DISP.MUST_ROLLBACK)
        self.assertIs(disp["write_capability"], False)

    # ------------------------------------------------------------------
    # C268 : Tests adversariaux transversaux (10 falsifications)
    # ------------------------------------------------------------------
    def test_c268_cross_cutting_adversarial_falsifications(self) -> None:
        # 1-3 : Identifiant proposition, manifeste, validation remplacé dans R9
        for key in ("builder_proposal_id", "builder_manifest_id", "builder_validation_id"):
            with self.subTest(case=f"replace_{key}"):
                bad_r9 = {
                    **self.r9,
                    "prepared_action": {
                        **self.r9["prepared_action"],
                        "builder_lineage": {**self.lineage, key: "forged-id"},
                    },
                }
                res = self.runtime.inspect_obsidure_r9_preparation(
                    r10_inspection=self.r10, r9_result=bad_r9,
                    stores_base_dir=self.root, expected_repo_identity_ref=self.repo_ref,
                )
                self.assertEqual(res["status"], "HOLD")
                self.assertIs(res["execution_authorized"], False)

        # 4 : Décision KX108 non liée
        self._write_simulated_kx108_post(record_id="kx-unlinked-c268", gate="ALLOW", linked_pre=False)
        self.assertEqual(
            _DISP.classify_post_execution_disposition(
                post_decision_record_id="kx-unlinked-c268", post_decision_store_dir=self.root / "kxpost"
            )["disposition"],
            _DISP.MUST_ROLLBACK,
        )

        # 5 : Reçu C2 modifié
        sre, _ = _SEV.build_sealed_rollback_evidence(
            batch_execution_id=self.v2id, child=self.c2_child,
            execution_authority_hash=self.eah, approval_id="apr-1",
            kx108_pre_decision_record_id="kxpre-1", kx108_pre_decision_record_hash="f" * 64,
            preimage_bytes=self.pre_bytes,
        )
        self.assertEqual(
            _SEV.verify_sealed_rollback_evidence({**sre, "pre_write_size": 999}),
            (False, "PREIMAGE_SIZE_MISMATCH"),
        )

        # 6 : Reçu R8 contradictoire (v2_exec_id divergent)
        exec_in = {"v2_exec_id": self.v2id}
        bad_r8 = _CRE.build_canonical_receipt_envelope(
            capability="G1_G2_PATCH", operation_type="V2_APPLY_PATCH",
            request_ref={"public_action": "APPLY_PATCH", "builder_lineage": dict(self.lineage)},
            session_ref={"v2_exec_id": "v2x-" + "9" * 32},
            prepare={"descriptor_ref": self.v2id, "descriptor_hash": self.desc_hash, "builder_lineage": dict(self.lineage)},
            authorization={"execution_authority_hash": self.eah, "approval_id": "NOT_REACHED", "kx108_pre_decision_record_id": "NOT_REACHED", "kx108_verdict": "HOLD", "binder_verdict_status": "NOT_REACHED"},
            execution={"executor_kind": "GOVERNED_PATCH", "executor_operation": "V2_APPLY_PATCH", "executor_status": "NOT_REACHED", "executor_input_ref": exec_in, "executor_input_hash": _CRE.compute_ref_hash(exec_in), "physical_effect_dispatched": False, "mutation_performed": False},
            realized_state={"outcome": _CRE.OUTCOME_KX108_HOLD, "physical_effect_dispatched": False, "mutation_performed": False, "realized_state_verified": False, "proof_strength": "NONE", "post_state_ref": {"status": "NOT_REACHED"}, "post_state_hash": _CRE.compute_ref_hash({"status": "NOT_REACHED"})},
            receipt={"source": "SYNTHETIC_C268"},
        )
        _CRE.store_canonical_receipt_envelope(bad_r8, self.root / "receipts")
        self.assertEqual(
            self.runtime.inspect_obsidure_r9_r12_outcome(
                action_evidence_id=bad_r8["action_evidence_id"], stores_base_dir=self.root,
                r10_inspection=self.r10, r9_result=self.r9, expected_repo_identity_ref=self.repo_ref,
            )["reason"],
            "R8_V2_EXEC_LINEAGE_MISMATCH",
        )

        # 7 : État réalisé divergent (after == before sur SUCCESS)
        div_r8 = _CRE.build_canonical_receipt_envelope(
            capability="G1_G2_PATCH", operation_type="V2_APPLY_PATCH",
            request_ref={"public_action": "APPLY_PATCH"}, session_ref={"v2_exec_id": self.v2id},
            prepare={"descriptor_ref": self.v2id, "descriptor_hash": self.desc_hash},
            authorization={"execution_authority_hash": self.eah, "approval_id": "NOT_REACHED", "kx108_pre_decision_record_id": "NOT_REACHED", "kx108_verdict": "ALLOW", "binder_verdict_status": "NOT_REACHED"},
            execution={"executor_kind": "GOVERNED_PATCH", "executor_operation": "V2_APPLY_PATCH", "executor_status": "EXECUTED", "executor_input_ref": exec_in, "executor_input_hash": _CRE.compute_ref_hash(exec_in), "physical_effect_dispatched": True, "mutation_performed": True},
            realized_state={"outcome": _CRE.OUTCOME_SUCCESS, "physical_effect_dispatched": True, "mutation_performed": True, "realized_state_verified": True, "proof_strength": "STRONG", "post_state_ref": {"target_paths": [self.target], "after_digests": {self.target: _sha(self.pre_bytes)}}, "post_state_hash": _CRE.compute_ref_hash({"target_paths": [self.target], "after_digests": {self.target: _sha(self.pre_bytes)}})},
            receipt={"source": "SYNTHETIC_C268_DIV"},
        )
        _CRE.store_canonical_receipt_envelope(div_r8, self.root / "receipts")
        self.assertEqual(
            _R8_RECON.reconcile_action_evidence(div_r8["action_evidence_id"], stores_base_dir=self.root)["reconciliation_status"],
            _R8_RECON.STATUS_MISMATCH,
        )

        # 8 : Disposition D1 incohérente
        self.assertEqual(
            _DISP.classify_post_execution_disposition(failure_signal="FORGED_SIGNAL")["status"],
            _DISP.DISPOSITION_HOLD,
        )

        # 9 : Preuve manquante
        self.assertEqual(
            _R8_REPLAY.replay_action_evidence("aev-" + "0" * 32, stores_base_dir=self.root)["replay_verdict"],
            _R8_REPLAY.VERDICT_NOT_FOUND,
        )

        # 10 : Rejeu d'un ancien nonce
        nonces_file = str(self.root / "consumed_nonces.jsonl")
        self.assertTrue(_TS.reserve_ticket_nonce("old-nonce-1", "tkt-1", store_path=nonces_file))
        self.assertFalse(_TS.reserve_ticket_nonce("old-nonce-1", "tkt-1", store_path=nonces_file))


if __name__ == "__main__":
    unittest.main()
