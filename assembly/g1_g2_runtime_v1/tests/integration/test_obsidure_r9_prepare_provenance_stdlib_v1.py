"""R9 PREPARE V2 -> R12 : vraie ABI R9, artefacts de test isolés.

Toutes les valeurs PASS, APPROVAL et les empreintes sont synthétiques.
Aucun preparateur, agent F7, serveur ou executor n'est appelé.
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

from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
from obsidure_builder_proposal_v1 import BuilderPatchRef, ObsidureBuilderProposalV1
from obsidure_proposal_manifest_v1 import ArtifactRef, EvidenceRecord, build_proposal_manifest
from obsidure_proposal_validation_v1 import (
    ValidationObligation, ValidationPolicy, validate_obsidure_proposal,
)
from obsidure_governance_handoff_v1 import build_governance_handoff
from obsidure_r10_repair_intake_v1 import _BOUNDARY
from scripts.proposal_meaning_validator import validate_proposal_meaning


def sha(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


class ObsidureR9PrepareProvenance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-r9-proof-synthetic-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = self.root / "v2exec"
        self.store.mkdir()
        self.runtime = ObsidiaGovernanceRuntime()
        self.target = "scripts/tool.py"
        self._make_case(
            targets=(self.target,),
            patch_content="--- a/scripts/tool.py\n+++ b/scripts/tool.py\n@@ -1 +1 @@\n-old\n+new\n",
        )

    def _make_case(self, *, targets: tuple[str, ...], patch_content: str):
        self.patch_content = patch_content
        self.patch_sha = sha(self.patch_content)
        self.base_sha = "a" * 40
        self.ids = {
            "repair_request_id": "r10-synthetic-request",
            "repair_proposal_id": "r10-synthetic-proposal",
            "repair_verdict_id": "r10-synthetic-verdict",
        }
        self.r10 = {"status": "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY", **self.ids}
        self.repo_ref = "synthetic-isolated-repo"
        proposal = ObsidureBuilderProposalV1(
            objective="Test synthetic R9", proposal_kind="REPAIR",
            base_commit_sha=self.base_sha, target_scope=tuple(sorted(targets)),
            files_touched=tuple(sorted(targets)),
            candidate_patch_ref=BuilderPatchRef("repair_candidate.patch", self.patch_sha),
            tests_proposed=("repair-sandbox-verdict",),
            source_context_refs=(self.ids["repair_request_id"],),
            declared_evidence={
                "c278_evidence": "CONTINUOUS", **self.ids,
                "tested_artifact_hashes": {target: sha(b"new\n") for target in targets},
            },
        )
        patch_artifact = ArtifactRef(
            artifact_kind="CANDIDATE_PATCH", logical_ref="repair_candidate.patch",
            content_sha256=self.patch_sha, artifact_format="REAL_UNIFIED_DIFF_V1",
        )
        test_artifact = ArtifactRef(
            artifact_kind="TEST_RESULT", logical_ref=self.ids["repair_verdict_id"],
            content_sha256=sha("synthetic-verdict"),
        )
        evidence = EvidenceRecord(
            evidence_kind="TEST_RESULT_EVIDENCE", subject_ref=proposal.proposal_id,
            producer_ref="SYNTHETIC_TEST", verification_status="VERIFIED",
            artifact_ref=test_artifact, scope=targets, result="VALIDATED_REPAIR_SANDBOX_PASS",
            provenance={"base_commit_sha": self.base_sha},
        )
        manifest = build_proposal_manifest(
            proposal, candidate_artifacts=(patch_artifact, test_artifact),
            evidence_records=(evidence,),
            verification_obligations=("repair-sandbox-verdict",),
            repo_identity_ref=self.repo_ref,
        )
        policy = ValidationPolicy(obligations=(ValidationObligation(
            obligation_kind="UNIT_TEST", target="repair-sandbox-verdict",
            scope=targets, required=True,
            expected_evidence_kind="TEST_RESULT_EVIDENCE", allow_observed=False,
        ),))
        validation = validate_obsidure_proposal(proposal, manifest, validation_policy=policy)
        self.assertEqual(validation.validation_verdict, "VALID")
        handoff = build_governance_handoff(proposal, manifest, validation,
                                           source_metadata={**self.ids, "c278_evidence": "CONTINUOUS"})
        self.handoff_fixture = (proposal, manifest, validation, handoff)
        self.lineage = {
            "lineage_schema_version": "OBSIDURE_GOVERNED_PATCH_PREPARE_ADAPTER_V1",
            "builder_proposal_id": proposal.proposal_id,
            "builder_manifest_id": manifest.manifest_id,
            "builder_validation_id": validation.validation_id,
            "builder_handoff_id": handoff.handoff_id,
        }
        self.desc = {
            "patch_sha256": self.patch_sha,
            "target_paths": sorted(targets),
            "before_digests": {target: "b" * 64 for target in targets},
            "execution_worktree": str(self.root / "isolated"),
            "main_worktree": str(self.root / "main"),
            "branch_name": "synthetic/r9-test", "base_sha": self.base_sha,
            "session_id": "synthetic-r9-session", "operation_type": "V2_APPLY_PATCH",
            "descriptor_lineage": self.lineage,
        }
        eah = sha(json.dumps({"v2_schema": "PC_CAPABILITIES_V2_EAH_V0",
                              "operation_type": "V2_APPLY_PATCH",
                              "action_descriptor": self.desc}, sort_keys=True))
        v2id = "v2x-" + sha(eah + self.base_sha + self.desc["session_id"])[:32]
        child = "chd-" + sha(eah + self.patch_sha)[:32]
        record = {
            "v2_exec_id": v2id, "operation_type": "V2_APPLY_PATCH",
            "eah": eah, "descriptor": self.desc, "decision_authority": "KX108_ONLY",
            "created_at": "2026-11-19T00:00:00+00:00",
        }
        raw_desc = json.dumps(record, sort_keys=True, ensure_ascii=False)
        (self.store / (v2id + ".json")).write_text(raw_desc, encoding="utf-8")
        (self.store / (v2id + ".patch")).write_bytes(self.patch_content.encode("utf-8"))
        prepared = {
            "status": "PREPARED_AWAITING_HUMAN_APPROVAL", "j5_phase": "PREPARE",
            "operation_type": "V2_APPLY_PATCH", "decision_authority": "KX108_ONLY",
            "execution_authority_hash": eah, "patch_sha256": self.patch_sha,
            "target_paths": sorted(targets), "before_digests": self.desc["before_digests"],
            "v2_exec_id": v2id, "child_id": child,
            "manifest_hash": sha(json.dumps(self.desc, sort_keys=True))[:16],
            "desc_hash": sha(raw_desc), "builder_lineage": self.lineage,
            "approval_created": False, "binder_runtime_called": False,
            "kx108_called": False, "executor_invoked": False,
            "physical_mutation": False, "action_evidence_id_created": False,
            "validation_equals_approval": False, "handoff_equals_authorization": False,
            "prepare_equals_authorization": False,
        }
        self.r9 = {
            "status": "R10_REPAIR_PREPARED", "r9_proposal": proposal,
            "r9_manifest": manifest, "r9_validation": validation,
            "r9_handoff": handoff, "prepared_action": prepared,
            "patch_content": self.patch_content, "tested_patch_hash": self.patch_sha,
            "repair_lineage": self.ids, "prepared": True,
            "approval_created": False, "kx108_called": False,
            "executor_invoked": False, "physical_mutation": False,
            "commit_created": False, "push_performed": False, "merge_performed": False,
        }

    def inspect(self):
        return self.runtime.inspect_obsidure_r9_preparation(
            r10_inspection=self.r10, r9_result=self.r9,
            stores_base_dir=self.root,
            expected_repo_identity_ref=self.repo_ref,
        )

    def assert_held_non_authorizing(self, result):
        self.assertIs(result["execution_authorized"], False)
        self.assertIs(result["human_approval_verified"], False)
        self.assertIs(result["executor_invoked"], False)
        self.assertIs(result["target_mutated"], False)
        self.assertEqual(result["decision_authority"], "KX108_ONLY")

    def test_runtime_handoff_adversarial_readonly(self):
        proposal, manifest, validation, handoff = self.handoff_fixture
        baseline = handoff.to_dict()

        cases = [
            ("VALID", baseline, True, None),
            ("MISSING", None, False, "OBSIDURE_HANDOFF_INVALID:"),
            ("PROPOSAL_ID", {**baseline, "proposal_id": "forged"},
             False, "PROPOSAL_ID_MISMATCH"),
            ("MANIFEST_DIGEST", {**baseline, "manifest_digest": "0" * 64},
             False, "MANIFEST_DIGEST_MISMATCH"),
            ("VALIDATION_DIGEST", {**baseline, "validation_digest": "0" * 64},
             False, "VALIDATION_DIGEST_MISMATCH"),
            ("AUTHORITY", {**baseline, "authority": "KX108_ONLY"},
             False, "AUTHORITY_MISMATCH"),
            ("EXECUTION", {**baseline, "execution_allowed": True},
             False, "EXECUTION_ALLOWED_MISMATCH"),
            ("HANDOFF_DIGEST", {**baseline, "handoff_digest": "f" * 64},
             False, "HANDOFF_DIGEST_MISMATCH"),
            ("HANDOFF_ID", {**baseline, "handoff_id": "obh-" + "f" * 64},
             False, "HANDOFF_ID_MISMATCH"),
        ]

        for name, candidate, expected_accept, expected_reason in cases:
            with self.subTest(case=name):
                result = self.runtime.inspect_obsidure_governance_handoff(
                    proposal=proposal,
                    manifest=manifest,
                    validation=validation,
                    handoff=candidate,
                )
                accepted = (
                    result.get("status")
                    == "OBSIDURE_HANDOFF_VERIFIED_READONLY"
                )
                self.assertEqual(accepted, expected_accept)
                self.assertEqual(result.get("decision_authority"), "KX108_ONLY")
                self.assertIs(result.get("execution_authorized"), False)
                self.assertIs(result.get("action_ticket_issued"), False)
                self.assertIs(result.get("target_mutated"), False)
                self.assertNotIn("ticket_id", result)
                if expected_reason is not None:
                    self.assertIn(expected_reason, result.get("reason") or "")

    def test_canonical_r9_objects_and_v2_artifacts_match_without_origin_attestation(self):
        before = {p.name: p.read_bytes() for p in self.store.iterdir()}
        result = self.inspect()
        self.assertEqual(result["status"], "R9_PREPARE_BINDING_MATCH_UNATTESTED", result)
        self.assertTrue(result["artifact_binding_verified"])
        self.assertFalse(result["provenance_verified"])
        self.assertEqual(result["v2_exec_id"], self.r9["prepared_action"]["v2_exec_id"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.store.iterdir()})
        self.assert_held_non_authorizing(result)

    def test_r9_r12_join_does_not_promote_missing_r8_receipt(self):
        result = self.runtime.inspect_obsidure_r9_r12_outcome(
            action_evidence_id="aev-" + "c" * 32,
            stores_base_dir=self.root, r10_inspection=self.r10,
            r9_result=self.r9, expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(result["r9_prepare"]["status"], "R9_PREPARE_BINDING_MATCH_UNATTESTED")
        self.assertEqual(result["reason"], "R8_CANONICAL_RECEIPT_MISSING_OR_INVALID")
        self.assertFalse(result["r9_provenance_verified"])
        self.assert_held_non_authorizing(result)

    def test_patch_tamper_detected_even_with_same_r9_typed_objects(self):
        vid = self.r9["prepared_action"]["v2_exec_id"]
        (self.store / (vid + ".patch")).write_text(self.patch_content + "#tampered\n", encoding="utf-8")
        result = self.inspect()
        self.assertEqual(result["reason"], "R9_PATCH_ARTIFACT_DRIFT")
        self.assert_held_non_authorizing(result)

    def test_multi_target_original_candidate_order_replays_validation_policy(self):
        # R9 conserve l'ordre des candidats dans l'obligation de validation,
        # même quand le scope canonique de la proposition est trié.
        other = "z/second.py"
        second_first = "--- a/z/second.py\n+++ b/z/second.py\n@@ -1 +1 @@\n-old2\n+new2\n"
        self._make_case(targets=(other, self.target), patch_content=second_first + self.patch_content)
        result = self.inspect()
        self.assertEqual(result["status"], "R9_PREPARE_BINDING_MATCH_UNATTESTED", result)
        self.assert_held_non_authorizing(result)

    def test_duplicate_descriptor_keys_refused(self):
        vid = self.r9["prepared_action"]["v2_exec_id"]
        descriptor_path = self.store / (vid + ".json")
        raw = descriptor_path.read_text(encoding="utf-8")
        descriptor_path.write_text('{"eah":"fake",' + raw[1:], encoding="utf-8")
        self.assertIn("DUPLICATE_JSON_KEY", self.inspect()["reason"])

    def test_descriptor_tamper_and_fake_approval_refused(self):
        prepared = self.r9["prepared_action"]
        vid = prepared["v2_exec_id"]
        altered = json.loads((self.store / (vid + ".json")).read_text(encoding="utf-8"))
        altered["descriptor"]["before_digests"][self.target] = "f" * 64
        (self.store / (vid + ".json")).write_text(json.dumps(altered, sort_keys=True), encoding="utf-8")
        self.assertEqual(self.inspect()["reason"], "R9_PERSISTED_DESCRIPTOR_BINDING_MISMATCH")
        self.r9["approval_created"] = True
        self.assertEqual(self.inspect()["reason"], "R9_RESULT_CLAIMS_EXECUTION_AUTHORITY")

    def test_canonical_lineage_and_repo_ref_substitution_refused(self):
        self.r10["repair_proposal_id"] = "swapped"
        self.assertEqual(self.inspect()["reason"], "R9_R10_REPAIR_LINEAGE_MISMATCH")
        self.r10["repair_proposal_id"] = self.ids["repair_proposal_id"]
        self.repo_ref = "attacker-repo"
        self.assertEqual(self.inspect()["reason"], "R9_REPO_IDENTITY_MISMATCH")

    def test_forged_validation_or_scope_refused(self):
        self.r9["r9_validation"] = {"validation_verdict": "VALID"}
        self.assertEqual(self.inspect()["reason"], "R9_CANONICAL_TYPED_ARTIFACTS_REQUIRED")
        self.r9["r9_validation"] = self.r9["r9_handoff"].validation
        self.r9["prepared_action"]["target_paths"] = ["scripts/tool.py", "secrets.txt"]
        self.assertEqual(self.inspect()["reason"], "R9_TARGET_SCOPE_OR_PATCH_FORMAT_MISMATCH")

    def test_no_second_runtime_and_no_apply(self):
        self.assertEqual(self.runtime.capabilities()["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertEqual(self.runtime.capabilities()["apply"], "HOLD")
        self.assertEqual(self.runtime.execute(operation_type="R9_PREPARE_APPLY")["status"], "HOLD")

    def test_complete_c278_sandbox_r9_r12_readonly_join_on_synthetic_artifacts(self):
        root = self.root / "source_repo"
        target = root / "scripts/tool.py"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"old\n")
        sb = root / "_EPHEMERAL_REPAIR_SANDBOX_SYNTHETIC"
        (sb / "scripts").mkdir(parents=True)
        (sb / "scripts/tool.py").write_bytes(b"new\n")
        request = {
            "request_id": self.ids["repair_request_id"],
            "repo_targets": [self.target],
            "objective": "Repair tool output", "summary": "tool output broken",
            "error_contexts": [{"target_path": self.target, "error_type": "TOOL_OUTPUT",
                                "raw_details": "tool output broken"}],
            "target_excerpts": {self.target: "old\n"},
            "tests_hint": ["tests/test_tool.py"], "boundary": dict(_BOUNDARY),
        }
        proposal = {
            "proposal_id": self.ids["repair_proposal_id"],
            "request_id": self.ids["repair_request_id"],
            "rationale": "Repair tool output",
            "candidate_files": [{"path": self.target, "change_kind": "MODIFY",
                                 "full_content": "new\n", "base_sha256": sha(b"old\n"),
                                 "rationale": "Repair broken tool output"}],
            "tests_to_run": ["tests/test_tool.py"], "confidence": "HIGH",
            "boundary": dict(_BOUNDARY),
        }
        c278 = validate_proposal_meaning(request=request, proposal=proposal)
        self.assertEqual(c278["evidence"], "CONTINUOUS")
        verdict = {
            "verdict_id": self.ids["repair_verdict_id"],
            "request_id": self.ids["repair_request_id"],
            "proposal_id": self.ids["repair_proposal_id"],
            "status": "PASS", "compiled_files": [self.target],
            "sandbox_dir": str(sb), "errors": [], "boundary": dict(_BOUNDARY),
            "tested_artifacts": [{"path": self.target, "sha256": sha(b"new\n")}],
            "tests_executed": [{"test": "tests/test_tool.py", "status": "PASS",
                                "returncode": 0, "isolation": "FULL"}],
        }
        r10 = self.runtime.inspect_obsidure_r10_repair(
            repair_request=request, repair_proposal=proposal,
            c278_evidence=c278, repair_verdict=verdict,
            worktree_root=root, declared_targets=[self.target],
        )
        self.assertEqual(r10["status"], "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY")
        outcome = self.runtime.inspect_obsidure_c278_r9_r12_outcome(
            action_evidence_id="aev-" + "c" * 32,
            stores_base_dir=self.root, r10_inspection=r10,
            r9_result=self.r9, expected_repo_identity_ref=self.repo_ref,
            repair_request=request, repair_proposal=proposal,
            c278_evidence=c278, repair_verdict=verdict,
            repo_root=root, execution_worktree_root=root,
        )
        self.assertEqual(outcome["c278_observation"]["status"], "C278_SANDBOX_BYTES_MATCH_UNATTESTED", outcome)
        self.assertEqual(outcome["r9_prepare"]["status"], "R9_PREPARE_BINDING_MATCH_UNATTESTED", outcome)
        self.assertEqual(outcome["reason"], "R8_CANONICAL_RECEIPT_MISSING_OR_INVALID")
        self.assertFalse(outcome["sandbox_origin_attested"])
        self.assertFalse(outcome["execution_authorized"])
        self.assertEqual(target.read_bytes(), b"old\n")


if __name__ == "__main__":
    unittest.main()
