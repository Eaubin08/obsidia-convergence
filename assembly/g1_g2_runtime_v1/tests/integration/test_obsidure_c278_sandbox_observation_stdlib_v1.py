"""C278/F7 sandbox → R9/R12 : fixtures isolées, aucun test réel relancé.

PASS, FULL, sandbox et leurs contenus sont synthétiques. Pas d'origine signée.
"""
from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
from obsidure_c278_sandbox_observation_v1 import reconstruct_r9_patch_without_execution
from scripts.proposal_meaning_validator import validate_proposal_meaning


BOUNDARY = {
    "decision_authority": "KX108_ONLY", "emits_act": False,
    "emits_verdict": False, "kernel_mutation": False,
    "memory_write": False, "canonical_write": False,
    "auto_apply": False, "auto_commit": False, "auto_push": False,
    "sandbox_mode": "HUMAN_APPROVED_WRITE", "external_engine_role": "PROPOSE_ONLY",
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class C278SandboxObservation(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="obsidia-c278-fixture-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.runtime = ObsidiaGovernanceRuntime()
        self.target = "scripts/tool.py"
        (self.root / "scripts").mkdir()
        self.before = b"def check_session():\n    return 'broken'\n"
        self.content = "def check_session():\n    return 'fixed_session_token'\n"
        (self.root / self.target).write_bytes(self.before)
        self.sandbox = self.root / "_EPHEMERAL_REPAIR_SANDBOX_SYNTHETIC"
        (self.sandbox / "scripts").mkdir(parents=True)
        (self.sandbox / self.target).write_bytes(self.content.encode("utf-8"))
        test = "tests/test_session.py"
        self.request = {
            "request_id": "rr-synthetic-c278", "repo_targets": [self.target],
            "objective": "Fix session token validation in check_session",
            "summary": "session token validation fails in check_session",
            "error_contexts": [
                {"target_path": self.target, "error_type": "SESSION_TOKEN_VALIDATION",
                 "raw_details": "session token validation broken in check_session"},
            ],
            "target_excerpts": {self.target: self.before.decode("utf-8")},
            "tests_hint": [test], "boundary": copy.deepcopy(BOUNDARY),
        }
        self.proposal = {
            "proposal_id": "rp-synthetic-c278", "request_id": self.request["request_id"],
            "rationale": "Repair session token validation in check_session",
            "candidate_files": [
                {"path": self.target, "change_kind": "MODIFY",
                 "full_content": self.content, "base_sha256": sha(self.before),
                 "rationale": "repair check_session session token validation"},
            ],
            "tests_to_run": [test], "confidence": "HIGH",
            "boundary": copy.deepcopy(BOUNDARY),
        }
        self.c278 = validate_proposal_meaning(request=self.request, proposal=self.proposal)
        self.assertEqual(self.c278["evidence"], "CONTINUOUS", self.c278)
        self.verdict = {
            "verdict_id": "rv-synthetic-c278", "request_id": self.request["request_id"],
            "proposal_id": self.proposal["proposal_id"], "status": "PASS",
            "compiled_files": [self.target], "errors": [],
            "sandbox_dir": str(self.sandbox),
            "tested_artifacts": [{"path": self.target, "sha256": sha(self.content.encode())}],
            "tests_executed": [{"test": test, "status": "PASS", "returncode": 0,
                                "isolation": "FULL"}],
            "boundary": copy.deepcopy(BOUNDARY),
        }
        self.r10 = self.runtime.inspect_obsidure_r10_repair(
            repair_request=self.request, repair_proposal=self.proposal,
            c278_evidence=self.c278, repair_verdict=self.verdict,
            worktree_root=self.root, declared_targets=[self.target],
        )
        self.assertEqual(self.r10["status"], "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY", self.r10)

    def observe(self):
        return self.runtime.inspect_obsidure_c278_sandbox(
            r10_inspection=self.r10, repair_request=self.request,
            repair_proposal=self.proposal, c278_evidence=self.c278,
            repair_verdict=self.verdict, repo_root=self.root,
        )

    def test_c278_canonical_replay_and_sandbox_bytes_are_only_observed(self):
        before = {p: p.read_bytes() for p in (self.root / self.target, self.sandbox / self.target)}
        result = self.observe()
        self.assertEqual(result["status"], "C278_SANDBOX_BYTES_MATCH_UNATTESTED", result)
        for flag in ("sandbox_origin_attested", "test_process_attested", "provenance_verified",
                     "human_approval_verified", "execution_authorized", "target_mutated"):
            self.assertIs(result[flag], False)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_fake_continuous_and_tampered_c278_checks_hold(self):
        self.c278["checks"]["provenance_ok"] = False
        self.assertEqual(self.observe()["reason"], "C278_CANONICAL_RECORD_DIVERGES")
        self.c278 = {"request_id": self.request["request_id"],
                     "proposal_id": self.proposal["proposal_id"], "evidence": "CONTINUOUS"}
        self.assertEqual(self.observe()["reason"], "C278_FULL_CANONICAL_RECORD_REQUIRED")

    def test_missing_or_false_declared_test_verdict_holds(self):
        self.verdict["tests_executed"] = []
        self.assertEqual(self.observe()["reason"], "C278_DECLARED_TEST_RESULTS_MISSING")
        self.verdict["tests_executed"] = [
            {"test": self.proposal["tests_to_run"][0], "status": "PASS",
             "returncode": True, "isolation": "FULL"}
        ]
        self.assertEqual(self.observe()["reason"], "C278_DECLARED_TEST_RESULT_INCONSISTENT")

    def test_sandbox_file_tamper_holds(self):
        (self.sandbox / self.target).write_text("tampered", encoding="utf-8")
        self.assertEqual(self.observe()["reason"], "C278_SANDBOX_BYTES_DIFFER_FROM_VERDICT")

    def test_sandbox_outside_expected_root_holds(self):
        self.verdict["sandbox_dir"] = str(self.root / "scripts")
        self.assertEqual(self.observe()["reason"], "C278_SANDBOX_ROOT_UNTRUSTED")

    def test_verdict_artifact_or_compiled_scope_swap_holds(self):
        self.verdict["tested_artifacts"][0]["sha256"] = "b" * 64
        self.assertEqual(self.observe()["reason"], "C278_TESTED_ARTIFACT_HASH_DIVERGES")
        self.verdict["tested_artifacts"][0]["sha256"] = sha(self.content.encode())
        self.verdict["compiled_files"] = []
        self.assertEqual(self.observe()["reason"], "C278_COMPILED_FILES_NOT_BOUND")

    def test_symlink_sandbox_file_refused(self):
        source = self.sandbox / self.target
        source.unlink()
        try:
            source.symlink_to(self.root / self.target)
        except OSError as exc:
            self.skipTest(f"Windows symlink privilege missing: {exc}")
        self.assertEqual(self.observe()["reason"], "C278_SANDBOX_FILE_UNSAFE_OR_MISSING")

    def test_partial_isolation_remains_unattested(self):
        self.verdict["tests_executed"][0]["isolation"] = "PARTIAL"
        result = self.observe()
        self.assertEqual(result["status"], "C278_SANDBOX_BYTES_MATCH_UNATTESTED")
        self.assertEqual(result["sandbox_test_isolation_observed"], ["PARTIAL"])
        self.assertFalse(result["test_isolation_certified"])

    def test_c278_r9_r12_join_never_promotes_unbound_r9(self):
        result = self.runtime.inspect_obsidure_c278_r9_r12_outcome(
            action_evidence_id="aev-" + "f" * 32,
            stores_base_dir=self.root, r10_inspection=self.r10,
            r9_result={"status": "HOLD"}, expected_repo_identity_ref="synthetic-repo",
            repair_request=self.request, repair_proposal=self.proposal,
            c278_evidence=self.c278, repair_verdict=self.verdict,
            repo_root=self.root, execution_worktree_root=self.root,
        )
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "R9_PREPARED_RESULT_REQUIRED")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["sandbox_origin_attested"])

    def test_reconstruction_binds_r9_patch_to_real_candidate_bytes(self):
        expected, why = reconstruct_r9_patch_without_execution(
            repair_proposal=self.proposal, repo_root=self.root,
        )
        self.assertIsNone(why)
        self.assertEqual(expected, (
            "--- a/scripts/tool.py\n+++ b/scripts/tool.py\n@@ -1,2 +1,2 @@\n"
            " def check_session():\n-    return 'broken'\n+    return 'fixed_session_token'\n"
        ))
        (self.root / self.target).write_bytes(b"tampered preimage\n")
        _, why = reconstruct_r9_patch_without_execution(
            repair_proposal=self.proposal, repo_root=self.root,
        )
        self.assertEqual(why, "R9_PATCH_SOURCE_PREIMAGE_DRIFT")

    def test_create_is_not_silently_promoted_into_r9_patch(self):
        self.proposal["candidate_files"][0]["change_kind"] = "CREATE"
        _, why = reconstruct_r9_patch_without_execution(
            repair_proposal=self.proposal, repo_root=self.root,
        )
        self.assertEqual(why, "R9_PATCH_SOURCE_MODIFY_ONLY")

    def test_runtime_still_single_and_apply_closed(self):
        self.assertEqual(self.runtime.capabilities()["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertEqual(self.runtime.capabilities()["apply"], "HOLD")
        self.assertEqual(self.runtime.execute(operation_type="C278_SANDBOX_APPLY")["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
