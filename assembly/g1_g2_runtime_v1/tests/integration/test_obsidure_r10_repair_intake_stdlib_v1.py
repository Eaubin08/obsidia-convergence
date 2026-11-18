"""F7/R10 serialized RepairRequest/Proposal/C278/Verdict -> runtime unique.

Les preuves sont des fixtures, jamais une attestation réelle de sandbox.
Toutes les écritures de fixture ont lieu dans TemporaryDirectory.
"""
from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from obsidia_governance_runtime_v1 import get_runtime


BOUNDARY = {
    "decision_authority": "KX108_ONLY", "emits_act": False,
    "emits_verdict": False, "kernel_mutation": False,
    "memory_write": False, "canonical_write": False, "auto_apply": False,
    "auto_commit": False, "auto_push": False,
    "sandbox_mode": "HUMAN_APPROVED_WRITE", "external_engine_role": "PROPOSE_ONLY",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class R10RepairIntake(unittest.TestCase):
    def setUp(self):
        self.runtime = get_runtime()
        tmp = tempfile.TemporaryDirectory(prefix="obsidia-r10-f7-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        (self.root / "scripts").mkdir()
        (self.root / "apps/obsidia_api").mkdir(parents=True)
        self.original = b"print('old')\n"
        self.updated = "print('new')\n"
        (self.root / "scripts/target.py").write_bytes(self.original)

    def fixture(self, *, create=False):
        path = "scripts/new_file.py" if create else "scripts/target.py"
        candidate = {
            "path": path, "full_content": self.updated,
            "change_kind": "CREATE" if create else "MODIFY",
            "base_sha256": "" if create else sha(self.original),
            "rationale": "repair in sandbox",
        }
        return {
            "repair_request": {
                "request_id": "rr_real_contract", "boundary": copy.deepcopy(BOUNDARY),
                "repo_targets": [path],
            },
            "repair_proposal": {
                "proposal_id": "rp_real_contract", "request_id": "rr_real_contract",
                "candidate_files": [candidate], "boundary": copy.deepcopy(BOUNDARY),
            },
            "c278_evidence": {
                "request_id": "rr_real_contract", "proposal_id": "rp_real_contract",
                "evidence": "CONTINUOUS",
            },
            "repair_verdict": {
                "verdict_id": "rv_real_contract", "request_id": "rr_real_contract",
                "proposal_id": "rp_real_contract", "status": "PASS",
                "tested_artifacts": [{"path": path, "sha256": sha(self.updated.encode())}],
                "boundary": copy.deepcopy(BOUNDARY),
            },
            "worktree_root": self.root, "declared_targets": [path],
        }

    def inspect(self, args):
        return self.runtime.inspect_obsidure_r10_repair(**args)

    def assert_hold(self, args, reason=None):
        result = self.inspect(args)
        self.assertEqual(result["status"], "HOLD", result)
        if reason:
            self.assertEqual(result["reason"], reason)
        self.assertFalse(result["action_ticket_issued"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["target_mutated"])
        self.assertFalse(result["kx108_pre_invoked"])

    def test_real_r10_modify_shape_is_readonly_and_non_authorizing(self):
        before = (self.root / "scripts/target.py").read_bytes()
        result = self.inspect(self.fixture())
        self.assertEqual(result["status"], "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY")
        self.assertEqual(result["candidates"][0]["candidate_content_sha256"], sha(self.updated.encode()))
        self.assertEqual(result["candidates"][0]["target_pre_sha256"], sha(before))
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertFalse(result["evidence_provenance_verified"])
        self.assertFalse(result["r9_prepare_executed"])
        self.assertFalse(result["human_approval_verified"])
        self.assertFalse(result["action_ticket_issued"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["target_mutated"])
        self.assertEqual((self.root / "scripts/target.py").read_bytes(), before)
        self.assertEqual(self.runtime.execute(operation_type="R10_REPAIR", evidence=result)["status"], "HOLD")

    def test_create_is_inspected_via_g2_without_r9_prepare(self):
        args = self.fixture(create=True)
        result = self.inspect(args)
        self.assertEqual(result["status"], "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY")
        self.assertEqual(result["candidates"][0]["operation"], "CREATE")
        self.assertIsNone(result["candidates"][0]["target_pre_sha256"])
        self.assertFalse((self.root / "scripts/new_file.py").exists())
        self.assertFalse(result["r9_prepare_executed"])

    def test_forged_boundary_and_verdict_are_rejected(self):
        for part, field, value in (
            ("repair_request", "auto_apply", True),
            ("repair_proposal", "decision_authority", "BRODY"),
            ("repair_verdict", "emits_act", True),
        ):
            with self.subTest(part=part, field=field):
                args = self.fixture()
                args[part]["boundary"][field] = value
                self.assert_hold(args, "R10_NON_SOVEREIGN_BOUNDARY_INVALID")
        args = self.fixture()
        args["repair_verdict"]["status"] = "BLOCKED"
        self.assert_hold(args, "R10_C278_OR_SANDBOX_VERDICT_NOT_PASS")
        args = self.fixture()
        args["c278_evidence"]["evidence"] = "UNKNOWN"
        self.assert_hold(args, "R10_C278_OR_SANDBOX_VERDICT_NOT_PASS")
        for part, field in (
            ("repair_request", "human_approved"),
            ("repair_proposal", "execution_authorized"),
            ("repair_verdict", "ticket_id"),
            ("c278_evidence", "x108_gate"),
        ):
            with self.subTest(injection=(part, field)):
                args = self.fixture()
                args[part][field] = "ALLOW"
                self.assert_hold(args, "R10_UNKNOWN_OR_AUTHORIZING_FIELDS")

    def test_request_proposal_c278_verdict_must_bind(self):
        for part, field in (
            ("repair_proposal", "request_id"),
            ("repair_verdict", "proposal_id"),
            ("repair_verdict", "request_id"),
            ("c278_evidence", "request_id"),
            ("c278_evidence", "proposal_id"),
        ):
            with self.subTest(part=part, field=field):
                args = self.fixture()
                args[part][field] = "forged-id"
                self.assert_hold(args, "R10_REPAIR_LINEAGE_MISMATCH")

    def test_tampered_content_digest_or_preimage_is_rejected(self):
        args = self.fixture()
        args["repair_proposal"]["candidate_files"][0]["full_content"] = "print('tampered')\n"
        self.assert_hold(args, "R10_TESTED_ARTIFACT_HASH_MISMATCH")
        args = self.fixture()
        (self.root / "scripts/target.py").write_bytes(b"moved base\n")
        self.assert_hold(args, "R10_MODIFY_BASE_SHA_DRIFT_OR_MISSING")

    def test_absent_modified_target_and_existing_created_target_refused(self):
        args = self.fixture()
        (self.root / "scripts/target.py").unlink()
        self.assert_hold(args, "R10_MODIFY_TARGET_MISSING")
        args = self.fixture(create=True)
        (self.root / "scripts/new_file.py").write_bytes(b"exists\n")
        self.assert_hold(args, "R10_CREATE_K1_PREFLIGHT_HOLD")

    def test_policy_escape_and_windows_alias_refusals(self):
        for path in ("../escape.py", "proofs/secret.py", "scripts/CON.py", "scripts/name.",
                     "scripts/FILE~1.py", "scripts/x:ads.py", "scripts\\target.py",
                     "docs/out.py", "scripts/../target.py", "C:/temp/target.py"):
            with self.subTest(path=path):
                args = self.fixture(create=True)
                args["repair_proposal"]["candidate_files"][0]["path"] = path
                args["repair_verdict"]["tested_artifacts"][0]["path"] = path
                args["declared_targets"] = [path]
                self.assert_hold(args)

    def test_unbounded_or_duplicate_scope_rejected(self):
        args = self.fixture()
        args["declared_targets"] = ["scripts/other.py"]
        args["repair_request"]["repo_targets"] = ["scripts/other.py"]
        self.assert_hold(args, "R10_CANDIDATE_NOT_IN_DECLARED_SCOPE")
        args = self.fixture()
        args["declared_targets"].append("scripts/target.py")
        self.assert_hold(args, "R10_DECLARED_SCOPE_INVALID")
        args = self.fixture()
        args["declared_targets"].append("scripts/TARGET.py")
        self.assert_hold(args, "R10_DECLARED_SCOPE_INVALID")
        args = self.fixture()
        args["repair_request"]["repo_targets"] = ["scripts/TARGET.py"]
        self.assert_hold(args, "R10_REQUEST_TARGET_SCOPE_MISMATCH")
        args = self.fixture()
        args["repair_proposal"]["candidate_files"].append(
            copy.deepcopy(args["repair_proposal"]["candidate_files"][0])
        )
        args["repair_verdict"]["tested_artifacts"].append(
            copy.deepcopy(args["repair_verdict"]["tested_artifacts"][0])
        )
        self.assert_hold(args, "R10_TESTED_ARTIFACT_IDENTITY_INVALID")

    def test_no_effective_diff_and_missing_test_hash_refused(self):
        args = self.fixture()
        args["repair_proposal"]["candidate_files"][0]["full_content"] = self.original.decode()
        args["repair_verdict"]["tested_artifacts"][0]["sha256"] = sha(self.original)
        self.assert_hold(args, "R10_NO_EFFECTIVE_REPAIR_DIFF")
        args = self.fixture()
        args["repair_verdict"]["tested_artifacts"] = []
        self.assert_hold(args, "R10_CANDIDATES_OR_TESTED_ARTIFACTS_INCOMPLETE")

    def test_parent_symlink_is_refused(self):
        try:
            (self.root / "scripts/linked").symlink_to(
                self.root / "apps/obsidia_api", target_is_directory=True,
            )
        except OSError as exc:
            self.skipTest(f"Windows symlink privilege missing: {exc}")
        args = self.fixture(create=True)
        path = "scripts/linked/file.py"
        args["repair_proposal"]["candidate_files"][0]["path"] = path
        args["repair_verdict"]["tested_artifacts"][0]["path"] = path
        args["declared_targets"] = [path]
        args["repair_request"]["repo_targets"] = [path]
        self.assert_hold(args, "R10_TARGET_REPARSE_UNSAFE")

    def test_runtime_still_single_engine(self):
        capabilities = self.runtime.capabilities()
        self.assertEqual(capabilities["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertEqual(capabilities["apply"], "HOLD")
        self.assertEqual(capabilities["obsidure_r10_repair"], "F7_REPAIR_CANDIDATES_READONLY_INSPECTION_NO_EXECUTION")


if __name__ == "__main__":
    unittest.main()
