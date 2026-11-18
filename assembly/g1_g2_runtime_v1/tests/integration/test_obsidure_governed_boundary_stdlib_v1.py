"""Obsidure C2 -> PRE : admission strictement sans mutation ni ticket.

Fixtures de la sortie du vrai bridge C2, pas de chargement d'Obsidure F7.
Toutes les ecritures de fixture restent dans TemporaryDirectory.
"""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from obsidia_governance_runtime_v1 import get_runtime


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ObsidurePreAdmissionContract(unittest.TestCase):
    def setUp(self):
        self.runtime = get_runtime()
        tmp = tempfile.TemporaryDirectory(prefix="obsidia-obsidure-pre-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        (self.root / "source").mkdir()
        (self.root / "targets").mkdir()
        self.source_bytes = b"proposed content\n"
        self.target_bytes = b"original content\n"
        (self.root / "source/content.txt").write_bytes(self.source_bytes)
        (self.root / "targets/output.txt").write_bytes(self.target_bytes)

    def _bridge(self, *, create=False):
        source_sha = _sha(self.source_bytes)
        target_sha = None if create else _sha(self.target_bytes)
        operation = "CREATE_TARGET_FROM_SOURCE" if create else "UPDATE_TARGET_FROM_SOURCE"
        target = "targets/new.txt" if create else "targets/output.txt"
        return {
            "status": "BRIDGE_CHILD_READY", "reason": None,
            "proposal_id": "proposal-local-1", "proposal_hash": "proposal-digest",
            "source_content_sha256": source_sha, "authority": "NON_SOVEREIGN",
            "write_capability": False,
            "child": {
                "candidate_entry_id": "candidate-1", "child_execution_id": "child-1",
                "source_kind": "FILESYSTEM_FILE", "source_path": "source/content.txt",
                "source_hash": source_sha[:16], "source_content_sha256": source_sha,
                "source_repository_identity": str(self.root),
                "source_git_commit_sha": "", "source_git_blob_sha": "",
                "source_git_historical_path": "", "target_path": target,
                "target_pre_hash": None if create else target_sha[:16],
                "target_pre_sha256": target_sha, "operation_type": operation,
                "operation_reason": "proposal", "execution_status": "PLANNED",
                "provenance_refs": {},
            },
            "bridge_report": {
                "target_path": target, "operation_type": operation,
                "source_kind": "FILESYSTEM_FILE", "source_path": "source/content.txt",
                "source_bytes": len(self.source_bytes),
                "target_pre_state": "ABSENT" if create else "EXISTS",
                "family_provenance_keys": [],
            },
        }

    def _run(self, bridge, scope=None):
        return self.runtime.admit_obsidure_bridge(
            bridge_result=bridge, worktree_root=self.root,
            approved_scope=scope if scope is not None else [bridge["child"]["target_path"]],
        )

    def _assert_hold(self, bridge, reason=None, scope=None):
        result = self._run(bridge, scope=scope)
        self.assertEqual(result["status"], "HOLD", result)
        if reason:
            self.assertEqual(result["reason"], reason)
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertFalse(result["action_ticket_issued"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["target_mutated"])

    def test_update_validates_preimage_and_remains_readonly(self):
        bridge = self._bridge()
        result = self._run(bridge)
        self.assertEqual(result["status"], "OBSIDURE_PRE_ADMISSION_READONLY")
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertEqual(result["next_gate"], "CANONICAL_HUMAN_APPROVAL_AND_KX108_PRE_NOT_INVOKED")
        self.assertFalse(result["action_ticket_issued"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["target_mutated"])
        self.assertEqual((self.root / "targets/output.txt").read_bytes(), self.target_bytes)
        self.assertEqual((self.root / "source/content.txt").read_bytes(), self.source_bytes)
        self.assertEqual(self.runtime.execute(operation_type="UPDATE_TARGET_FROM_SOURCE", bridge_result=result)["status"], "HOLD")

    def test_create_only_accepts_explicit_canonical_operation(self):
        bridge = self._bridge(create=True)
        result = self._run(bridge)
        self.assertEqual(result["status"], "OBSIDURE_PRE_ADMISSION_READONLY")
        self.assertEqual(result["operation_type"], "CREATE_TARGET_FROM_SOURCE")
        self.assertIsNone(result["target_pre_sha256"])
        self.assertFalse((self.root / "targets/new.txt").exists())
        self.assertFalse(result["execution_authorized"])

    def test_legacy_c2_update_with_absent_target_is_not_converted_to_create(self):
        bridge = self._bridge(create=True)
        bridge["child"]["operation_type"] = "UPDATE_TARGET_FROM_SOURCE"
        bridge["bridge_report"]["operation_type"] = "UPDATE_TARGET_FROM_SOURCE"
        self._assert_hold(bridge, "OBSIDURE_UPDATE_TARGET_MISSING")
        self.assertFalse((self.root / "targets/new.txt").exists())

    def test_untrusted_authority_write_and_ticket_injections_hold(self):
        for slot, field, value in (
            ("root", "authority", "KX108_ONLY"),
            ("root", "write_capability", True),
            ("root", "execution_authorized", True),
            ("child", "ticket_id", "FORGED"),
            ("root", "status", "ALLOW"),
            ("child", "execution_status", "EXECUTED_ACT"),
        ):
            with self.subTest(field=field):
                bridge = self._bridge()
                where = bridge if slot == "root" else bridge["child"]
                where[field] = value
                self._assert_hold(bridge)

    def test_tampered_source_and_preimage_drift_hold(self):
        bridge = self._bridge()
        (self.root / "source/content.txt").write_bytes(b"tampered\n")
        self._assert_hold(bridge, "OBSIDURE_SOURCE_CANONICAL_RESOLVE_FAILED")
        (self.root / "source/content.txt").write_bytes(self.source_bytes)
        (self.root / "targets/output.txt").write_bytes(b"tampered-target\n")
        self._assert_hold(self._bridge(), "OBSIDURE_UPDATE_BASE_DRIFT")
        self.assertEqual((self.root / "targets/output.txt").read_bytes(), b"tampered-target\n")

    def test_scope_protected_target_and_traversal_hold(self):
        self._assert_hold(self._bridge(), "OBSIDURE_SCOPE_NOT_BOUNDED", scope=["other.txt"])
        self._assert_hold(self._bridge(), "OBSIDURE_SCOPE_NOT_BOUNDED", scope=["targets/output.txt"] * 2)
        bridge = self._bridge()
        bridge["child"]["target_path"] = "../escape.txt"
        self._assert_hold(bridge, "OBSIDURE_TARGET_OR_SOURCE_PATH_INVALID")
        bridge = self._bridge(create=True)
        bridge["child"]["target_path"] = "proofs/new.txt"
        bridge["bridge_report"]["target_path"] = "proofs/new.txt"
        self._assert_hold(bridge, "OBSIDURE_TARGET_PROTECTED")

    def test_windows_aliases_and_noncanonical_operation_hold(self):
        for target in ("targets/CON.txt", "targets/FILE~1.txt", "targets/name.", "targets/x:ads", "targets\\output.txt", "targets//output.txt", "C:/out.txt"):
            with self.subTest(target=target):
                bridge = self._bridge(create=True)
                bridge["child"]["target_path"] = target
                bridge["bridge_report"]["target_path"] = target
                self._assert_hold(bridge, scope=[target])
        bridge = self._bridge()
        bridge["child"]["operation_type"] = "APPLY"
        bridge["bridge_report"]["operation_type"] = "APPLY"
        self._assert_hold(bridge, "OBSIDURE_OPERATION_NOT_CANONICAL")

    def test_bad_report_identity_scope_and_create_prestate_hold(self):
        for section, key, value in (
            ("bridge_report", "source_bytes", 9000),
            ("bridge_report", "target_path", "targets/other.txt"),
            ("child", "source_repository_identity", "F:/forged"),
            ("child", "source_hash", "0" * 16),
            ("child", "source_kind", "GIT_BLOB"),
            ("child", "source_git_blob_sha", "sha1"),
        ):
            with self.subTest(key=key):
                bridge = self._bridge()
                bridge[section][key] = value
                self._assert_hold(bridge)
        bridge = self._bridge(create=True)
        bridge["bridge_report"]["target_pre_state"] = "EXISTS"
        self._assert_hold(bridge, "OBSIDURE_CREATE_REPORT_PRESTATE_MISMATCH")
        bridge = self._bridge(create=True)
        (self.root / "targets/new.txt").write_bytes(b"exists")
        self._assert_hold(bridge, reason="OBSIDURE_CREATE_K1_PRE_HOLD:CREATE_TARGET_ALREADY_EXISTS")

    def test_source_symlink_is_refused_without_privileges(self):
        try:
            (self.root / "source/link.txt").symlink_to(self.root / "source/content.txt")
        except OSError as exc:
            self.skipTest(f"symlink unavailable on this Windows account: {exc}")
        bridge = self._bridge()
        bridge["child"]["source_path"] = "source/link.txt"
        bridge["bridge_report"]["source_path"] = "source/link.txt"
        self._assert_hold(bridge, "OBSIDURE_SOURCE_REPARSE_UNSAFE")

    def test_create_parent_symlink_is_refused(self):
        try:
            (self.root / "linked").symlink_to(self.root / "targets", target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink unavailable on this Windows account: {exc}")
        bridge = self._bridge(create=True)
        bridge["child"]["target_path"] = "linked/new.txt"
        bridge["bridge_report"]["target_path"] = "linked/new.txt"
        self._assert_hold(bridge, "OBSIDURE_TARGET_REPARSE_UNSAFE")

    def test_one_runtime_api_and_no_authorizing_capability(self):
        self.assertEqual(self.runtime.capabilities()["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertEqual(self.runtime.capabilities()["obsidure_proposal"], "C2_BRIDGE_READONLY_PRE_ADMISSION_NO_EXECUTION")
        self.assertEqual(self.runtime.capabilities()["apply"], "HOLD")
        self.assertEqual(self.runtime.execute(operation_type="OBSIDURE_APPLY")["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
