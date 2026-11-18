"""G2 CREATE : refus des alias Windows et des chemins protégés, sans pytest.

Les répertoires de tests sont temporaires, sans APPLY ni service.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.obsidia_batch_execution import _is_protected
from scripts.obsidia_create_pre_contract_v0 import prepare_create_target_pre_evidence


class CreateWindowsAliasContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="g2-windows-path-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def prepare(self, name: str, root=None, policy=_is_protected):
        return prepare_create_target_pre_evidence(
            worktree_root=self.root if root is None else root,
            operation_type="CREATE_TARGET_FROM_SOURCE",
            target_path=name,
            source_content_sha256="a" * 64,
            is_protected=policy,
        )

    def test_case_insensitive_protected_k1_paths_are_denied(self):
        for path in ("Proofs/example.txt", "FoRmAl/example.tla", "MerKle_Seal.JSON"):
            with self.subTest(path=path):
                result = self.prepare(path)
                self.assertEqual(result["reason"], "CREATE_TARGET_PROTECTED")
                self.assertFalse(result["authorized"])

    def test_windows_reserved_names_and_ambiguous_components_denied(self):
        for path in (
            "src/CON", "src/nul.txt", "src/Lpt9", "src/COM1.log",
            "src/file.txt.", "src/file.txt ", " src/file.txt",
            "src/part /file.txt", "src/PROOFS~1/file.txt", "src/a?.txt",
            "src/invalid\x01.txt",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.prepare(path)["status"], "HOLD_CREATE_PRE")

    def test_broken_root_denied_as_result_not_exception(self):
        result = self.prepare("new.txt", root=object())
        self.assertEqual(result["reason"], "WORKTREE_OR_TARGET_UNVERIFIED")

    def test_normal_unprotected_create_remains_preflight_only(self):
        result = self.prepare("src/new.txt")
        self.assertEqual(result["status"], "READY_FOR_CANONICAL_PRE_EVIDENCE")
        self.assertFalse(result["authorized"])
        self.assertFalse(result["target_mutated"])
        self.assertFalse((self.root / "src/new.txt").exists())


if __name__ == "__main__":
    unittest.main()
