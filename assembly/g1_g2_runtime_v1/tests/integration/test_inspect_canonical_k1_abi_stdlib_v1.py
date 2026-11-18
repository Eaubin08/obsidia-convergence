"""Le relevé d'ABI ne doit ni importer ni exécuter les sources canoniques."""
from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


_PATH = Path(__file__).resolve().parents[2] / "tools" / "inspect_canonical_k1_abi_portable_v1.py"
_SPEC = importlib.util.spec_from_file_location("canonical_abi_inspector", _PATH)
assert _SPEC and _SPEC.loader
INSPECT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(INSPECT)


class CanonicalAbiInspection(unittest.TestCase):
    def test_source_is_parsed_not_executed(self):
        # Si la source était importée/exécutée, ce test échouerait.
        raw = (b"raise RuntimeError('MUST_NOT_EXECUTE')\n"
               b"from periphery.agents.agent_obsidure import AgentObsidure\n"
               b"class AgentObsidure:\n"
               b"    def prepare(self, target_path, *, approval_id=None): ...\n"
               b"def load_and_validate_proposal(path, *, strict=True): ...\n")
        report = INSPECT.inspect_python(raw)
        self.assertEqual(report["bytes"], len(raw))
        self.assertIn("periphery.agents.agent_obsidure", report["static_imports"])
        self.assertEqual(report["public_symbols"][0], {
            "kind": "class", "name": "AgentObsidure",
            "public_methods": [{"name": "prepare",
                                "parameters": ["self", "target_path", "approval_id"],
                                "positional_only": [],
                                "keyword_only": ["approval_id"],
                                "variadic": False}],
        })
        self.assertEqual(report["public_symbols"][1]["name"],
                         "load_and_validate_proposal")

    def test_static_audit_fails_closed_on_invalid_python(self):
        with self.assertRaises(INSPECT.ScopeHold):
            INSPECT.inspect_python(b"def unfinished(\n")

    def test_static_audit_fails_closed_on_oversize(self):
        with self.assertRaises(INSPECT.ScopeHold):
            INSPECT.inspect_python(b"x" * (INSPECT.MAX_FILE_BYTES + 1))

    def test_machine_and_head_are_pinned(self):
        self.assertEqual(INSPECT.PORTABLE_HOST, "DESKTOP-Q5MD7J7")
        self.assertEqual(INSPECT.SOURCE_HEAD,
                         "ecaf6729f1bcdb05bb8896b7c698d1ae90e56de7")
        self.assertNotIn("periphery/world_calls/world_action_bus.py", INSPECT.FILES)

    def test_advanced_head_only_allowed_if_exact_six_file_identity_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="abi-frozen-git-") as tmp:
            root = Path(tmp).resolve()

            def git(*args):
                return subprocess.run(
                    ["git", "-C", str(root), *args], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ).stdout.decode("utf-8").strip()

            git("init", "-q")
            git("config", "user.name", "OBSIDIA-TEST")
            git("config", "user.email", "tests@example.invalid")
            (root / "sigma").mkdir()
            (root / "sigma/base.py").write_bytes(b"class Base: pass\n")
            git("add", "--", "sigma/base.py")
            git("commit", "-qm", "frozen")
            frozen_head = git("rev-parse", "HEAD")

            (root / "unrelated.py").write_bytes(b"UNCHANGED_SCOPE = True\n")
            git("add", "--", "unrelated.py")
            git("commit", "-qm", "parallel work")
            self.assertNotEqual(git("rev-parse", "HEAD"), frozen_head)
            self.assertEqual(
                INSPECT._read_checked(root, "sigma/base.py", frozen_head),
                b"class Base: pass\n",
            )

            # Une mutation non commitée d'un module gouverné reste HOLD.
            (root / "sigma/base.py").write_bytes(b"class Base: pass\n# drift\n")
            with self.assertRaisesRegex(INSPECT.ScopeHold,
                                        "SOURCE_FILE_DIFFERS_FROM_FROZEN_K1_HEAD"):
                INSPECT._read_checked(root, "sigma/base.py", frozen_head)

            # Même si le worktree revient au gel, un HEAD contenant une autre
            # version canonique doit être refusé (pas de version mixte).
            git("add", "--", "sigma/base.py")
            git("commit", "-qm", "diverged canonical component")
            (root / "sigma/base.py").write_bytes(b"class Base: pass\n")
            with self.assertRaisesRegex(INSPECT.ScopeHold,
                                        "SOURCE_FILE_DRIFT_FROM_CURRENT_HEAD"):
                INSPECT._read_checked(root, "sigma/base.py", frozen_head)


if __name__ == "__main__":
    unittest.main()
