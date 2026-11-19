"""Le profil statique n'est jamais une provenance du runner C278."""
from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[2] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import inspect_c278_producer_portable_readonly_v1 as profile


SAMPLE = '''
import subprocess

def _run_declared_tests(tests, sandbox_root, root):
    isolation = "PARTIAL"
    if (sandbox_root / "__init__.py").is_file():
        isolation = "FULL"
    return subprocess.run(["python", "-m", "pytest"], cwd=root)

def test_repair_proposal(proposal, root):
    sb = root / "_EPHEMERAL_REPAIR_SANDBOX_123"
    sb.mkdir(parents=True, exist_ok=True)
    out = sb / "candidate.py"
    out.write_text("x = 1", encoding="utf-8")
    return _run_declared_tests([], sb, root)
'''


class C278ProducerStaticProfile(unittest.TestCase):
    def test_known_runner_shape_detects_test_process_and_sandbox_writes(self):
        result = profile.profile_producer_source(SAMPLE)
        self.assertTrue(result["required_symbols_present"])
        self.assertTrue(result["symbols"]["_run_declared_tests"]["subprocess_run_call"])
        self.assertIn("out.write_text", result["symbols"]["test_repair_proposal"]["sandbox_write_calls"])
        self.assertEqual(result["symbols"]["_run_declared_tests"]["literal_isolation_labels"],
                         ["FULL", "PARTIAL"])

    def test_observation_never_proves_process_or_isolation(self):
        result = profile.profile_producer_source(SAMPLE)
        for key in ("signed_test_process_proven", "real_import_origin_proven",
                    "sandbox_test_execution_proven", "human_approval_verified",
                    "release_authorized"):
            self.assertFalse(result[key])

    def test_missing_essential_functions_stays_unresolved(self):
        result = profile.profile_producer_source("def test_repair_proposal(): pass")
        self.assertFalse(result["required_symbols_present"])
        self.assertFalse(result["symbols"]["_run_declared_tests"]["present"])

    def test_source_syntax_error_is_not_silently_accepted(self):
        with self.assertRaises(SyntaxError):
            profile.profile_producer_source("def test_repair_proposal(:")

    def test_wrong_machine_does_not_probe_files(self):
        with patch.dict("os.environ", {"COMPUTERNAME": "DESKTOP-SDOG0EL"}):
            self.assertEqual(profile.inspect_portable_fix()["reason"], "C278_WRONG_MACHINE")

    def test_cli_wrong_machine_is_hold_without_source_execution(self):
        with patch.dict("os.environ", {"COMPUTERNAME": "DESKTOP-SDOG0EL"}), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(profile.main(), 2)
            self.assertIn('"reason":"C278_WRONG_MACHINE"', out.getvalue())
            self.assertNotIn("C278_PRODUCER_STATIC_READONLY_PASS=True", out.getvalue())


if __name__ == "__main__":
    unittest.main()
