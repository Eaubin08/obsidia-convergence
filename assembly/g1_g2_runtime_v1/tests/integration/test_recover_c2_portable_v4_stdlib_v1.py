"""Static recovery checks for the staged portable C2 import package."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[2] / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

import recover_c2_portable_v4 as RECOVERY  # noqa: E402


class C2RecoverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="obsidia-c2-recover-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.dest = self.root / "dest"
        (self.source / "scripts").mkdir(parents=True)
        (self.source / "periphery/agents").mkdir(parents=True)
        (self.dest / RECOVERY.ASSEMBLY / "scripts").mkdir(parents=True)

    def test_recovers_periphery_agents_and_transitive_bounded_imports(self):
        (self.dest / RECOVERY.ASSEMBLY / RECOVERY.V3_SOURCE).write_text(
            "from periphery.agents.agent_obsidure import Agent\n", encoding="utf-8")
        (self.source / "periphery/agents/agent_obsidure.py").write_text(
            "import obsidure_synth_session\n", encoding="utf-8")
        (self.source / "scripts/obsidure_synth_session.py").write_text(
            "import json\n", encoding="utf-8")
        (self.source / "periphery/agents/__init__.py").write_text("", encoding="utf-8")
        imported = RECOVERY.collect_recovery(self.source, self.dest)
        self.assertEqual(set(imported), {
            "periphery/agents/agent_obsidure.py",
            "periphery/agents/__init__.py",
            "scripts/obsidure_synth_session.py",
        })

    def test_refuses_missing_project_module(self):
        (self.dest / RECOVERY.ASSEMBLY / RECOVERY.V3_SOURCE).write_text(
            "from periphery.agents.not_found import Agent\n", encoding="utf-8")
        with self.assertRaises(RECOVERY.ExportHold):
            RECOVERY.collect_recovery(self.source, self.dest)

    def test_ignores_unrelated_standard_imports(self):
        (self.dest / RECOVERY.ASSEMBLY / RECOVERY.V3_SOURCE).write_text(
            "import json, pathlib\n", encoding="utf-8")
        self.assertEqual(RECOVERY.collect_recovery(self.source, self.dest), {})


if __name__ == "__main__":
    unittest.main()
