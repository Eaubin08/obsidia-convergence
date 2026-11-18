"""Le scanner d'Obsidure ne doit jamais importer les sources privees."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


_TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(_TOOLS))
_PATH = _TOOLS / "inspect_obsidure_effects_portable_v1.py"
_SPEC = importlib.util.spec_from_file_location("obsidure_effects_inspector", _PATH)
assert _SPEC and _SPEC.loader
INSPECT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(INSPECT)


class ObsidureEffectsInspection(unittest.TestCase):
    def test_synthetic_code_is_parsed_not_executed(self):
        raw = b'''raise RuntimeError("MUST_NOT_EXECUTE")
class AgentObsidure:
    def evaluate_repair_proposal(self, proposal_source, run_tests):
        self.last_evidence = None
        data = proposal_source.read_text()
        if run_tests:
            subprocess.run(["do-not-run"])
        return {"status": "READY", "proposal": data}
'''
        result = INSPECT.inspect_effects(raw, "fixture.py", ("AgentObsidure.evaluate_repair_proposal",))
        report = result["entrypoints"]["AgentObsidure.evaluate_repair_proposal"]
        self.assertIn("proposal_source.read_text", report["direct_effect_indicators"]["file_reads_or_parses"])
        self.assertIn("subprocess.run", report["direct_effect_indicators"]["possible_process_exec"])
        self.assertIn("self.last_evidence", report["attribute_assignments"])
        self.assertEqual(report["return_shapes"], [{"kind": "DICT", "keys": ["proposal", "status"]}])
        self.assertEqual(report["effect_certification"], "INDETERMINATE_STATIC_ONLY")

    def test_public_bridge_global_write_indicator(self):
        raw = b'''def build_child_execution_from_obsidure_proposal():
    _OBA.PROPOSALS_DIR = Path("sandbox")
    return {"status": "BRIDGE_CHILD_READY", "child": {"operation_type": "UPDATE_TARGET_FROM_SOURCE"}}
'''
        report = INSPECT.inspect_effects(raw, "bridge.py", ("build_child_execution_from_obsidure_proposal",))
        self.assertIn("_OBA.PROPOSALS_DIR", report["entrypoints"]["build_child_execution_from_obsidure_proposal"]["attribute_assignments"])

    def test_missing_entrypoint_holds(self):
        with self.assertRaises(INSPECT.ScopeHold):
            INSPECT.inspect_effects(b"def unused(): pass\n", "file.py", ("missing",))

    def test_oversize_holds(self):
        with self.assertRaises(INSPECT.ScopeHold):
            INSPECT.inspect_effects(b" " * 2_000_001, "file.py", ("missing",))

    def test_exact_three_canonical_paths_only(self):
        self.assertEqual(len(INSPECT.TARGETS), 3)
        self.assertIn("scripts/obsidure_bounded_apply.py", INSPECT.TARGETS)
        self.assertNotIn("periphery/world_calls/world_action_bus.py", INSPECT.TARGETS)


if __name__ == "__main__":
    unittest.main()
