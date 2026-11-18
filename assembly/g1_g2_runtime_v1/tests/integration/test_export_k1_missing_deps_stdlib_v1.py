"""Tests locaux du collecteur de dépendances, sans git push ni accès FIX."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


_FILE = Path(__file__).resolve().parents[2] / "tools" / "export_k1_missing_deps_portable_v1.py"
_SPEC = importlib.util.spec_from_file_location("k1_missing_exporter", _FILE)
assert _SPEC and _SPEC.loader
EXPORT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(EXPORT)

_TOOLS = Path(__file__).resolve().parents[2] / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))
import export_k1_c2_bridge_deps_portable_v2 as C2_EXPORT  # noqa: E402
import export_k1_obsidure_c2_deps_portable_v3 as OBA_EXPORT  # noqa: E402


class ExporterGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="obsidia-export-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "sigma").mkdir()

    def test_manifest_scope_is_strict(self):
        self.assertEqual(EXPORT.SOURCE_MACHINE, "DESKTOP-Q5MD7J7")
        self.assertEqual(EXPORT.DEST_BRANCH, "build/g1-g2-runtime-v1")
        self.assertTrue(all(s.endswith(".py") for s in EXPORT.REQUIRED))
        self.assertFalse(any("obsidia_cli.py" in s for s in EXPORT.REQUIRED))

    def test_source_code_can_be_read_without_execution(self):
        (self.root / "sigma/registry.py").write_text("VALUE = 108\n", encoding="utf-8")
        self.assertEqual(EXPORT.guarded_read(self.root, "sigma/registry.py"), b"VALUE = 108\n")

    def test_blocks_parent_escape(self):
        with self.assertRaises(EXPORT.ExportHold):
            EXPORT.guarded_read(self.root, "../private.py")

    def test_blocks_known_secret_pattern(self):
        sample = "ghp_" + "a" * 28
        (self.root / "sigma/registry.py").write_text(sample, encoding="utf-8")
        with self.assertRaises(EXPORT.ExportHold):
            EXPORT.guarded_read(self.root, "sigma/registry.py")

    def test_blocks_missing_file(self):
        with self.assertRaises(EXPORT.ExportHold):
            EXPORT.guarded_read(self.root, "sigma/registry.py")

    def test_c2_static_import_closure_is_bounded_to_rails(self):
        raw = (b"import obsidia_candidate_patch_v1\n"
               b"from scripts import obsidia_build\n"
               b"from sigma.domains.meta_agents import build_meta_agents\n"
               b"from periphery.world_calls import ticket_store\n"
               b"import unrelated_module\n")
        found = C2_EXPORT._static_imports(raw, "scripts/bridge.py")
        self.assertEqual(found, {
            "scripts/obsidia_candidate_patch_v1.py",
            "scripts/obsidia_build.py",
            "sigma/domains/meta_agents.py",
            "periphery/world_calls/ticket_store.py",
        })

    def test_c2_obsidure_import_resolution(self):
        raw = (b"import obsidure_bounded_apply\n"
               b"from obsidure_synth_session import load\n"
               b"from scripts import obsidure_session\n")
        self.assertEqual(C2_EXPORT._static_imports(raw, "scripts/test_bridge.py"), {
            "scripts/obsidure_bounded_apply.py",
            "scripts/obsidure_synth_session.py",
            "scripts/obsidure_session.py",
        })

    def test_c2_validator_import_closure_follows_nested_dependencies(self):
        source = self.root / "src"
        dest = self.root / "dst"
        (source / "scripts").mkdir(parents=True)
        (dest / C2_EXPORT.ASSEMBLY / "scripts").mkdir(parents=True)
        (source / "scripts/obsidure_bounded_apply.py").write_text(
            "import obsidure_synth_session\n", encoding="utf-8")
        (source / "scripts/obsidure_synth_session.py").write_text(
            "import obsidia_mission_authority_v0\n", encoding="utf-8")
        (source / "scripts/obsidia_mission_authority_v0.py").write_text(
            "PASS = True\n", encoding="utf-8")
        (dest / C2_EXPORT.ASSEMBLY / "scripts/obsidia_mission_authority_v0.py").write_text(
            "PASS = True\n", encoding="utf-8")
        selected = C2_EXPORT.select_static_closure(
            source, dest, seeds=OBA_EXPORT.SEEDS, manifest_path=OBA_EXPORT.MANIFEST)
        self.assertEqual(set(selected), {
            "scripts/obsidure_bounded_apply.py", "scripts/obsidure_synth_session.py",
        })

    def test_c2_closure_selects_only_missing_static_deps(self):
        source = self.root / "src"
        dest = self.root / "dst"
        (source / "scripts").mkdir(parents=True)
        (dest / C2_EXPORT.ASSEMBLY / "scripts").mkdir(parents=True)
        bridge = source / "scripts/obsidia_family_wiring_apply_bridge_v0.py"
        bridge.write_text("import obsidia_test_contract\n", encoding="utf-8")
        (source / "scripts/obsidia_test_contract.py").write_text("PASS = True\n", encoding="utf-8")
        (dest / C2_EXPORT.ASSEMBLY / "scripts/obsidia_test_contract.py").write_text("PASS = True\n")
        result = C2_EXPORT.select_bridge_closure(source, dest)
        self.assertEqual(set(result), {"scripts/obsidia_family_wiring_apply_bridge_v0.py"})


if __name__ == "__main__":
    unittest.main()
