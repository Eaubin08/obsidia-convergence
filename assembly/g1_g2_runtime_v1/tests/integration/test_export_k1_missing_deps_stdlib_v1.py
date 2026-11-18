"""Tests locaux du collecteur de dépendances, sans git push ni accès FIX."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


_FILE = Path(__file__).resolve().parents[2] / "tools" / "export_k1_missing_deps_portable_v1.py"
_SPEC = importlib.util.spec_from_file_location("k1_missing_exporter", _FILE)
assert _SPEC and _SPEC.loader
EXPORT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(EXPORT)


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


if __name__ == "__main__":
    unittest.main()
