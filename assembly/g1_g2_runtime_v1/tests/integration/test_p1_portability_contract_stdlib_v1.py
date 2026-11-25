"""C272 : contrat de portabilité permanent (états de dépendance distincts)."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT / "scripts"), str(ROOT)):
    if _p in sys.path:
        sys.path.remove(_p)
    sys.path.insert(0, _p)

import obsidia_portability_contract_v1 as P


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class PortabilityContractSynthetic(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-port-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "scripts").mkdir()
        self.good = b"VALUE = 1\n"

    def _manifest(self, **entry):
        base = {
            "module": "mod_a", "relative_path": "scripts/mod_a.py",
            "expected_sha256": _sha(self.good), "superseded_sha256": [],
            "required": True,
        }
        base.update(entry)
        return {"schema": "OBSIDIA_P1_PORTABILITY_MANIFEST_V1", "entries": [base]}

    def _inspect(self, manifest, origin="same"):
        file = self.root / "scripts" / "mod_a.py"
        resolver = (lambda m: str(file)) if origin == "same" else (lambda m: origin)
        return P.inspect_portability(manifest, runtime_root=self.root, resolver=resolver)

    def status(self, res):
        return res["entries"][0]["status"]

    def assert_never_authority(self, res):
        self.assertEqual(res["decision_authority"], "KX108_ONLY")
        self.assertIs(res["pin_is_authority"], False)
        self.assertIs(res["execution_authorized"], False)
        self.assertIs(res["release_authorized"], False)

    def test_available_pinned_is_the_only_closed_state(self):
        (self.root / "scripts" / "mod_a.py").write_bytes(self.good)
        res = self._inspect(self._manifest())
        self.assertEqual(self.status(res), P.AVAILABLE_PINNED)
        self.assertTrue(res["portable_closure_verified"])
        self.assertEqual(res["status"], "PORTABLE_CLOSURE_VERIFIED")
        self.assert_never_authority(res)

    def test_missing(self):
        res = self._inspect(self._manifest())
        self.assertEqual(self.status(res), P.MISSING)
        self.assertFalse(res["portable_closure_verified"])
        self.assertEqual(res["reason"], "PORTABLE_CLOSURE_BLOCKED:mod_a")
        self.assert_never_authority(res)

    def test_hash_divergent(self):
        (self.root / "scripts" / "mod_a.py").write_bytes(self.good + b"# tampered\n")
        res = self._inspect(self._manifest())
        self.assertEqual(self.status(res), P.HASH_DIVERGENT)
        self.assertFalse(res["portable_closure_verified"])

    def test_wrong_version_superseded(self):
        old = b"VALUE = 0\n"
        (self.root / "scripts" / "mod_a.py").write_bytes(old)
        res = self._inspect(self._manifest(superseded_sha256=[_sha(old)]))
        self.assertEqual(self.status(res), P.WRONG_VERSION_SUPERSEDED)
        self.assertFalse(res["portable_closure_verified"])

    def test_unexpected_import_source(self):
        (self.root / "scripts" / "mod_a.py").write_bytes(self.good)
        for origin in (None, str(self.root / "elsewhere" / "mod_a.py")):
            with self.subTest(origin=origin):
                res = self._inspect(self._manifest(), origin=origin)
                self.assertEqual(self.status(res), P.UNEXPECTED_SOURCE)
                self.assertFalse(res["portable_closure_verified"])

    def test_present_but_unpinned_is_never_accepted(self):
        (self.root / "scripts" / "mod_a.py").write_bytes(b"# fabricated substitute\n")
        res = self._inspect(self._manifest(expected_sha256=None))
        self.assertEqual(self.status(res), P.UNPINNED_PRESENT)
        self.assertFalse(res["portable_closure_verified"])

    def test_invalid_manifest_holds(self):
        res = P.inspect_portability({"schema": "x", "entries": []}, runtime_root=self.root)
        self.assertEqual(res["status"], "HOLD")
        self.assertEqual(res["reason"], "PORTABILITY_MANIFEST_INVALID")


class PortabilityContractOnRealRuntime(unittest.TestCase):
    def test_real_manifest_state_is_honest(self):
        res = P.inspect_portability(P.load_manifest(), runtime_root=ROOT)
        by = {e["module"]: e for e in res["entries"]}
        for module in ("obsidia_isolated_work_unit_v0",
                       "obsidia_mission_local_snapshot_v0",
                       "obsidia_mission_authority_v0"):
            self.assertEqual(by[module]["status"], P.AVAILABLE_PINNED, by[module])
        # Aucune source canonique pour periphery.ecom_attestation, et agent_obsidure non intégré :
        self.assertEqual(by["periphery.ecom_attestation"]["status"], P.MISSING)
        self.assertEqual(by["periphery.agents.agent_obsidure"]["status"], P.MISSING)
        self.assertFalse(res["portable_closure_verified"])
        self.assertEqual(res["status"], "HOLD")
        self.assertEqual(
            res["blocking_modules"],
            ["periphery.ecom_attestation", "periphery.agents.agent_obsidure"],
        )

    def test_isolated_resolution_does_not_leave_the_runtime(self):
        resolver = P.isolated_origin_resolver(ROOT)
        origin = resolver("obsidia_isolated_work_unit_v0")
        self.assertTrue(origin)
        self.assertEqual(Path(origin).resolve(),
                         (ROOT / "scripts" / "obsidia_isolated_work_unit_v0.py").resolve())

    def test_no_personal_path_in_hma_test_or_manifest(self):
        for rel in ("tests/integration/test_hma_revocation_fail_closed_v1.py",
                    "portability_manifest_v1.json"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertNotIn("Desktop", text, rel)
            self.assertNotIn("C:\\Users", text, rel)
        json.loads((ROOT / "portability_manifest_v1.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
