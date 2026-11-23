import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obsidia_os4_mapping_registry_v1 import (
    inspect_os4_mapping_registry,
    inspect_os4_mapping_registry_file,
)


class OS4MappingRegistryV1(unittest.TestCase):

    def setUp(self):
        self.registry = {
            "schema": "OBSIDIA_OS4_MAPPING_REGISTRY_V1",
            "registry_version": "1",
            "decision_authority": "KX108_ONLY",
            "mappings": [{
                "domain": "agriculture_irrigation",
                "metric": "soil_moisture",
                "dimension": "relative_humidity",
                "source_unit": "percent",
                "canonical_unit": "ratio",
                "scale": "0.01",
                "mapping_ref": "candidate:001",
                "version": "1",
                "issuer_ref": None,
                "qualification_ref": None,
                "revocation_ref": None,
            }],
        }

    def test_valid_structure_remains_untrusted(self):
        before = copy.deepcopy(self.registry)
        result = inspect_os4_mapping_registry(self.registry)

        self.assertEqual(result["status"], "STRUCTURE_VALID_UNTRUSTED")
        self.assertFalse(result["registry_authenticated"])
        self.assertFalse(result["semantic_qualification_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(before, self.registry)

    def test_authority_injection_refused(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["approved"] = True

        self.assertEqual(
            inspect_os4_mapping_registry(registry)["status"], "HOLD"
        )

    def test_fake_issuer_does_not_authenticate(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["issuer_ref"] = "founder:claimed"
        registry["mappings"][0]["qualification_ref"] = "proof:claimed"

        result = inspect_os4_mapping_registry(registry)

        self.assertEqual(result["status"], "STRUCTURE_VALID_UNTRUSTED")
        self.assertFalse(result["registry_authenticated"])
        self.assertFalse(result["semantic_qualification_verified"])

    def test_duplicate_mapping_refused(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"].append(copy.deepcopy(registry["mappings"][0]))

        self.assertEqual(
            inspect_os4_mapping_registry(registry)["reason"],
            "MAPPING_AMBIGUOUS_OR_DUPLICATE",
        )

    def test_persistent_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registry.json"
            path.write_text(json.dumps(self.registry), encoding="utf-8")

            before = path.read_bytes()
            result = inspect_os4_mapping_registry_file(path)

            self.assertEqual(result["status"], "STRUCTURE_VALID_UNTRUSTED")
            self.assertEqual(path.read_bytes(), before)

    def test_duplicate_json_key_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registry.json"
            path.write_text(
                '{"schema":"a","schema":"b"}',
                encoding="utf-8",
            )

            result = inspect_os4_mapping_registry_file(path)

            self.assertEqual(result["status"], "HOLD")

    def test_nonfinite_json_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registry.json"
            path.write_text('{"value":NaN}', encoding="utf-8")

            result = inspect_os4_mapping_registry_file(path)

            self.assertEqual(result["status"], "HOLD")


    def test_invalid_scales_refused(self):
        for scale in ("invalid", "NaN", "Infinity", "0", "-1", "1e100"):
            with self.subTest(scale=scale):
                registry = copy.deepcopy(self.registry)
                registry["mappings"][0]["scale"] = scale

                result = inspect_os4_mapping_registry(registry)

                self.assertEqual(result["status"], "HOLD")
                self.assertFalse(result["registry_authenticated"])

    def test_competing_destination_refused(self):
        registry = copy.deepcopy(self.registry)
        second = copy.deepcopy(registry["mappings"][0])
        second["canonical_unit"] = "percent"
        second["mapping_ref"] = "candidate:002"
        registry["mappings"].append(second)

        result = inspect_os4_mapping_registry(registry)

        self.assertEqual(result["reason"], "MAPPING_AMBIGUOUS_OR_DUPLICATE")

    def test_competing_version_refused(self):
        registry = copy.deepcopy(self.registry)
        second = copy.deepcopy(registry["mappings"][0])
        second["version"] = "2"
        second["mapping_ref"] = "candidate:003"
        registry["mappings"].append(second)

        result = inspect_os4_mapping_registry(registry)

        self.assertEqual(result["reason"], "MAPPING_AMBIGUOUS_OR_DUPLICATE")

    def test_revocation_reference_holds(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["revocation_ref"] = "revocation:claimed:001"

        result = inspect_os4_mapping_registry(registry)

        self.assertEqual(result["reason"], "MAPPING_REVOCATION_UNVERIFIED")
        self.assertFalse(result["registry_authenticated"])


if __name__ == "__main__":
    unittest.main()
