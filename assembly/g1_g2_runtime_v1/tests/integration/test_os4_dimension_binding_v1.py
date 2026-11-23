import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from obsidia_os4_dimension_binding_v1 import bind_dimension_readonly


class OS4DimensionBindingV1(unittest.TestCase):

    def setUp(self):
        self.observation = {
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "dimension": "proportion",
            "value": 12,
            "unit": "percent",
            "evidence_ref": "synthetic:irrigation:001",
        }

        self.mapping = {
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "dimension": "proportion",
            "source_unit": "percent",
            "canonical_unit": "ratio",
            "scale": "0.01",
            "mapping_ref": "synthetic:mapping:001",
        }

    def test_deterministic_conversion(self):
        result = bind_dimension_readonly(
            self.observation, self.mapping
        )

        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertEqual(
            result["canonical_measure"]["canonical_value"],
            "0.12",
        )
        self.assertFalse(result["trust_verified"])
        self.assertFalse(result["measure_valid"])
        self.assertFalse(result["execution_authorized"])

    def test_dimension_mismatch_hold(self):
        mapping = copy.deepcopy(self.mapping)
        mapping["dimension"] = "distance"

        result = bind_dimension_readonly(self.observation, mapping)

        self.assertEqual(result["status"], "HOLD")

    def test_source_unit_mismatch_hold(self):
        mapping = copy.deepcopy(self.mapping)
        mapping["source_unit"] = "meters"

        result = bind_dimension_readonly(self.observation, mapping)

        self.assertEqual(result["status"], "HOLD")

    def test_missing_mapping_hold(self):
        result = bind_dimension_readonly(self.observation, {})

        self.assertEqual(result["status"], "HOLD")

    def test_nonfinite_measure_hold(self):
        observation = copy.deepcopy(self.observation)
        observation["value"] = float("nan")

        result = bind_dimension_readonly(observation, self.mapping)

        self.assertEqual(result["status"], "HOLD")

    def test_authority_injection_hold(self):
        mapping = copy.deepcopy(self.mapping)
        mapping["decision_authority"] = "OS4"

        result = bind_dimension_readonly(self.observation, mapping)

        self.assertEqual(result["status"], "HOLD")

    def test_conversion_never_authenticates(self):
        mapping = copy.deepcopy(self.mapping)
        mapping["mapping_ref"] = "forged:sovereign"

        result = bind_dimension_readonly(self.observation, mapping)

        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertFalse(result["trust_verified"])
        self.assertFalse(result["measure_valid"])
        self.assertFalse(result["kernel_ready"])


if __name__ == "__main__":
    unittest.main()
