import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obsidia_os4_registry_binding_v1 import (
    bind_os4_registry_observation,
)


class OS4RegistryBindingV1(unittest.TestCase):

    def setUp(self):
        self.observation = {
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "dimension": "relative_humidity",
            "value": 12,
            "unit": "percent",
            "evidence_ref": "synthetic:irrigation:001",
        }

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

    def assert_no_authority(self, result):
        self.assertFalse(result["trust_verified"])
        self.assertFalse(result["measure_valid"])
        self.assertFalse(result["kernel_ready"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["decision_authority"], "KX108_ONLY")

    def test_valid_mapping_remains_candidate(self):
        before_observation = copy.deepcopy(self.observation)
        before_registry = copy.deepcopy(self.registry)

        result = bind_os4_registry_observation(
            self.observation,
            self.registry,
        )

        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertEqual(
            result["canonical_measure"]["canonical_value"],
            "0.12",
        )
        self.assert_no_authority(result)
        self.assertEqual(self.observation, before_observation)
        self.assertEqual(self.registry, before_registry)

    def test_unknown_mapping_holds(self):
        observation = copy.deepcopy(self.observation)
        observation["metric"] = "unknown_metric"

        result = bind_os4_registry_observation(observation, self.registry)

        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_competing_version_holds(self):
        registry = copy.deepcopy(self.registry)
        second = copy.deepcopy(registry["mappings"][0])
        second["version"] = "2"
        second["mapping_ref"] = "candidate:002"
        registry["mappings"].append(second)

        result = bind_os4_registry_observation(self.observation, registry)

        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_revocation_holds(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["revocation_ref"] = "revocation:001"

        result = bind_os4_registry_observation(self.observation, registry)

        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_invalid_scale_holds(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["scale"] = "NaN"

        result = bind_os4_registry_observation(self.observation, registry)

        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_forged_issuer_never_authenticates(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["issuer_ref"] = "founder:claimed"
        registry["mappings"][0]["qualification_ref"] = "proof:claimed"

        result = bind_os4_registry_observation(self.observation, registry)

        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assert_no_authority(result)

    def test_observation_authority_injection_holds(self):
        observation = copy.deepcopy(self.observation)
        observation["execution_authorized"] = True

        result = bind_os4_registry_observation(observation, self.registry)

        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)


if __name__ == "__main__":
    unittest.main()
