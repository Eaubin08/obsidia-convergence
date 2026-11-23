import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from obsidia_os4_sigma_adapter_v1 import (
    evaluate_domain_observation_readonly,
)


class OS4SigmaAdapterV1(unittest.TestCase):

    def observation(self, value):
        return {
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "value": value,
            "unit": "percent",
            "evidence_ref": f"synthetic:irrigation:{value}",
        }

    def test_unknown_domain_hold(self):
        result = evaluate_domain_observation_readonly(
            self.observation(12)
        )
        self.assertEqual(result["kx108_gate"], "HOLD")
        self.assertFalse(result["execution_authorized"])
        self.assertIn("UNKNOWN_RULE", result["reason"])

    def test_distinct_observations_preserved(self):
        a = evaluate_domain_observation_readonly(
            self.observation(12)
        )
        b = evaluate_domain_observation_readonly(
            self.observation(80)
        )
        self.assertNotEqual(
            a["translation"]["canonical_observation"],
            b["translation"]["canonical_observation"],
        )

    def test_authority_injection_hold(self):
        observation = self.observation(12)
        observation["decision_authority"] = "OS4"
        result = evaluate_domain_observation_readonly(observation)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["kx108_gate"], "HOLD")
        self.assertFalse(result["execution_authorized"])


    def test_unknowns_not_duplicated_by_guard(self):
        result = evaluate_domain_observation_readonly(
            self.observation(12)
        )

        unknowns = result["translation"]["canonical_observation"]["unknowns"]

        self.assertEqual(
            unknowns,
            ["DOMAIN_RULE_NOT_VERIFIED"],
        )
        self.assertEqual(result["kx108_gate"], "HOLD")
        self.assertFalse(result["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
