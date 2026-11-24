import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from obsidia_domain_translator_v0 import (
    translate_domain_observation,
)


class DomainTranslatorV0(unittest.TestCase):

    def observation(self, value):
        return {
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "value": value,
            "unit": "percent",
            "evidence_ref": f"synthetic:irrigation:{value}",
        }

    def test_unknown_domain_structurally_supported(self):
        result = translate_domain_observation(
            self.observation(12)
        )

        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertEqual(
            result["canonical_observation"]["domain"],
            "agriculture_irrigation",
        )
        self.assertFalse(result["kernel_ready"])
        self.assertFalse(result["execution_authorized"])

    def test_distinct_values_remain_distinct(self):
        a = translate_domain_observation(self.observation(12))
        b = translate_domain_observation(self.observation(80))

        self.assertNotEqual(
            a["canonical_observation"],
            b["canonical_observation"],
        )

    def test_evidence_preserved(self):
        result = translate_domain_observation(
            self.observation(12)
        )

        self.assertEqual(
            result["canonical_observation"]["evidence_refs"],
            ["synthetic:irrigation:12"],
        )

    def test_missing_evidence_refused(self):
        observation = self.observation(12)
        del observation["evidence_ref"]

        result = translate_domain_observation(observation)

        self.assertEqual(result["status"], "HOLD")

    def test_invalid_measurement_refused(self):
        for value in (True, float("nan"), float("inf"), "12"):
            with self.subTest(value=value):
                result = translate_domain_observation(
                    self.observation(value)
                )
                self.assertEqual(result["status"], "HOLD")

    def test_authority_injection_refused(self):
        observation = self.observation(12)
        observation["decision_authority"] = "OBSIDURE"

        result = translate_domain_observation(observation)

        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
