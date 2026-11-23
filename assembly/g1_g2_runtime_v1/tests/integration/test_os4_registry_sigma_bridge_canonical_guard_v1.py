import copy
import unittest
from unittest.mock import patch

from obsidia_os4_registry_binding_v1 import (
    bind_os4_registry_observation,
)
from obsidia_os4_registry_sigma_bridge_v1 import (
    evaluate_os4_registry_sigma_readonly,
)


class CanonicalMeasureBoundary(unittest.TestCase):

    def setUp(self):
        self.observation = {
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "dimension": "relative_humidity",
            "value": 12,
            "unit": "percent",
            "evidence_ref": "local:unattested",
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

        self.sigma = {
            "status": "CANDIDATE_ONLY",
            "reason": "UNKNOWN_RULE",
            "kx108_gate": "HOLD",
            "execution_authorized": False,
            "decision_authority": "KX108_ONLY",
            "readonly": True,
        }

    def baseline_binding(self):
        return bind_os4_registry_observation(
            self.observation,
            self.registry,
        )

    def evaluate(self, binding):
        with patch(
            "obsidia_os4_registry_sigma_bridge_v1.bind_os4_registry_observation",
            return_value=binding,
        ), patch(
            "obsidia_os4_registry_sigma_bridge_v1.evaluate_domain_observation_readonly",
            return_value=dict(self.sigma),
        ):
            return evaluate_os4_registry_sigma_readonly(
                self.observation,
                self.registry,
            )

    def assert_closed(self, result):
        self.assertEqual(result["kx108_gate"], "HOLD")
        self.assertIs(result["execution_authorized"], False)
        self.assertIs(result["measure_valid"], False)
        self.assertIs(result["trust_verified"], False)
        self.assertEqual(result["decision_authority"], "KX108_ONLY")

    def test_forged_nested_authority_fields_refused(self):
        cases = {
            "trust_verified": True,
            "measure_valid": True,
            "decision_authority": "OS4_ONLY",
            "approved": True,
            "execution_authorized": True,
        }

        for field, value in cases.items():
            with self.subTest(field=field):
                forged = copy.deepcopy(self.baseline_binding())
                forged["canonical_measure"][field] = value

                result = self.evaluate(forged)

                self.assertEqual(result["status"], "HOLD")
                self.assert_closed(result)

    def test_forged_mapping_authenticity_refused(self):
        forged = copy.deepcopy(self.baseline_binding())
        forged["canonical_measure"]["mapping_authenticity"] = "VERIFIED"

        result = self.evaluate(forged)

        self.assertEqual(result["status"], "HOLD")
        self.assert_closed(result)

    def test_missing_unknown_refused(self):
        forged = copy.deepcopy(self.baseline_binding())
        forged["canonical_measure"]["unknowns"] = []

        result = self.evaluate(forged)

        self.assertEqual(result["status"], "HOLD")
        self.assert_closed(result)

    def test_nominal_candidate_preserved(self):
        result = self.evaluate(self.baseline_binding())

        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assert_closed(result)

        canonical = result["registry_binding"]["canonical_measure"]

        self.assertEqual(canonical["canonical_value"], "0.12")
        self.assertEqual(canonical["mapping_authenticity"], "UNVERIFIED")
        self.assertNotIn("approved", canonical)


if __name__ == "__main__":
    unittest.main()
