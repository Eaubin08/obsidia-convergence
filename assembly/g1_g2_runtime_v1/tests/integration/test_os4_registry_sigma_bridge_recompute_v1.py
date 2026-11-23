import copy
import unittest
from unittest.mock import patch

from obsidia_os4_registry_binding_v1 import (
    bind_os4_registry_observation,
)
from obsidia_os4_registry_sigma_bridge_v1 import (
    evaluate_os4_registry_sigma_readonly,
)


class RegistryBindingRecompute(unittest.TestCase):

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

        self.binding = bind_os4_registry_observation(
            self.observation,
            self.registry,
        )

        self.sigma = {
            "status": "CANDIDATE_ONLY",
            "reason": "UNKNOWN_RULE",
            "kx108_gate": "HOLD",
            "execution_authorized": False,
            "decision_authority": "KX108_ONLY",
            "readonly": True,
        }

    def evaluate(self, forged):
        with patch(
            "obsidia_os4_registry_sigma_bridge_v1.bind_os4_registry_observation",
            return_value=forged,
        ), patch(
            "obsidia_os4_registry_sigma_bridge_v1.evaluate_domain_observation_readonly",
            return_value=dict(self.sigma),
        ):
            return evaluate_os4_registry_sigma_readonly(
                self.observation,
                self.registry,
            )

    def test_forged_values_refused(self):
        cases = [
            ("canonical_measure", "canonical_value", "999"),
            ("canonical_measure", "source_value", "999"),
            ("canonical_measure", "canonical_unit", "kg"),
            ("canonical_measure", "mapping_sha256", "0" * 64),
            ("root", "registry_sha256", "0" * 64),
            ("root", "mapping_version", "999"),
            ("canonical_measure", "evidence_refs", ["proof:claimed"]),
        ]

        for location, field, value in cases:
            with self.subTest(field=field):
                forged = copy.deepcopy(self.binding)
                target = (
                    forged if location == "root"
                    else forged["canonical_measure"]
                )
                target[field] = value

                result = self.evaluate(forged)

                self.assertEqual(result["status"], "HOLD")
                self.assertEqual(result["kx108_gate"], "HOLD")
                self.assertIs(result["execution_authorized"], False)
                self.assertIs(result["trust_verified"], False)

    def test_nominal_binding_remains_candidate(self):
        result = self.evaluate(copy.deepcopy(self.binding))
        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertEqual(result["kx108_gate"], "HOLD")
        self.assertIs(result["measure_valid"], False)
        self.assertIs(result["trust_verified"], False)


if __name__ == "__main__":
    unittest.main()
