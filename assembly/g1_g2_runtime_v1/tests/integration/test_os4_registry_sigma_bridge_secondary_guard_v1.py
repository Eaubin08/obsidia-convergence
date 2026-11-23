import unittest
from unittest.mock import patch

from obsidia_os4_registry_sigma_bridge_v1 import (
    evaluate_os4_registry_sigma_readonly,
)

class OS4SecondaryAuthorityGuard(unittest.TestCase):

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

        self.baseline = {
            "status": "CANDIDATE_ONLY",
            "reason": "UNKNOWN_RULE",
            "kx108_gate": "HOLD",
            "execution_authorized": False,
            "decision_authority": "KX108_ONLY",
            "readonly": True,
        }

    def evaluate(self, forged):
        with patch(
            "obsidia_os4_registry_sigma_bridge_v1.evaluate_domain_observation_readonly",
            return_value=forged,
        ):
            return evaluate_os4_registry_sigma_readonly(
                self.observation,
                self.registry,
            )

    def assert_safe(self, result):
        self.assertEqual(result["kx108_gate"], "HOLD")
        self.assertIs(result["execution_authorized"], False)
        self.assertIs(result["measure_valid"], False)
        self.assertIs(result["trust_verified"], False)
        self.assertEqual(result["decision_authority"], "KX108_ONLY")

    def test_forged_secondary_authorities_refused(self):
        for field in (
            "action_ticket_issued",
            "release_authorized",
            "target_mutated",
            "measure_valid",
            "trust_verified",
            "kernel_ready",
        ):
            with self.subTest(field=field):
                forged = dict(self.baseline)
                forged[field] = True
                result = self.evaluate(forged)
                self.assertEqual(result["status"], "HOLD")
                self.assert_safe(result)

    def test_forged_act_status_refused(self):
        forged = dict(self.baseline)
        forged["status"] = "ACT"
        result = self.evaluate(forged)
        self.assertEqual(result["status"], "HOLD")
        self.assert_safe(result)

    def test_unrecognized_fields_not_forwarded(self):
        forged = dict(self.baseline)
        forged["invented_authority"] = "SOVEREIGN"
        result = self.evaluate(forged)
        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertNotIn(
            "invented_authority",
            result["sigma_evaluation"],
        )
        self.assert_safe(result)

    def test_nominal_diagnostic_stays_untrusted(self):
        result = self.evaluate(dict(self.baseline))
        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assert_safe(result)
        nested = result["sigma_evaluation"]
        self.assertIs(nested["release_authorized"], False)
        self.assertIs(nested["action_ticket_issued"], False)
        self.assertIs(nested["target_mutated"], False)

if __name__ == "__main__":
    unittest.main()
