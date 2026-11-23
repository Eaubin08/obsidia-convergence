import contextlib
import copy
import io
import unittest

from obsidia_os4_registry_sigma_bridge_v1 import (
    evaluate_os4_registry_sigma_readonly,
)


class OS4RegistrySigmaBridgeV1(unittest.TestCase):

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

    def evaluate(self, observation=None, registry=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return evaluate_os4_registry_sigma_readonly(
                self.observation if observation is None else observation,
                self.registry if registry is None else registry,
            )

    def assert_boundary(self, result):
        self.assertEqual(result["kx108_gate"], "HOLD")
        self.assertIs(result["execution_authorized"], False)
        self.assertIs(result["trust_verified"], False)
        self.assertIs(result["measure_valid"], False)
        self.assertIs(result["action_ticket_issued"], False)
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertIs(result["readonly"], True)

    def test_end_to_end_candidate_remains_untrusted(self):
        result = self.evaluate()
        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertEqual(
            result["registry_binding"]["canonical_measure"]["canonical_value"],
            "0.12",
        )
        self.assertEqual(
            result["sigma_evaluation"]["kx108_gate"],
            "HOLD",
        )
        self.assert_boundary(result)

    def test_input_immutability(self):
        observation_before = copy.deepcopy(self.observation)
        registry_before = copy.deepcopy(self.registry)
        self.evaluate()
        self.assertEqual(self.observation, observation_before)
        self.assertEqual(self.registry, registry_before)

    def test_unknown_mapping(self):
        observation = copy.deepcopy(self.observation)
        observation["metric"] = "unknown_metric"
        result = self.evaluate(observation=observation)
        self.assertEqual(result["status"], "HOLD")
        self.assert_boundary(result)

    def test_revoked_mapping(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["revocation_ref"] = "revoked:001"
        result = self.evaluate(registry=registry)
        self.assertEqual(result["status"], "HOLD")
        self.assert_boundary(result)

    def test_invalid_scale(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["scale"] = "NaN"
        result = self.evaluate(registry=registry)
        self.assertEqual(result["status"], "HOLD")
        self.assert_boundary(result)

    def test_fake_issuer_cannot_promote(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["issuer_ref"] = "founder:claimed"
        registry["mappings"][0]["qualification_ref"] = "proof:claimed"
        result = self.evaluate(registry=registry)
        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assert_boundary(result)

    def test_authority_injection(self):
        registry = copy.deepcopy(self.registry)
        registry["mappings"][0]["approved"] = True
        result = self.evaluate(registry=registry)
        self.assertEqual(result["status"], "HOLD")
        self.assert_boundary(result)


if __name__ == "__main__":
    unittest.main()
