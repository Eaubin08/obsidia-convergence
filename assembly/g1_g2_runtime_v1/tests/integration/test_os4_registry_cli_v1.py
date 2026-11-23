import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "obsidia_governance_cli_v1.py"


class OS4RegistryCLI(unittest.TestCase):

    def setUp(self):
        self.payload = {
            "observation": {
                "domain": "agriculture_irrigation",
                "metric": "soil_moisture",
                "dimension": "relative_humidity",
                "value": 12,
                "unit": "percent",
                "evidence_ref": "local:unattested",
            },
            "registry": {
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
            },
        }

    def invoke(self, payload):
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(CLI),
                "os4-registry-evaluate",
                "--stdin",
            ],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            cwd=ROOT,
            timeout=30,
        )
        return completed, json.loads(completed.stdout)

    def assert_closed(self, completed, result):
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertIs(result["execution_authorized"], False)
        self.assertIs(result["action_ticket_issued"], False)
        self.assertIs(result["target_mutated"], False)
        self.assertIs(result["release_authorized"], False)
        self.assertEqual(result["decision_authority"], "KX108_ONLY")

    def test_valid_mapping_remains_hold(self):
        completed, result = self.invoke(self.payload)
        self.assert_closed(completed, result)
        self.assertEqual(
            result["os4_result"]["status"],
            "CANDIDATE_ONLY",
        )
        self.assertEqual(
            result["os4_result"]["kx108_gate"],
            "HOLD",
        )

    def test_authority_field_injection_refused(self):
        payload = json.loads(json.dumps(self.payload))
        payload["approved"] = True
        completed, result = self.invoke(payload)
        self.assert_closed(completed, result)

    def test_revoked_mapping_refused(self):
        payload = json.loads(json.dumps(self.payload))
        payload["registry"]["mappings"][0]["revocation_ref"] = "revoked:001"
        completed, result = self.invoke(payload)
        self.assert_closed(completed, result)


if __name__ == "__main__":
    unittest.main()
