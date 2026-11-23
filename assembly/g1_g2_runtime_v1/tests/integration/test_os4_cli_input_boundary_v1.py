import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "obsidia_governance_cli_v1.py"


class OS4CLIInputBoundary(unittest.TestCase):

    def run_cli(self, raw):
        process = subprocess.run(
            [sys.executable, "-B", str(CLI), "os4-evaluate", "--stdin"],
            input=raw,
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=15,
        )

        self.assertEqual(process.returncode, 2)
        self.assertNotIn("[KERNEL_TRACE]", process.stdout)

        result = json.loads(process.stdout)

        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["action_ticket_issued"])

        return result

    def test_valid_observation_remains_hold(self):
        result = self.run_cli(json.dumps({
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "value": 12,
            "unit": "percent",
            "evidence_ref": "synthetic:irrigation:001",
        }))
        self.assertEqual(
            result["os4_result"]["kx108_gate"],
            "HOLD",
        )
        self.assertEqual(
            result["os4_result"]["translation"]
                  ["canonical_observation"]["unknowns"],
            ["DOMAIN_RULE_NOT_VERIFIED"],
        )

    def test_duplicate_json_keys_refused(self):
        self.run_cli(
            '{"domain":"bank","domain":"agriculture_irrigation"}'
        )

    def test_nonfinite_json_refused(self):
        self.run_cli(
            '{"domain":"test","value":NaN}'
        )

    def test_malformed_json_refused(self):
        self.run_cli('{"domain":')

    def test_authority_injection_refused(self):
        result = self.run_cli(json.dumps({
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "value": 12,
            "unit": "percent",
            "evidence_ref": "synthetic:irrigation:001",
            "decision_authority": "OS4",
        }))
        self.assertEqual(
            result["os4_result"]["status"],
            "HOLD",
        )


if __name__ == "__main__":
    unittest.main()
