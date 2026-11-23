"""P1-C66: F62 canonical packet boundary, read-only regression."""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sigma.packets import (
    build_sigma_domain_packet,
    validate_sigma_packet,
)


class SigmaF62Boundary(unittest.TestCase):

    def setUp(self):
        self.packet = build_sigma_domain_packet(
            "bank", {}, None
        )

        result = validate_sigma_packet(self.packet)

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["errors"], [])

    def test_baseline_valid(self):
        result = validate_sigma_packet(self.packet)
        self.assertEqual(result["status"], "PASS")

    def test_scalar_gate_refused(self):
        packet = copy.deepcopy(self.packet)
        packet["x108_gate"] = "ALLOW"

        result = validate_sigma_packet(packet)

        self.assertEqual(result["status"], "FAIL")
        self.assertIn(
            "x108_gate must be a dict",
            result["errors"],
        )

    def test_readonly_false_refused(self):
        packet = copy.deepcopy(self.packet)
        packet["boundary"]["readonly"] = False

        result = validate_sigma_packet(packet)

        self.assertEqual(result["status"], "FAIL")
        self.assertIn(
            "boundary.readonly != True",
            result["errors"],
        )

    def test_advisory_false_refused(self):
        packet = copy.deepcopy(self.packet)
        packet["boundary"]["advisory_only"] = False

        result = validate_sigma_packet(packet)

        self.assertEqual(result["status"], "FAIL")
        self.assertIn(
            "boundary.advisory_only != True",
            result["errors"],
        )


if __name__ == "__main__":
    unittest.main()
