"""OS4 -> Sigma -> GuardX108: unknown-domain fail-closed boundary."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from obsidia_domain_translator_v0 import translate_domain_observation
from sigma.contracts import AgentVote, DomainAggregate
from sigma.guard import GuardX108


class OS4SigmaGuardBoundary(unittest.TestCase):

    def _evaluate(self, value):
        observation = {
            "domain": "agriculture_irrigation",
            "metric": "soil_moisture",
            "value": value,
            "unit": "percent",
            "evidence_ref": f"synthetic:irrigation:{value}",
        }

        translation = translate_domain_observation(observation)

        self.assertEqual(translation["status"], "CANDIDATE_ONLY")
        self.assertFalse(translation["kernel_ready"])
        self.assertFalse(translation["execution_authorized"])

        canonical = translation["canonical_observation"]

        vote = AgentVote(
            agent_id="OS4_STRUCTURAL_TRANSLATOR",
            vote="HOLD",
            proposed_verdict="HOLD",
            confidence=0.0,
            domain=canonical["domain"],
            rule_id="OS4_UNVERIFIED_DOMAIN_RULE",
            observed_value=canonical["observed_value"],
            evidence_refs=canonical["evidence_refs"],
            unknowns=canonical["unknowns"],
            measure_valid=False,
        )

        aggregate = DomainAggregate(
            domain=canonical["domain"],
            market_verdict="HOLD",
            confidence=0.0,
            agent_votes=[vote],
            evidence_refs=canonical["evidence_refs"],
            unknowns=canonical["unknowns"],
        )

        decision = GuardX108().decide(aggregate)

        gate = getattr(decision, "x108_gate", None)
        reason = getattr(decision, "reason_code", "")

        self.assertEqual(
            str(getattr(gate, "value", gate)),
            "HOLD",
        )
        self.assertIn("UNKNOWN_RULE", str(reason))

        return canonical

    def test_low_moisture_unknown_rule_hold(self):
        canonical = self._evaluate(12)
        self.assertEqual(canonical["observed_value"], 12)
        self.assertEqual(
            canonical["evidence_refs"],
            ["synthetic:irrigation:12"],
        )

    def test_high_moisture_unknown_rule_hold(self):
        canonical = self._evaluate(80)
        self.assertEqual(canonical["observed_value"], 80)
        self.assertEqual(
            canonical["evidence_refs"],
            ["synthetic:irrigation:80"],
        )


if __name__ == "__main__":
    unittest.main()
