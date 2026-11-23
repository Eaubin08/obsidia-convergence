import contextlib
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sigma.contracts import AgentVote, DomainAggregate
from sigma.guard import GuardX108


class GuardIndependentAttestationV1(unittest.TestCase):

    def _evaluate(self, rule_id, measure_valid, provenance):
        vote = AgentVote(
            agent_id="p1_c137_probe",
            domain="gps_defense_aviation",
            proposed_verdict="AUTHORIZE",
            confidence=1.0,
            rule_id=rule_id,
            rule_version="1.0",
            measure_valid=measure_valid,
            measure_provenance=provenance,
            measure_age_s=0.0,
            observed_value=0.0,
        )

        aggregate = DomainAggregate(
            domain="gps_defense_aviation",
            agent_votes=[vote],
            market_verdict="AUTHORIZE",
            confidence=1.0,
        )

        with contextlib.redirect_stdout(io.StringIO()):
            return GuardX108().decide(aggregate)

    def _assert_hold_without_ticket(self, decision):
        gate = decision.x108_gate
        value = getattr(gate, "value", gate)

        self.assertEqual(value, "HOLD")
        self.assertFalse(decision.ticket_required)
        self.assertIsNone(decision.ticket_id)
        self.assertEqual(decision.market_verdict, "HOLD")

    def test_ruleless_unqualified(self):
        decision = self._evaluate("", False, None)

        self._assert_hold_without_ticket(decision)
        self.assertEqual(
            decision.reason_code,
            "RULELESS_VOTE_CANNOT_AUTHORIZE",
        )

    def test_ruleless_claimed_valid(self):
        decision = self._evaluate(
            "",
            True,
            "caller:unattested",
        )

        self._assert_hold_without_ticket(decision)
        self.assertEqual(
            decision.reason_code,
            "RULELESS_VOTE_CANNOT_AUTHORIZE",
        )

    def test_registered_rule_self_attestation(self):
        decision = self._evaluate(
            "INV_GPS_DRIFT_MAX",
            True,
            "caller:unattested",
        )

        self._assert_hold_without_ticket(decision)
        self.assertEqual(
            decision.reason_code,
            "INDEPENDENT_MEASURE_ATTESTATION_REQUIRED",
        )


if __name__ == "__main__":
    unittest.main()
