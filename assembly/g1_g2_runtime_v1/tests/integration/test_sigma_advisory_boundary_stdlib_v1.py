"""G1/G2: avis Sigma uniquement, sans ticket HMAC ni APPLY.

Les votes sont fabriques en memoire, aucun serveur ou worktree de production.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obsidia_governance_runtime_v1 import get_runtime
from sigma.contracts import AgentVote, AuthorityLevel


def _votes(count: int = 4, **overrides) -> list[AgentVote]:
    return [
        AgentVote(
            agent_id=f"observateur-{i}",
            domain="tooling_build",
            proposed_verdict="ACT",
            claim="observation",
            confidence=0.99,
            **overrides,
        )
        for i in range(count)
    ]


class SigmaAdvisoryBoundary(unittest.TestCase):
    def setUp(self):
        self.runtime = get_runtime()

    def test_zero_votes_stays_non_authorizing(self):
        result = self.runtime.evaluate_tooling_build_advisory([])
        self.assertEqual(result["status"], "SIGMA_ADVISORY_ONLY")
        self.assertEqual(result["advisory"]["vote_count"], 0)
        self.assertEqual(result["advisory"]["market_verdict"], "BUILD_BLOCK")
        self.assertNotEqual(result["advisory"]["guard_gate_observed"], "ALLOW")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["action_ticket_issued"])

    def test_four_positive_votes_may_be_advisory_allow_but_never_auth(self):
        result = self.runtime.evaluate_tooling_build_advisory(_votes())
        self.assertEqual(result["status"], "SIGMA_ADVISORY_ONLY")
        self.assertEqual(result["advisory"]["market_verdict"], "READY_FOR_COMMIT_REVIEW")
        self.assertEqual(result["advisory"]["guard_gate_observed"], "HOLD")
        self.assertEqual(result["advisory"]["reason_code"], "RULELESS_VOTE_CANNOT_AUTHORIZE")
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["action_ticket_issued"])
        self.assertFalse(result["target_mutated"])
        self.assertNotIn("ticket_id", str(result))
        self.assertNotIn("decision_id", str(result))
        action = self.runtime.execute(operation_type="WORLD_ACTION", sigma_result=result)
        self.assertEqual(action["status"], "HOLD")

    def test_unknowns_stay_visible_and_non_authorizing(self):
        result = self.runtime.evaluate_tooling_build_advisory(_votes(unknowns=["SOURCE_NOT_ATTESTED"]))
        self.assertEqual(result["advisory"]["market_verdict"], "BUILD_HOLD")
        self.assertIn("SOURCE_NOT_ATTESTED", result["advisory"]["unknowns"])
        self.assertFalse(result["execution_authorized"])

    def test_incomplete_and_duplicate_quorum_fail_closed(self):
        for count in (1, 2, 3, 5):
            with self.subTest(count=count):
                result = self.runtime.evaluate_tooling_build_advisory(_votes(count))
                self.assertEqual(result["status"], "HOLD")
        duplicates = _votes()
        duplicates[1].agent_id = duplicates[0].agent_id
        self.assertEqual(self.runtime.evaluate_tooling_build_advisory(duplicates)["status"], "HOLD")

    def test_wrong_type_domain_or_forged_authority_fail_closed(self):
        for item in ("ACT", {"agent_id": "fake"}):
            with self.subTest(item=item):
                result = self.runtime.evaluate_tooling_build_advisory([item] + _votes(3))
                self.assertEqual(result["status"], "HOLD")
        wrong_domain = _votes()
        wrong_domain[0].domain = "bank"
        self.assertEqual(self.runtime.evaluate_tooling_build_advisory(wrong_domain)["status"], "HOLD")
        forged = _votes()
        forged[0].authority_level = AuthorityLevel.MANDATORY_VETO
        self.assertEqual(self.runtime.evaluate_tooling_build_advisory(forged)["status"], "HOLD")
        forged_rule = _votes()
        forged_rule[0].rule_id = "INV_GPS_DRIFT_MAX"
        self.assertEqual(self.runtime.evaluate_tooling_build_advisory(forged_rule)["status"], "HOLD")

    def test_non_finite_confidence_and_malformed_signals_fail_closed(self):
        invalid = _votes()
        invalid[0].confidence = float("nan")
        self.assertEqual(self.runtime.evaluate_tooling_build_advisory(invalid)["status"], "HOLD")
        invalid = _votes()
        invalid[0].unknowns = "not-list"
        self.assertEqual(self.runtime.evaluate_tooling_build_advisory(invalid)["status"], "HOLD")
        self.assertEqual(self.runtime.evaluate_tooling_build_advisory(tuple(_votes()))["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
