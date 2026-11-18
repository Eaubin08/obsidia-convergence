import pytest

from sigma.contracts import Domain, DomainAggregate
from sigma.guard import GuardX108
from sigma.aggregation import (
    aggregate_bank,
    aggregate_trading,
    aggregate_ecom,
    aggregate_gps_defense_aviation,
    aggregate_tooling_build,
)


@pytest.mark.parametrize(
    "domain,verdict",
    [
        (Domain.BANK, "AUTHORIZE"),
        (Domain.TRADING, "EXECUTE_LONG"),
        (Domain.ECOM, "PAY"),
        (Domain.GPS_DEFENSE_AVIATION, "TRAJECTORY_VALID"),
        (Domain.TOOLING_BUILD, "READY_FOR_COMMIT_REVIEW"),
    ],
)
def test_zero_votes_cannot_promote_positive_verdict(domain, verdict):
    aggregate = DomainAggregate(
        domain=domain,
        market_verdict=verdict,
        confidence=0.98,
        agent_votes=[],
    )

    result = GuardX108().decide(aggregate)

    assert result.x108_gate == "HOLD"
    assert result.market_verdict == "HOLD"
    assert result.reason_code == "NO_AGENT_VOTES_FAIL_CLOSED"
    assert result.confidence_integrity == 0.0
    assert result.confidence_readiness == 0.0
    assert result.ticket_required is False
    assert result.ticket_id is None
    assert result.raw_engine["vote_count"] == 0


@pytest.mark.parametrize(
    "aggregator",
    [
        aggregate_bank,
        aggregate_trading,
        aggregate_ecom,
        aggregate_gps_defense_aviation,
        aggregate_tooling_build,
    ],
)
def test_empty_aggregators_remain_non_authorizing(aggregator):
    result = GuardX108().decide(aggregator([]))

    assert result.x108_gate in ("HOLD", "BLOCK")
    assert result.ticket_required is False
    assert result.ticket_id is None
    assert result.raw_engine["vote_count"] == 0
