from __future__ import annotations

import pathlib
import sys
from unittest.mock import patch

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts import obsidia_kx108_decision_store as DS
from periphery.world_calls import sovereign_ticket as ST


NON_SOVEREIGN_PRODUCERS = (
    "persist_kx108_agent_pre_execution_decision",
    "persist_kx108_world_action_pre_execution_decision",
)


@pytest.mark.parametrize("producer", NON_SOVEREIGN_PRODUCERS)
def test_non_sovereign_producer_cannot_cross_ticket_boundary(producer):
    record_id = "p1-c381-synthetic-" + producer

    record = {
        "decision_record_id": record_id,
        "decision_record_producer": producer,
        "decision_phase": "PRE_EXECUTION",
        "decision_authority": "KX108_ONLY",
        "x108_gate": "ALLOW",
    }

    expected = (
        "SOVEREIGN_TICKET_DECISION_PRODUCER_NOT_ELIGIBLE:"
        + producer
    )

    assert producer not in DS.TICKET_ELIGIBLE_PRODUCERS

    with (
        patch.object(
            ST,
            "load_decision_store",
            return_value=DS,
        ) as module_loader,
        patch.object(
            DS,
            "load_kx108_decision_record",
            return_value=record,
        ) as record_loader,
        patch.object(
            DS,
            "verify_kx108_decision_record_authenticity",
            return_value=(True, None),
        ) as verifier,
    ):
        with pytest.raises(AssertionError) as captured:
            ST._verified_decision_record(record_id)

        assert str(captured.value) == expected

        module_loader.assert_called_once_with()
        record_loader.assert_called_once_with(record_id, None)
        verifier.assert_called_once_with(record)


def test_ticket_eligible_producers_exclude_peripheral_rails():
    eligible = set(DS.TICKET_ELIGIBLE_PRODUCERS)

    assert "run_and_persist_kx108_pre_execution_decision" in eligible

    for producer in NON_SOVEREIGN_PRODUCERS:
        assert producer not in eligible