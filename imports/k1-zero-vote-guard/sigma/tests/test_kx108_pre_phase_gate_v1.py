
from types import SimpleNamespace
import pytest
from periphery.world_calls import sovereign_ticket as st


@pytest.mark.parametrize("phase", [None, "POST_EXECUTION", "AGENT_PRE_EXECUTION"])
def test_post_or_other_phase_cannot_issue_write_ticket(monkeypatch, phase):
    monkeypatch.setattr(
        st, "_verified_decision_record",
        lambda *_a, **_k: {
            "decision_phase": phase,
            "decision_record_producer": "run_and_persist_kx108_decision",
            "x108_gate": "ALLOW",
            "domain": "tooling_build",
        },
    )

    with pytest.raises(AssertionError, match="PRE_EXECUTION_REQUIRED"):
        st.issue_sovereign_ticket_from_decision_record(
            "kxd-test",
            action_id="test-action",
            scope="bounded_apply",
            input_hash="a" * 64,
            world_call_class="GOVERNED_WRITE",
        )


@pytest.mark.parametrize("phase", [None, "POST_EXECUTION", "AGENT_PRE_EXECUTION"])
def test_post_or_other_phase_cannot_be_consumed(monkeypatch, phase):
    monkeypatch.setattr(
        st, "_verified_decision_record",
        lambda *_a, **_k: {
            "decision_phase": phase,
            "decision_record_producer": "run_and_persist_kx108_decision",
            "x108_gate": "ALLOW",
            "domain": "tooling_build",
        },
    )

    ticket = SimpleNamespace(
        version=st.TICKET_VERSION_V2,
        decision_record_id="kxd-test",
        decision_record_hash="test-hash",
        ticket_id="test-ticket",
        scope="bounded_apply",
        world_call_class="GOVERNED_WRITE",
    )

    with pytest.raises(AssertionError, match="PRE_EXECUTION_REQUIRED"):
        st.verify_ticket_decision_binding(ticket)


def test_pre_phase_with_wrong_producer_is_refused(monkeypatch):
    monkeypatch.setattr(
        st, "_verified_decision_record",
        lambda *_a, **_k: {
            "decision_phase": "PRE_EXECUTION",
            "decision_record_producer": "run_and_persist_kx108_decision",
            "x108_gate": "ALLOW",
            "domain": "tooling_build",
        },
    )

    with pytest.raises(AssertionError, match="PRE_PRODUCER_REQUIRED"):
        st.issue_sovereign_ticket_from_decision_record(
            "kxpre-test",
            action_id="test-action",
            scope="bounded_apply",
            input_hash="a" * 64,
        )
