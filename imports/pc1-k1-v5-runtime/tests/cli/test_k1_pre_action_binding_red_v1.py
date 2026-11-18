
import runpy
import pytest

from periphery.world_calls.sovereign_ticket import (
    issue_sovereign_ticket_from_decision_record,
)


def test_canonical_pre_cannot_authorize_unrelated_action(tmp_path):
    helpers = runpy.run_path(
        "tests/cli/test_kx108_pre_execution_gate_v0.py"
    )

    ADP = helpers["ADP"]
    DS = helpers["DS"]

    pre_ctx = helpers["_make_pre_ctx_record"]()
    envelope = helpers["_make_envelope"](pre_ctx)

    ex = tmp_path / "executions"
    cx = tmp_path / "contexts"
    dc = tmp_path / "decisions"

    helpers["_store_pre_ctx"](pre_ctx, cx)
    helpers["_store_envelope"](envelope, ex)

    approval_id = helpers["_store_canonical_approval"](
        envelope, ex
    )

    tr = ADP.translate_pre_execution_evidence_to_tooling_build_state(
        envelope["batch_execution_id"],
        "child-1",
        approval_id,
        execution_dir=ex,
        pre_execution_context_dir=cx,
    )

    assert tr["status"] == ADP.STATUS_READY, tr

    result = DS.run_and_persist_kx108_pre_execution_decision(
        tr["pre_tooling_build_state_kwargs"],
        tr["pre_binding_context"],
        store_dir=dc,
        execution_dir=ex,
        pre_execution_context_dir=cx,
    )

    assert result["verify_ok"] is True
    assert result["record"]["decision_phase"] == "PRE_EXECUTION"
    assert result["record"]["x108_gate"] == "ALLOW"
    assert DS.verify_kx108_decision_record_authenticity(
        result["record"]
    ) == (True, None)

    # Different action and content from the canonical child.
    # A PRE decision must not authorize arbitrary caller values.
    with pytest.raises(AssertionError):
        issue_sovereign_ticket_from_decision_record(
            result["decision_record_id"],
            action_id="UNRELATED_ACTION_B",
            scope="bounded_apply",
            input_hash="f" * 64,
            decision_store_dir=dc,
            world_call_class="GOVERNED_WRITE",
        )
