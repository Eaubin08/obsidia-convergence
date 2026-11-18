
import pytest

from periphery.world_calls.sovereign_ticket import (
    load_decision_store,
)


@pytest.mark.parametrize(
    "action_id,input_hash",
    [
        ("ACTION_A", "a" * 64),
        ("ACTION_B", "b" * 64),
    ],
)
def test_synthetic_pre_evidence_cannot_authorize_write(
    tmp_path, action_id, input_hash, monkeypatch
):
    """
    K1_SYNTHETIC_PRE_PROVENANCE_V2

    A caller-supplied ALLOW claim and forged PRE binding
    must never produce a sovereign decision or ticket.
    """
    import sigma.protocols as protocols

    store = load_decision_store()
    decision_dir = tmp_path / "decisions"

    assert not decision_dir.exists()

    # Synthetic claim: this is not a canonical ToolingBuildState
    # translated from authenticated PRE evidence.
    state = {
        "x108_gate": "ALLOW",
        "action_id": action_id,
        "input_hash": input_hash,
    }

    # No actual HumanApproval, ExecutionEnvelope or
    # PreExecutionContext corresponds to this binding.
    binding = {
        field: (
            input_hash if "hash" in field
            else f"TEST_ONLY_{field}_{action_id}"
        )
        for field in store._PRE_BINDING_CONTEXT_FIELDS
    }

    kernel_calls = []

    def forbidden_kernel(*args, **kwargs):
        kernel_calls.append(True)
        raise AssertionError(
            "KERNEL_CALLED_WITH_UNVERIFIED_PRE_EVIDENCE"
        )

    with monkeypatch.context() as patch:
        patch.setattr(
            protocols,
            "run_tooling_build_pipeline",
            forbidden_kernel,
        )

        result = store.run_and_persist_kx108_pre_execution_decision(
            state,
            binding,
            decision_dir,
        )

    print("SYNTHETIC_ACTION:", action_id)
    print("SYNTHETIC_INPUT_HASH:", input_hash)
    print("RESULT_STATUS:", result.get("status"))
    print("REJECTION_REASON:", result.get("reason"))
    print("KERNEL_CALLS:", len(kernel_calls))
    print("DECISION_RECORD_CREATED:",
          bool(list(decision_dir.glob("*.json"))))
    print("DECISION_RECORD_ID_ISSUED:",
          bool(result.get("decision_record_id")))

    assert result.get("status") == "REJECTED", result

    assert result.get("reason", "").startswith(
        "PRE_EVIDENCE_"
    ), result

    assert result.get("kx108_kernel_call_count") == 0
    assert kernel_calls == []

    assert "decision_record_id" not in result
    assert "record" not in result
    assert not list(decision_dir.glob("*.json"))
