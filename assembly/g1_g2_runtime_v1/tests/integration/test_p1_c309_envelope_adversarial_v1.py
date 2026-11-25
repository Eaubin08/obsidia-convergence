from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import obsidia_governed_apply_v0 as GA


CASES = {
    "MISSING_ENVELOPE": (None, "ENVELOPE_NOT_FOUND"),
    "CORRUPTED_JSON": (b"{invalid-json", "ENVELOPE_NOT_FOUND"),
    "EMPTY_OBJECT": (b"{}", "ENVELOPE_INTEGRITY_NOT_VERIFIED"),
    "ARRAY_INSTEAD_OF_OBJECT": (b"[]", "ENVELOPE_MALFORMED"),
    "FORGED_AUTHORITY": (
        json.dumps({
            "batch_execution_id": "synthetic-batch",
            "decision_authority": "AGENT_ONLY",
            "execution_authority_hash": "0" * 64,
        }).encode(),
        "ENVELOPE_INTEGRITY_NOT_VERIFIED",
    ),
}


@pytest.mark.parametrize("case", CASES)
def test_p1_c309_envelope_falsification_fail_closed(tmp_path, case):
    payload, expected_reason = CASES[case]

    repo = tmp_path / "repo"
    repo.mkdir()

    target = repo / "target.py"
    original = b"VALUE = 108\n"
    target.write_bytes(original)

    execution_dir = tmp_path / "executions"

    if payload is not None:
        envelope = (
            execution_dir
            / "executions"
            / "synthetic-batch"
            / "execution.json"
        )
        envelope.parent.mkdir(parents=True)
        envelope.write_bytes(payload)

    result = GA.run_governed_content_apply(
        batch_execution_id="synthetic-batch",
        child_execution_id="synthetic-child",
        approval_id="synthetic-approval",
        kx108_pre_decision_record_id="synthetic-pre",
        execution_dir=execution_dir,
        pre_execution_context_dir=tmp_path / "contexts",
        kx108_decision_dir=tmp_path / "decisions",
        post_decision_store_dir=tmp_path / "post",
        test_contract_results_dir=tmp_path / "contracts",
        sealed_receipt_dir=tmp_path / "receipts",
        sealed_rollback_evidence_dir=tmp_path / "evidence",
        rollback_result_dir=tmp_path / "rollback",
        repo_root=repo,
    )

    assert result["status"] == (
        GA.GOVERNED_REMEDIATION_APPLY_REJECTED_NO_MUTATION
    )
    assert result["reason"] == f"PREFLIGHT_HOLD:{expected_reason}"
    assert result["target_mutated"] is False
    assert result["decision_authority"] == "KX108_ONLY"
    assert target.read_bytes() == original