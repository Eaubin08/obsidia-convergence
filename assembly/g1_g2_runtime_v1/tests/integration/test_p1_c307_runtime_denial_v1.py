from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import obsidia_governed_apply_v0 as GA


def test_p1_c307_missing_envelope_denies_without_mutation(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    target = repo / "target.py"
    original = b"VALUE = 108\n"
    target.write_bytes(original)

    result = GA.run_governed_content_apply(
        batch_execution_id="missing-batch",
        child_execution_id="missing-child",
        approval_id="missing-approval",
        kx108_pre_decision_record_id="missing-pre",
        execution_dir=tmp_path / "executions",
        pre_execution_context_dir=tmp_path / "contexts",
        kx108_decision_dir=tmp_path / "decisions",
        post_decision_store_dir=tmp_path / "post",
        test_contract_results_dir=tmp_path / "contracts",
        sealed_receipt_dir=tmp_path / "receipts",
        sealed_rollback_evidence_dir=tmp_path / "rollback-evidence",
        rollback_result_dir=tmp_path / "rollback",
        repo_root=repo,
    )

    assert result["status"] == (
        GA.GOVERNED_REMEDIATION_APPLY_REJECTED_NO_MUTATION
    )
    assert result["reason"] == "PREFLIGHT_HOLD:ENVELOPE_NOT_FOUND"
    assert result["target_mutated"] is False
    assert result["decision_authority"] == "KX108_ONLY"
    assert target.read_bytes() == original