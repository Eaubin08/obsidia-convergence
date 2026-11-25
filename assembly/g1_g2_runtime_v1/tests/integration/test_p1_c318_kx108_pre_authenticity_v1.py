"""P1-C318: unauthenticated KX108 PRE must fail at governed preflight."""
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import obsidia_governed_apply_v0 as G

E = G._E
DS = G._DS


def test_p1_c318_unauthenticated_pre_denied(tmp_path):
    batch_id = "p1-c318-batch"
    child_id = "p1-c318-child"
    approval_id = "p1-c318-approval"
    pre_id = "p1-c318-pre"

    envelope = {
        "integrity_verified": True,
        "decision_authority": G.DECISION_AUTHORITY,
        "batch_execution_id": batch_id,
        "children": [{
            "child_execution_id": child_id,
            "execution_status": E.PLANNED,
            "operation_type": G.OPERATION_TYPE,
        }],
    }
    envelope["execution_authority_hash"] = (
        E.compute_execution_authority_hash(envelope)
    )
    eah = envelope["execution_authority_hash"]

    approval = {
        "approval_id": approval_id,
        "execution_authority_hash": eah,
    }

    pre = {field: None for field in DS._PRE_RECORD_BOUND_FIELDS}
    pre.update({
        "decision_record_schema_version": DS.SCHEMA_VERSION,
        "decision_record_id": pre_id,
        "created_at": "2026-11-25T00:00:00+00:00",
        "decision_phase": DS.PRE_DECISION_PHASE,
        "batch_execution_id": batch_id,
        "child_execution_id": child_id,
        "execution_authority_hash": eah,
        "approval_id": approval_id,
        "pre_execution_context_id": "synthetic-context",
        "pre_execution_context_record_hash": "b" * 64,
        "test_contract_hash": "c" * 64,
        "kx108_input_translation_hash": "d" * 64,
        "decision_id": "synthetic-decision",
        "trace_id": "synthetic-trace",
        "domain": "tooling_build",
        "x108_gate": "ALLOW",
        "reason_code": "SYNTHETIC_ONLY",
        "severity": "LOW",
        "market_verdict": "BUILD_ALLOW",
        "contradictions": [],
        "unknowns": [],
        "risk_flags": [],
        "decision_authority": "KX108_ONLY",
        "canonical_envelope": {},
    })
    pre["decision_record_hash"] = (
        DS.compute_kx108_decision_record_hash(pre)
    )

    assert DS.verify_kx108_decision_record(pre) == (True, None)
    assert DS.verify_kx108_decision_record_authenticity(pre) == (
        False, "DECISION_RECORD_NOT_AUTHENTICATED"
    )

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(E, "_load_execution", return_value=envelope)
        )
        stack.enter_context(
            patch.object(E, "load_approval_artifact", return_value=approval)
        )
        stack.enter_context(
            patch.object(E, "verify_approval_artifact", return_value=(True, None))
        )
        stack.enter_context(
            patch.object(E, "_validate_approval", return_value=(True, None))
        )
        stack.enter_context(
            patch.object(DS, "load_kx108_decision_record", return_value=pre)
        )

        original = DS.verify_kx108_decision_record_authenticity

        with patch.object(
            DS,
            "verify_kx108_decision_record_authenticity",
            wraps=original,
        ) as verifier:
            result = G.validate_governed_apply_preflight(
                batch_id, child_id, approval_id, pre_id,
                repo_root=tmp_path,
            )
            assert verifier.call_count == 1

    assert result["status"] == G.STATUS_HOLD
    assert result["reason"] == (
        "KX108_PRE_DECISION_INVALID:DECISION_RECORD_NOT_AUTHENTICATED"
    )
    assert result["write_capability"] is False
    assert list(tmp_path.rglob("*")) == []