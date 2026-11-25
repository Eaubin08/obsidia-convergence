"""P1-C346: KX108 consumer boundaries reject unsigned decision records."""

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import obsidia_kx108_decision_store as DS
import obsidia_canonical_receipt_replay_v1 as RECEIPTS
import obsidia_governance_decision_replay_v1 as GOVERNANCE
import obsidia_mission_local_snapshot_v0 as SNAPSHOT


EAH = "a" * 64
APPROVAL = "p1-c346-approval"
PRE_ID = "p1-c346-pre"
POST_ID = "p1-c346-post"
EXPECTED_REASON = "DECISION_RECORD_NOT_AUTHENTICATED"


def make_record(record_id, phase):
    fields = DS._record_bound_fields_for({"decision_phase": phase})
    record = {field: None for field in fields}
    record.update({
        "decision_record_schema_version": DS.SCHEMA_VERSION,
        "decision_record_id": record_id,
        "decision_phase": phase,
        "decision_authority": DS.DECISION_AUTHORITY,
        "execution_authority_hash": EAH,
        "approval_id": APPROVAL,
        "x108_gate": "ALLOW",
        "canonical_envelope": {"x108_gate": "ALLOW"},
    })
    return record


def records():
    pre = make_record(PRE_ID, DS.PRE_DECISION_PHASE)
    pre["decision_record_hash"] = DS.compute_kx108_decision_record_hash(pre)

    post = make_record(POST_ID, DS.POST_DECISION_PHASE)
    post["kx108_pre_decision_record_id"] = PRE_ID
    post["kx108_pre_decision_record_hash"] = pre["decision_record_hash"]
    post["decision_record_hash"] = DS.compute_kx108_decision_record_hash(post)
    return pre, post


def receipt_envelope(pre):
    return {
        "authorization": {
            "kx108_pre_decision_record_id": PRE_ID,
            "kx108_pre_decision_record_hash": pre["decision_record_hash"],
            "execution_authority_hash": EAH,
            "approval_id": APPROVAL,
            "kx108_verdict": "ALLOW",
        }
    }


def snapshot_inputs():
    store = ROOT / "P1_C346_NONEXISTENT_SYNTHETIC_STORE"
    batch = "p1-c346-batch"
    child = "p1-c346-child"
    target = "synthetic.txt"

    sar = {
        "batch_execution_id": batch,
        "child_execution_id": child,
        "execution_authority_hash": EAH,
        "approval_id": APPROVAL,
        "kx108_pre_decision_record_id": PRE_ID,
        "target_path": target,
        "status": "CONTENT_APPLIED",
        "operation_type": SNAPSHOT.SUPPORTED_OPERATION,
        "decision_authority": SNAPSHOT.EXPECTED_GOVERNED_DECISION_AUTHORITY,
        "target_pre_sha256": "b" * 64,
        "target_post_sha256": "c" * 64,
        "source_content_sha256": "c" * 64,
        "sealed_rollback_evidence_id": "p1-c346-sre",
    }

    sre = {
        "batch_execution_id": batch,
        "child_execution_id": child,
        "execution_authority_hash": EAH,
        "approval_id": APPROVAL,
        "target_path": target,
    }

    arguments = {
        "mission_id": "p1-c346-mission",
        "action_id": "p1-c346-action",
        "ordinal": 1,
        "expected_branch_name": "synthetic",
        "expected_worktree_path": ROOT / "P1_C346_NONEXISTENT_WORKTREE",
        "expected_previous_mission_tip_sha": "d" * 40,
        "batch_execution_id": batch,
        "child_execution_id": child,
        "execution_authority_hash": EAH,
        "approval_id": APPROVAL,
        "kx108_pre_decision_record_id": PRE_ID,
        "kx108_post_decision_record_id": POST_ID,
        "test_contract_result_id": "p1-c346-tcr",
        "sealed_apply_receipt_id": "p1-c346-sar",
        "sealed_rollback_evidence_id": "p1-c346-sre",
        "target_path": target,
        "execution_dir": store,
        "kx108_pre_decision_dir": store,
        "kx108_post_decision_dir": store,
        "test_contract_results_dir": store,
        "sealed_receipt_dir": store,
        "sealed_rollback_evidence_dir": store,
        "rollback_result_dir": store,
    }

    return sar, sre, arguments


def test_c346_receipt_rejects_unsigned_kx108_pre():
    pre, _ = records()

    assert DS.verify_kx108_decision_record(pre) == (True, None)
    assert DS.verify_kx108_decision_record_authenticity(pre) == (
        False, EXPECTED_REASON
    )

    result = {
        "linked_ids": {},
        "KX108_ref_valid": None,
        "evidence_missing": [],
        "evidence_conflicts": [],
    }

    with patch.object(
        RECEIPTS._DS, "load_kx108_decision_record", return_value=pre
    ):
        RECEIPTS._verify_kx108(
            receipt_envelope(pre),
            {"kxpre": ROOT / "P1_C346_NONEXISTENT_SYNTHETIC_STORE"},
            result,
        )

    assert result["KX108_ref_valid"] == RECEIPTS.NO
    assert EXPECTED_REASON in result["evidence_conflicts"]


def test_c346_governance_replay_rejects_unsigned_kx108_pre():
    pre, _ = records()

    result = {
        "missing_inputs": [],
        "conflicts": [],
        "evidence_limits": [],
        "kx108_match": None,
    }

    with patch.object(
        GOVERNANCE._DS, "load_kx108_decision_record", return_value=pre
    ):
        GOVERNANCE._replay_kx108_from_frozen_record(
            receipt_envelope(pre),
            None,
            {"kxpre": ROOT / "P1_C346_NONEXISTENT_SYNTHETIC_STORE"},
            result,
        )

    assert result["kx108_match"] != GOVERNANCE.YES
    assert EXPECTED_REASON in result["conflicts"]


def run_snapshot(pre, post, *, allow_pre_authentication):
    sar, sre, arguments = snapshot_inputs()

    real_auth = DS.verify_kx108_decision_record_authenticity
    auth_ids = []

    def controlled_auth(record):
        auth_ids.append(record["decision_record_id"])

        if allow_pre_authentication and record is pre:
            return True, None

        return real_auth(record)

    with (
        patch.object(
            SNAPSHOT._SEV, "load_sealed_apply_receipt", return_value=sar
        ),
        patch.object(
            SNAPSHOT._SEV, "verify_sealed_apply_receipt",
            return_value=(True, None)
        ),
        patch.object(
            SNAPSHOT._SEV, "load_sealed_rollback_evidence",
            return_value=sre
        ),
        patch.object(
            SNAPSHOT._SEV, "verify_sealed_rollback_evidence",
            return_value=(True, None)
        ),
        patch.object(
            SNAPSHOT._DS, "load_kx108_decision_record",
            side_effect=[pre, post]
        ) as loader,
        patch.object(
            SNAPSHOT._DS,
            "verify_kx108_decision_record_authenticity",
            side_effect=controlled_auth
        ),
        patch.object(
            SNAPSHOT._TC, "load_test_contract_result"
        ) as tcr_loader,
    ):
        result = SNAPSHOT.check_local_snapshot_eligibility(**arguments)
        loader_calls = loader.call_count
        tcr_calls = tcr_loader.call_count

    return result, auth_ids, loader_calls, tcr_calls


def test_c346_snapshot_rejects_unsigned_pre():
    pre, post = records()

    result, auth_ids, loader_calls, tcr_calls = run_snapshot(
        pre, post, allow_pre_authentication=False
    )

    assert result == {
        "eligible": False,
        "reason": "KX108_PRE_INVALID:" + EXPECTED_REASON,
    }
    assert auth_ids == [PRE_ID]
    assert loader_calls == 1
    assert tcr_calls == 0


def test_c346_snapshot_rejects_unsigned_post():
    pre, post = records()

    assert DS.verify_kx108_decision_record(post) == (True, None)
    assert DS.verify_kx108_decision_record_authenticity(post) == (
        False, EXPECTED_REASON
    )

    result, auth_ids, loader_calls, tcr_calls = run_snapshot(
        pre, post, allow_pre_authentication=True
    )

    assert result == {
        "eligible": False,
        "reason": "KX108_POST_INVALID:" + EXPECTED_REASON,
    }
    assert auth_ids == [PRE_ID, POST_ID]
    assert loader_calls == 2
    assert tcr_calls == 0