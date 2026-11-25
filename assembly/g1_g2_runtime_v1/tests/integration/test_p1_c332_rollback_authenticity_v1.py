"""P1-C332 — KX108 PRE authenticity at the governed rollback boundary."""

import ast
import pathlib
import sys
import tempfile
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import obsidia_kx108_decision_store as DS
import obsidia_governed_rollback_v0 as RB
import obsidia_post_execution_disposition_v0 as DISP


def _unsigned_pre():
    pre = {
        "decision_record_schema_version": DS.SCHEMA_VERSION,
        "decision_record_id": "p1-c332-synthetic-pre",
        "decision_phase": DS.PRE_DECISION_PHASE,
        "decision_authority": DS.DECISION_AUTHORITY,
        "x108_gate": "ALLOW",
        "batch_execution_id": "p1-c332-synthetic-batch",
        "child_execution_id": "p1-c332-synthetic-child",
        "approval_id": "p1-c332-synthetic-approval",
        "execution_authority_hash": "a" * 64,
        "canonical_envelope": {},
    }

    for name in DS._record_bound_fields_for(pre):
        pre.setdefault(name, None)

    pre["decision_record_hash"] = (
        DS.compute_kx108_decision_record_hash(pre)
    )

    return pre


def test_c332_unsigned_pre_rejected_before_envelope():
    pre = _unsigned_pre()

    assert DS.verify_kx108_decision_record(pre) == (True, None)

    assert DS.verify_kx108_decision_record_authenticity(pre) == (
        False, "DECISION_RECORD_NOT_AUTHENTICATED"
    )

    signals = sorted(DISP.CANONICAL_FAILURE_SIGNALS)
    assert signals

    with tempfile.TemporaryDirectory(
        prefix="OBSIDIA_P1_C332_"
    ) as tmp:
        store = pathlib.Path(tmp)

        with (
            patch.object(
                RB._DS,
                "load_kx108_decision_record",
                return_value=pre,
            ) as loader,
            patch.object(
                RB._E,
                "_load_execution",
            ) as envelope_loader,
            patch.object(
                RB,
                "_atomic_restore",
            ) as restore,
        ):
            result = RB.run_governed_rollback(
                child_execution_id="p1-c332-synthetic-child",
                kx108_pre_decision_record_id=pre[
                    "decision_record_id"
                ],
                rollback_trigger_code=signals[0],
                execution_dir=store / "executions",
                evidence_dir=store / "evidence",
                pre_decision_store_dir=store / "decisions",
                rollback_result_dir=store / "results",
                repo_root=store / "targets",
            )

        assert loader.call_count == 1
        envelope_loader.assert_not_called()
        restore.assert_not_called()

        assert result["status"] == (
            RB.ROLLBACK_REFUSED_PRE_DECISION_INVALID
        )

        assert result["reason"] == (
            "PRE_INVALID:DECISION_RECORD_NOT_AUTHENTICATED"
        )

        assert result["commit_review_eligible"] is False
        assert result["rollback_required"] is True
        assert result["quarantine_required"] is True
        assert result["kx108_invocations_during_rollback"] == 0


def test_c332_pre_and_post_use_authenticity_verifier():
    path = ROOT / "scripts" / "obsidia_governed_rollback_v0.py"
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))

    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "run_governed_rollback"
    ]

    assert len(functions) == 1

    calls = []

    for node in ast.walk(functions[0]):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Attribute):
            continue

        if not isinstance(node.func.value, ast.Name):
            continue

        if node.func.value.id != "_DS":
            continue

        if node.func.attr.startswith(
            "verify_kx108_decision_record"
        ):
            calls.append(node.func.attr)

    assert calls.count(
        "verify_kx108_decision_record_authenticity"
    ) == 2

    assert "verify_kx108_decision_record" not in calls


def test_c335_unsigned_post_rejected_before_disposition_and_restore():
    pre = _unsigned_pre()
    pre_id = pre["decision_record_id"]
    post_id = "p1-c335-synthetic-post"
    eah = pre["execution_authority_hash"]
    approval_id = pre["approval_id"]
    batch_id = pre["batch_execution_id"]
    child_id = pre["child_execution_id"]

    post = {
        "decision_record_schema_version": DS.SCHEMA_VERSION,
        "decision_record_id": post_id,
        "decision_phase": DS.POST_DECISION_PHASE,
        "decision_authority": DS.DECISION_AUTHORITY,
        "x108_gate": "HOLD",
        "batch_execution_id": batch_id,
        "child_execution_id": child_id,
        "approval_id": approval_id,
        "execution_authority_hash": eah,
        "kx108_pre_decision_record_id": pre_id,
        "kx108_pre_decision_record_hash": pre["decision_record_hash"],
        "canonical_envelope": {},
    }

    for field in DS._record_bound_fields_for(post):
        post.setdefault(field, None)

    post["decision_record_hash"] = (
        DS.compute_kx108_decision_record_hash(post)
    )

    assert DS.verify_kx108_decision_record(post) == (True, None)
    assert DS.verify_kx108_decision_record_authenticity(post) == (
        False, "DECISION_RECORD_NOT_AUTHENTICATED"
    )

    env = {
        "integrity_verified": True,
        "decision_authority": DS.DECISION_AUTHORITY,
        "execution_authority_hash": eah,
        "children": [{
            "child_execution_id": child_id,
            "operation_type": RB.OPERATION_TYPE,
            "target_pre_sha256": "b" * 64,
        }],
    }

    approval = {
        "approval_id": approval_id,
        "execution_authority_hash": eah,
    }

    real_authenticator = DS.verify_kx108_decision_record_authenticity
    calls = []

    def selective_authenticator(record):
        calls.append(record.get("decision_record_id"))
        if record is pre:
            return True, None
        return real_authenticator(record)

    def synthetic_loader(record_id, store_dir=None):
        if record_id == pre_id:
            return pre
        if record_id == post_id:
            return post
        return None

    with tempfile.TemporaryDirectory(prefix="OBSIDIA_P1_C335S_") as tmp:
        store = pathlib.Path(tmp)

        with (
            patch.object(
                RB._DS, "load_kx108_decision_record",
                side_effect=synthetic_loader
            ),
            patch.object(
                RB._DS, "verify_kx108_decision_record_authenticity",
                side_effect=selective_authenticator
            ),
            patch.object(RB._E, "_load_execution", return_value=env),
            patch.object(
                RB._E, "compute_execution_authority_hash",
                return_value=eah
            ),
            patch.object(
                RB._E, "load_approval_artifact",
                return_value=approval
            ),
            patch.object(
                RB._E, "verify_approval_artifact",
                return_value=(True, None)
            ),
            patch.object(
                RB._E, "_validate_approval",
                return_value=(True, None)
            ),
            patch.object(RB, "_atomic_restore") as restore,
            patch.object(
                RB._DISP, "classify_post_execution_disposition"
            ) as disposition,
        ):
            result = RB.run_governed_rollback(
                child_execution_id=child_id,
                kx108_pre_decision_record_id=pre_id,
                kx108_post_decision_record_id=post_id,
                execution_dir=store / "executions",
                evidence_dir=store / "evidence",
                pre_decision_store_dir=store / "pre",
                post_decision_store_dir=store / "post",
                rollback_result_dir=store / "results",
                repo_root=store / "targets",
            )

        restore.assert_not_called()
        disposition.assert_not_called()

    assert calls == [pre_id, post_id]
    assert result["status"] == RB.ROLLBACK_REFUSED_POST_DECISION_INVALID
    assert result["reason"] == (
        "POST_INVALID:DECISION_RECORD_NOT_AUTHENTICATED"
    )
    assert result["commit_review_eligible"] is False
    assert result["rollback_required"] is True
    assert result["quarantine_required"] is True
    assert result["kx108_invocations_during_rollback"] == 0
