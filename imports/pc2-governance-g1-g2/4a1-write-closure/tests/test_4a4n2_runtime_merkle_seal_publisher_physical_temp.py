from __future__ import annotations
import copy
import hashlib
import json
import sys
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import obsidia_runtime_merkle_seal_publisher_v1 as P
FAKE_EAH = "e" * 64
FAKE_DECISION = P.CANONICAL_DECISION_SHA256
BASE_SHA = "1" * 40
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def _candidate():
    return {
        "schema_version": "OBSIDIA_RUNTIME_MERKLE_SEAL_V1",
        "decision_authority": "NONE",
        "runtime_bound": True,
        "attestation_only": True,
        "algorithm": {
            "digest": "SHA-256",
        },
        "canonical_scope": [
            "proofs/",
            "formal/",
            "sigma/",
            "runtime_terrain_bank_trading_gps/server.kernel.sealed.cjs",
        ],
        "excluded_scope": [
            "merkle_seal.json",
            "server.kernel.sealed.cjs",
            ".claude/",
        ],
        "total_files": 4,
        "first_path": "formal/a",
        "last_path": "sigma/z",
        "merkle_root": "b" * 64,
        "entries": [
            {"path": "formal/a", "sha256": "1" * 64},
            {"path": "proofs/b", "sha256": "2" * 64},
            {"path": "runtime_terrain_bank_trading_gps/server.kernel.sealed.cjs",
             "sha256": "3" * 64},
            {"path": "sigma/z", "sha256": "4" * 64},
        ],
    }
@pytest.fixture
def physical_rail(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    stores = tmp_path / "stores"
    target = repo / P.TARGET_RELATIVE_PATH
    historical_bytes = (
        b'{"status":"HISTORICAL_TEMP_TEST","root":"legacy"}'
    )
    target.write_bytes(historical_bytes)
    target_pre_sha256 = _sha256(historical_bytes)
    candidate = _candidate()
    identity = P._candidate_identity(candidate)
    contract_hash = P._publication_contract_hash(
        identity=identity,
        canonical_decision_sha256=FAKE_DECISION,
        target_pre_sha256=target_pre_sha256,
    )
    publication_id = "merklepub-temp-physical"
    child_execution_id = "merklechild-temp-physical"
    monkeypatch.setattr(
        P._E,
        "compute_execution_authority_hash",
        lambda envelope: FAKE_EAH,
    )
    envelope = P._build_execution_envelope(
        publication_id=publication_id,
        child_execution_id=child_execution_id,
        identity=identity,
        canonical_decision_sha256=FAKE_DECISION,
        target_pre_sha256=target_pre_sha256,
        base_sha=BASE_SHA,
        publication_contract_hash=contract_hash,
    )
    descriptor = {
        "schema_version": P.SCHEMA_VERSION,
        "publication_id": publication_id,
        "child_execution_id": child_execution_id,
        "base_sha": BASE_SHA,
        "canonical_decision_sha256": FAKE_DECISION,
        "target_pre_sha256": target_pre_sha256,
        "publication_contract_hash": contract_hash,
        "execution_authority_hash": FAKE_EAH,
        "envelope": envelope,
        **identity,
    }
    descriptor["descriptor_hash"] = P._sha256_json(
        descriptor
    )
    prepared = {
        "status": P.STATUS_PREPARED,
        "publication_id": publication_id,
        "execution_authority_hash": FAKE_EAH,
    }
    monkeypatch.setattr(
        P,
        "_load_prepared_descriptor",
        lambda stores_base_dir, pid: copy.deepcopy(descriptor),
    )
    monkeypatch.setattr(
        P,
        "_canonical_decision_hash",
        lambda root: FAKE_DECISION,
    )
    monkeypatch.setattr(
        P._M,
        "compute_runtime_seal",
        lambda root: copy.deepcopy(candidate),
    )
    approval = {}
    def store_approval(record, *args, **kwargs):
        approval["record"] = copy.deepcopy(record)
        return {"status": "STORED"}
    def load_approval(*args, **kwargs):
        return copy.deepcopy(approval["record"])
    monkeypatch.setattr(
        P._E,
        "store_approval_artifact",
        store_approval,
    )
    monkeypatch.setattr(
        P._E,
        "load_approval_artifact",
        load_approval,
    )
    monkeypatch.setattr(
        P._E,
        "verify_approval_artifact",
        lambda record: (True, None),
    )
    monkeypatch.setattr(
        P._E,
        "_validate_approval",
        lambda record, env: (True, None),
    )
    monkeypatch.setattr(
        P._DS,
        "run_and_persist_kx108_pre_execution_decision",
        lambda *args, **kwargs: {
            "verify_ok": True,
            "x108_gate": "ALLOW",
            "decision_record_id": "kxpre-temp-test",
            "record": {
                "decision_record_hash": "5" * 64,
            },
        },
    )
    return {
        "repo": repo,
        "stores": stores,
        "target": target,
        "historical_bytes": historical_bytes,
        "descriptor": descriptor,
        "prepared": prepared,
        "candidate": candidate,
    }
def _publish(ctx):
    return P.publish_runtime_seal(
        ctx["prepared"],
        FAKE_EAH,
        "HUMAN_TEST_AUTHORIZATION",
        stores_base_dir=ctx["stores"],
        repo_root=ctx["repo"],
    )
def _journal_state(ctx):
    return P._PDJ.classify_interrupted_dispatch(
        stores_base_dir=(
            ctx["stores"]
            / "runtime_merkle_seal_publisher"
        ),
        v2_exec_id=ctx["descriptor"]["publication_id"],
        operation_type=P.OPERATION_TYPE,
        execution_authority_hash=FAKE_EAH,
    )
def test_allow_executes_real_atomic_write_and_completes_journal(
    physical_rail,
):
    ctx = physical_rail
    result = _publish(ctx)
    assert result["status"] == P.STATUS_PUBLISHED
    assert result["post_write_status"] == P.POST_WRITE_VERIFIED
    assert result["target_mutated"] is True
    assert ctx["target"].read_bytes() != ctx["historical_bytes"]
    persisted = json.loads(
        ctx["target"].read_text(encoding="utf-8")
    )
    assert (
        persisted["merkle_root"]
        == ctx["candidate"]["merkle_root"]
    )
    assert (
        persisted["historical_provenance"]
        ["two_decision_bank_runtime_seal"]
        ["status"]
        == "HISTORICAL_HOLD_NON_BLOCKING"
    )
    assert (
        _journal_state(ctx)
        == P._PDJ.CLASS_COMPLETED
    )
def test_crash_after_intent_before_act_restart_blocks_replay(
    monkeypatch,
    physical_rail,
):
    ctx = physical_rail
    def crash_before_act(*args, **kwargs):
        raise SystemExit(
            "SIMULATED_CRASH_AFTER_INTENT_BEFORE_ACT"
        )
    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        crash_before_act,
    )
    with pytest.raises(
        SystemExit,
        match="SIMULATED_CRASH_AFTER_INTENT_BEFORE_ACT",
    ):
        _publish(ctx)
    assert (
        ctx["target"].read_bytes()
        == ctx["historical_bytes"]
    )
    assert (
        _journal_state(ctx)
        == P._PDJ.CLASS_OUTCOME_UNKNOWN
    )
    second_act = {"called": False}
    def forbidden_replay(*args, **kwargs):
        second_act["called"] = True
        raise AssertionError(
            "PHYSICAL_REPLAY_MUST_NOT_OCCUR"
        )
    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        forbidden_replay,
    )
    result = _publish(ctx)
    assert (
        result["reason"]
        == "PHYSICAL_DISPATCH_REENTRY_BLOCKED:"
        + P._PDJ.CLASS_OUTCOME_UNKNOWN
    )
    assert result["target_mutated"] is False
    assert second_act["called"] is False
def test_crash_after_act_before_post_verify_restart_fails_closed(
    monkeypatch,
    physical_rail,
):
    ctx = physical_rail
    real_verify = P._M.verify_runtime_seal
    def crash_after_act(*args, **kwargs):
        raise SystemExit(
            "SIMULATED_CRASH_AFTER_ACT_BEFORE_POST_VERIFY"
        )
    monkeypatch.setattr(
        P._M,
        "verify_runtime_seal",
        crash_after_act,
    )
    with pytest.raises(
        SystemExit,
        match="SIMULATED_CRASH_AFTER_ACT_BEFORE_POST_VERIFY",
    ):
        _publish(ctx)
    assert (
        ctx["target"].read_bytes()
        != ctx["historical_bytes"]
    )
    assert (
        _journal_state(ctx)
        == P._PDJ.CLASS_OUTCOME_UNKNOWN
    )
    monkeypatch.setattr(
        P._M,
        "verify_runtime_seal",
        real_verify,
    )
    result = _publish(ctx)
    assert result["reason"] == "TARGET_PRESTATE_DRIFT"
    assert result["target_mutated"] is False
def test_post_write_mismatch_requires_recovery_and_never_completes(
    monkeypatch,
    physical_rail,
):
    ctx = physical_rail
    monkeypatch.setattr(
        P._M,
        "verify_runtime_seal",
        lambda expected, root: {
            "verified": False,
            "status": "RUNTIME_SEAL_MISMATCH",
        },
    )
    result = _publish(ctx)
    assert (
        result["reason"]
        == "POST_WRITE_RUNTIME_SEAL_VERIFY_FAILED"
    )
    assert result["target_mutated"] is True
    assert result["recovery_required"] is True
    assert (
        _journal_state(ctx)
        == P._PDJ.CLASS_OUTCOME_UNKNOWN
    )



def test_atomic_write_then_raise_is_never_reported_as_pre_act(
    monkeypatch,
    physical_rail,
):
    ctx = physical_rail

    before = ctx["target"].read_bytes()

    real_atomic = P._CA.atomic_replace_with_bytes

    def write_then_raise(*args, **kwargs):
        result = real_atomic(*args, **kwargs)

        assert (
            ctx["target"].read_bytes()
            != before
        )

        raise RuntimeError(
            "SIMULATED_EXCEPTION_AFTER_PHYSICAL_WRITE_BEFORE_RETURN"
        )

    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        write_then_raise,
    )

    result = _publish(ctx)

    # Physical truth:
    # target was changed even though atomic primitive never returned.
    assert ctx["target"].read_bytes() != before

    # MUST NEVER be classified as definitely PRE-ACT.
    assert not result["reason"].startswith(
        "PRE_ACT_EXCEPTION:"
    )

    # Outcome is unknown because execution entered physical ACT
    # but the primitive failed before returning its contract.
    assert result["reason"].startswith(
        "ACT_OUTCOME_UNKNOWN_EXCEPTION:"
    )

    assert result["recovery_required"] is True

    # Unknown is acceptable; FALSE is not.
    assert result["target_mutated"] is not False

    assert (
        _journal_state(ctx)
        == P._PDJ.CLASS_OUTCOME_UNKNOWN
    )
