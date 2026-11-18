from __future__ import annotations
import copy
import sys
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import obsidia_runtime_merkle_seal_publisher_v1 as P
FAKE_EAH = "e" * 64
FAKE_PRE = "a" * 64
FAKE_ROOT = "b" * 64
FAKE_MANIFEST = "c" * 64
FAKE_SCOPE = "d" * 64
FAKE_DECISION = P.CANONICAL_DECISION_SHA256
def _descriptor():
    envelope = {
        "batch_execution_id": "merklepub-test",
        "batch_id": "merklepub-test",
        "batch_hash": "1" * 64,
        "batch_hash_version": "MERKLE_SEAL_PUBLICATION_V2",
        "candidate_scope_hash": FAKE_SCOPE,
        "execution_order": ["critical-cryptographic-seal-v2"],
        "dependency_edges": [],
        "children": [{
            "candidate_entry_id": "critical-cryptographic-seal-v2",
            "child_execution_id": "merklechild-test",
            "source_kind": "DETERMINISTIC_RUNTIME_MERKLE_CANDIDATE",
            "source_hash": FAKE_MANIFEST,
            "source_content_sha256": FAKE_MANIFEST,
            "source_repository_identity": "CURRENT_REPOSITORY",
            "source_git_commit_sha": "1" * 40,
            "source_git_blob_sha": None,
            "source_git_historical_path": None,
            "target_path": P.TARGET_RELATIVE_PATH,
            "target_pre_hash": FAKE_PRE[:16],
            "target_pre_sha256": FAKE_PRE,
            "operation_type": P.OPERATION_TYPE,
            "execution_status": "PLANNED",
        }],
        "test_contract_hash": "f" * 64,
        "decision_authority": "KX108_ONLY",
        "pre_execution_context_id": "merkle-ctx-test",
        "pre_execution_context_record_hash": "2" * 64,
        "integrity_verified": True,
    }
    # EAH is patched/recomputed by fixture.
    return {
        "schema_version": P.SCHEMA_VERSION,
        "publication_id": "merklepub-test",
        "child_execution_id": "merklechild-test",
        "base_sha": "1" * 40,
        "canonical_decision_sha256": FAKE_DECISION,
        "target_pre_sha256": FAKE_PRE,
        "publication_contract_hash": "f" * 64,
        "execution_authority_hash": FAKE_EAH,
        "candidate_merkle_root": FAKE_ROOT,
        "candidate_manifest_hash": FAKE_MANIFEST,
        "candidate_scope_hash": FAKE_SCOPE,
        "candidate_total_files": 418,
        "envelope": envelope,
    }
def _prepared(desc):
    return {
        "status": P.STATUS_PREPARED,
        "publication_id": desc["publication_id"],
        "execution_authority_hash": desc["execution_authority_hash"],
    }
def _candidate():
    return {
        "schema_version": "OBSIDIA_RUNTIME_MERKLE_SEAL_V1",
        "decision_authority": "NONE",
        "runtime_bound": True,
        "attestation_only": True,
        "algorithm": {},
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
        "total_files": 418,
        "first_path": "formal/a",
        "last_path": "sigma/z",
        "merkle_root": FAKE_ROOT,
        "entries": [{"path": "formal/a"}],
    }
@pytest.fixture
def rail(monkeypatch, tmp_path):
    desc = _descriptor()
    monkeypatch.setattr(
        P._E,
        "compute_execution_authority_hash",
        lambda envelope: FAKE_EAH,
    )
    desc["descriptor_hash"] = P._sha256_json(desc)
    monkeypatch.setattr(
        P,
        "_load_prepared_descriptor",
        lambda stores, publication_id: copy.deepcopy(desc),
    )
    monkeypatch.setattr(
        P,
        "_canonical_decision_hash",
        lambda root: FAKE_DECISION,
    )
    monkeypatch.setattr(
        P,
        "_current_target_hash",
        lambda root: FAKE_PRE,
    )
    monkeypatch.setattr(
        P._M,
        "compute_runtime_seal",
        lambda root: copy.deepcopy(_candidate()),
    )
    monkeypatch.setattr(
        P,
        "_candidate_identity",
        lambda candidate: {
            "candidate_merkle_root": FAKE_ROOT,
            "candidate_manifest_hash": FAKE_MANIFEST,
            "candidate_scope_hash": FAKE_SCOPE,
            "candidate_total_files": 418,
        },
    )
    monkeypatch.setattr(
        P._E,
        "store_approval_artifact",
        lambda *a, **kw: {"status": "STORED"},
    )
    monkeypatch.setattr(
        P._E,
        "load_approval_artifact",
        lambda *a, **kw: {"approval_id": "fake"},
    )
    monkeypatch.setattr(
        P._E,
        "verify_approval_artifact",
        lambda approval: (True, None),
    )
    monkeypatch.setattr(
        P._E,
        "_validate_approval",
        lambda approval, envelope: (True, None),
    )
    return desc, tmp_path
def test_wrong_eah_blocks_before_kx_and_atomic(monkeypatch, rail):
    desc, store = rail
    calls = {"kx": 0, "atomic": 0}
    monkeypatch.setattr(
        P._DS,
        "run_and_persist_kx108_pre_execution_decision",
        lambda *a, **kw: calls.__setitem__("kx", calls["kx"] + 1),
    )
    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        lambda *a, **kw: calls.__setitem__("atomic", calls["atomic"] + 1),
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        "WRONG",
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"] == "HUMAN_AUTHORIZED_EAH_MISMATCH"
    assert result["target_mutated"] is False
    assert calls == {"kx": 0, "atomic": 0}
def test_missing_human_reference_blocks_before_kx(monkeypatch, rail):
    desc, store = rail
    called = {"kx": False}
    monkeypatch.setattr(
        P._DS,
        "run_and_persist_kx108_pre_execution_decision",
        lambda *a, **kw: called.__setitem__("kx", True),
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"] == "HUMAN_AUTHORIZATION_REFERENCE_REQUIRED"
    assert result["target_mutated"] is False
    assert called["kx"] is False
def test_canonical_decision_drift_blocks_before_kx(monkeypatch, rail):
    desc, store = rail
    monkeypatch.setattr(
        P,
        "_canonical_decision_hash",
        lambda root: "9" * 64,
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"] == "CANONICAL_DECISION_DRIFT"
    assert result["target_mutated"] is False
def test_target_prestate_drift_blocks_before_kx(monkeypatch, rail):
    desc, store = rail
    monkeypatch.setattr(
        P,
        "_current_target_hash",
        lambda root: "8" * 64,
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"] == "TARGET_PRESTATE_DRIFT"
    assert result["target_mutated"] is False
def test_candidate_root_drift_blocks_before_approval(monkeypatch, rail):
    desc, store = rail
    monkeypatch.setattr(
        P,
        "_candidate_identity",
        lambda candidate: {
            "candidate_merkle_root": "7" * 64,
            "candidate_manifest_hash": FAKE_MANIFEST,
            "candidate_scope_hash": FAKE_SCOPE,
            "candidate_total_files": 418,
        },
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"] == "CANDIDATE_IDENTITY_DRIFT:candidate_merkle_root"
    assert result["target_mutated"] is False
@pytest.mark.parametrize("gate", ["HOLD", "BLOCK", ""])
def test_kx108_pre_non_allow_never_reaches_atomic(monkeypatch, rail, gate):
    desc, store = rail
    atomic_called = {"value": False}
    monkeypatch.setattr(
        P._DS,
        "run_and_persist_kx108_pre_execution_decision",
        lambda *a, **kw: {
            "verify_ok": True,
            "record": {"decision_record_hash": "3" * 64},
            "decision_record_id": "kxpre-test",
            "x108_gate": gate,
        },
    )
    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        lambda *a, **kw: atomic_called.__setitem__("value", True),
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"] == "KX108_PRE_GATE_NOT_ALLOW:" + gate
    assert result["target_mutated"] is False
    assert atomic_called["value"] is False
def test_unverified_kx108_pre_never_reaches_atomic(monkeypatch, rail):
    desc, store = rail
    atomic_called = {"value": False}
    monkeypatch.setattr(
        P._DS,
        "run_and_persist_kx108_pre_execution_decision",
        lambda *a, **kw: {
            "verify_ok": False,
            "record": None,
            "x108_gate": "ALLOW",
        },
    )
    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        lambda *a, **kw: atomic_called.__setitem__("value", True),
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"] == "KX108_PRE_NOT_PERSISTED"
    assert atomic_called["value"] is False
@pytest.mark.parametrize(
    "state",
    [
        "DISPATCH_OUTCOME_UNKNOWN",
        "DISPATCH_COMPLETED",
    ],
)
def test_dispatch_reentry_blocks_physical_replay(monkeypatch, rail, state):
    desc, store = rail
    atomic_called = {"value": False}
    monkeypatch.setattr(
        P._DS,
        "run_and_persist_kx108_pre_execution_decision",
        lambda *a, **kw: {
            "verify_ok": True,
            "record": {"decision_record_hash": "3" * 64},
            "decision_record_id": "kxpre-test",
            "x108_gate": "ALLOW",
        },
    )
    monkeypatch.setattr(
        P._PDJ,
        "classify_interrupted_dispatch",
        lambda **kw: state,
    )
    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        lambda *a, **kw: atomic_called.__setitem__("value", True),
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"] == "PHYSICAL_DISPATCH_REENTRY_BLOCKED:" + state
    assert result["target_mutated"] is False
    assert atomic_called["value"] is False
def test_dispatch_intent_precedes_atomic_act(monkeypatch, rail):
    desc, store = rail
    order = []
    monkeypatch.setattr(
        P._DS,
        "run_and_persist_kx108_pre_execution_decision",
        lambda *a, **kw: {
            "verify_ok": True,
            "record": {"decision_record_hash": "3" * 64},
            "decision_record_id": "kxpre-test",
            "x108_gate": "ALLOW",
        },
    )
    monkeypatch.setattr(
        P._PDJ,
        "classify_interrupted_dispatch",
        lambda **kw: P._PDJ.CLASS_NOT_DISPATCHED,
    )
    monkeypatch.setattr(
        P._PDJ,
        "persist_dispatch_intent",
        lambda **kw: order.append("INTENT") or {"state": "DISPATCH_INTENT"},
    )
    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        lambda *a, **kw: order.append("ACT") or {
            "status": "NOT_APPLIED"
        },
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert order == ["INTENT", "ACT"]
    assert result["reason"].startswith("ATOMIC_PUBLICATION_FAILED:")
def test_atomic_failure_leaves_dispatch_uncompleted(monkeypatch, rail):
    desc, store = rail
    completed = {"value": False}
    monkeypatch.setattr(
        P._DS,
        "run_and_persist_kx108_pre_execution_decision",
        lambda *a, **kw: {
            "verify_ok": True,
            "record": {"decision_record_hash": "3" * 64},
            "decision_record_id": "kxpre-test",
            "x108_gate": "ALLOW",
        },
    )
    monkeypatch.setattr(
        P._PDJ,
        "classify_interrupted_dispatch",
        lambda **kw: P._PDJ.CLASS_NOT_DISPATCHED,
    )
    monkeypatch.setattr(
        P._PDJ,
        "persist_dispatch_intent",
        lambda **kw: {"state": "DISPATCH_INTENT"},
    )
    monkeypatch.setattr(
        P._PDJ,
        "persist_dispatch_complete",
        lambda **kw: completed.__setitem__("value", True),
    )
    monkeypatch.setattr(
        P._CA,
        "atomic_replace_with_bytes",
        lambda *a, **kw: {
            "status": "PRECONDITION_FAILED"
        },
    )
    result = P.publish_runtime_seal(
        _prepared(desc),
        FAKE_EAH,
        "human-test",
        stores_base_dir=store,
        repo_root=ROOT,
    )
    assert result["reason"].startswith("ATOMIC_PUBLICATION_FAILED:")
    assert completed["value"] is False
def test_publisher_has_no_arbitrary_target_parameter():
    import inspect
    params = inspect.signature(
        P.publish_runtime_seal
    ).parameters
    assert "target_path" not in params
    assert "destination_path" not in params
    assert "output_path" not in params
    assert P.TARGET_RELATIVE_PATH == "merkle_seal.json"
