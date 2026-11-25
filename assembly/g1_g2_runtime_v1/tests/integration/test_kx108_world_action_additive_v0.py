"""Tests locaux du premier merge contractuel : aucune exécution/egress.

Ce test est volontairement indépendant des services et des clés K1.
Il ne prouve PAS l'intégration fonctionnelle avec le moteur complet.
"""
from __future__ import annotations

import ast
import copy
import dataclasses
import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "obsidia_kx108_decision_store.py"
spec = importlib.util.spec_from_file_location("kx108_candidate", MODULE_PATH)
assert spec and spec.loader
DS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DS)


@dataclasses.dataclass
class CallerConstructedEnvelope:
    decision_id: str = "world-decision-001"
    trace_id: str = "world-trace-001"
    domain: str = "administration"
    x108_gate: str = "ALLOW"
    reason_code: str = "caller-supplied-value"
    severity: str = "low"
    market_verdict: str = "PROOF_ONLY"
    contradictions: tuple = ()
    unknowns: tuple = ()
    risk_flags: tuple = ()


@pytest.fixture
def binding():
    return {field: "fixed-" + field for field in DS._WORLD_ACTION_PRE_BINDING_CONTEXT_FIELDS}


def test_world_action_is_additive_and_not_ticket_eligible():
    assert DS.PRE_DECISION_PHASE == "PRE_EXECUTION"
    assert DS.POST_DECISION_PHASE == "POST_EXECUTION"
    assert DS.WORLD_ACTION_PRE_DECISION_PHASE == "WORLD_ACTION_PRE_EXECUTION"
    assert "persist_kx108_world_action_pre_execution_decision" not in DS.TICKET_ELIGIBLE_PRODUCERS
    assert "run_and_persist_kx108_pre_execution_decision" in DS.TICKET_ELIGIBLE_PRODUCERS
    assert callable(DS.verify_kx108_decision_record_authenticity)
    assert callable(DS.run_and_persist_kx108_pre_execution_decision)


def test_even_caller_constructed_allow_is_evidence_only(tmp_path, binding):
    result = DS.persist_kx108_world_action_pre_execution_decision(
        CallerConstructedEnvelope(), binding, tmp_path
    )
    assert result["status"] == "EVIDENCE_ONLY"
    assert result["x108_gate"] == "ALLOW"
    assert result["execution_authorized"] is False
    assert result["decision_phase"] == DS.WORLD_ACTION_PRE_DECISION_PHASE
    assert result["verify_ok"] is True
    ok, reason = DS.verify_kx108_decision_record_authenticity(result["record"])
    assert not ok
    assert reason == "DECISION_RECORD_NOT_AUTHENTICATED"


@pytest.mark.parametrize("missing_field", [
    "human_approval_hash",
    "world_action_request_hash",
    "target_prestate_hash",
    "required_scope",
    "connector_call_hash",
    "idempotency_key",
])
def test_required_world_binding_missing_fail_closed(tmp_path, binding, missing_field):
    binding.pop(missing_field)
    result = DS.persist_kx108_world_action_pre_execution_decision(
        CallerConstructedEnvelope(), binding, tmp_path
    )
    assert result["status"] == "REJECTED"
    assert missing_field in result["reason"]
    assert list(tmp_path.iterdir()) == []


def test_plain_dict_cannot_claim_kernel_envelope(tmp_path, binding):
    result = DS.persist_kx108_world_action_pre_execution_decision(
        dataclasses.asdict(CallerConstructedEnvelope()), binding, tmp_path
    )
    assert result["status"] == "REJECTED"
    assert result["reason"] == "DECISION_ENVELOPE_NOT_A_KERNEL_DATACLASS"
    assert list(tmp_path.iterdir()) == []


def test_invalid_gate_cannot_persist(tmp_path, binding):
    result = DS.persist_kx108_world_action_pre_execution_decision(
        CallerConstructedEnvelope(x108_gate="UNKNOWN"), binding, tmp_path
    )
    assert result["status"] == "REJECTED"
    assert result["reason"] == "X108_GATE_INVALID"


@pytest.mark.parametrize("field", [
    "connector_call_hash", "human_approval_hash", "source_domain",
    "action_id", "idempotency_key", "x108_gate",
])
def test_world_action_hash_binds_every_critical_field(tmp_path, binding, field):
    result = DS.persist_kx108_world_action_pre_execution_decision(
        CallerConstructedEnvelope(), binding, tmp_path
    )
    assert result["verify_ok"] is True
    tampered = copy.deepcopy(result["record"])
    tampered[field] = "tampered"
    ok, reason = DS.verify_kx108_decision_record(tampered)
    assert not ok
    if field == "x108_gate":
        assert reason == "X108_GATE_INVALID"
    else:
        assert reason == "DECISION_RECORD_HASH_MISMATCH"


def test_legacy_post_and_pre_hash_field_sets_are_preserved():
    original = {"decision_phase": DS.PRE_DECISION_PHASE}
    assert DS._record_bound_fields_for(original) == DS._PRE_RECORD_BOUND_FIELDS
    assert DS._record_bound_fields_for({}) == DS._RECORD_BOUND_FIELDS
    assert DS._record_bound_fields_for({"decision_phase": DS.WORLD_ACTION_PRE_DECISION_PHASE}) == DS._WORLD_ACTION_PRE_RECORD_BOUND_FIELDS


def test_all_existing_k1_function_bodies_unchanged_except_phase_dispatch():
    root = MODULE_PATH.parents[3]
    base = root / "imports" / "k1-zero-vote-guard" / "scripts" / "obsidia_kx108_decision_store.py"
    if not base.is_file():
        base = root / "reference" / "k1" / "obsidia_kx108_decision_store.py"
    assert base.is_file(), "K1 baseline required to verify non-regression"
    old = ast.parse(base.read_text(encoding="utf-8"))
    new = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    funcs = lambda tree: {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    original, merged = funcs(old), funcs(new)
    assert set(original).issubset(set(merged))
    baseline_source = base.read_text(encoding="utf-8")

    for name, function in original.items():
        if name == "_record_bound_fields_for":
            continue

        expected_function = function

        if name == "run_and_persist_kx108_post_execution_decision":
            baseline_body = ast.get_source_segment(
                baseline_source, function
            )
            assert baseline_body is not None

            allowed_changes = (
                (
                    "ok_pre, reason_pre = verify_kx108_decision_record(pre)",
                    "ok_pre, reason_pre = verify_kx108_decision_record_authenticity(pre)",
                ),
                (
                    'record["decision_record_hash"] = compute_kx108_decision_record_hash(record)',
                    'record["decision_record_hash"] = compute_kx108_decision_record_hash(record)\n'
                    '    _authenticate_decision_record(record, "run_and_persist_kx108_post_execution_decision")',
                ),
                (
                    "verify_ok, verify_reason = verify_kx108_decision_record(reloaded)",
                    "verify_ok, verify_reason = verify_kx108_decision_record_authenticity(reloaded)",
                ),
            )

            expected_body = baseline_body

            for before, after in allowed_changes:
                assert expected_body.count(before) == 1, (
                    f"K1 baseline exception mismatch: {before}"
                )
                expected_body = expected_body.replace(
                    before, after, 1
                )

            expected_function = ast.parse(expected_body).body[0]

        if name in (
            "run_and_persist_kx108_decision",
            "run_and_persist_kx108_pre_execution_decision",
        ):
            baseline_body = ast.get_source_segment(
                baseline_source, function
            )
            assert baseline_body is not None

            before = (
                "verify_ok, verify_reason = "
                "verify_kx108_decision_record(reloaded)"
            )
            after = (
                "verify_ok, verify_reason = "
                "verify_kx108_decision_record_authenticity(reloaded)"
            )

            assert baseline_body.count(before) == 1, (
                f"K1 C368 baseline exception mismatch: {name}"
            )

            expected_body = baseline_body.replace(before, after, 1)
            expected_function = ast.parse(expected_body).body[0]

        assert ast.dump(
            expected_function, include_attributes=False
        ) == ast.dump(
            merged[name], include_attributes=False
        ), f"K1 existing function modified beyond approved C354/C368 scope: {name}"


def test_duplicate_world_evidence_is_idempotent_and_never_authorizing(tmp_path, binding):
    first = DS.persist_kx108_world_action_pre_execution_decision(
        CallerConstructedEnvelope(), binding, tmp_path
    )
    second = DS.persist_kx108_world_action_pre_execution_decision(
        CallerConstructedEnvelope(), binding, tmp_path
    )
    assert first["status"] == second["status"] == "EVIDENCE_ONLY"
    assert first["decision_record_id"] == second["decision_record_id"]
    assert second["store_result"]["status"] == DS.STATUS_IDEMPOTENT_EXISTING_IDENTICAL
    assert second["execution_authorized"] is False
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_same_action_id_with_invalid_existing_evidence_is_rejected(tmp_path, binding):
    first = DS.persist_kx108_world_action_pre_execution_decision(
        CallerConstructedEnvelope(), binding, tmp_path
    )
    path = tmp_path / (first["decision_record_id"] + ".json")
    path.write_text("not-json", encoding="utf-8")
    second = DS.persist_kx108_world_action_pre_execution_decision(
        CallerConstructedEnvelope(), binding, tmp_path
    )
    assert second["status"] == "REJECTED"
    assert second["reason"] == DS.STATUS_IMMUTABILITY_VIOLATION
    assert second["execution_authorized"] is False

