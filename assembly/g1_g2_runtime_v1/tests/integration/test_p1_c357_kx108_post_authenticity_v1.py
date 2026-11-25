"""P1-C357 : authenticité PRE/POST KX108, preuves synthétiques isolées."""
from __future__ import annotations

import dataclasses
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts" / "obsidia_kx108_decision_store.py"

for directory in (ROOT / "scripts", ROOT):
    value = str(directory)
    if value not in sys.path:
        sys.path.insert(0, value)

spec = importlib.util.spec_from_file_location("p1_c357_ds", SOURCE)
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)


@dataclasses.dataclass
class SyntheticDecision:
    decision_id: str = "synthetic-post-decision"
    trace_id: str = "synthetic-post-trace"
    domain: str = "tooling_build"
    x108_gate: str = "HOLD"
    reason_code: str = "SYNTHETIC_ONLY"
    severity: str = "INFO"
    market_verdict: str = "BUILD_HOLD"
    contradictions: tuple = ()
    unknowns: tuple = ()
    risk_flags: tuple = ()


class SyntheticToolingState:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def test_unsigned_pre_rejected_before_post_kernel():
    pre = {
        "decision_record_id": "p1-c357-unsigned-pre",
        "decision_phase": ds.PRE_DECISION_PHASE,
        "x108_gate": "ALLOW",
        "approval_id": "synthetic-approval",
        "execution_authority_hash": "a" * 64,
    }

    with (
        patch.object(ds, "_validate_binding_context", return_value=None),
        patch.object(ds, "load_kx108_decision_record", return_value=pre),
        patch.object(
            ds, "verify_kx108_decision_record", return_value=(True, None)
        ) as structural,
        patch.object(ds, "_batch_execution_module") as execution_module,
    ):
        result = ds.run_and_persist_kx108_post_execution_decision(
            tooling_build_state_kwargs={},
            binding_context={"approval_id": "synthetic-approval"},
            kx108_pre_decision_record_id="p1-c357-unsigned-pre",
        )

    assert result["status"] == "REJECTED"
    assert result["reason"] == (
        "KX108_PRE_DECISION_INVALID:DECISION_RECORD_NOT_AUTHENTICATED"
    )
    assert result["kx108_kernel_call_count"] == 0
    assert structural.call_count == 1
    assert execution_module.call_count == 0


def test_synthetic_post_signed_stored_and_authenticated():
    contracts = types.ModuleType("sigma.contracts")
    contracts.ToolingBuildState = SyntheticToolingState

    protocols = types.ModuleType("sigma.protocols")
    kernel_calls = []

    def synthetic_pipeline(state):
        kernel_calls.append(state)
        return SyntheticDecision()

    protocols.run_tooling_build_pipeline = synthetic_pipeline

    eah = "a" * 64
    pre_id = "p1-c357-authenticated-pre"

    binding = {
        field: "synthetic-" + field
        for field in ds._BINDING_CONTEXT_FIELDS
    }

    binding["approval_id"] = "synthetic-approval"
    binding["batch_execution_id"] = "synthetic-batch"
    binding["execution_authority_hash"] = eah

    pre = {
        "decision_record_id": pre_id,
        "decision_record_hash": "b" * 64,
        "decision_phase": ds.PRE_DECISION_PHASE,
        "x108_gate": "ALLOW",
        "approval_id": binding["approval_id"],
        "execution_authority_hash": eah,
    }

    execution_envelope = {
        "integrity_verified": True,
        "execution_authority_hash": eah,
    }

    execution_module = types.SimpleNamespace(
        _load_execution=lambda *args: execution_envelope,
        compute_execution_authority_hash=lambda value: eah,
    )

    stored = {}
    real_authenticity = ds.verify_kx108_decision_record_authenticity

    def loader(record_id, store_dir=None):
        if record_id == pre_id:
            return pre
        return stored.get(record_id)

    def store(record, store_dir=None):
        stored[record["decision_record_id"]] = dict(record)
        return {
            "status": ds.STATUS_STORED,
            "decision_record_id": record["decision_record_id"],
        }

    def authenticity(record):
        if record is pre:
            return True, None
        return real_authenticity(record)

    with (
        patch.dict(sys.modules, {
            "sigma.contracts": contracts,
            "sigma.protocols": protocols,
        }),
        patch.object(ds, "_validate_binding_context", return_value=None),
        patch.object(ds, "_batch_execution_module", return_value=execution_module),
        patch.object(ds, "load_kx108_decision_record", side_effect=loader),
        patch.object(ds, "store_kx108_decision_record", side_effect=store),
        patch.object(
            ds,
            "_kernel_key",
            return_value=b"P1-C357-SYNTHETIC-KEY-ONLY",
        ),
        patch.object(
            ds,
            "verify_kx108_decision_record_authenticity",
            side_effect=authenticity,
        ),
    ):
        result = ds.run_and_persist_kx108_post_execution_decision(
            tooling_build_state_kwargs={},
            binding_context=binding,
            kx108_pre_decision_record_id=pre_id,
        )

        post = result.get("record")
        verification = real_authenticity(post)

    assert result["status"] == "STORED"
    assert result["verify_ok"] is True
    assert result["verify_reason"] is None
    assert verification == (True, None)
    assert len(kernel_calls) == 1
    assert len(stored) == 1
    assert post["decision_record_authenticator"]
    assert post["decision_phase"] == ds.POST_DECISION_PHASE
    assert post["kx108_pre_decision_record_id"] == pre_id