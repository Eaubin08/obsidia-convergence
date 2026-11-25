def test_p1_c374_signed_producer_dynamic_denial():
    import copy
    import dataclasses
    import pathlib
    import sys
    import types
    from unittest.mock import patch

    sys.path.insert(
        0,
        str(pathlib.Path(__file__).resolve().parents[2]),
    )
    from scripts import obsidia_kx108_decision_store as DS


    class SyntheticState:
        def __init__(self, **kwargs):
            self.kwargs = kwargs


    @dataclasses.dataclass
    class SyntheticDecision:
        decision_id: str = "synthetic-decision"
        trace_id: str = "synthetic-trace"
        domain: str = "TOOLING"
        x108_gate: str = "HOLD"
        reason_code: str = "SYNTHETIC_HOLD"
        severity: str = "LOW"
        market_verdict: str = "HOLD"
        contradictions: tuple = ()
        unknowns: tuple = ()
        risk_flags: tuple = ()


    fake_contracts = types.ModuleType("sigma.contracts")
    fake_contracts.ToolingBuildState = SyntheticState

    fake_protocols = types.ModuleType("sigma.protocols")

    pipeline_calls = []

    def synthetic_pipeline(state):
        pipeline_calls.append(state)
        return SyntheticDecision()

    fake_protocols.run_tooling_build_pipeline = synthetic_pipeline

    fake_adapter = types.ModuleType(
        "scripts.obsidia_kx108_pre_execution_evidence_adapter_v0"
    )

    def synthetic_pre_adapter(**kwargs):
        return {
            "status": "READY_FOR_KX108_PRE_SUBMISSION",
            "pre_binding_context": pre_context,
            "pre_tooling_build_state_kwargs": {},
        }

    fake_adapter.translate_pre_execution_evidence_to_tooling_build_state = (
        synthetic_pre_adapter
    )

    generic_context = {
        key: "synthetic-" + key
        for key in DS._BINDING_CONTEXT_FIELDS
    }

    pre_context = {
        key: "synthetic-" + key
        for key in DS._PRE_BINDING_CONTEXT_FIELDS
    }

    stored = {}
    sign_calls = []
    auth_calls = []

    real_structural = DS.verify_kx108_decision_record
    real_authenticity = DS.verify_kx108_decision_record_authenticity


    def fake_sign(record, producer):
        # Aucun HMAC : simule une publication dépourvue d'authentificateur.
        sign_calls.append(producer)


    def fake_store(record, store_dir=None):
        stored["record"] = copy.deepcopy(record)
        return {"status": "STORED"}


    def fake_load(record_id, store_dir=None):
        record = copy.deepcopy(stored["record"])
        assert record["decision_record_id"] == record_id
        return record


    def observed_authenticity(record):
        auth_calls.append(record["decision_record_id"])
        return real_authenticity(record)


    modules = {
        "sigma.contracts": fake_contracts,
        "sigma.protocols": fake_protocols,
        "scripts.obsidia_kx108_pre_execution_evidence_adapter_v0": fake_adapter,
    }

    failures = []

    print("=== P1-C373 — DYNAMIC ADVERSARIAL REPLAY ===")

    with patch.dict(sys.modules, modules):
        with (
            patch.object(DS, "_validate_binding_context", return_value=None),
            patch.object(DS, "_validate_pre_binding_context", return_value=None),
            patch.object(DS, "_authenticate_decision_record", side_effect=fake_sign),
            patch.object(DS, "store_kx108_decision_record", side_effect=fake_store),
            patch.object(DS, "load_kx108_decision_record", side_effect=fake_load),
            patch.object(
                DS,
                "verify_kx108_decision_record_authenticity",
                side_effect=observed_authenticity,
            ),
        ):
            cases = [
                (
                    "GENERIC",
                    lambda: DS.run_and_persist_kx108_decision(
                        {},
                        generic_context,
                        store_dir=pathlib.Path("synthetic-not-used"),
                    ),
                ),
                (
                    "PRE_EXECUTION",
                    lambda: DS.run_and_persist_kx108_pre_execution_decision(
                        {},
                        pre_context,
                        store_dir=pathlib.Path("synthetic-not-used"),
                    ),
                ),
            ]

            for name, execute in cases:
                before_pipeline = len(pipeline_calls)
                before_auth = len(auth_calls)
                before_sign = len(sign_calls)

                stored.clear()

                result = execute()
                record = result.get("record")

                structural = real_structural(record)

                passed = (
                    structural == (True, None)
                    and result.get("verify_ok") is False
                    and result.get("verify_reason")
                        == "DECISION_RECORD_NOT_AUTHENTICATED"
                    and len(pipeline_calls) == before_pipeline + 1
                    and len(auth_calls) == before_auth + 1
                    and len(sign_calls) == before_sign + 1
                    and "decision_record_authenticator" not in record
                )

                print(
                    "CASE=" + name
                    + " STRUCTURAL=" + str(structural)
                    + " VERIFY_OK=" + str(result.get("verify_ok"))
                    + " VERIFY_REASON=" + str(result.get("verify_reason"))
                    + " PIPELINE_CALL_DELTA="
                        + str(len(pipeline_calls) - before_pipeline)
                    + " AUTH_CALL_DELTA="
                        + str(len(auth_calls) - before_auth)
                    + " PASS=" + str(passed)
                )

                if not passed:
                    failures.append(name)

    print("\n=== P1-C373 — VERDICT ===")
    print("CASES=2")
    print("FAILURES=" + str(failures))
    print("KERNEL=MOCKED_SYNTHETIC")
    print("SIGNING=MOCKED_NO_KEY")
    print("STORE=IN_MEMORY_ONLY")
    print("PRODUCTION_RECORD_WRITTEN=False")
    print("REAL_ACT=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")

    if failures:
        raise SystemExit(1)

    print("P1_C373_DYNAMIC_AUTHENTICITY_DENIAL=PASS")