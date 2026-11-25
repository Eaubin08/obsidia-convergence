def test_p1_c297_authority_preflight():
    import pathlib
    import sys
    import tempfile
    from unittest.mock import patch
    from contextlib import ExitStack

    root = pathlib.Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "scripts"))
    sys.path.insert(0, str(root))

    import obsidia_governed_apply_v0 as G

    E = G._E
    DS = G._DS

    batch_id = "p1-c297-batch"
    child_id = "p1-c297-child"
    approval_id = "p1-c297-approval"
    pre_id = "p1-c297-pre"

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

    envelope["execution_authority_hash"] = E.compute_execution_authority_hash(envelope)
    eah = envelope["execution_authority_hash"]

    approval = {
        "approval_id": approval_id,
        "execution_authority_hash": eah,
    }

    pre = {
        "x108_gate": "ALLOW",
        "execution_authority_hash": eah,
        "approval_id": approval_id,
    }

    cases = [
        ("MISSING_APPROVAL", None, None, True, True,
         "HUMAN_APPROVAL_NOT_FOUND"),
        ("INVALID_APPROVAL", approval, pre, False, True,
         "HUMAN_APPROVAL_ARTIFACT_INVALID:FORGED_APPROVAL"),
        ("WRONG_APPROVAL_BINDING", approval, pre, True, False,
         "HUMAN_APPROVAL_NOT_BOUND_TO_EXECUTION:FORGED_BINDING"),
        ("MISSING_PRE_DECISION", approval, None, True, True,
         "KX108_PRE_DECISION_NOT_FOUND"),
        ("PRE_GATE_HOLD", approval, dict(pre, x108_gate="HOLD"),
         True, True, "KX108_PRE_GATE_NOT_ALLOW"),
        ("PRE_WRONG_EAH", approval,
         dict(pre, execution_authority_hash="0" * 64),
         True, True, "KX108_PRE_EXECUTION_AUTHORITY_HASH_MISMATCH"),
    ]

    failures = []

    with tempfile.TemporaryDirectory(prefix="P1_C297_") as tmp:
        target = pathlib.Path(tmp)

        for name, a, p, structural_ok, binding_ok, expected in cases:
            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(E, "_load_execution", return_value=envelope)
                )
                stack.enter_context(
                    patch.object(E, "load_approval_artifact", return_value=a)
                )
                stack.enter_context(
                    patch.object(
                        E, "verify_approval_artifact",
                        return_value=(
                            structural_ok,
                            None if structural_ok else "FORGED_APPROVAL",
                        ),
                    )
                )
                stack.enter_context(
                    patch.object(
                        E, "_validate_approval",
                        return_value=(
                            binding_ok,
                            None if binding_ok else "FORGED_BINDING",
                        ),
                    )
                )
                stack.enter_context(
                    patch.object(
                        DS, "load_kx108_decision_record", return_value=p
                    )
                )
                stack.enter_context(
                    patch.object(
                        DS, "verify_kx108_decision_record",
                        return_value=(True, None),
                    )
                )
                stack.enter_context(
                    patch.object(
                        DS, "decision_phase_of",
                        return_value=DS.PRE_DECISION_PHASE,
                    )
                )

                result = G.validate_governed_apply_preflight(
                    batch_execution_id=batch_id,
                    child_execution_id=child_id,
                    approval_id=approval_id,
                    kx108_pre_decision_record_id=pre_id,
                    repo_root=target,
                )

            observed = result.get("reason")
            passed = (
                result.get("status") == G.STATUS_HOLD
                and observed == expected
            )

            print(
                f"CASE={name} REASON={observed} "
                f"EXPECTED={expected} PASS={passed}"
            )

            if not passed:
                failures.append(name)

        written = [str(p.relative_to(target)) for p in target.rglob("*")]

    print("\n=== P1-C297 — VERDICT ===")
    print("CASES=" + str(len(cases)))
    print("FAILURES=" + repr(failures))
    print("TEMPORARY_FILES=" + repr(written))
    print("UPSTREAM_EVIDENCE=MOCKED_SYNTHETIC")
    print("PREFLIGHT_FUNCTION=REAL_IMPLEMENTATION")
    print("INDEPENDENT_HUMAN_AUTHENTICITY=NOT_TESTED")
    print("PRODUCTION_APPROVAL_LOADED=False")
    print("SOURCE_MUTATION=False")
    print("REAL_ACT=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")

    if failures or written:
        print("P1_C297_ADVERSARIAL=HOLD")
        raise SystemExit(1)

    print("P1_C297_ADVERSARIAL=PASS")
