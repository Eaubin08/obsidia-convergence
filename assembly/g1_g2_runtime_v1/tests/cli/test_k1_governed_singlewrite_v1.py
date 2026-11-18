"""KX108 K1: real canonical PRE authorization at governed APPLY boundary.

These tests exercise the production GovernedBoundedApply, ticket issuer,
verifier, and rollback. No guards, decision records, or kernel are mocked.
All filesystem effects are confined to pytest tmp_path.
"""
from __future__ import annotations

import runpy
from pathlib import Path

import pytest

from periphery.world_calls import ticket_store as TS
from periphery.world_calls.sovereign_ticket import issue_sovereign_ticket_from_decision_record
from sigma.tooling.governed_bounded_apply import (
    GovernedBoundedApply,
    PatchOperation,
    PatchProposal,
)


@pytest.fixture
def case(tmp_path, monkeypatch):
    # Never write to the repository's default sovereign ticket ledgers.
    monkeypatch.setattr(TS, "_DEFAULT_STORE", str(tmp_path / "tickets.jsonl"))
    monkeypatch.setattr(TS, "_DEFAULT_CONSUMED_STORE", str(tmp_path / "nonces.jsonl"))
    fixture_file = Path(__file__).with_name("test_k1_pre_action_binding_positive_v1.py")
    helper = runpy.run_path(str(fixture_file))["_fixture"]
    world, target, proposal, ticket_args = helper(tmp_path)
    assert target.is_file() and len(proposal.operations) == 1
    return world, target, proposal, ticket_args


def _execution_args(world):
    return {
        "decision_record_id": world["pre_id"],
        "decision_store_dir": world["dc"],
        "execution_dir": world["ex"],
        "pre_execution_context_dir": world["cx"],
        "repo_root": world["repo"],
    }


def _engine(base_sha: str):
    return GovernedBoundedApply(worktree_head_provider=lambda _: base_sha)


def test_canonical_single_write_governed_apply_commits(case):
    world, target, proposal, _ = case
    before = target.read_bytes()
    engine = _engine(proposal.base_sha)
    result = engine.apply_proposal_governed(proposal, **_execution_args(world))
    assert result.status == "COMMITTED", (result.status, result.error_detail, result.kx108_reason)
    assert result.disk_written and not result.rolled_back
    assert target.read_bytes() == proposal.operations[0].content.encode("utf-8")
    assert target.read_bytes() != before
    ledger = TS.load_consumed_nonces()
    marker = f"kx108-decision-record:{world['pre_id']}"
    assert marker in ledger and ledger[marker]["state"] == "COMMITTED"


def test_canonical_post_test_failure_rolls_back(case):
    world, target, proposal, _ = case
    before = target.read_bytes()
    result = _engine(proposal.base_sha).apply_proposal_governed(
        proposal, post_test_runner=lambda _: False, **_execution_args(world)
    )
    assert result.status == "ROLLED_BACK", (result.status, result.error_detail, result.kx108_reason)
    assert result.rolled_back and not result.disk_written
    assert target.read_bytes() == before


def test_crash_after_authorization_before_write_preserves_target(case):
    world, target, proposal, _ = case
    before = target.read_bytes()
    with pytest.raises(RuntimeError, match="CRASH_AFTER_AUTHORIZATION_BEFORE_MUTATION"):
        _engine(proposal.base_sha).apply_proposal_governed(
            proposal, simulate_crash_after_auth=True, **_execution_args(world)
        )
    assert target.read_bytes() == before


def test_head_drift_after_authorization_is_refused(case):
    world, target, proposal, _ = case
    before = target.read_bytes()
    calls = 0

    def head(_):
        nonlocal calls
        calls += 1
        return proposal.base_sha if calls == 1 else "DRIFTED_HEAD"

    result = GovernedBoundedApply(worktree_head_provider=head).apply_proposal_governed(
        proposal, **_execution_args(world)
    )
    assert result.status == "REFUSED_PRE_DECISION", (result.status, result.error_detail, result.kx108_reason)
    assert "TOCTOU_HEAD_DRIFT_DETECTED" in result.kx108_reason
    assert not result.disk_written and target.read_bytes() == before


def test_unapproved_patch_bytes_refused_before_write(case):
    world, target, proposal, _ = case
    before = target.read_bytes()
    altered = PatchProposal(
        proposal_id=proposal.proposal_id, base_sha=proposal.base_sha,
        target_worktree=proposal.target_worktree,
        approved_scope=list(proposal.approved_scope),
        operations=[PatchOperation(proposal.operations[0].path, "UNAPPROVED", "WRITE")],
    )
    result = _engine(altered.base_sha).apply_proposal_governed(altered, **_execution_args(world))
    assert result.status == "REFUSED_PRE_DECISION"
    assert "SOVEREIGN_TICKET_PRE_ACTION_BINDING" in result.kx108_reason
    assert not result.disk_written and target.read_bytes() == before


def test_multiple_operations_fail_closed(case):
    world, target, proposal, _ = case
    before = target.read_bytes()
    additional = "periphery/xdomain/extra.py"
    altered = PatchProposal(
        proposal_id=proposal.proposal_id, base_sha=proposal.base_sha,
        target_worktree=proposal.target_worktree,
        approved_scope=[*proposal.approved_scope, additional],
        operations=[*proposal.operations, PatchOperation(additional, "OTHER", "WRITE")],
    )
    result = _engine(altered.base_sha).apply_proposal_governed(altered, **_execution_args(world))
    assert result.status == "REFUSED_PRE_DECISION"
    assert "SINGLE_WRITE_PAYLOAD_REQUIRED" in result.kx108_reason
    assert not result.disk_written and target.read_bytes() == before
    assert not (Path(proposal.target_worktree) / additional).exists()


def test_delete_is_not_authorized_by_single_write_pre(case):
    world, target, proposal, _ = case
    before = target.read_bytes()
    altered = PatchProposal(
        proposal_id=proposal.proposal_id, base_sha=proposal.base_sha,
        target_worktree=proposal.target_worktree,
        approved_scope=list(proposal.approved_scope),
        operations=[PatchOperation(proposal.operations[0].path, "", "DELETE")],
    )
    result = _engine(altered.base_sha).apply_proposal_governed(altered, **_execution_args(world))
    assert result.status == "REFUSED_PRE_DECISION"
    assert not result.disk_written and target.read_bytes() == before


def test_changed_canonical_source_is_refused(case):
    world, target, proposal, _ = case
    before = target.read_bytes()
    world["mk"]["sandbox"].write_bytes(b"CHANGED_AFTER_PRE")
    result = _engine(proposal.base_sha).apply_proposal_governed(proposal, **_execution_args(world))
    assert result.status == "REFUSED_PRE_DECISION"
    assert not result.disk_written and target.read_bytes() == before


def test_injected_authentic_pre_ticket_can_commit(case):
    world, target, proposal, ticket_args = case
    before = target.read_bytes()
    ticket = issue_sovereign_ticket_from_decision_record(world["pre_id"], **ticket_args)
    result = _engine(proposal.base_sha).apply_proposal_governed(
        proposal, injected_ticket=ticket, **_execution_args(world)
    )
    assert result.status == "COMMITTED", (result.status, result.error_detail, result.kx108_reason)
    assert result.disk_written and target.read_bytes() != before



def test_k1_unresolved_wal_blocks_valid_pre_reentry(case):
    """
    A valid KX108 PRE must not bypass an unresolved WAL.
    The physical target and WAL must remain unchanged.
    """
    world, target, proposal, _ = case
    before = target.read_bytes()

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    wal_dir.mkdir(parents=True, exist_ok=True)

    wal = wal_dir / "wal_unresolved_reentry.json"
    wal_content = b"UNAUTHENTICATED_PENDING_WAL"
    wal.write_bytes(wal_content)

    result = _engine(proposal.base_sha).apply_proposal_governed(
        proposal,
        **_execution_args(world),
    )

    assert result.status == "REFUSED_PRE_DECISION", (
        result.status, result.error_detail, result.kx108_reason
    )
    assert result.kx108_reason == "WAL_UNRESOLVED_FAIL_CLOSED"
    assert result.disk_written is False
    assert result.rolled_back is False
    assert target.read_bytes() == before
    assert wal.read_bytes() == wal_content



def test_k1_authorized_wal_recovery_after_physical_interruption(
    case, monkeypatch
):
    """
    Valid KX108 PRE -> real WAL -> physical write -> abrupt
    interruption -> authenticated recovery of original bytes.
    """
    from sigma.tooling.governed_bounded_apply import (
        SealedRollbackEvidence,
    )

    world, target, proposal, _ = case
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"

    from sigma.tooling import governed_bounded_apply as mod
    real_write_bytes = mod._k1_physical_write_bytes
    injected = {"count": 0}

    def write_then_interrupt(path, data, expected_attestation, worktree):
        if (
            Path(path).resolve() == target.resolve()
            and data == payload
        ):
            injected["count"] += 1
            real_write_bytes(path, data, expected_attestation, worktree)
            raise SystemExit("K1_PHYSICAL_WRITE_THEN_INTERRUPT")

        return real_write_bytes(path, data, expected_attestation, worktree)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", write_then_interrupt)

        with pytest.raises(
            SystemExit,
            match="K1_PHYSICAL_WRITE_THEN_INTERRUPT",
        ):
            _engine(proposal.base_sha).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert injected["count"] == 1
    assert target.read_bytes() == payload
    assert target.read_bytes() != original

    journals = list(wal_dir.glob("wal_*.json"))
    assert len(journals) == 1
    journal = journals[0]
    assert journal.exists()

    recovered = SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    assert proposal.proposal_id in recovered
    assert target.read_bytes() == original
    assert not journal.exists()


def test_k1_completed_transaction_wal_replay_must_be_refused(
    case, monkeypatch
):
    """
    An authentic WAL from a COMMITTED transaction must not
    authorize restoration when replayed later.
    """
    from sigma.tooling.governed_bounded_apply import (
        SealedRollbackEvidence,
    )

    world, target, proposal, _ = case
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    captured = {}
    real_persist = SealedRollbackEvidence.persist_wal

    def capture_authentic_wal(self, *args, **kwargs):
        wal = real_persist(self, *args, **kwargs)
        captured["wal_bytes"] = wal.read_bytes()
        captured["name"] = wal.name
        return wal

    with monkeypatch.context() as patch:
        patch.setattr(
            SealedRollbackEvidence,
            "persist_wal",
            capture_authentic_wal,
        )

        result = _engine(proposal.base_sha).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

    assert result.status == "COMMITTED", (
        result.status,
        result.error_detail,
        result.kx108_reason,
    )

    assert target.read_bytes() == payload
    assert target.read_bytes() != original
    assert captured["wal_bytes"]

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    wal = wal_dir / captured["name"]

    assert not wal.exists(), "COMMIT_MUST_CLEAR_WAL"

    # Replay the exact authentic WAL of the completed transaction.
    wal.write_bytes(captured["wal_bytes"])

    recovered = SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    # A completed transaction must never be rolled back by
    # replaying its old, otherwise authentic journal.
    assert recovered == []
    assert target.read_bytes() == payload
    assert wal.read_bytes() == captured["wal_bytes"]



def test_k1_act_write_then_raise_restores_physical_bytes(
    case, monkeypatch
):
    """
    Physical write occurs, then write_bytes raises OSError.
    Rollback must restore actual bytes before reporting success.
    """
    world, target, proposal, _ = case

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    from sigma.tooling import governed_bounded_apply as mod
    real_write = mod._k1_physical_write_bytes

    injected = []
    result = None
    caught = None

    def write_then_raise(path, data, expected_attestation, worktree):
        if (
            Path(path).resolve() == target.resolve()
            and data == payload
        ):
            real_write(path, data, expected_attestation, worktree)
            injected.append(True)
            raise OSError("K1_WRITE_SUCCEEDED_THEN_RAISED")

        return real_write(path, data, expected_attestation, worktree)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", write_then_raise)

        try:
            result = _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )
        except Exception as exc:
            caught = exc

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))

    print("INJECTED_WRITE_COUNT:", len(injected))
    print("CAUGHT_EXCEPTION:", repr(caught))
    print("RESULT_STATUS:", getattr(result, "status", None))
    print("PHYSICAL_BYTES_RESTORED:", target.read_bytes() == original)
    print("WAL_FILES_RETAINED:", len(journals))

    assert len(injected) == 1

    assert target.read_bytes() == original, (
        "ACT_WRITE_THEN_RAISE_PHYSICAL_STATE_NOT_RESTORED"
    )

    assert caught is None, (
        f"ACT_ROLLBACK_UNHANDLED_EXCEPTION:{caught}"
    )

    assert result is not None
    assert result.status == "ROLLED_BACK"
    assert result.rolled_back is True
    assert result.disk_written is False


def test_k1_wal_replay_after_lifecycle_history_rollback(
    case, tmp_path, monkeypatch
):
    """
    An older, correctly authenticated lifecycle prefix
    must not reauthorize a completed WAL transaction.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    # Private ledger: never alter the actual K1 ticket registry.
    ledger = tmp_path / "private_wal_lifecycle_v2.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    captured = {}
    real_persist = mod.SealedRollbackEvidence.persist_wal

    def capture_prepared_state(self, *args, **kwargs):
        wal = real_persist(self, *args, **kwargs)
        captured["wal_bytes"] = wal.read_bytes()
        captured["wal_name"] = wal.name
        captured["prepared_history"] = ledger.read_bytes()
        return wal

    with monkeypatch.context() as patch:
        patch.setattr(
            mod.SealedRollbackEvidence,
            "persist_wal",
            capture_prepared_state,
        )
        result = _engine(proposal.base_sha).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    assert result.status == "COMMITTED", result.kx108_reason
    assert target.read_bytes() == payload
    assert payload != original

    history = [
        json.loads(line)
        for line in ledger.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["state"] for event in history] == [
        "PREPARED", "FINALIZING", "COMMITTED"
    ]

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    wal = wal_dir / captured["wal_name"]
    assert not wal.exists()

    # Simulate rollback to a valid, older ledger prefix.
    ledger.write_bytes(captured["prepared_history"])

    # Replay the authentic WAL from the completed execution.
    wal.write_bytes(captured["wal_bytes"])

    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("RECOVERED:", recovered)
    print("TARGET_UNCHANGED:", target.read_bytes() == payload)
    print("WAL_RETAINED:", wal.exists())

    assert recovered == [], "LIFECYCLE_HISTORY_ROLLBACK_REPLAY"
    assert target.read_bytes() == payload
    assert wal.read_bytes() == captured["wal_bytes"]


def test_k1_recovering_after_physical_restore_is_resumable(
    case, tmp_path, monkeypatch
):
    """
    Two interruptions:
    1. ACT writes, then process interruption.
    2. Recovery restores bytes, then raises before finalization.
    A later recovery must reconcile the same authenticated WAL.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    private_ledger = tmp_path / "private_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: private_ledger,
    )

    real_write = mod._k1_physical_write_bytes

    def write_then_interrupt(path, data, expected_attestation, worktree):
        if (
            Path(path).resolve() == target.resolve()
            and data == payload
        ):
            real_write(path, data, expected_attestation, worktree)
            raise SystemExit("K1_ACT_INTERRUPTED")

        return real_write(path, data, expected_attestation, worktree)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", write_then_interrupt)

        with pytest.raises(SystemExit, match="K1_ACT_INTERRUPTED"):
            _engine(proposal.base_sha).apply_proposal_governed(
                proposal, **_execution_args(world)
            )

    assert target.read_bytes() == payload

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))
    assert len(journals) == 1
    wal = journals[0]

    real_restore = mod._k1_physical_write_bytes
    injected = []

    def restore_then_interrupt(path, content, attestation, worktree):
        result = real_restore(path, content, attestation, worktree)

        if (Path(path).resolve() == target.resolve()
                and content == original):
            injected.append(True)
            raise OSError("K1_RECOVERY_INTERRUPTED_AFTER_RESTORE")

        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", restore_then_interrupt)

        first_recovery = mod.SealedRollbackEvidence.recover_dangling_wal(
            proposal.target_worktree
        )

    assert len(injected) == 1
    assert first_recovery == []
    assert wal.exists()
    assert target.read_bytes() == original

    wal_data = json.loads(wal.read_text(encoding="utf-8"))
    state = mod._k1_wal_current_state(wal_data)

    print("STATE_AFTER_INTERRUPTION:", state)

    assert state == "RECOVERING"

    second_recovery = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("SECOND_RECOVERY:", second_recovery)
    print("PHYSICAL_BYTES_CORRECT:", target.read_bytes() == original)
    print("WAL_RETAINED:", wal.exists())

    assert proposal.proposal_id in second_recovery, (
        "K1_RECOVERING_CANNOT_RESUME"
    )
    assert target.read_bytes() == original
    assert not wal.exists()


def test_k1_recovered_wal_cleanup_after_unlink_interruption(
    case, tmp_path, monkeypatch
):
    """
    ACT interrupted; recovery reaches RECOVERED but WAL deletion
    fails. A subsequent recovery must complete cleanup without
    changing the already-restored physical bytes.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    ledger = tmp_path / "private_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    real_write = mod._k1_physical_write_bytes

    def interrupt_act(path, data, expected_attestation, worktree):
        if (
            Path(path).resolve() == target.resolve()
            and data == payload
        ):
            real_write(path, data, expected_attestation, worktree)
            raise SystemExit("K1_ACT_INTERRUPTED")

        return real_write(path, data, expected_attestation, worktree)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", interrupt_act)

        with pytest.raises(
            SystemExit,
            match="K1_ACT_INTERRUPTED",
        ):
            _engine(proposal.base_sha).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert target.read_bytes() == payload

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))
    assert len(journals) == 1

    wal = journals[0]
    wal_data = json.loads(wal.read_text(encoding="utf-8"))

    real_unlink = Path.unlink
    interrupted = []

    def interrupt_wal_unlink(path, *args, **kwargs):
        if Path(path).resolve() == wal.resolve():
            interrupted.append(True)
            raise OSError("K1_WAL_UNLINK_INTERRUPTED")

        return real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", interrupt_wal_unlink)

        first = mod.SealedRollbackEvidence.recover_dangling_wal(
            proposal.target_worktree
        )

    assert len(interrupted) == 1
    assert first == []
    assert target.read_bytes() == original
    assert wal.exists()

    first_state = mod._k1_wal_current_state(wal_data)

    print("STATE_AFTER_INTERRUPTION:", first_state)

    assert first_state == "RECOVERED"

    second = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("SECOND_RECOVERY:", second)
    print("PHYSICAL_BYTES_CORRECT:", target.read_bytes() == original)
    print("WAL_RETAINED:", wal.exists())

    assert target.read_bytes() == original

    assert second == [proposal.proposal_id], (
        "K1_RECOVERED_FINALIZATION_CANNOT_RESUME"
    )

    assert not wal.exists(), (
        "K1_RECOVERED_WAL_NOT_CLEARED"
    )

    assert mod._k1_wal_current_state(wal_data) == "RECOVERED"

def test_k1_recovered_divergent_bytes_refuse_wal_cleanup(
    case, tmp_path, monkeypatch
):
    """
    ACT interrupted; recovery reaches RECOVERED but WAL deletion
    fails. A subsequent recovery must complete cleanup without
    changing the already-restored physical bytes.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    ledger = tmp_path / "private_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    real_write = mod._k1_physical_write_bytes

    def interrupt_act(path, data, expected_attestation, worktree):
        if (
            Path(path).resolve() == target.resolve()
            and data == payload
        ):
            real_write(path, data, expected_attestation, worktree)
            raise SystemExit("K1_ACT_INTERRUPTED")

        return real_write(path, data, expected_attestation, worktree)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", interrupt_act)

        with pytest.raises(
            SystemExit,
            match="K1_ACT_INTERRUPTED",
        ):
            _engine(proposal.base_sha).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert target.read_bytes() == payload

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))
    assert len(journals) == 1

    wal = journals[0]
    wal_data = json.loads(wal.read_text(encoding="utf-8"))

    real_unlink = Path.unlink
    interrupted = []

    def interrupt_wal_unlink(path, *args, **kwargs):
        if Path(path).resolve() == wal.resolve():
            interrupted.append(True)
            raise OSError("K1_WAL_UNLINK_INTERRUPTED")

        return real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", interrupt_wal_unlink)

        first = mod.SealedRollbackEvidence.recover_dangling_wal(
            proposal.target_worktree
        )

    assert len(interrupted) == 1
    assert first == []
    assert target.read_bytes() == original
    assert wal.exists()

    first_state = mod._k1_wal_current_state(wal_data)

    print("STATE_AFTER_INTERRUPTION:", first_state)

    assert first_state == "RECOVERED"


    # A physical divergence appears after RECOVERED.
    # Cleanup must not conceal that inconsistency.
    tampered = b"# K1 EXTERNAL DIVERGENCE\\nVALUE = 999\\n"

    assert tampered != original
    assert tampered != payload

    target.write_bytes(tampered)

    wal_before = wal.read_bytes()

    second = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("SECOND_RECOVERY:", second)
    print("DIVERGENCE_PRESERVED:", target.read_bytes() == tampered)
    print("WAL_RETAINED:", wal.exists())
    print("LIFECYCLE_STATE:", mod._k1_wal_current_state(wal_data))

    assert second == [], (
        "K1_RECOVERED_DIVERGENT_CLEANUP_ACCEPTED"
    )
    assert target.read_bytes() == tampered, (
        "K1_RECOVERED_UNAUTHORIZED_PHYSICAL_REWRITE"
    )
    assert wal.exists(), (
        "K1_RECOVERED_DIVERGENT_WAL_DELETED"
    )
    assert wal.read_bytes() == wal_before
    assert mod._k1_wal_current_state(wal_data) == "RECOVERED"



def test_k1_authenticated_wal_recovery_across_python_processes(
    case, tmp_path, monkeypatch
):
    """
    Process A: authorized ACT writes and is interrupted.
    Process B: a fresh interpreter authenticates and recovers
    the WAL with the independently loaded kernel key.
    """
    import json
    import subprocess
    import sys
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    ledger = tmp_path / "cross_process_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    real_write = mod._k1_physical_write_bytes

    def interrupted_act(path, data, expected_attestation, worktree):
        if (
            Path(path).resolve() == target.resolve()
            and data == payload
        ):
            real_write(path, data, expected_attestation, worktree)
            raise SystemExit("K1_PROCESS_A_INTERRUPTED")
        return real_write(path, data, expected_attestation, worktree)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", interrupted_act)

        with pytest.raises(
            SystemExit, match="K1_PROCESS_A_INTERRUPTED"
        ):
            _engine(proposal.base_sha).apply_proposal_governed(
                proposal, **_execution_args(world)
            )

    assert target.read_bytes() == payload

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))
    assert len(journals) == 1

    wal = journals[0]
    wal_data = json.loads(wal.read_text(encoding="utf-8"))

    assert mod._k1_wal_current_state(wal_data) == "PREPARED"

    child_code = """
import sys
from pathlib import Path
from sigma.tooling import governed_bounded_apply as mod

worktree, ledger_path, proposal_id = sys.argv[1:]

mod._k1_wal_lifecycle_path = lambda: Path(ledger_path)

recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
    worktree
)

if recovered != [proposal_id]:
    print("PROCESS_B_RECOVERY_REFUSED")
    raise SystemExit(12)

print("PROCESS_B_WAL_RECOVERY_GREEN")
"""

    child = subprocess.run(
        [
            sys.executable, "-B", "-c", child_code,
            str(proposal.target_worktree),
            str(ledger),
            proposal.proposal_id,
        ],
        cwd=str(Path.cwd()),
        capture_output=True,
        text=True,
        timeout=45,
    )

    print("PROCESS_B_EXIT:", child.returncode)
    print("PROCESS_B_STATUS:", child.stdout.strip())

    if child.returncode != 0:
        print("PROCESS_B_ERROR:", child.stderr[-1600:])

    assert child.returncode == 0, (
        "K1_INTERPROCESS_WAL_RECOVERY_FAILED"
    )

    assert target.read_bytes() == original, (
        "K1_INTERPROCESS_PHYSICAL_RESTORE_FAILED"
    )

    assert not wal.exists(), (
        "K1_INTERPROCESS_WAL_NOT_FINALIZED"
    )

    assert mod._k1_wal_current_state(wal_data) == "RECOVERED"

    print("PHYSICAL_BYTES_CORRECT: True")
    print("WAL_RETAINED: False")
    print("LIFECYCLE_STATE: RECOVERED")



def test_k1_pre_signed_decision_rejects_key_change(
    case, monkeypatch
):
    """
    A PRE record signed with an earlier key must be rejected
    after a different configured key is loaded.
    """
    import os

    from periphery.world_calls import sovereign_ticket as ticket
    from periphery.world_calls import k1_dpapi_bootstrap as dpapi

    world, target, proposal, _ = case
    before = target.read_bytes()

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"

    with monkeypatch.context() as patch:
        for key in list(os.environ):
            if (
                key.upper().startswith("OBSIDIA_KEY_")
                or key.upper() == "OBSIDIA_KX108_SECRET_KEY"
            ):
                patch.delenv(key, raising=False)

        patch.setenv("OBSIDIA_ENV", "development")

        # No DPAPI source in this isolated execution.
        patch.setattr(
            dpapi,
            "load_k1_dpapi_key_text",
            lambda: None,
        )

        # Simulate key rotation after the PRE was signed.
        # A newly configured key is present, so this must
        # test signature authentication, not missing-key refusal.
        import secrets

        patch.setenv(
            "OBSIDIA_KX108_SECRET_KEY",
            "K1_ROTATED_TEST_" + secrets.token_hex(32),
        )

        # Simulate a fresh process without the old cached key.
        patch.setattr(ticket, "_KEY_REGISTRY", {})

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

    print("RESULT_STATUS:", result.status)
    print("KX108_REASON:", result.kx108_reason)
    print("PHYSICAL_UNCHANGED:", target.read_bytes() == before)

    journals = (
        list(wal_dir.iterdir())
        if wal_dir.exists()
        else []
    )

    print("WAL_ENTRIES:", len(journals))

    assert result.status == "REFUSED_PRE_DECISION"
    assert "DECISION_RECORD_AUTHENTICATOR_INVALID" in result.kx108_reason
    assert result.disk_written is False
    assert target.read_bytes() == before
    assert journals == []



def test_k1_act_requires_persistent_key_from_start(
    monkeypatch, request, tmp_path
):
    """
    Build PRE and execute ACT under the SAME ephemeral key.

    A valid ephemeral signature must not be sufficient to
    authorize physical K1 execution.
    """
    import os

    from periphery.world_calls import sovereign_ticket as ticket
    from periphery.world_calls import k1_dpapi_bootstrap as dpapi

    with monkeypatch.context() as patch:
        for name in list(os.environ):
            upper = name.upper()
            if (
                upper.startswith("OBSIDIA_KEY_")
                or upper.startswith("OBSIDIA_KX108_KEY_")
                or upper == "OBSIDIA_KX108_SECRET_KEY"
            ):
                patch.delenv(name, raising=False)

        patch.setenv("OBSIDIA_ENV", "development")

        patch.setattr(
            dpapi,
            "load_k1_dpapi_key_text",
            lambda: None,
        )

        # An empty registry BEFORE PRE is created.
        patch.setattr(ticket, "_KEY_REGISTRY", {})

        # Late fixture creation: PRE is now signed inside
        # the isolated no-persistent-key environment.
        world, target, proposal, _ = request.getfixturevalue(
            "case"
        )

        try:
            Path(proposal.target_worktree).resolve().relative_to(
                tmp_path.resolve()
            )
            target.resolve().relative_to(tmp_path.resolve())
        except ValueError:
            raise AssertionError(
                "REFUSED_NON_TEMPORARY_ACT_TARGET"
            )

        key_sources = [
            name for name in os.environ
            if (
                name.upper().startswith("OBSIDIA_KEY_")
                or name.upper().startswith("OBSIDIA_KX108_KEY_")
                or name.upper() == "OBSIDIA_KX108_SECRET_KEY"
            )
        ]

        assert not key_sources, (
            "NO_KEY_FIXTURE_REPROVISIONED_ENV:" +
            ",".join(key_sources)
        )

        before = target.read_bytes()

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

        after = target.read_bytes()
        wal_dir = (
            Path(proposal.target_worktree) / ".obsidia_wal"
        )

        journals = (
            list(wal_dir.iterdir())
            if wal_dir.exists()
            else []
        )

        print("RESULT_STATUS:", result.status)
        print("KX108_REASON:", result.kx108_reason)
        print("PHYSICAL_UNCHANGED:", after == before)
        print("WAL_ENTRIES:", len(journals))
        print("NO_PERSISTENT_KEY_SOURCES=True")

        assert result.status == "REFUSED_PRE_DECISION"
        assert result.kx108_reason == (
            "K1_PERSISTENT_KEY_REQUIRED"
        )
        assert result.disk_written is False
        assert after == before
        assert journals == []



def test_k1_act_refuses_cached_key_mismatching_persistent_source(
    monkeypatch, request, tmp_path
):
    """A cached key cannot override a different persistent key."""
    import os
    import secrets

    from periphery.world_calls import sovereign_ticket as ticket

    with monkeypatch.context() as patch:
        # Isolate this test from any existing process key.
        for name in list(os.environ):
            upper = name.upper()
            if (
                upper.startswith("OBSIDIA_KEY_")
                or upper.startswith("OBSIDIA_KX108_KEY_")
                or upper == "OBSIDIA_KX108_SECRET_KEY"
            ):
                patch.delenv(name, raising=False)

        # Explicit persistent source for the entire PRE fixture.
        configured = (
            "K1_CACHE_PROVENANCE_TEST_"
            + secrets.token_hex(32)
        )
        patch.setenv("OBSIDIA_KX108_SECRET_KEY", configured)
        patch.setattr(ticket, "_KEY_REGISTRY", {})

        world, target, proposal, _ = request.getfixturevalue(
            "case"
        )

        # Only test files in the pytest temporary directory.
        target.resolve().relative_to(tmp_path.resolve())
        Path(proposal.target_worktree).resolve().relative_to(
            tmp_path.resolve()
        )

        key_id = ticket._DEFAULT_KEY_ID
        original = ticket.get_kernel_key(key_id)

        assert original == configured.encode("utf-8"), (
            "PRE_KEY_SOURCE_NOT_EXPLICIT"
        )

        # Same key ID, but different key material in RAM.
        poisoned = bytes([original[0] ^ 1]) + original[1:]
        assert poisoned != original

        registry = dict(ticket._KEY_REGISTRY)
        registry[key_id] = poisoned
        patch.setattr(ticket, "_KEY_REGISTRY", registry)

        before = target.read_bytes()

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

        after = target.read_bytes()
        wal_dir = (
            Path(proposal.target_worktree) / ".obsidia_wal"
        )

        journals = (
            list(wal_dir.iterdir())
            if wal_dir.exists()
            else []
        )

        print("RESULT_STATUS:", result.status)
        print("KX108_REASON:", result.kx108_reason)
        print("PHYSICAL_UNCHANGED:", after == before)
        print("WAL_ENTRIES:", len(journals))
        print("KEY_MATERIAL_EXPOSED=False")

        assert result.status == "REFUSED_PRE_DECISION"
        assert result.kx108_reason == (
            "K1_KEY_PROVENANCE_MISMATCH"
        )
        assert result.disk_written is False
        assert after == before
        assert journals == []

def test_k1_committed_wal_replay_after_dual_witness_rollback(
    case, tmp_path, monkeypatch
):
    """
    An older, correctly authenticated lifecycle prefix
    must not reauthorize a completed WAL transaction.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    # All physical mutation must remain inside pytest tmp_path.
    try:
        target.resolve().relative_to(tmp_path.resolve())
        Path(proposal.target_worktree).resolve().relative_to(
            tmp_path.resolve()
        )
    except ValueError:
        raise AssertionError("REFUSED_NON_TEMPORARY_WAL_TARGET")
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    # Private ledger: never alter the actual K1 ticket registry.
    ledger = tmp_path / "private_wal_lifecycle_v2.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    captured = {}
    real_persist = mod.SealedRollbackEvidence.persist_wal

    def capture_prepared_state(self, *args, **kwargs):
        wal = real_persist(self, *args, **kwargs)
        captured["wal_bytes"] = wal.read_bytes()
        captured["wal_name"] = wal.name
        captured["prepared_history"] = ledger.read_bytes()
        return wal

    with monkeypatch.context() as patch:
        patch.setattr(
            mod.SealedRollbackEvidence,
            "persist_wal",
            capture_prepared_state,
        )
        result = _engine(proposal.base_sha).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    assert result.status == "COMMITTED", result.kx108_reason
    assert target.read_bytes() == payload
    assert payload != original

    history = [
        json.loads(line)
        for line in ledger.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["state"] for event in history] == [
        "PREPARED", "FINALIZING", "COMMITTED"
    ]

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    wal = wal_dir / captured["wal_name"]
    assert not wal.exists()

    # Simulate rollback to a valid, older ledger prefix.
    ledger.write_bytes(captured["prepared_history"])

    # Simulate loss of the independent COMMITTED terminal receipt.
    # The terminal is derived from this test's PRIVATE ledger.
    wal_data = json.loads(
        captured["wal_bytes"].decode("utf-8")
    )

    terminal = mod._k1_wal_terminal_receipt_path(wal_data)

    try:
        terminal.resolve().relative_to(tmp_path.resolve())
    except ValueError:
        raise AssertionError("REFUSED_NON_TEMPORARY_TERMINAL_PATH")

    assert terminal.is_file(), (
        "EXPECTED_COMMITTED_TERMINAL_RECEIPT_MISSING"
    )

    # Delete ONLY the receipt created within pytest tmp_path.
    terminal.unlink()

    assert not terminal.exists()

    print("LIFECYCLE_ROLLED_BACK_TO_PREPARED=True")
    print("TERMINAL_RECEIPT_REMOVED=True")
    print("NONCE_STORE_UNCHANGED=True")

    # Replay the authentic WAL from the completed execution.
    wal.write_bytes(captured["wal_bytes"])

    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("RECOVERED:", recovered)
    print("TARGET_UNCHANGED:", target.read_bytes() == payload)
    print("WAL_RETAINED:", wal.exists())

    assert recovered == [], "LIFECYCLE_HISTORY_ROLLBACK_REPLAY"
    assert target.read_bytes() == payload
    assert wal.read_bytes() == captured["wal_bytes"]



def test_k1_post_terminal_commit_failure_must_not_restore_bytes(
    case, tmp_path, monkeypatch
):
    """
    Once a COMMITTED terminal witness has been durably written,
    a subsequent lifecycle failure must never restore preimages.
    """
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    # Prevent mutation outside this pytest temporary directory.
    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    assert original != payload

    ledger = tmp_path / "post_terminal_failure_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    captured = {}
    real_persist = mod.SealedRollbackEvidence.persist_wal
    real_record = mod._k1_wal_record_state

    def capture_wal(self, *args, **kwargs):
        wal = real_persist(self, *args, **kwargs)
        captured["wal_data"] = dict(self._k1_wal_v2_data)
        captured["wal_name"] = wal.name
        return wal

    def fail_after_terminal(data, state):
        if state == "COMMITTED":
            raise OSError("K1_INJECTED_LIFECYCLE_COMMIT_FAILURE")
        return real_record(data, state)

    with monkeypatch.context() as patch:
        patch.setattr(
            mod.SealedRollbackEvidence,
            "persist_wal",
            capture_wal,
        )
        patch.setattr(
            mod,
            "_k1_wal_record_state",
            fail_after_terminal,
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

    assert "wal_data" in captured, "WAL_NOT_CREATED"

    terminal = mod._k1_wal_terminal_receipt_path(
        captured["wal_data"]
    )
    terminal.resolve().relative_to(tmp_path.resolve())

    wal = (
        Path(proposal.target_worktree)
        / ".obsidia_wal"
        / captured["wal_name"]
    )

    print("RESULT_STATUS:", result.status)
    print("TERMINAL_EXISTS:", terminal.is_file())
    print("LIFECYCLE_STATES:", [
        mod.json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ])
    print("PHYSICAL_PAYLOAD_PRESERVED:", (
        target.read_bytes() == payload
    ))
    print("WAL_RETAINED:", wal.is_file())

    assert terminal.is_file(), "TERMINAL_NOT_WRITTEN"
    assert target.read_bytes() == payload, (
        "POST_TERMINAL_PHYSICAL_ROLLBACK_FORBIDDEN"
    )
    assert wal.is_file(), (
        "POST_TERMINAL_WAL_MUST_BE_RETAINED"
    )
    assert result.status != "ROLLED_BACK", (
        "COMMITTED_WITNESS_CANNOT_BE_ROLLED_BACK"
    )



def test_k1_partial_finality_write_must_hold_physical_state(
    case, tmp_path, monkeypatch
):
    """
    Partial Finality witness + process write failure must not
    trigger automatic physical rollback or unsafe WAL recovery.
    """
    import json
    import os

    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    # Restrict physical mutation to the pytest temporary tree.
    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    before = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert before != payload

    ledger = tmp_path / "partial_finality_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    witness_paths = []

    def interrupted_finality(data):
        witness = mod._k1_wal_finality_receipt_path(data)

        # Safety boundary: no access to actual K1 receipts.
        witness.resolve().relative_to(tmp_path.resolve())
        mod._k1_wal_finality_check_path(witness)

        witness.parent.mkdir(parents=True, exist_ok=True)

        with witness.open("xb") as stream:
            stream.write(b'{"schema":')
            stream.flush()
            os.fsync(stream.fileno())

        witness_paths.append(witness)
        raise OSError("K1_INJECTED_PARTIAL_FINALITY_WRITE")

    with monkeypatch.context() as patch:
        patch.setattr(
            mod,
            "_k1_wal_write_finality_receipt",
            interrupted_finality,
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

    wal_dir = (
        Path(proposal.target_worktree) / ".obsidia_wal"
    )
    journals = list(wal_dir.glob("wal_*.json"))

    assert len(witness_paths) == 1
    assert len(journals) == 1

    witness = witness_paths[0]
    wal = journals[0]
    data = json.loads(wal.read_text(encoding="utf-8"))

    print("RESULT_STATUS:", result.status)
    print("FINALITY_PARTIAL_EXISTS:", witness.is_file())
    print("LIFECYCLE_STATE:", mod._k1_wal_current_state(data))
    print("PHYSICAL_PAYLOAD_PRESERVED:", (
        target.read_bytes() == payload
    ))
    print("WAL_RETAINED:", wal.is_file())

    assert result.status == "ERROR"
    assert result.rolled_back is False
    assert witness.is_file()
    assert target.read_bytes() == payload
    assert wal.is_file()

    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("RECOVERY_RESULT:", recovered)
    print("PHYSICAL_STILL_PRESERVED:", (
        target.read_bytes() == payload
    ))
    print("UNRESOLVED_WAL_RETAINED:", wal.is_file())

    assert recovered == []
    assert target.read_bytes() == payload
    assert wal.is_file()



def test_k1_missing_finality_after_commit_phase_must_not_restore(
    case, tmp_path, monkeypatch
):
    """
    ACT and post-tests succeed. Finality creation fails before
    creating any file. Recovery must expose the ambiguity safely.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert payload != original

    ledger = tmp_path / "missing_finality_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    finality_paths = []
    post_tests_called = []

    def passing_post_tests(worktree):
        assert Path(worktree).resolve() == Path(
            proposal.target_worktree
        ).resolve()
        assert target.read_bytes() == payload
        post_tests_called.append(True)
        return True

    def fail_before_finality_create(data):
        path = mod._k1_wal_finality_receipt_path(data)
        path.resolve().relative_to(tmp_path.resolve())
        assert not path.exists()
        finality_paths.append(path)
        raise OSError("K1_FINALITY_CREATE_INTERRUPTED")

    kwargs = dict(_execution_args(world))
    kwargs["post_test_runner"] = passing_post_tests

    with monkeypatch.context() as patch:
        patch.setattr(
            mod,
            "_k1_wal_write_finality_receipt",
            fail_before_finality_create,
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal, **kwargs
        )

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))

    assert post_tests_called == [True]
    assert len(finality_paths) == 1
    assert len(journals) == 1

    wal = journals[0]
    data = json.loads(wal.read_text(encoding="utf-8"))

    assert result.status == "ERROR"
    assert result.rolled_back is False
    assert target.read_bytes() == payload
    assert not finality_paths[0].exists()
    assert wal.is_file()
    assert mod._k1_wal_current_state(data) == "FINALIZING"

    print("POST_TESTS_PASS=True")
    print("FINALITY_FILE_EXISTS=False")
    print("RESULT_STATUS:", result.status)
    print("LIFECYCLE_STATE: FINALIZING")
    print("PAYLOAD_BEFORE_RECOVERY:",
          target.read_bytes() == payload)

    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("RECOVERY_RESULT:", recovered)
    print("PAYLOAD_AFTER_RECOVERY:",
          target.read_bytes() == payload)
    print("WAL_RETAINED:", wal.is_file())

    # Strict policy under examination:
    # recovery must not silently undo post-test-complete ACT.
    assert recovered == [], (
        "K1_MISSING_FINALITY_RECOVERY_AMBIGUITY"
    )
    assert target.read_bytes() == payload, (
        "K1_PHYSICAL_COMMIT_UNDONE"
    )
    assert wal.is_file(), (
        "K1_AMBIGUOUS_WAL_MUST_BE_RETAINED"
    )



def test_k1_torn_finalizing_event_must_hold_wal_and_payload(
    case, tmp_path, monkeypatch
):
    """A torn FINALIZING event must not authorize restoration."""
    import json
    import os
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    ledger = tmp_path / "torn_finalizing_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    real_record = mod._k1_wal_record_state
    post_tests = []
    interrupted = []

    def passing_post_tests(worktree):
        assert Path(worktree).resolve() == Path(
            proposal.target_worktree
        ).resolve()
        assert target.read_bytes() == payload
        post_tests.append(True)
        return True

    def record_then_interrupt(data, state):
        if state != "FINALIZING":
            return real_record(data, state)

        assert mod._k1_wal_current_state(data) == "PREPARED"

        # Simulate a torn append inside the PRIVATE ledger.
        ledger.resolve().relative_to(tmp_path.resolve())

        with ledger.open("ab") as stream:
            stream.write(b'{"schema":')
            stream.flush()
            os.fsync(stream.fileno())

        interrupted.append(True)
        raise OSError("K1_FINALIZING_TORN_WRITE")

    kwargs = dict(_execution_args(world))
    kwargs["post_test_runner"] = passing_post_tests

    with monkeypatch.context() as patch:
        patch.setattr(
            mod,
            "_k1_wal_record_state",
            record_then_interrupt,
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal, **kwargs
        )

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))

    assert post_tests == [True]
    assert interrupted == [True]
    assert len(journals) == 1
    assert ledger.read_bytes().endswith(b'{"schema":')

    wal = journals[0]
    data = json.loads(wal.read_text(encoding="utf-8"))

    finality = mod._k1_wal_finality_receipt_path(data)
    finality.resolve().relative_to(tmp_path.resolve())

    print("RESULT_STATUS:", result.status)
    print("FINALIZING_EVENT_TORN=True")
    print("FINALITY_EXISTS:", finality.exists())
    print("PAYLOAD_BEFORE_RECOVERY:",
          target.read_bytes() == payload)
    print("WAL_BEFORE_RECOVERY:", wal.exists())

    assert result.status == "ERROR"
    assert result.rolled_back is False
    assert target.read_bytes() == payload
    assert wal.is_file()
    assert not finality.exists()

    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("RECOVERY_RESULT:", recovered)
    print("PAYLOAD_AFTER_RECOVERY:",
          target.read_bytes() == payload)
    print("WAL_RETAINED:", wal.exists())

    assert recovered == [], "TORN_FINALIZING_REPLAY_ACCEPTED"
    assert target.read_bytes() == payload
    assert wal.is_file()



def test_k1_zero_byte_finalizing_failure_allows_precommit_recovery(
    case, tmp_path, monkeypatch
):
    """
    No durable FINALIZING event means no commit boundary.
    Recovery may restore the authenticated preimage.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    ledger = tmp_path / "zero_byte_finalizing_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    real_record = mod._k1_wal_record_state
    post_tests = []
    injected = []
    ledger_before_failure = []

    def passing_post_tests(worktree):
        assert Path(worktree).resolve() == Path(
            proposal.target_worktree
        ).resolve()
        assert target.read_bytes() == payload
        post_tests.append(True)
        return True

    def refuse_finalizing_without_write(data, state):
        if state != "FINALIZING":
            return real_record(data, state)

        ledger.resolve().relative_to(tmp_path.resolve())

        assert mod._k1_wal_current_state(data) == "PREPARED"

        # Capture ledger bytes before injecting the failure.
        ledger_before_failure.append(ledger.read_bytes())
        injected.append(True)

        # No append, no truncate, no file creation.
        raise OSError("K1_FINALIZING_ZERO_BYTES_WRITTEN")

    kwargs = dict(_execution_args(world))
    kwargs["post_test_runner"] = passing_post_tests

    with monkeypatch.context() as patch:
        patch.setattr(
            mod,
            "_k1_wal_record_state",
            refuse_finalizing_without_write,
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal, **kwargs
        )

    assert post_tests == [True]
    assert injected == [True]
    assert len(ledger_before_failure) == 1
    assert ledger.read_bytes() == ledger_before_failure[0]

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))
    assert len(journals) == 1

    wal = journals[0]
    data = json.loads(wal.read_text(encoding="utf-8"))

    finality = mod._k1_wal_finality_receipt_path(data)
    terminal = mod._k1_wal_terminal_receipt_path(data)

    finality.resolve().relative_to(tmp_path.resolve())
    terminal.resolve().relative_to(tmp_path.resolve())

    initial_state = mod._k1_wal_current_state(data)

    print("POST_TESTS_PASS:", post_tests == [True])
    print("FINALIZING_BYTES_WRITTEN:", False)
    print("INITIAL_RESULT:", result.status)
    print("INITIAL_LIFECYCLE_STATE:", initial_state)
    print("PAYLOAD_BEFORE_RECOVERY:", target.read_bytes() == payload)
    print("WAL_BEFORE_RECOVERY:", wal.is_file())

    assert result.status == "ERROR"
    assert result.rolled_back is False
    assert initial_state == "PREPARED"
    assert target.read_bytes() == payload
    assert wal.is_file()
    assert not finality.exists()
    assert not terminal.exists()

    # The fault injection is no longer active here.
    # The transaction has not crossed its durable commit boundary.
    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    final_state = mod._k1_wal_current_state(data)
    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("RECOVERY_RESULT:", recovered)
    print("PREIMAGE_RESTORED:", target.read_bytes() == original)
    print("FINAL_LIFECYCLE_STATE:", final_state)
    print("LIFECYCLE_HISTORY:", history)
    print("WAL_CLEARED:", not wal.exists())

    assert recovered == [proposal.proposal_id]
    assert target.read_bytes() == original
    assert not wal.exists()
    assert final_state == "RECOVERED"
    assert history == [
        "PREPARED",
        "RECOVERING",
        "RECOVERED",
    ]



def test_k1_existing_target_fsync_precedes_finalizing(
    case, tmp_path, monkeypatch
):
    """
    Existing target's new bytes must be fsynced before the
    durable FINALIZING lifecycle event is written.
    This does not prove directory-entry durability.
    """
    import os
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    assert target.is_file(), "TEST_REQUIRES_EXISTING_TARGET"

    payload = proposal.operations[0].content.encode("utf-8")
    assert target.read_bytes() != payload

    initial_stat = target.stat()
    assert initial_stat.st_ino != 0, (
        "FILE_ID_UNAVAILABLE_FOR_FSYNC_PROOF"
    )

    real_fsync = os.fsync
    real_record = mod._k1_wal_record_state

    target_fsync_events = []
    finalizing_observations = []

    def traced_fsync(fd):
        # Identify the actual file associated with this fd.
        # Lifecycle/WAL fsync does not count as target fsync.
        try:
            descriptor_stat = os.fstat(fd)
            current_stat = target.stat()

            same_file = (
                descriptor_stat.st_ino != 0
                and descriptor_stat.st_dev == current_stat.st_dev
                and descriptor_stat.st_ino == current_stat.st_ino
            )

            target_has_payload = (
                target.read_bytes() == payload
            )

            if same_file and target_has_payload:
                result = real_fsync(fd)
                target_fsync_events.append(True)
                return result
        except (OSError, ValueError):
            pass

        return real_fsync(fd)

    def traced_record(data, state):
        if state == "FINALIZING":
            finalizing_observations.append({
                "target_fsync_complete": bool(
                    target_fsync_events
                ),
                "payload_present": (
                    target.read_bytes() == payload
                ),
            })

        return real_record(data, state)

    with monkeypatch.context() as patch:
        patch.setattr(mod.os, "fsync", traced_fsync)
        patch.setattr(
            mod, "_k1_wal_record_state", traced_record
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

    print("RESULT_STATUS:", result.status)
    print("TARGET_FSYNC_EVENTS:", len(target_fsync_events))
    print("FINALIZING_OBSERVATIONS:", finalizing_observations)
    print("PHYSICAL_PAYLOAD_CORRECT:",
          target.read_bytes() == payload)

    assert result.status == "COMMITTED", (
        result.status, result.kx108_reason
    )
    assert finalizing_observations == [{
        "target_fsync_complete": True,
        "payload_present": True,
    }], "K1_PHYSICAL_FSYNC_MISSING_BEFORE_FINALIZING"



def test_k1_target_fsync_failure_blocks_finalizing(
    case, tmp_path, monkeypatch
):
    """
    Failed physical target fsync must prevent FINALIZING,
    Finality receipt creation and COMMITTED.
    """
    import json
    import os
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    before = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert before != payload
    assert target.stat().st_ino != 0

    ledger = tmp_path / "failed_target_fsync_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    real_fsync = os.fsync
    injected = []
    post_tests_called = []

    def fail_target_fsync_once(fd):
        if not injected:
            try:
                descriptor = os.fstat(fd)
                current = target.stat()
                same_target = (
                    descriptor.st_ino != 0
                    and descriptor.st_dev == current.st_dev
                    and descriptor.st_ino == current.st_ino
                )
            except (OSError, ValueError):
                same_target = False

            if same_target and target.read_bytes() == payload:
                injected.append(True)
                raise OSError(
                    "K1_INJECTED_TARGET_FSYNC_FAILURE"
                )

        return real_fsync(fd)

    def post_tests(worktree):
        post_tests_called.append(True)
        return True

    kwargs = dict(_execution_args(world))
    kwargs["post_test_runner"] = post_tests

    with monkeypatch.context() as patch:
        patch.setattr(
            mod.os, "fsync", fail_target_fsync_once
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal, **kwargs
        )

    assert injected == [True], (
        "TARGET_FSYNC_FAILURE_NOT_INJECTED"
    )

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = (
        list(wal_dir.iterdir())
        if wal_dir.exists() else []
    )

    terminal_dir = ledger.with_name(
        ledger.name + ".terminals_v2"
    )
    finality_dir = terminal_dir.with_name(
        terminal_dir.name + ".finality_v1"
    )

    print("FSYNC_FAILURE_INJECTED:", len(injected) == 1)
    print("RESULT_STATUS:", result.status)
    print("LIFECYCLE_HISTORY:", history)
    print("POST_TESTS_CALLED:", post_tests_called)
    print("FINALITY_DIRECTORY_EXISTS:", finality_dir.exists())
    print("TERMINAL_DIRECTORY_EXISTS:", terminal_dir.exists())
    print("PREIMAGE_RESTORED:", target.read_bytes() == before)
    print("WAL_ENTRIES:", len(journals))

    assert result.status == "ROLLED_BACK", (
        result.status,
        result.kx108_reason,
        result.error_detail,
    )
    assert result.rolled_back is True
    assert result.disk_written is False

    assert history == ["PREPARED", "ROLLED_BACK"]
    assert post_tests_called == []

    assert not finality_dir.exists()
    assert not terminal_dir.exists()
    assert target.read_bytes() == before
    assert journals == []



def test_k1_rollback_fsync_precedes_rolled_back_lifecycle(
    case, tmp_path, monkeypatch
):
    """
    Restored bytes must be fsynced before recording ROLLED_BACK
    and clearing the authenticated WAL.
    """
    import json
    import os
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload
    assert target.stat().st_ino != 0

    ledger = tmp_path / "rollback_fsync_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    real_fsync = os.fsync
    real_record = mod._k1_wal_record_state

    injected = []
    restored_fsync_events = []
    rolled_back_observations = []

    def traced_fsync(fd):
        try:
            descriptor = os.fstat(fd)
            current = target.stat()

            is_target = (
                descriptor.st_ino != 0
                and descriptor.st_dev == current.st_dev
                and descriptor.st_ino == current.st_ino
            )
        except (OSError, ValueError):
            is_target = False

        # First: force ACT target fsync failure.
        if (
            is_target
            and not injected
            and target.read_bytes() == payload
        ):
            injected.append(True)
            raise OSError(
                "K1_INJECTED_ACT_TARGET_FSYNC_FAILURE"
            )

        result = real_fsync(fd)

        # Count only a completed fsync of the restored
        # physical target, never WAL or lifecycle fsync.
        if (
            is_target
            and injected
            and target.read_bytes() == original
        ):
            restored_fsync_events.append(True)

        return result

    def traced_record(data, state):
        if state == "ROLLED_BACK":
            rolled_back_observations.append({
                "preimage_present": (
                    target.read_bytes() == original
                ),
                "preimage_fsync_complete": bool(
                    restored_fsync_events
                ),
            })

        return real_record(data, state)

    with monkeypatch.context() as patch:
        patch.setattr(
            mod.os, "fsync", traced_fsync
        )
        patch.setattr(
            mod, "_k1_wal_record_state", traced_record
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = (
        list(wal_dir.iterdir())
        if wal_dir.exists()
        else []
    )

    print("ACT_FSYNC_FAILURE_INJECTED:", bool(injected))
    print("RESULT_STATUS:", result.status)
    print("RESTORED_TARGET_FSYNC_EVENTS:",
          len(restored_fsync_events))
    print("ROLLED_BACK_OBSERVATIONS:",
          rolled_back_observations)
    print("LIFECYCLE_HISTORY:", history)
    print("PREIMAGE_PRESENT:",
          target.read_bytes() == original)
    print("WAL_ENTRIES:", len(journals))

    assert injected == [True], (
        "ACT_FSYNC_FAILURE_NOT_INJECTED"
    )
    assert result.status == "ROLLED_BACK"
    assert target.read_bytes() == original

    assert rolled_back_observations == [{
        "preimage_present": True,
        "preimage_fsync_complete": True,
    }], "K1_ROLLBACK_NOT_FSYNCED_BEFORE_TERMINAL"

    assert history == ["PREPARED", "ROLLED_BACK"]
    assert journals == []



def test_k1_rollback_fsync_failure_retains_wal_until_recovery(
    case, tmp_path, monkeypatch
):
    """
    Failed preimage fsync cannot finalize ROLLED_BACK.
    An authenticated recovery may subsequently finish.
    """
    import json
    import os

    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    target.resolve().relative_to(tmp_path.resolve())
    Path(proposal.target_worktree).resolve().relative_to(
        tmp_path.resolve()
    )

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload
    assert target.stat().st_ino != 0

    ledger = tmp_path / "failed_rollback_fsync_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    real_fsync = os.fsync
    injected = []
    post_tests_called = []

    def fail_restored_target_fsync(fd):
        try:
            descriptor = os.fstat(fd)
            current = target.stat()

            is_target = (
                descriptor.st_ino != 0
                and descriptor.st_dev == current.st_dev
                and descriptor.st_ino == current.st_ino
            )
        except (OSError, ValueError):
            is_target = False

        if (
            is_target
            and post_tests_called
            and not injected
            and target.read_bytes() == original
        ):
            injected.append(True)
            raise OSError(
                "K1_INJECTED_ROLLBACK_FSYNC_FAILURE"
            )

        return real_fsync(fd)

    def reject_post_tests(worktree):
        assert Path(worktree).resolve() == Path(
            proposal.target_worktree
        ).resolve()
        assert target.read_bytes() == payload
        post_tests_called.append(True)
        return False

    kwargs = dict(_execution_args(world))
    kwargs["post_test_runner"] = reject_post_tests

    result = None
    raised = None

    with monkeypatch.context() as patch:
        patch.setattr(
            mod.os, "fsync", fail_restored_target_fsync
        )

        try:
            result = _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal, **kwargs
            )
        except OSError as exc:
            raised = str(exc)

    assert post_tests_called == [True]
    assert injected == [True], (
        "ROLLBACK_FSYNC_FAILURE_NOT_INJECTED"
    )

    if raised is not None:
        assert "K1_INJECTED_ROLLBACK_FSYNC_FAILURE" in raised
    else:
        assert result is not None
        assert result.status == "ERROR"
        assert result.rolled_back is False

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))
    assert len(journals) == 1, "UNRESOLVED_WAL_MISSING"

    wal = journals[0]
    data = json.loads(wal.read_text(encoding="utf-8"))

    state = mod._k1_wal_current_state(data)
    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    finality = mod._k1_wal_finality_receipt_path(data)
    terminal = mod._k1_wal_terminal_receipt_path(data)

    finality.resolve().relative_to(tmp_path.resolve())
    terminal.resolve().relative_to(tmp_path.resolve())

    print("ROLLBACK_FSYNC_FAILURE_INJECTED:", bool(injected))
    print("INITIAL_RESULT:", (
        result.status if result else "EXCEPTION"
    ))
    print("INITIAL_LIFECYCLE_HISTORY:", history)
    print("PREIMAGE_VISIBLE:", target.read_bytes() == original)
    print("WAL_RETAINED:", wal.is_file())
    print("FINALITY_EXISTS:", finality.exists())
    print("TERMINAL_EXISTS:", terminal.exists())

    assert state == "PREPARED"
    assert history == ["PREPARED"]
    assert target.read_bytes() == original
    assert wal.is_file()
    assert not finality.exists()
    assert not terminal.exists()

    # The fsync fault injection is no longer active.
    # Recovery must re-apply and sync the preimage.
    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    final_state = mod._k1_wal_current_state(data)
    final_history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("RECOVERY_RESULT:", recovered)
    print("FINAL_LIFECYCLE_HISTORY:", final_history)
    print("FINAL_PREIMAGE_CORRECT:",
          target.read_bytes() == original)
    print("WAL_CLEARED:", not wal.exists())

    assert recovered == [proposal.proposal_id]
    assert target.read_bytes() == original
    assert final_state == "RECOVERED"
    assert final_history == [
        "PREPARED",
        "RECOVERING",
        "RECOVERED",
    ]
    assert not wal.exists()

def test_k1_wal_metadata_flush_precedes_prepared(
    case, tmp_path, monkeypatch
):
    """WAL directory barriers must complete before PREPARED."""
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    target.resolve().relative_to(tmp_path.resolve())

    ledger = tmp_path / "wal_metadata_success.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    real_flush = mod._k1_wal_flush_metadata_parents
    real_record = mod._k1_wal_record_state
    flushed = []
    observations = []
    finalizing_seen = []

    expected_wal = (
        Path(proposal.target_worktree)
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()
    expected_lifecycle = ledger.resolve()

    def traced_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(tmp_path.resolve())
        # K1_WAL_CLEANUP_POST_UNLINK_OBSERVER
        if resolved == expected_wal and not Path(path).exists():
            assert finalizing_seen, "CLEANUP_BEFORE_FINALIZING"
            return real_flush(path)

        assert Path(path).is_file()

        if resolved == expected_wal:
            kind = "WAL"
        elif resolved == expected_lifecycle:
            kind = "LIFECYCLE"
        else:
            # K1_POST_FINALIZING_RECEIPT_FLUSH_SCOPE
            # Only receipt flushes after durable FINALIZING
            # are outside this test's WAL/Lifecycle scope.
            if not finalizing_seen:
                raise AssertionError(
                    "UNEXPECTED_PRE_FINALIZING_METADATA_TARGET"
                )
            return real_flush(path)

        result = real_flush(path)
        flushed.append(kind)
        return result

    def traced_record(data, state):
        if state == "PREPARED":
            observations.append({
                "wal_directory_flushed": flushed == ["WAL"],
            })
        result = real_record(data, state)
        if state == "FINALIZING":
            finalizing_seen.append(True)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            traced_flush,
        )
        patch.setattr(
            mod, "_k1_wal_record_state",
            traced_record,
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    print("RESULT_STATUS:", result.status)
    print("WAL_METADATA_FLUSH_EVENTS:", len(flushed))
    print("PREPARED_OBSERVATIONS:", observations)

    assert result.status == "COMMITTED"
    assert flushed == ["WAL", "LIFECYCLE"]
    assert observations == [{
        "wal_directory_flushed": True
    }]

def test_k1_wal_metadata_flush_failure_blocks_act(
    case, tmp_path, monkeypatch
):
    """An unconfirmed WAL directory flush must prevent ACT."""
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    target.resolve().relative_to(tmp_path.resolve())

    before = target.read_bytes()

    ledger = tmp_path / "wal_metadata_failure.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    injected = []

    def fail_after_rename(wal):
        Path(wal).resolve().relative_to(tmp_path.resolve())
        assert Path(wal).is_file()
        injected.append(True)
        raise OSError("K1_INJECTED_WAL_DIRECTORY_FLUSH_FAILURE")

    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            fail_after_rename,
        )

        try:
            _engine(proposal.base_sha).apply_proposal_governed(
                proposal, **_execution_args(world)
            )
        except OSError as exc:
            assert "K1_INJECTED_WAL_DIRECTORY_FLUSH_FAILURE" in str(exc)
        else:
            raise AssertionError(
                "WAL_DIRECTORY_FLUSH_FAILURE_NOT_PROPAGATED"
            )

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    journals = list(wal_dir.glob("wal_*.json"))

    print("FLUSH_FAILURE_INJECTED:", bool(injected))
    print("PHYSICAL_UNCHANGED:", target.read_bytes() == before)
    print("WAL_RETAINED:", len(journals) == 1)
    print("PREPARED_NOT_PUBLISHED:", not ledger.exists())

    assert injected == [True]
    assert target.read_bytes() == before
    assert len(journals) == 1
    assert not ledger.exists()



def test_k1_lifecycle_directory_flush_precedes_physical_act(
    case, tmp_path, monkeypatch
):
    """
    The first PREPARED lifecycle file must be fsynced and
    its parent directory flushed before physical ACT.
    """
    import os
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)

    payload = proposal.operations[0].content.encode("utf-8")
    assert target.read_bytes() != payload

    ledger = tmp_path / "lifecycle_metadata_v2.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        Path(proposal.target_worktree)
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    )

    real_flush = mod._k1_wal_flush_metadata_parents
    real_fsync = os.fsync
    real_write = mod._k1_physical_write_bytes

    events = []

    def observed_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        result = real_flush(path)

        if resolved == ledger.resolve():
            events.append("LIFECYCLE_DIR_FLUSH")
        elif resolved == wal.resolve():
            # K1_LIFECYCLE_POST_UNLINK_SCOPE
            if not wal.exists():
                assert "PHYSICAL_WRITE" in events
                events.append("WAL_CLEANUP_DIR_FLUSH")
            else:
                events.append("WAL_DIR_FLUSH")
        else:
            # K1_POST_ACT_RECEIPT_FLUSH_SCOPE
            # Unknown metadata operations remain forbidden
            # before physical ACT.
            if "PHYSICAL_WRITE" not in events:
                raise AssertionError(
                    "UNEXPECTED_PRE_ACT_METADATA_TARGET"
                )
            events.append("POST_ACT_RECEIPT_DIR_FLUSH")

        return result

    def observed_fsync(fd):
        result = real_fsync(fd)

        if ledger.is_file():
            try:
                descriptor = os.fstat(fd)
                current = ledger.stat()
                is_ledger = (
                    descriptor.st_ino != 0
                    and descriptor.st_dev == current.st_dev
                    and descriptor.st_ino == current.st_ino
                )
            except (OSError, ValueError):
                is_ledger = False

            if is_ledger:
                events.append("LIFECYCLE_FSYNC")

        return result

    def observed_write(path, data, expected_attestation, worktree):
        result = real_write(path, data, expected_attestation, worktree)

        if (
            Path(path).resolve() == target.resolve()
            and data == payload
        ):
            events.append("PHYSICAL_WRITE")

        return result

    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            observed_flush,
        )
        patch.setattr(mod.os, "fsync", observed_fsync)
        patch.setattr(mod, "_k1_physical_write_bytes", observed_write)

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    assert result.status == "COMMITTED", (
        result.status, result.kx108_reason
    )
    assert target.read_bytes() == payload
    assert "PHYSICAL_WRITE" in events

    before_act = events[:events.index("PHYSICAL_WRITE")]

    print("EVENTS_BEFORE_ACT:", before_act)
    print("WAL_DIRECTORY_FLUSHED:",
          "WAL_DIR_FLUSH" in before_act)
    print("LIFECYCLE_FILE_FSYNCED:",
          "LIFECYCLE_FSYNC" in before_act)
    print("LIFECYCLE_DIRECTORY_FLUSHED:",
          "LIFECYCLE_DIR_FLUSH" in before_act)

    required = [
        "WAL_DIR_FLUSH",
        "LIFECYCLE_FSYNC",
        "LIFECYCLE_DIR_FLUSH",
    ]

    assert all(item in before_act for item in required), (
        "K1_PREPARED_METADATA_DURABILITY_MISSING"
    )

    positions = [before_act.index(item) for item in required]

    assert positions == sorted(positions), (
        "K1_PREPARED_METADATA_BARRIER_OUT_OF_ORDER"
    )



def test_k1_lifecycle_directory_flush_failure_blocks_act(
    case, tmp_path, monkeypatch
):
    """
    Failed PREPARED directory flush must prevent physical ACT.
    WAL remains unresolved; no terminal status may be claimed.
    """
    import json
    import os
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)

    before = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert before != payload
    assert target.stat().st_ino != 0

    ledger = tmp_path / "lifecycle_failure_v2.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        Path(proposal.target_worktree)
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    )

    real_flush = mod._k1_wal_flush_metadata_parents
    real_fsync = os.fsync
    real_write = mod._k1_physical_write_bytes

    events = []
    injected = []

    def observed_fsync(fd):
        result = real_fsync(fd)

        if ledger.is_file():
            try:
                descriptor = os.fstat(fd)
                stat = ledger.stat()
                same_ledger = (
                    descriptor.st_ino != 0
                    and descriptor.st_dev == stat.st_dev
                    and descriptor.st_ino == stat.st_ino
                )
            except (OSError, ValueError):
                same_ledger = False

            if same_ledger:
                events.append("LIFECYCLE_FILE_FSYNC")

        return result

    def injected_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if resolved == wal.resolve():
            result = real_flush(path)
            events.append("WAL_DIRECTORY_FLUSH")
            return result

        if resolved == ledger.resolve():
            assert ledger.is_file()
            events.append("LIFECYCLE_DIRECTORY_FLUSH_ATTEMPT")
            injected.append(True)
            raise OSError(
                "K1_INJECTED_LIFECYCLE_DIRECTORY_FLUSH_FAILURE"
            )

        raise AssertionError("UNEXPECTED_DIRECTORY_FLUSH")

    def observed_write(path, data, expected_attestation, worktree):
        if Path(path).resolve() == target.resolve():
            events.append("PHYSICAL_WRITE_ATTEMPT")
        return real_write(path, data, expected_attestation, worktree)

    result = None
    raised = None

    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            injected_flush
        )
        patch.setattr(mod.os, "fsync", observed_fsync)
        patch.setattr(mod, "_k1_physical_write_bytes", observed_write)

        try:
            result = _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )
        except OSError as exc:
            raised = str(exc)

    if raised is None:
        assert result is not None
        assert result.status not in (
            "COMMITTED", "ROLLED_BACK"
        ), result.status
    else:
        assert (
            "K1_INJECTED_LIFECYCLE_DIRECTORY_FLUSH_FAILURE"
            in raised
        ), raised

    assert ledger.is_file()
    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    wal_dir = wal.parent
    journals = sorted(wal_dir.glob("wal_*.json"))

    print("LIFECYCLE_FLUSH_FAILURE_INJECTED:",
          injected == [True])
    print("EVENTS:", events)
    print("INITIAL_RESULT:",
          result.status if result else "EXCEPTION")
    print("LIFECYCLE_HISTORY:", history)
    print("PHYSICAL_UNCHANGED:",
          target.read_bytes() == before)
    print("WAL_RETAINED:", wal.is_file())
    print("WAL_ENTRY_COUNT:", len(journals))

    assert injected == [True]
    assert events == [
        "WAL_DIRECTORY_FLUSH",
        "LIFECYCLE_FILE_FSYNC",
        "LIFECYCLE_DIRECTORY_FLUSH_ATTEMPT",
    ], "LIFECYCLE_FAILURE_ORDER_INCORRECT"

    assert history == ["PREPARED"], (
        "UNEXPECTED_TERMINAL_LIFECYCLE_STATE"
    )
    assert target.read_bytes() == before
    assert journals == [wal]

    data = json.loads(wal.read_text(encoding="utf-8"))
    assert mod._k1_wal_current_state(data) == "PREPARED"

    finality = mod._k1_wal_finality_receipt_path(data)
    terminal = mod._k1_wal_terminal_receipt_path(data)

    finality.resolve().relative_to(root)
    terminal.resolve().relative_to(root)

    assert not finality.exists()
    assert not terminal.exists()

    print("FINALITY_EXISTS:", finality.exists())
    print("TERMINAL_EXISTS:", terminal.exists())
    print("NO_PHYSICAL_ACT=True")
    print("UNRESOLVED_WAL_PRESERVED=True")

def test_k1_finality_terminal_metadata_before_committed(
    case, tmp_path, monkeypatch
):
    """
    Finality's directory barrier must precede Terminal.
    Terminal's directory barrier must precede COMMITTED.

    Validates explicit synchronization order, not physical
    power-loss durability.
    """
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)

    payload = proposal.operations[0].content.encode("utf-8")
    assert target.read_bytes() != payload

    ledger = tmp_path / "receipt_metadata_lifecycle.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    wal = (
        Path(proposal.target_worktree)
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    real_flush = mod._k1_wal_flush_metadata_parents
    real_finality = mod._k1_wal_write_finality_receipt
    real_terminal = mod._k1_wal_write_terminal_receipt
    real_record = mod._k1_wal_record_state

    receipt_paths = {}
    events = []
    terminal_observations = []
    committed_observations = []

    def traced_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        # K1_RECEIPT_POST_UNLINK_SCOPE
        if resolved == wal and not Path(path).exists():
            assert "COMMITTED_ENTERED" in events
            result = real_flush(path)
            events.append("WAL_CLEANUP_DIR_FLUSH")
            return result

        if resolved == wal:
            kind = "WAL_DIR_FLUSH"
        elif resolved == ledger.resolve():
            kind = "LIFECYCLE_DIR_FLUSH"
        elif resolved == receipt_paths.get("finality"):
            kind = "FINALITY_DIR_FLUSH"
        elif resolved == receipt_paths.get("terminal"):
            kind = "TERMINAL_DIR_FLUSH"
        else:
            raise AssertionError(
                "UNKNOWN_METADATA_FLUSH_TARGET:"
                + str(resolved)
            )

        assert Path(path).is_file(), (
            "METADATA_FLUSH_TARGET_FILE_MISSING"
        )

        result = real_flush(path)
        events.append(kind)
        return result

    def traced_finality(data):
        path = mod._k1_wal_finality_receipt_path(data)
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        receipt_paths["finality"] = resolved
        assert not resolved.exists()

        result = real_finality(data)

        assert resolved.is_file()
        events.append("FINALITY_WRITER_COMPLETED")
        return result

    def traced_terminal(data):
        path = mod._k1_wal_terminal_receipt_path(data)
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        receipt_paths["terminal"] = resolved

        assert receipt_paths["finality"] != resolved

        terminal_observations.append({
            "finality_exists": (
                receipt_paths["finality"].is_file()
            ),
            "finality_directory_flushed": (
                "FINALITY_DIR_FLUSH" in events
            ),
        })

        events.append("TERMINAL_WRITER_ENTERED")
        result = real_terminal(data)

        assert resolved.is_file()
        events.append("TERMINAL_WRITER_COMPLETED")
        return result

    def traced_record(data, state):
        if state == "COMMITTED":
            committed_observations.append({
                "finality_directory_flushed": (
                    "FINALITY_DIR_FLUSH" in events
                ),
                "terminal_exists": (
                    receipt_paths["terminal"].is_file()
                ),
                "terminal_directory_flushed": (
                    "TERMINAL_DIR_FLUSH" in events
                ),
            })

            events.append("COMMITTED_ENTERED")

        return real_record(data, state)

    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            traced_flush,
        )
        patch.setattr(
            mod, "_k1_wal_write_finality_receipt",
            traced_finality,
        )
        patch.setattr(
            mod, "_k1_wal_write_terminal_receipt",
            traced_terminal,
        )
        patch.setattr(
            mod, "_k1_wal_record_state",
            traced_record,
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

    print("RESULT_STATUS:", result.status)
    print("METADATA_EVENTS:", events)
    print("TERMINAL_ENTRY:", terminal_observations)
    print("COMMITTED_ENTRY:", committed_observations)
    print("PHYSICAL_PAYLOAD_CORRECT:",
          target.read_bytes() == payload)

    assert result.status == "COMMITTED", (
        result.status, result.kx108_reason
    )

    assert target.read_bytes() == payload

    assert len(terminal_observations) == 1
    assert len(committed_observations) == 1

    assert "WAL_DIR_FLUSH" in events
    assert "LIFECYCLE_DIR_FLUSH" in events

    assert terminal_observations == [{
        "finality_exists": True,
        "finality_directory_flushed": True,
    }], "K1_FINALITY_METADATA_NOT_DURABLE_BEFORE_TERMINAL"

    assert committed_observations == [{
        "finality_directory_flushed": True,
        "terminal_exists": True,
        "terminal_directory_flushed": True,
    }], "K1_TERMINAL_METADATA_NOT_DURABLE_BEFORE_COMMITTED"

def test_k1_finality_directory_flush_failure_retains_finalizing_wal(
    case, tmp_path, monkeypatch
):
    """
    Finality metadata flush failure after FINALIZING:
    no rollback, no Terminal, no COMMITTED, WAL retained.
    """
    import json
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    ledger = tmp_path / "finality_flush_failure_lifecycle.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        Path(proposal.target_worktree)
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    )

    real_flush = mod._k1_wal_flush_metadata_parents
    real_finality = mod._k1_wal_write_finality_receipt
    real_terminal = mod._k1_wal_write_terminal_receipt

    finality_target = []
    injected = []
    terminal_calls = []
    events = []

    def traced_finality(data):
        path = Path(
            mod._k1_wal_finality_receipt_path(data)
        ).resolve()

        path.relative_to(root)
        assert not path.exists()

        finality_target.append(path)
        result = real_finality(data)

        assert path.is_file()
        events.append("FINALITY_FILE_WRITTEN")
        return result

    def fail_finality_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if finality_target and resolved == finality_target[0]:
            assert resolved.is_file()
            assert events[-1] == "FINALITY_FILE_WRITTEN"
            injected.append(True)
            events.append("FINALITY_DIR_FLUSH_FAILED")
            raise OSError(
                "K1_INJECTED_FINALITY_DIRECTORY_FLUSH_FAILURE"
            )

        result = real_flush(path)
        events.append("OTHER_METADATA_FLUSH_OK")
        return result

    def traced_terminal(data):
        terminal_calls.append(True)
        return real_terminal(data)

    result = None
    raised = None

    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_wal_write_finality_receipt",
            traced_finality,
        )
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            fail_finality_flush,
        )
        patch.setattr(
            mod, "_k1_wal_write_terminal_receipt",
            traced_terminal,
        )

        try:
            result = _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )
        except OSError as exc:
            raised = str(exc)

    assert injected == [True], (
        "FINALITY_FLUSH_FAILURE_NOT_INJECTED"
    )
    assert len(finality_target) == 1
    assert terminal_calls == [], (
        "TERMINAL_WRITTEN_AFTER_FINALITY_FLUSH_FAILURE"
    )

    if raised is None:
        assert result is not None
        assert result.status == "ERROR", (
            result.status,
            result.kx108_reason,
            result.error_detail,
        )
        assert result.rolled_back is False
    else:
        assert (
            "K1_INJECTED_FINALITY_DIRECTORY_FLUSH_FAILURE"
            in raised
        )

    assert wal.is_file(), "FINALIZING_WAL_MISSING"
    data = json.loads(wal.read_text(encoding="utf-8"))

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    finality = Path(
        mod._k1_wal_finality_receipt_path(data)
    )
    terminal = Path(
        mod._k1_wal_terminal_receipt_path(data)
    )

    finality.resolve().relative_to(root)
    terminal.resolve().relative_to(root)

    print("FINALITY_FLUSH_FAILURE_INJECTED:",
          bool(injected))
    print("EVENTS:", events)
    print("RESULT_STATUS:",
          result.status if result else "EXCEPTION")
    print("LIFECYCLE_HISTORY:", history)
    print("PHYSICAL_PAYLOAD_PRESERVED:",
          target.read_bytes() == payload)
    print("WAL_RETAINED:", wal.is_file())
    print("FINALITY_EXISTS:", finality.is_file())
    print("TERMINAL_EXISTS:", terminal.exists())
    print("TERMINAL_WRITER_CALLED:", bool(terminal_calls))

    assert history == [
        "PREPARED", "FINALIZING"
    ], "INVALID_LIFECYCLE_AFTER_FINALITY_FLUSH_FAILURE"

    assert mod._k1_wal_current_state(data) == "FINALIZING"
    assert target.read_bytes() == payload
    assert finality.is_file()
    assert not terminal.exists()

    # The finalization state must not authorize restoration
    # of the old physical bytes.
    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("RECOVERY_RESULT:", recovered)
    print("PHYSICAL_UNCHANGED_AFTER_RECOVERY:",
          target.read_bytes() == payload)
    print("WAL_STILL_RETAINED:", wal.is_file())

    assert recovered == []
    assert target.read_bytes() == payload
    assert wal.is_file()

def test_k1_terminal_directory_flush_failure_retains_finalizing_wal(
    case, tmp_path, monkeypatch
):
    """
    Terminal directory flush failure after FINALIZING:
    Finality persists, Terminal exists but its metadata
    barrier failed, no COMMITTED, no rollback, WAL retained.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    ledger = tmp_path / "terminal_flush_failure_lifecycle.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        Path(proposal.target_worktree)
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    )

    real_flush = mod._k1_wal_flush_metadata_parents
    real_finality = mod._k1_wal_write_finality_receipt
    real_terminal = mod._k1_wal_write_terminal_receipt

    finality_paths = []
    terminal_paths = []
    injected = []
    events = []

    def traced_finality(data):
        path = Path(
            mod._k1_wal_finality_receipt_path(data)
        ).resolve()

        path.relative_to(root)
        assert not path.exists()
        finality_paths.append(path)

        result = real_finality(data)

        assert path.is_file()
        events.append("FINALITY_WRITTEN")
        return result

    def traced_terminal(data):
        assert len(finality_paths) == 1
        assert "FINALITY_DIR_FLUSH_OK" in events

        path = Path(
            mod._k1_wal_terminal_receipt_path(data)
        ).resolve()

        path.relative_to(root)
        assert not path.exists()
        terminal_paths.append(path)

        result = real_terminal(data)

        assert path.is_file()
        events.append("TERMINAL_WRITTEN")
        return result

    def fail_terminal_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if finality_paths and resolved == finality_paths[0]:
            assert resolved.is_file()
            result = real_flush(path)
            events.append("FINALITY_DIR_FLUSH_OK")
            return result

        if terminal_paths and resolved == terminal_paths[0]:
            assert resolved.is_file()
            assert events[-1] == "TERMINAL_WRITTEN"
            injected.append(True)
            events.append("TERMINAL_DIR_FLUSH_FAILED")
            raise OSError(
                "K1_INJECTED_TERMINAL_DIRECTORY_FLUSH_FAILURE"
            )

        result = real_flush(path)
        events.append("PRECOMMIT_METADATA_FLUSH_OK")
        return result

    result = None
    raised = None

    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_wal_write_finality_receipt",
            traced_finality,
        )
        patch.setattr(
            mod, "_k1_wal_write_terminal_receipt",
            traced_terminal,
        )
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            fail_terminal_flush,
        )

        try:
            result = _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )
        except OSError as exc:
            raised = str(exc)

    assert injected == [True], (
        "TERMINAL_FLUSH_FAILURE_NOT_INJECTED"
    )
    assert len(finality_paths) == 1
    assert len(terminal_paths) == 1

    if raised is None:
        assert result is not None
        assert result.status == "ERROR", (
            result.status,
            result.kx108_reason,
            result.error_detail,
        )
        assert result.rolled_back is False
    else:
        assert (
            "K1_INJECTED_TERMINAL_DIRECTORY_FLUSH_FAILURE"
            in raised
        )

    assert wal.is_file(), "FINALIZING_WAL_MISSING"

    data = json.loads(
        wal.read_text(encoding="utf-8")
    )

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    finality = Path(
        mod._k1_wal_finality_receipt_path(data)
    )
    terminal = Path(
        mod._k1_wal_terminal_receipt_path(data)
    )

    finality.resolve().relative_to(root)
    terminal.resolve().relative_to(root)

    print("TERMINAL_FLUSH_FAILURE_INJECTED:",
          injected == [True])
    print("EVENTS:", events)
    print("RESULT_STATUS:",
          result.status if result else "EXCEPTION")
    print("LIFECYCLE_HISTORY:", history)
    print("PHYSICAL_PAYLOAD_PRESERVED:",
          target.read_bytes() == payload)
    print("WAL_RETAINED:", wal.is_file())
    print("FINALITY_EXISTS:", finality.is_file())
    print("TERMINAL_EXISTS:", terminal.is_file())

    assert history == [
        "PREPARED", "FINALIZING"
    ], "INVALID_LIFECYCLE_AFTER_TERMINAL_FLUSH_FAILURE"

    assert mod._k1_wal_current_state(data) == "FINALIZING"
    assert target.read_bytes() == payload
    assert finality.is_file()
    assert terminal.is_file()

    assert "FINALITY_DIR_FLUSH_OK" in events
    assert "TERMINAL_DIR_FLUSH_FAILED" in events

    assert events.index(
        "FINALITY_DIR_FLUSH_OK"
    ) < events.index(
        "TERMINAL_WRITTEN"
    ) < events.index(
        "TERMINAL_DIR_FLUSH_FAILED"
    )

    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("RECOVERY_RESULT:", recovered)
    print("PHYSICAL_UNCHANGED_AFTER_RECOVERY:",
          target.read_bytes() == payload)
    print("WAL_STILL_RETAINED:", wal.is_file())

    assert recovered == []
    assert target.read_bytes() == payload
    assert wal.is_file()

    print("NO_ROLLBACK=True")
    print("NO_COMMITTED=True")

def test_k1_wal_cleanup_directory_flush_after_unlink(
    case, tmp_path, monkeypatch
):
    """
    K1 WAL cleanup durability boundary.

    A successful COMMITTED result must not be returned
    before the WAL unlink metadata barrier completes.
    """
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    worktree = Path(proposal.target_worktree).resolve()

    worktree.relative_to(root)
    target.resolve().relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    assert original != payload

    ledger = tmp_path / "wal_cleanup_lifecycle_v2.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod,
        "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    wal = (
        worktree
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()

    real_unlink = Path.unlink
    real_flush = mod._k1_wal_flush_metadata_parents
    real_record = mod._k1_wal_record_state

    events = []
    deleted = []
    cleanup_flushed = []

    def observed_record(data, state):
        result = real_record(data, state)

        if state == "COMMITTED":
            events.append("COMMITTED_RECORDED")

        return result

    def observed_unlink(path, *args, **kwargs):
        resolved = Path(path).resolve()

        if resolved != wal:
            return real_unlink(path, *args, **kwargs)

        assert resolved.is_file()
        assert "COMMITTED_RECORDED" in events
        assert target.read_bytes() == payload

        data = json.loads(
            resolved.read_text(encoding="utf-8")
        )

        assert mod._k1_wal_current_state(data) == "COMMITTED"

        events.append("WAL_UNLINK_ATTEMPT")
        result = real_unlink(path, *args, **kwargs)

        assert not resolved.exists()

        deleted.append(True)
        events.append("WAL_UNLINK_COMPLETED")
        return result

    def observed_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        result = real_flush(path)

        if deleted:
            if (
                resolved == wal
                or resolved == wal.parent
                or resolved.parent == wal.parent
            ):
                cleanup_flushed.append(True)
                events.append("WAL_CLEANUP_DIR_FLUSH")
            else:
                events.append("OTHER_POST_DELETE_FLUSH")
        else:
            events.append("PRE_CLEANUP_DIR_FLUSH")

        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", observed_unlink)
        patch.setattr(
            mod,
            "_k1_wal_flush_metadata_parents",
            observed_flush,
        )
        patch.setattr(
            mod,
            "_k1_wal_record_state",
            observed_record,
        )

        result = _engine(
            proposal.base_sha
        ).apply_proposal_governed(
            proposal,
            **_execution_args(world),
        )

    print("RESULT_STATUS:", result.status)
    print("CLEANUP_EVENTS:", events)
    print("WAL_UNLINK_OBSERVED:", deleted == [True])
    print("WAL_CLEANUP_DIRECTORY_FLUSHED:",
          bool(cleanup_flushed))
    print("WAL_EXISTS_AFTER_RESULT:", wal.exists())
    print("PHYSICAL_PAYLOAD_CORRECT:",
          target.read_bytes() == payload)

    assert result.status == "COMMITTED", (
        result.status,
        result.kx108_reason,
        result.error_detail,
    )

    assert target.read_bytes() == payload
    assert deleted == [True]
    assert not wal.exists()

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("LIFECYCLE_HISTORY:", history)

    assert history == [
        "PREPARED",
        "FINALIZING",
        "COMMITTED",
    ]

    assert events.count("COMMITTED_RECORDED") == 1
    assert events.count("WAL_UNLINK_COMPLETED") == 1

    assert events.index(
        "COMMITTED_RECORDED"
    ) < events.index(
        "WAL_UNLINK_COMPLETED"
    )

    assert cleanup_flushed == [True], (
        "WAL_UNLINK_DIRECTORY_METADATA_NOT_FLUSHED"
    )

    assert events.index(
        "WAL_UNLINK_COMPLETED"
    ) < events.index(
        "WAL_CLEANUP_DIR_FLUSH"
    )

    print("WAL_CLEANUP_ORDER_VERIFIED=True")

def test_k1_wal_cleanup_flush_failure_never_returns_success(
    case, tmp_path, monkeypatch
):
    """
    A failed WAL directory flush after unlink must not
    return COMMITTED or restore the physical preimage.

    Lifecycle COMMITTED may already have been recorded.
    WAL absence does not prove durable deletion.
    """
    import json
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    worktree = Path(proposal.target_worktree).resolve()
    worktree.relative_to(root)
    target.resolve().relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    ledger = tmp_path / "wal_cleanup_failure_lifecycle.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        worktree / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()

    real_unlink = Path.unlink
    real_flush = mod._k1_wal_flush_metadata_parents
    real_record = mod._k1_wal_record_state

    events = []
    deleted = []
    injected = []
    wal_data = []

    def traced_record(data, state):
        result = real_record(data, state)

        if state == "COMMITTED":
            assert target.read_bytes() == payload
            events.append("COMMITTED_RECORDED")

        return result

    def traced_unlink(path, *args, **kwargs):
        resolved = Path(path).resolve()

        if resolved != wal:
            return real_unlink(path, *args, **kwargs)

        resolved.relative_to(root)
        assert resolved.is_file()
        assert "COMMITTED_RECORDED" in events
        assert target.read_bytes() == payload

        wal_data.append(
            json.loads(
                resolved.read_text(encoding="utf-8")
            )
        )

        events.append("WAL_UNLINK_ATTEMPT")
        result = real_unlink(path, *args, **kwargs)

        assert not wal.exists()
        deleted.append(True)
        events.append("WAL_UNLINK_COMPLETED")
        return result

    def failed_cleanup_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if resolved == wal and deleted:
            assert not wal.exists()
            assert events[-1] == "WAL_UNLINK_COMPLETED"

            injected.append(True)
            events.append("WAL_CLEANUP_DIR_FLUSH_FAILED")

            raise OSError(
                "K1_INJECTED_WAL_CLEANUP_DIRECTORY_FLUSH_FAILURE"
            )

        result = real_flush(path)
        events.append("PRE_CLEANUP_METADATA_FLUSH_OK")
        return result

    result = None
    raised = None

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", traced_unlink)
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            failed_cleanup_flush,
        )
        patch.setattr(
            mod, "_k1_wal_record_state",
            traced_record,
        )

        try:
            result = _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )
        except OSError as exc:
            raised = str(exc)

    print("FLUSH_FAILURE_INJECTED:", injected == [True])
    print("EVENTS:", events)
    print("RESULT_STATUS:",
          result.status if result else "EXCEPTION")
    print("RESULT_REASON:",
          result.kx108_reason if result else raised)
    print("WAL_EXISTS:", wal.exists())
    print("PHYSICAL_PAYLOAD_PRESERVED:",
          target.read_bytes() == payload)

    assert deleted == [True]
    assert injected == [True]
    assert len(wal_data) == 1

    assert events.index(
        "COMMITTED_RECORDED"
    ) < events.index(
        "WAL_UNLINK_COMPLETED"
    ) < events.index(
        "WAL_CLEANUP_DIR_FLUSH_FAILED"
    )

    # The public API must never report nominal success.
    if raised is None:
        assert result is not None
        assert result.status == "ERROR", (
            result.status,
            result.kx108_reason,
            result.error_detail,
        )
        assert result.rolled_back is False
    else:
        assert (
            "K1_INJECTED_WAL_CLEANUP_DIRECTORY_FLUSH_FAILURE"
            in raised
        )

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("LIFECYCLE_HISTORY:", history)

    assert history == [
        "PREPARED", "FINALIZING", "COMMITTED"
    ]

    data = wal_data[0]
    finality = Path(
        mod._k1_wal_finality_receipt_path(data)
    )
    terminal = Path(
        mod._k1_wal_terminal_receipt_path(data)
    )

    finality.resolve().relative_to(root)
    terminal.resolve().relative_to(root)

    print("FINALITY_EXISTS:", finality.is_file())
    print("TERMINAL_EXISTS:", terminal.is_file())

    assert finality.is_file()
    assert terminal.is_file()

    # WAL deletion has occurred in the current process,
    # but the failed directory flush leaves durability
    # unconfirmed.
    assert not wal.exists()
    assert target.read_bytes() == payload

    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )

    print("RECOVERY_RESULT:", recovered)
    print("PHYSICAL_UNCHANGED_AFTER_RECOVERY:",
          target.read_bytes() == payload)

    assert recovered == []
    assert target.read_bytes() == payload

    print("NO_NOMINAL_SUCCESS=True")
    print("NO_PHYSICAL_ROLLBACK=True")
    print("CLEANUP_DURABILITY_UNCONFIRMED=True")

def test_k1_committed_crash_recovery_wal_cleanup_barrier(
    case, tmp_path, monkeypatch
):
    """
    Crash after authenticated COMMITTED, before WAL unlink.

    Recovery may retain WAL and HOLD, or clean it after
    verifying terminal evidence. If it deletes WAL,
    directory metadata must be flushed before success.
    """
    import json
    import pytest
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    worktree = Path(proposal.target_worktree).resolve()

    worktree.relative_to(root)
    target.resolve().relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    ledger = tmp_path / "committed_crash_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        worktree / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()

    real_unlink = Path.unlink
    crash_events = []

    def interrupt_before_cleanup(path, *args, **kwargs):
        resolved = Path(path).resolve()

        if resolved == wal:
            assert wal.is_file()
            assert target.read_bytes() == payload
            crash_events.append("WAL_UNLINK_INTERRUPTED")
            raise SystemExit(
                "K1_CRASH_AFTER_COMMITTED_BEFORE_WAL_UNLINK"
            )

        return real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", interrupt_before_cleanup)

        with pytest.raises(
            SystemExit,
            match="K1_CRASH_AFTER_COMMITTED_BEFORE_WAL_UNLINK",
        ):
            _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert crash_events == ["WAL_UNLINK_INTERRUPTED"]
    assert wal.is_file()
    assert target.read_bytes() == payload

    data = json.loads(wal.read_text(encoding="utf-8"))

    finality = Path(
        mod._k1_wal_finality_receipt_path(data)
    )
    terminal = Path(
        mod._k1_wal_terminal_receipt_path(data)
    )

    finality.resolve().relative_to(root)
    terminal.resolve().relative_to(root)

    assert finality.is_file()
    assert terminal.is_file()

    history_before = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert history_before == [
        "PREPARED", "FINALIZING", "COMMITTED"
    ]

    assert mod._k1_wal_current_state(data) == "COMMITTED"

    events = []
    removed = []
    synchronized = []

    real_flush = mod._k1_wal_flush_metadata_parents

    def trace_recovery_unlink(path, *args, **kwargs):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if resolved == wal:
            assert wal.is_file()
            assert target.read_bytes() == payload

            events.append("RECOVERY_WAL_UNLINK_ATTEMPT")
            result = real_unlink(path, *args, **kwargs)

            assert not wal.exists()
            removed.append(True)
            events.append("RECOVERY_WAL_UNLINK_COMPLETED")
            return result

        return real_unlink(path, *args, **kwargs)

    def trace_recovery_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        result = real_flush(path)

        if resolved == wal and removed:
            assert not wal.exists()
            synchronized.append(True)
            events.append("RECOVERY_WAL_DIR_FLUSH")
        else:
            events.append("OTHER_METADATA_FLUSH")

        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", trace_recovery_unlink)
        patch.setattr(
            mod,
            "_k1_wal_flush_metadata_parents",
            trace_recovery_flush,
        )

        recovered = (
            mod.SealedRollbackEvidence.recover_dangling_wal(
                proposal.target_worktree
            )
        )

    history_after = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("CRASH_INJECTED:", bool(crash_events))
    print("LIFECYCLE_BEFORE:", history_before)
    print("LIFECYCLE_AFTER:", history_after)
    print("RECOVERY_RESULT:", recovered)
    print("RECOVERY_EVENTS:", events)
    print("WAL_EXISTS_AFTER_RECOVERY:", wal.exists())
    print("RECOVERY_WAL_DELETED:", bool(removed))
    print("RECOVERY_WAL_DIRECTORY_FLUSHED:",
          bool(synchronized))
    print("PHYSICAL_PAYLOAD_PRESERVED:",
          target.read_bytes() == payload)

    assert history_after == history_before
    assert target.read_bytes() == payload
    assert finality.is_file()
    assert terminal.is_file()

    if removed:
        assert recovered == [proposal.proposal_id], (
            "RECOVERY_DELETED_WAL_WITHOUT_SUCCESS_CLAIM"
        )
        assert not wal.exists()
        assert synchronized == [True], (
            "RECOVERY_WAL_DELETE_NOT_DURABLY_FLUSHED"
        )

        assert events.index(
            "RECOVERY_WAL_UNLINK_COMPLETED"
        ) < events.index(
            "RECOVERY_WAL_DIR_FLUSH"
        )
    else:
        assert recovered == [], (
            "RECOVERY_CLAIMED_SUCCESS_WITH_WAL_RETAINED"
        )
        assert wal.is_file()

    print("NO_ROLLBACK=True")
    print("RECOVERY_CLEANUP_BOUNDARY_VALID=True")

def test_k1_recovered_wal_unlink_requires_directory_flush(
    case, tmp_path, monkeypatch
):
    """
    K1 test 95: authenticated PREPARED -> RECOVERING
    -> RECOVERED must not claim durable WAL cleanup
    without flushing the directory after WAL deletion.
    """
    import json
    import pytest
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    worktree = Path(proposal.target_worktree).resolve()
    worktree.relative_to(root)
    target.resolve().relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    ledger = tmp_path / "recovered_cleanup_lifecycle_v2.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        worktree / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()

    real_write = mod._k1_physical_write_bytes
    interrupted = []

    def crash_after_physical_write(path, content, expected_attestation, worktree):
        result = real_write(path, content, expected_attestation, worktree)

        if (
            Path(path).resolve() == target.resolve()
            and content == payload
        ):
            interrupted.append(True)
            raise SystemExit(
                "K1_INTERRUPTED_AFTER_PHYSICAL_WRITE"
            )

        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", crash_after_physical_write)

        with pytest.raises(
            SystemExit,
            match="K1_INTERRUPTED_AFTER_PHYSICAL_WRITE",
        ):
            _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert interrupted == [True]
    assert target.read_bytes() == payload
    assert wal.is_file()

    data = json.loads(wal.read_text(encoding="utf-8"))
    assert mod._k1_wal_current_state(data) == "PREPARED"

    events = []
    deleted = []
    synchronized = []

    real_unlink = Path.unlink
    real_flush = mod._k1_wal_flush_metadata_parents

    def observed_unlink(path, *args, **kwargs):
        resolved = Path(path).resolve()

        if resolved != wal:
            return real_unlink(path, *args, **kwargs)

        resolved.relative_to(root)
        assert wal.is_file()
        assert target.read_bytes() == original

        events.append("RECOVERY_WAL_UNLINK_ATTEMPT")
        result = real_unlink(path, *args, **kwargs)

        assert not wal.exists()
        deleted.append(True)
        events.append("RECOVERY_WAL_UNLINK_COMPLETED")
        return result

    def observed_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        result = real_flush(path)

        if deleted and resolved == wal:
            assert not wal.exists()
            synchronized.append(True)
            events.append("RECOVERY_WAL_DIR_FLUSH")
        else:
            events.append("OTHER_METADATA_FLUSH")

        return result

    with monkeypatch.context() as patch:
        patch.setattr(
            Path, "unlink", observed_unlink
        )
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            observed_flush,
        )

        recovered = (
            mod.SealedRollbackEvidence.recover_dangling_wal(
                proposal.target_worktree
            )
        )

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("RECOVERY_RESULT:", recovered)
    print("LIFECYCLE_HISTORY:", history)
    print("RECOVERY_EVENTS:", events)
    print("PHYSICAL_PREIMAGE_RESTORED:",
          target.read_bytes() == original)
    print("WAL_UNLINK_OBSERVED:", deleted == [True])
    print("WAL_DIRECTORY_FLUSHED:", synchronized == [True])
    print("WAL_EXISTS:", wal.exists())

    assert recovered == [proposal.proposal_id], (
        "AUTHENTICATED_RECOVERY_DID_NOT_COMPLETE"
    )

    assert history == [
        "PREPARED", "RECOVERING", "RECOVERED"
    ], "RECOVERY_LIFECYCLE_INVALID"

    assert target.read_bytes() == original
    assert deleted == [True]
    assert not wal.exists()

    assert synchronized == [True], (
        "RECOVERY_WAL_DELETE_NOT_DURABLY_FLUSHED"
    )

    assert events.index(
        "RECOVERY_WAL_UNLINK_COMPLETED"
    ) < events.index(
        "RECOVERY_WAL_DIR_FLUSH"
    )

    print("RECOVERY_CLEANUP_ORDER_VERIFIED=True")

def test_k1_recovered_cleanup_flush_failure_returns_hold(
    case, tmp_path, monkeypatch
):
    """
    Test 96: inject WAL directory flush failure after
    authenticated RECOVERED and physical WAL unlink.

    Recovery must not claim success. Restored preimage
    must remain intact. No second rollback is allowed.
    """
    import json
    import pytest
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    worktree = Path(proposal.target_worktree).resolve()

    worktree.relative_to(root)
    target.resolve().relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    assert original != payload

    ledger = tmp_path / "recovered_flush_failure_lifecycle.jsonl"

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        worktree
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()
    assert not ledger.exists()

    # ------------------------------------------------
    # 1. Simulated interruption after physical WRITE
    # ------------------------------------------------

    real_write = mod._k1_physical_write_bytes
    crash_injected = []

    def interrupt_after_write(path, content, expected_attestation, worktree):
        result = real_write(path, content, expected_attestation, worktree)

        if (
            Path(path).resolve() == target.resolve()
            and content == payload
        ):
            crash_injected.append(True)
            raise SystemExit(
                "K1_TEST96_INTERRUPTED_AFTER_WRITE"
            )

        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", interrupt_after_write)

        with pytest.raises(
            SystemExit,
            match="K1_TEST96_INTERRUPTED_AFTER_WRITE",
        ):
            _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert crash_injected == [True]
    assert target.read_bytes() == payload
    assert wal.is_file()

    data = json.loads(
        wal.read_text(encoding="utf-8")
    )

    assert mod._k1_wal_current_state(data) == "PREPARED"

    # ------------------------------------------------
    # 2. Inject failure only AFTER WAL unlink
    # ------------------------------------------------

    real_unlink = Path.unlink
    real_flush = mod._k1_wal_flush_metadata_parents

    events = []
    deleted = []
    failure_injected = []

    def observed_unlink(path, *args, **kwargs):
        resolved = Path(path).resolve()

        if resolved != wal:
            return real_unlink(path, *args, **kwargs)

        resolved.relative_to(root)

        assert wal.is_file()
        assert target.read_bytes() == original

        events.append("RECOVERY_WAL_UNLINK_ATTEMPT")

        result = real_unlink(path, *args, **kwargs)

        assert not wal.exists()

        deleted.append(True)
        events.append("RECOVERY_WAL_UNLINK_COMPLETED")

        return result

    def injected_flush_failure(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if resolved == wal and deleted:
            assert not wal.exists()
            assert events[-1] == "RECOVERY_WAL_UNLINK_COMPLETED"

            failure_injected.append(True)
            events.append(
                "RECOVERY_WAL_DIR_FLUSH_FAILED"
            )

            raise OSError(
                "K1_TEST96_RECOVERED_CLEANUP_FLUSH_FAILED"
            )

        return real_flush(path)

    with monkeypatch.context() as patch:
        patch.setattr(
            Path, "unlink", observed_unlink
        )
        patch.setattr(
            mod,
            "_k1_wal_flush_metadata_parents",
            injected_flush_failure,
        )

        recovered = (
            mod.SealedRollbackEvidence.recover_dangling_wal(
                proposal.target_worktree
            )
        )

    # ------------------------------------------------
    # 3. Verify fail-closed behavior
    # ------------------------------------------------

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("CRASH_INJECTED:", crash_injected == [True])
    print("FLUSH_FAILURE_INJECTED:",
          failure_injected == [True])
    print("RECOVERY_EVENTS:", events)
    print("RECOVERY_RESULT:", recovered)
    print("LIFECYCLE_HISTORY:", history)
    print("PHYSICAL_PREIMAGE_RESTORED:",
          target.read_bytes() == original)
    print("WAL_UNLINK_COMPLETED:", deleted == [True])
    print("WAL_EXISTS:", wal.exists())

    assert deleted == [True]
    assert failure_injected == [True]

    assert events == [
        "RECOVERY_WAL_UNLINK_ATTEMPT",
        "RECOVERY_WAL_UNLINK_COMPLETED",
        "RECOVERY_WAL_DIR_FLUSH_FAILED",
    ]

    assert history == [
        "PREPARED",
        "RECOVERING",
        "RECOVERED",
    ]

    assert mod._k1_wal_current_state(data) == "RECOVERED"

    assert recovered == [], (
        "RECOVERY_CLAIMED_SUCCESS_AFTER_FLUSH_FAILURE"
    )

    assert target.read_bytes() == original
    assert not wal.exists()

    # Failure happened after unlink: absence of WAL
    # is not a durability guarantee.
    print("NO_RECOVERY_SUCCESS_CLAIM=True")
    print("RESTORED_BYTES_PRESERVED=True")
    print("WAL_DELETION_DURABILITY_UNCONFIRMED=True")

def test_k1_recovery_restore_replace_requires_metadata_flush(
    case, tmp_path, monkeypatch
):
    """
    K1 test 97.

    During authenticated recovery, a restored physical
    target created with os.replace must receive its
    directory metadata barrier before RECOVERED is
    published.

    All operations stay inside pytest tmp_path.
    """
    import json
    import pytest
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    worktree = Path(proposal.target_worktree).resolve()
    target = target.resolve()

    worktree.relative_to(root)
    target.relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    assert original != payload

    ledger = tmp_path / "restore_metadata_lifecycle_v1.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod,
        "_k1_wal_lifecycle_path",
        lambda: ledger,
    )

    wal = (
        worktree
        / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()

    # ------------------------------------------------
    # 1. Create authenticated PREPARED WAL and simulate
    #    interruption after the physical WRITE.
    # ------------------------------------------------

    real_write = mod._k1_physical_write_bytes
    crash_events = []

    def interrupted_write(path, content, expected_attestation, worktree):
        result = real_write(path, content, expected_attestation, worktree)

        if (
            Path(path).resolve() == target
            and content == payload
        ):
            crash_events.append(
                "PHYSICAL_WRITE_INTERRUPTED"
            )
            raise SystemExit(
                "K1_TEST97_INTERRUPT_AFTER_PHYSICAL_WRITE"
            )

        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", interrupted_write)

        with pytest.raises(
            SystemExit,
            match="K1_TEST97_INTERRUPT_AFTER_PHYSICAL_WRITE",
        ):
            _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert crash_events == [
        "PHYSICAL_WRITE_INTERRUPTED"
    ]

    assert wal.is_file()
    assert target.read_bytes() == payload

    wal_data = json.loads(
        wal.read_text(encoding="utf-8")
    )

    assert mod._k1_wal_current_state(
        wal_data
    ) == "PREPARED"

    # ------------------------------------------------
    # 2. Instrument native in-place restore, directory
    #    flush and publication of RECOVERED.
    # ------------------------------------------------

    real_restore = mod._k1_physical_write_bytes
    real_flush = mod._k1_wal_flush_metadata_parents
    real_record = mod._k1_wal_record_state

    events = []
    restore_replaced = []
    restore_flushed = []
    recovered_observations = []

    def observed_restore(path, content, attestation, worktree):
        resolved_dst = Path(path).resolve()
        if resolved_dst != target or content != original:
            return real_restore(path, content, attestation, worktree)
        resolved_dst.relative_to(root)
        assert target.read_bytes() == payload

        events.append("RESTORE_NATIVE_WRITE_ENTERED")

        result = real_restore(path, content, attestation, worktree)

        assert target.read_bytes() == original

        restore_replaced.append(True)
        events.append("RESTORE_NATIVE_WRITE_COMPLETED")

        return result

    def observed_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        result = real_flush(path)

        if resolved == target:
            assert restore_replaced == [True]
            assert target.read_bytes() == original

            restore_flushed.append(True)
            events.append("RESTORE_TARGET_DIR_FLUSH")

        elif resolved == wal and not wal.exists():
            events.append("RECOVERY_WAL_CLEANUP_FLUSH")

        else:
            events.append("OTHER_METADATA_FLUSH")

        return result

    def observed_record(data, state):
        if state == "RECOVERED":
            observation = {
                "physical_restored":
                    target.read_bytes() == original,
                "target_directory_flushed":
                    restore_flushed == [True],
            }

            recovered_observations.append(
                observation
            )

            events.append("RECOVERED_ENTERED")

        return real_record(data, state)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", observed_restore)

        patch.setattr(
            mod,
            "_k1_wal_flush_metadata_parents",
            observed_flush,
        )

        patch.setattr(
            mod,
            "_k1_wal_record_state",
            observed_record,
        )

        recovered = (
            mod.SealedRollbackEvidence.recover_dangling_wal(
                proposal.target_worktree
            )
        )

    # ------------------------------------------------
    # 3. Verify metadata order before RECOVERED.
    # ------------------------------------------------

    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("RECOVERY_RESULT:", recovered)
    print("LIFECYCLE_HISTORY:", history)
    print("RESTORE_EVENTS:", events)

    print(
        "RESTORE_REPLACE_OBSERVED:",
        restore_replaced == [True],
    )

    print(
        "RESTORE_DIRECTORY_FLUSHED:",
        restore_flushed == [True],
    )

    print(
        "RECOVERED_OBSERVATIONS:",
        recovered_observations,
    )

    print(
        "PHYSICAL_PREIMAGE_RESTORED:",
        target.read_bytes() == original,
    )

    print(
        "WAL_EXISTS_AFTER_RECOVERY:",
        wal.exists(),
    )

    assert restore_replaced == [True], (
        "RECOVERY_REPLACE_NOT_OBSERVED"
    )

    assert recovered == [proposal.proposal_id], (
        "AUTHENTICATED_RECOVERY_DID_NOT_COMPLETE"
    )

    assert history == [
        "PREPARED",
        "RECOVERING",
        "RECOVERED",
    ]

    assert target.read_bytes() == original
    assert not wal.exists()

    assert recovered_observations == [
        {
            "physical_restored": True,
            "target_directory_flushed": True,
        }
    ], "RECOVERED_PUBLISHED_BEFORE_RESTORE_METADATA_FLUSH"

    assert restore_flushed == [True], (
        "RECOVERY_REPLACE_METADATA_NOT_FLUSHED"
    )

    assert events.index(
        "RESTORE_NATIVE_WRITE_COMPLETED"
    ) < events.index(
        "RESTORE_TARGET_DIR_FLUSH"
    ) < events.index(
        "RECOVERED_ENTERED"
    )

    print(
        "RESTORE_METADATA_BEFORE_RECOVERED=True"
    )

def test_k1_recovery_restore_metadata_flush_failure_holds_wal(
    case, tmp_path, monkeypatch
):
    """
    Test 98.

    Fail the restored target's directory barrier immediately
    after os.replace and before RECOVERED.

    Preserve the authenticated WAL, physical preimage,
    and fail-closed recovery state.
    """
    import json
    import pytest
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    target = target.resolve()
    worktree = Path(proposal.target_worktree).resolve()

    target.relative_to(root)
    worktree.relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")

    assert original != payload

    ledger = tmp_path / "restore_flush_failure_lifecycle.jsonl"
    assert not ledger.exists()

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        worktree / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()

    # 1. Prepare authentic WAL and interrupt physical ACT.
    real_write = mod._k1_physical_write_bytes
    crash = []

    def interrupted_write(path, content, expected_attestation, worktree):
        result = real_write(path, content, expected_attestation, worktree)

        if (
            Path(path).resolve() == target
            and content == payload
        ):
            crash.append(True)
            raise SystemExit(
                "K1_TEST98_INTERRUPT_AFTER_WRITE"
            )

        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", interrupted_write)

        with pytest.raises(
            SystemExit,
            match="K1_TEST98_INTERRUPT_AFTER_WRITE",
        ):
            _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert crash == [True]
    assert wal.is_file()
    assert target.read_bytes() == payload

    data = json.loads(wal.read_text(encoding="utf-8"))
    assert mod._k1_wal_current_state(data) == "PREPARED"

    # 2. Inject failure specifically on target directory flush.
    real_restore = mod._k1_physical_write_bytes
    real_flush = mod._k1_wal_flush_metadata_parents
    real_record = mod._k1_wal_record_state
    real_unlink = Path.unlink

    events = []
    replaced = []
    injected = []
    recovered_attempted = []
    wal_unlinked = []

    def observed_restore(path, content, attestation, worktree):
        dest = Path(path).resolve()
        if dest != target or content != original:
            return real_restore(path, content, attestation, worktree)
        dest.relative_to(root)
        assert target.read_bytes() == payload

        result = real_restore(path, content, attestation, worktree)

        replaced.append(True)
        events.append("RESTORE_NATIVE_WRITE_COMPLETED")
        assert target.read_bytes() == original

        return result

    def failed_target_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if resolved == target:
            assert replaced == [True]
            assert target.read_bytes() == original

            injected.append(True)
            events.append("RESTORE_TARGET_DIR_FLUSH_FAILED")

            raise OSError(
                "K1_TEST98_RESTORE_DIRECTORY_FLUSH_FAILURE"
            )

        return real_flush(path)

    def observed_record(data, state):
        if state == "RECOVERED":
            recovered_attempted.append(True)

        return real_record(data, state)

    def observed_unlink(path, *args, **kwargs):
        resolved = Path(path).resolve()

        if resolved == wal:
            wal_unlinked.append(True)

        return real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", observed_restore)
        patch.setattr(
            mod, "_k1_wal_flush_metadata_parents",
            failed_target_flush,
        )
        patch.setattr(
            mod, "_k1_wal_record_state",
            observed_record,
        )
        patch.setattr(Path, "unlink", observed_unlink)

        recovered = (
            mod.SealedRollbackEvidence.recover_dangling_wal(
                proposal.target_worktree
            )
        )

    # 3. Validate no premature finalization.
    history = [
        json.loads(line)["state"]
        for line in ledger.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    print("CRASH_INJECTED:", crash == [True])
    print("RESTORE_FLUSH_FAILURE_INJECTED:",
          injected == [True])
    print("RECOVERY_EVENTS:", events)
    print("RECOVERY_RESULT:", recovered)
    print("LIFECYCLE_HISTORY:", history)
    print("PHYSICAL_PREIMAGE_RESTORED:",
          target.read_bytes() == original)
    print("WAL_RETAINED:", wal.is_file())
    print("RECOVERED_ATTEMPTED:", bool(recovered_attempted))
    print("WAL_UNLINK_ATTEMPTED:", bool(wal_unlinked))

    assert replaced == [True]
    assert injected == [True]

    assert events == [
        "RESTORE_NATIVE_WRITE_COMPLETED",
        "RESTORE_TARGET_DIR_FLUSH_FAILED",
    ]

    assert recovered == [], (
        "RECOVERY_SUCCESS_CLAIMED_AFTER_RESTORE_FLUSH_FAILURE"
    )

    assert history == [
        "PREPARED",
        "RECOVERING",
    ], "RECOVERED_PREMATURELY_PUBLISHED"

    assert recovered_attempted == []
    assert wal_unlinked == []

    assert wal.is_file()
    assert target.read_bytes() == original
    assert mod._k1_wal_current_state(data) == "RECOVERING"

    print("RECOVERY_FAIL_CLOSED=True")
    print("RECOVERED_NOT_PUBLISHED=True")
    print("WAL_PRESERVED_FOR_RESUME=True")
    print("RESTORE_DURABILITY_UNCONFIRMED=True")

def test_k1_recovering_resume_after_restore_flush_failure(
    case, tmp_path, monkeypatch
):
    """
    K1 test 99.

    First recovery fails after restore replacement,
    leaving authenticated WAL in RECOVERING.

    A second recovery invocation must reach RECOVERED
    without replaying the RECOVERING transition.
    """
    import json
    import pytest
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    target = target.resolve()
    worktree = Path(proposal.target_worktree).resolve()

    target.relative_to(root)
    worktree.relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    ledger = tmp_path / "recovering_resume_lifecycle.jsonl"

    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        worktree / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()

    def history():
        return [
            json.loads(line)["state"]
            for line in ledger.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

    # ------------------------------------------------
    # 1. Create authentic PREPARED WAL.
    # ------------------------------------------------

    real_write = mod._k1_physical_write_bytes
    crash_events = []

    def interrupt_write(path, content, expected_attestation, worktree):
        result = real_write(path, content, expected_attestation, worktree)

        if (
            Path(path).resolve() == target
            and content == payload
        ):
            crash_events.append(True)
            raise SystemExit(
                "K1_TEST99_INTERRUPT_AFTER_WRITE"
            )

        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", interrupt_write)

        with pytest.raises(
            SystemExit,
            match="K1_TEST99_INTERRUPT_AFTER_WRITE",
        ):
            _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert crash_events == [True]
    assert wal.is_file()
    assert target.read_bytes() == payload

    data = json.loads(
        wal.read_text(encoding="utf-8")
    )

    assert mod._k1_wal_current_state(data) == "PREPARED"

    # ------------------------------------------------
    # 2. Fail first recovery at target metadata flush.
    # ------------------------------------------------

    real_flush = mod._k1_wal_flush_metadata_parents
    failure_events = []

    def fail_target_metadata(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if resolved == target:
            assert target.read_bytes() == original

            failure_events.append(
                "TARGET_DIRECTORY_FLUSH_FAILED"
            )
            raise OSError(
                "K1_TEST99_INJECTED_RESTORE_FLUSH_FAILURE"
            )

        return real_flush(path)

    with monkeypatch.context() as patch:
        patch.setattr(
            mod,
            "_k1_wal_flush_metadata_parents",
            fail_target_metadata,
        )

        first_recovery = (
            mod.SealedRollbackEvidence.recover_dangling_wal(
                proposal.target_worktree
            )
        )

    assert first_recovery == []
    assert failure_events == [
        "TARGET_DIRECTORY_FLUSH_FAILED"
    ]

    assert history() == [
        "PREPARED",
        "RECOVERING",
    ]

    assert wal.is_file()
    assert target.read_bytes() == original
    assert mod._k1_wal_current_state(data) == "RECOVERING"

    print("FIRST_RECOVERY_RESULT:", first_recovery)
    print("FIRST_RECOVERY_HISTORY:", history())
    print("WAL_RETAINED_AFTER_FAILURE:", wal.is_file())

    # ------------------------------------------------
    # 3. Retry recovery with the fault removed.
    # ------------------------------------------------

    real_record = mod._k1_wal_record_state
    real_unlink = Path.unlink

    events = []
    target_flushed = []
    cleanup_flushed = []
    unlink_completed = []
    duplicate_recovering = []
    observations = []

    def trace_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        result = real_flush(path)

        if resolved == target:
            assert target.read_bytes() == original

            target_flushed.append(True)
            events.append("RESTORE_TARGET_DIR_FLUSH")

        elif resolved == wal and not wal.exists():
            cleanup_flushed.append(True)
            events.append("WAL_CLEANUP_DIR_FLUSH")

        return result

    def trace_record(data, state):
        if state == "RECOVERING":
            duplicate_recovering.append(True)
            events.append("DUPLICATE_RECOVERING_ATTEMPT")

        if state == "RECOVERED":
            observations.append({
                "target_restored":
                    target.read_bytes() == original,
                "target_directory_flushed":
                    target_flushed == [True],
            })

            events.append("RECOVERED_ENTERED")

        return real_record(data, state)

    def trace_unlink(path, *args, **kwargs):
        resolved = Path(path).resolve()

        if resolved != wal:
            return real_unlink(path, *args, **kwargs)

        resolved.relative_to(root)
        assert wal.is_file()
        assert "RECOVERED_ENTERED" in events

        result = real_unlink(path, *args, **kwargs)

        assert not wal.exists()
        unlink_completed.append(True)
        events.append("RECOVERY_WAL_UNLINKED")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(
            mod,
            "_k1_wal_flush_metadata_parents",
            trace_flush,
        )
        patch.setattr(
            mod,
            "_k1_wal_record_state",
            trace_record,
        )
        patch.setattr(
            Path,
            "unlink",
            trace_unlink,
        )

        second_recovery = (
            mod.SealedRollbackEvidence.recover_dangling_wal(
                proposal.target_worktree
            )
        )

    print("SECOND_RECOVERY_RESULT:", second_recovery)
    print("FINAL_LIFECYCLE_HISTORY:", history())
    print("RESUME_EVENTS:", events)
    print("RECOVERED_OBSERVATIONS:", observations)
    print("DUPLICATE_RECOVERING:", bool(duplicate_recovering))
    print("TARGET_DIRECTORY_FLUSHED:",
          target_flushed == [True])
    print("WAL_DIRECTORY_FLUSHED:",
          cleanup_flushed == [True])
    print("PHYSICAL_PREIMAGE_PRESERVED:",
          target.read_bytes() == original)
    print("WAL_EXISTS:", wal.exists())

    assert second_recovery == [proposal.proposal_id], (
        "RECOVERING_RESUME_DID_NOT_COMPLETE"
    )

    assert history() == [
        "PREPARED",
        "RECOVERING",
        "RECOVERED",
    ], "RECOVERING_LIFECYCLE_DUPLICATED_OR_INVALID"

    assert duplicate_recovering == []

    assert observations == [{
        "target_restored": True,
        "target_directory_flushed": True,
    }], "RECOVERED_BEFORE_RESTORE_METADATA_BARRIER"

    assert target_flushed == [True]
    assert unlink_completed == [True]
    assert cleanup_flushed == [True]

    assert events.index(
        "RESTORE_TARGET_DIR_FLUSH"
    ) < events.index(
        "RECOVERED_ENTERED"
    ) < events.index(
        "RECOVERY_WAL_UNLINKED"
    ) < events.index(
        "WAL_CLEANUP_DIR_FLUSH"
    )

    assert target.read_bytes() == original
    assert not wal.exists()

    print("RECOVERING_RESUME_VALID=True")
    print("NO_DUPLICATE_LIFECYCLE=True")
    print("RECOVERY_DURABILITY_ORDER_VALID=True")

def test_k1_recovering_resume_in_fresh_python_process(
    case, tmp_path, monkeypatch
):
    """
    Test 100.

    Recovery must resume an authenticated RECOVERING WAL
    in a new Python interpreter, without duplicating
    lifecycle transitions or changing authorization.

    Only pytest tmp_path is used for physical mutations.
    """
    import hashlib
    import json
    import os
    import subprocess
    import sys
    import pytest
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case

    root = tmp_path.resolve()
    worktree = Path(proposal.target_worktree).resolve()
    target = target.resolve()

    worktree.relative_to(root)
    target.relative_to(root)

    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    assert original != payload

    original_hash = hashlib.sha256(original).hexdigest()

    ledger = tmp_path / "fresh_process_recovery_lifecycle.jsonl"
    monkeypatch.setattr(
        mod, "_k1_wal_lifecycle_path", lambda: ledger
    )

    wal = (
        worktree / ".obsidia_wal"
        / f"wal_{proposal.proposal_id}.json"
    ).resolve()

    assert not wal.exists()
    assert not ledger.exists()

    def history():
        return [
            json.loads(line)["state"]
            for line in ledger.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

    # 1. Produce an authenticated PREPARED WAL.
    real_write = mod._k1_physical_write_bytes
    crash = []

    def interrupted_write(path, content, expected_attestation, worktree):
        result = real_write(path, content, expected_attestation, worktree)

        if (
            Path(path).resolve() == target
            and content == payload
        ):
            crash.append(True)
            raise SystemExit(
                "K1_TEST100_INTERRUPT_AFTER_PHYSICAL_WRITE"
            )

        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", interrupted_write)

        with pytest.raises(
            SystemExit,
            match="K1_TEST100_INTERRUPT_AFTER_PHYSICAL_WRITE",
        ):
            _engine(
                proposal.base_sha
            ).apply_proposal_governed(
                proposal,
                **_execution_args(world),
            )

    assert crash == [True]
    assert wal.is_file()
    assert target.read_bytes() == payload
    assert history() == ["PREPARED"]

    data = json.loads(wal.read_text(encoding="utf-8"))
    assert mod._k1_wal_current_state(data) == "PREPARED"

    # 2. First recovery fails at the physical directory barrier.
    real_flush = mod._k1_wal_flush_metadata_parents
    failed = []

    def first_recovery_flush(path):
        resolved = Path(path).resolve()
        resolved.relative_to(root)

        if resolved == target:
            assert target.read_bytes() == original
            failed.append(True)
            raise OSError(
                "K1_TEST100_RESTORE_METADATA_FAILURE"
            )

        return real_flush(path)

    with monkeypatch.context() as patch:
        patch.setattr(
            mod,
            "_k1_wal_flush_metadata_parents",
            first_recovery_flush,
        )
        first = mod.SealedRollbackEvidence.recover_dangling_wal(
            proposal.target_worktree
        )

    assert first == []
    assert failed == [True]
    assert wal.is_file()
    assert target.read_bytes() == original
    assert history() == ["PREPARED", "RECOVERING"]
    assert mod._k1_wal_current_state(data) == "RECOVERING"

    print("FIRST_RECOVERY_RESULT:", first)
    print("PRE_RESTART_HISTORY:", history())
    print("WAL_BEFORE_NEW_PROCESS:", wal.is_file())

    # 3. Restart the recovery code in a fresh interpreter.
    #    The child is not given the parent's in-memory
    #    module objects, monkeypatches, or recovery state.
    child_script = r"""
import hashlib
import json
import os
import sys
from pathlib import Path
from sigma.tooling import governed_bounded_apply as mod

root = Path(sys.argv[1]).resolve()
worktree = Path(sys.argv[2]).resolve()
ledger = Path(sys.argv[3]).resolve()
wal = Path(sys.argv[4]).resolve()
target = Path(sys.argv[5]).resolve()
original_hash = sys.argv[6]

for item in (worktree, ledger, wal, target):
    item.relative_to(root)

assert wal.is_file()
assert ledger.is_file()

mod._k1_wal_lifecycle_path = lambda: ledger

try:
    recovered = (
        mod.SealedRollbackEvidence.recover_dangling_wal(
            str(worktree)
        )
    )
    error = None
except Exception as exc:
    recovered = []
    error = type(exc).__name__ + ":" + str(exc)

history = [
    json.loads(line)["state"]
    for line in ledger.read_text(
        encoding="utf-8"
    ).splitlines()
]

report = {
    "pid": os.getpid(),
    "recovered": recovered,
    "error": error,
    "history": history,
    "wal_exists": wal.exists(),
    "physical_preimage_correct": (
        hashlib.sha256(target.read_bytes()).hexdigest()
        == original_hash
    ),
}

print(
    "K1_CHILD_RESULT_JSON="
    + json.dumps(report, sort_keys=True),
    flush=True,
)
"""

    repo = Path(__file__).resolve().parents[2]
    assert (repo / "sigma").is_dir()

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-X", "utf8",
            "-c", child_script,
            str(root),
            str(worktree),
            str(ledger),
            str(wal),
            str(target),
            original_hash,
        ],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )

    print("CHILD_PROCESS_EXIT:", completed.returncode)
    print("CHILD_STDOUT:", completed.stdout[-8000:])
    print("CHILD_STDERR:", completed.stderr[-8000:])

    assert completed.returncode == 0, (
        "FRESH_PROCESS_EXECUTION_FAILED"
    )

    reports = [
        line.split("K1_CHILD_RESULT_JSON=", 1)[1]
        for line in completed.stdout.splitlines()
        if line.startswith("K1_CHILD_RESULT_JSON=")
    ]

    assert len(reports) == 1, (
        "FRESH_PROCESS_REPORT_MISSING_OR_DUPLICATED"
    )

    report = json.loads(reports[0])

    print("FRESH_PROCESS_PID:", report["pid"])
    print("PARENT_PROCESS_PID:", os.getpid())
    print("FRESH_PROCESS_RESULT:", report["recovered"])
    print("FRESH_PROCESS_ERROR:", report["error"])
    print("FINAL_HISTORY:", report["history"])
    print("FINAL_WAL_EXISTS:", report["wal_exists"])
    print(
        "PHYSICAL_PREIMAGE_PRESERVED:",
        report["physical_preimage_correct"],
    )

    assert report["pid"] != os.getpid(), (
        "NOT_A_FRESH_PYTHON_PROCESS"
    )

    assert report["error"] is None
    assert report["recovered"] == [
        proposal.proposal_id
    ], "FRESH_PROCESS_RECOVERY_DID_NOT_COMPLETE"

    assert report["history"] == [
        "PREPARED",
        "RECOVERING",
        "RECOVERED",
    ], "FRESH_PROCESS_LIFECYCLE_INVALID"

    assert report["wal_exists"] is False
    assert report["physical_preimage_correct"] is True

    # Verify the child's disk changes from the parent.
    assert history() == report["history"]
    assert not wal.exists()
    assert target.read_bytes() == original

    print("FRESH_PROCESS_RECOVERY_VALID=True")
    print("NO_DUPLICATE_RECOVERING=True")
    print("PHYSICAL_PREIMAGE_INTACT=True")
    print("WAL_CLEANUP_COMPLETED=True")

def test_k1_recovered_residual_wal_new_invocation_fail_closed(case, tmp_path, monkeypatch):
    """Keep an authentic RECOVERED WAL across interruption; re-enter recovery safely."""
    import json
    import pytest
    from pathlib import Path
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    root = tmp_path.resolve()
    target = target.resolve()
    worktree = Path(proposal.target_worktree).resolve()
    target.relative_to(root)
    worktree.relative_to(root)
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode('utf-8')
    assert original != payload
    ledger = tmp_path / 'onepass_recovered_replay.jsonl'
    monkeypatch.setattr(mod, '_k1_wal_lifecycle_path', lambda: ledger)
    wal = (worktree / '.obsidia_wal' / f'wal_{proposal.proposal_id}.json').resolve()
    assert not wal.exists()

    write_real = mod._k1_physical_write_bytes
    def crash_after_write(path, content, expected_attestation, worktree):
        result = write_real(path, content, expected_attestation, worktree)
        if Path(path).resolve() == target and content == payload:
            raise SystemExit('K1_ONEPASS_CRASH_AFTER_WRITE')
        return result
    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", crash_after_write)
        with pytest.raises(SystemExit, match='K1_ONEPASS_CRASH_AFTER_WRITE'):
            _engine(proposal.base_sha).apply_proposal_governed(proposal, **_execution_args(world))
    assert wal.is_file() and target.read_bytes() == payload

    unlink_real = Path.unlink
    def crash_before_cleanup(path, *args, **kwargs):
        if Path(path).resolve() == wal:
            raise SystemExit('K1_ONEPASS_CRASH_BEFORE_RECOVERED_UNLINK')
        return unlink_real(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'unlink', crash_before_cleanup)
        with pytest.raises(SystemExit, match='K1_ONEPASS_CRASH_BEFORE_RECOVERED_UNLINK'):
            mod.SealedRollbackEvidence.recover_dangling_wal(proposal.target_worktree)

    assert wal.is_file() and target.read_bytes() == original
    states = lambda: [json.loads(x)['state'] for x in ledger.read_text(encoding='utf-8').splitlines()]
    assert states() == ['PREPARED', 'RECOVERING', 'RECOVERED']
    data = json.loads(wal.read_text(encoding='utf-8'))
    assert mod._k1_wal_current_state(data) == 'RECOVERED'

    flush_real = mod._k1_wal_flush_metadata_parents
    deleted = []
    flushed = []
    def trace_unlink(path, *args, **kwargs):
        if Path(path).resolve() == wal:
            result = unlink_real(path, *args, **kwargs)
            deleted.append(True)
            return result
        return unlink_real(path, *args, **kwargs)
    def trace_flush(path):
        result = flush_real(path)
        if Path(path).resolve() == wal and deleted:
            flushed.append(True)
        return result
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'unlink', trace_unlink)
        patch.setattr(mod, '_k1_wal_flush_metadata_parents', trace_flush)
        replay = mod.SealedRollbackEvidence.recover_dangling_wal(proposal.target_worktree)

    print('RESIDUAL_RECOVERED_REPLAY:', replay)
    print('RESIDUAL_WAL_DELETED:', bool(deleted))
    print('RESIDUAL_CLEANUP_FLUSHED:', bool(flushed))
    assert states() == ['PREPARED', 'RECOVERING', 'RECOVERED']
    assert target.read_bytes() == original
    if deleted:
        assert replay == [proposal.proposal_id]
        assert flushed == [True]
        assert not wal.exists()
    else:
        assert replay == []
        assert wal.is_file()
    print('RESIDUAL_RECOVERED_FAIL_CLOSED=True')

def test_k1_toctou_drift_after_ticket_and_after_wal_v1(case, tmp_path, monkeypatch):
    """Authenticated PRE, but external change after verification: no WAL or ACT."""
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    target.resolve().relative_to(tmp_path.resolve())
    original = target.read_bytes()
    altered = b"K1_EXTERNAL_CHANGE_AFTER_TICKET"
    assert altered != original
    real_verify = mod.verify_and_consume_sovereign_ticket
    called = []

    def genuine_verify_then_change(*args, **kwargs):
        verified = real_verify(*args, **kwargs)
        target.write_bytes(altered)
        called.append(True)
        return verified

    with monkeypatch.context() as patch:
        patch.setattr(mod, "verify_and_consume_sovereign_ticket", genuine_verify_then_change)
        result = _engine(proposal.base_sha).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    assert called == [True]
    assert result.status == "REFUSED_PRE_DECISION", (result.status, result.kx108_reason)
    assert result.kx108_reason == "TOCTOU_PRE_WAL_REFUSED"
    assert not result.disk_written and not result.rolled_back
    assert target.read_bytes() == altered
    assert not list(wal_dir.glob("wal_*.json"))
    print("K1_TOCTOU_POST_TICKET_HOLD=True")


def test_k1_toctou_drift_after_wal_holds_without_rollback_v1(case, tmp_path, monkeypatch):
    """Authenticated WAL persists; third-party target change forbids ACT and rollback."""
    import json
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    target.resolve().relative_to(tmp_path.resolve())
    changed = b"K1_EXTERNAL_CHANGE_AFTER_AUTHENTICATED_WAL"
    original = target.read_bytes()
    assert changed != original
    ledger = tmp_path / "k1_toctou_post_wal_lifecycle.jsonl"
    monkeypatch.setattr(mod, "_k1_wal_lifecycle_path", lambda: ledger)

    real_persist = mod.SealedRollbackEvidence.persist_wal
    called = []

    def persist_real_wal_then_change(self, *args, **kwargs):
        result = real_persist(self, *args, **kwargs)
        target.write_bytes(changed)
        called.append(True)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod.SealedRollbackEvidence, "persist_wal", persist_real_wal_then_change)
        result = _engine(proposal.base_sha).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    wal = Path(proposal.target_worktree) / ".obsidia_wal" / (
        f"wal_{proposal.proposal_id}.json"
    )
    states = [json.loads(line)["state"] for line in ledger.read_text(encoding="utf-8").splitlines()]
    assert called == [True]
    assert result.status == "ERROR", (result.status, result.kx108_reason)
    assert result.kx108_reason == "TOCTOU_TARGET_CHANGED_AFTER_WAL"
    assert not result.disk_written and not result.rolled_back
    assert wal.is_file() and states == ["PREPARED"]
    assert target.read_bytes() == changed
    print("K1_TOCTOU_POST_WAL_HOLD=True")
    print("K1_EXTERNAL_CHANGE_NOT_ROLLED_BACK=True")


def test_k1_post_wal_external_drift_survives_deferred_recovery_v1(
    case, tmp_path, monkeypatch
):
    """K1 104: external edit after authentic PREPARED WAL survives recovery."""
    import json
    import hashlib
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = case
    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    external = b"K1_EXTERNAL_MODIFICATION_AFTER_AUTHENTICATED_PREPARED_V3"
    assert len({original, payload, external}) == 3

    ledger = tmp_path / "k1_external_drift_recovery_v3.jsonl"
    monkeypatch.setattr(mod, "_k1_wal_lifecycle_path", lambda: ledger)
    real_persist = mod.SealedRollbackEvidence.persist_wal
    injected = []

    def persist_then_external_edit(self, *args, **kwargs):
        wal = real_persist(self, *args, **kwargs)
        target.write_bytes(external)
        injected.append(True)
        return wal

    with monkeypatch.context() as patch:
        patch.setattr(
            mod.SealedRollbackEvidence, "persist_wal",
            persist_then_external_edit,
        )
        result = _engine(proposal.base_sha).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    wal = (
        Path(proposal.target_worktree) / ".obsidia_wal" /
        f"wal_{proposal.proposal_id}.json"
    )
    assert injected == [True]
    assert result.status == "ERROR", (result.status, result.kx108_reason)
    assert result.kx108_reason == "TOCTOU_TARGET_CHANGED_AFTER_WAL"
    assert not result.disk_written and not result.rolled_back
    assert wal.is_file()
    assert target.read_bytes() == external

    wal_data = json.loads(wal.read_text(encoding="utf-8"))
    assert mod._k1_wal_current_state(wal_data) == "PREPARED"
    assert wal_data["post_state_hashes"][proposal.operations[0].path] == (
        hashlib.sha256(payload).hexdigest()
    )

    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )
    print("K1_TEST104_DEFERRED_RECOVERED:", recovered)
    print("K1_TEST104_EXTERNAL_BYTES_UNCHANGED:", target.read_bytes() == external)
    print("K1_TEST104_WAL_RETAINED:", wal.is_file())
    assert recovered == [], "K1_DEFERRED_RECOVERY_EXTERNAL_CLOBBER"
    assert target.read_bytes() == external
    assert wal.is_file()
    assert mod._k1_wal_current_state(wal_data) == "PREPARED"


def test_k1_windows_pinned_handle_denies_concurrent_replacement_v1(
    case, tmp_path, monkeypatch
):
    """K1 105: a pinned Windows target refuses outside write + rename."""
    import os
    import pytest
    from sigma.tooling import governed_bounded_apply as mod

    if os.name != "nt":
        pytest.skip("K1 native sharing proof requires Windows")

    world, target, proposal, _ = case
    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)
    payload = proposal.operations[0].content.encode("utf-8")
    intruder = tmp_path / "attempted_replacement.bin"
    intruder.write_bytes(b"K1_OUTSIDE_REPLACEMENT")
    original_fsync = mod.os.fsync
    denied = []

    def observed_fsync(fd):
        try:
            info = os.fstat(fd)
            current = target.stat()
            matches = (
                info.st_ino != 0
                and info.st_dev == current.st_dev
                and info.st_ino == current.st_ino
                and target.read_bytes() == payload
            )
        except (OSError, ValueError):
            matches = False
        if matches and not denied:
            with pytest.raises(OSError):
                target.write_bytes(b"K1_INTRUDER_OVERWRITE")
            denied.append("WRITE_DENIED")
            with pytest.raises(OSError):
                os.replace(intruder, target)
            denied.append("RENAME_DENIED")
        return original_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(mod.os, "fsync", observed_fsync)
        result = _engine(proposal.base_sha).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    print("K1_TEST105_WRITE_REPLACE_DENIED:", denied)
    assert result.status == "COMMITTED", (result.status, result.kx108_reason)
    assert denied == ["WRITE_DENIED", "RENAME_DENIED"]
    assert target.read_bytes() == payload


def test_k1_last_moment_swap_before_pinned_handle_holds_v1(
    case, tmp_path, monkeypatch
):
    """K1 106: last-moment replacement MUST NOT reach physical ACT."""
    import os
    import json
    import pytest
    from sigma.tooling import governed_bounded_apply as mod

    if os.name != "nt":
        pytest.skip("K1 native stable-handle proof requires Windows")

    world, target, proposal, _ = case
    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)
    original = target.read_bytes()
    authorized = proposal.operations[0].content.encode("utf-8")
    external = b"K1_EXTERNAL_SWAP_IN_AT_NATIVE_OPEN"
    assert len({original, authorized, external}) == 3
    ledger = tmp_path / "late_swap_lifecycle.jsonl"
    monkeypatch.setattr(mod, "_k1_wal_lifecycle_path", lambda: ledger)

    real_writer = mod._k1_physical_write_bytes
    injected = []

    def drift_before_native_open(path, data, expected, worktree):
        assert Path(path).resolve() == target.resolve()
        target.write_bytes(external)
        injected.append(True)
        return real_writer(path, data, expected, worktree)

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", drift_before_native_open)
        result = _engine(proposal.base_sha).apply_proposal_governed(
            proposal, **_execution_args(world)
        )

    wal = Path(proposal.target_worktree) / ".obsidia_wal" / (
        f"wal_{proposal.proposal_id}.json"
    )
    assert injected == [True]
    assert result.status == "ERROR", (result.status, result.kx108_reason)
    assert result.kx108_reason == "K1_STABLE_HANDLE_REFUSED"
    assert not result.disk_written and not result.rolled_back
    assert target.read_bytes() == external and wal.is_file()
    recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    )
    print("K1_TEST106_EXTERNAL_BYTES_PRESERVED:", target.read_bytes() == external)
    print("K1_TEST106_RECOVERY_RESULT:", recovered)
    assert recovered == [] and target.read_bytes() == external
    assert wal.is_file()


def test_k1_v5_posttest_foreign_bytes_never_committed(
    case, tmp_path, monkeypatch
):
    """K1 107: a post-test foreign edit cannot be finalized as K1 output."""
    import json
    import os
    import pytest
    from sigma.tooling import governed_bounded_apply as mod

    if os.name != "nt":
        pytest.skip("K1 Win32 postimage guard proof requires Windows")

    world, target, proposal, _ = case
    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)
    payload = proposal.operations[0].content.encode("utf-8")
    foreign = b"K1_V5_POSTTEST_FOREIGN_CONTENT"
    assert payload != foreign

    ledger = tmp_path / "k1_v5_posttest_lifecycle.jsonl"
    monkeypatch.setattr(mod, "_k1_wal_lifecycle_path", lambda: ledger)
    callbacks = []

    def posttest_with_outside_edit(worktree):
        assert Path(worktree).resolve() == Path(proposal.target_worktree).resolve()
        assert target.read_bytes() == payload
        target.write_bytes(foreign)
        callbacks.append(True)
        return True

    kwargs = dict(_execution_args(world))
    kwargs["post_test_runner"] = posttest_with_outside_edit
    result = _engine(proposal.base_sha).apply_proposal_governed(
        proposal, **kwargs
    )

    wal = Path(proposal.target_worktree) / ".obsidia_wal" / (
        f"wal_{proposal.proposal_id}.json"
    )
    states = [
        json.loads(line)["state"]
        for line in ledger.read_text(encoding="utf-8").splitlines()
    ]

    print("K1_TEST107_RESULT:", result.status)
    print("K1_TEST107_FOREIGN_PRESERVED:", target.read_bytes() == foreign)
    print("K1_TEST107_LIFECYCLE:", states)
    assert callbacks == [True]
    assert result.status == "ERROR"
    assert result.kx108_reason == "K1_STABLE_HANDLE_REFUSED"
    assert target.read_bytes() == foreign
    assert wal.is_file()
    assert states == ["PREPARED"]


def test_k1_v5_recovery_late_foreign_edit_not_clobbered(
    case, tmp_path, monkeypatch
):
    """K1 108: a write after recovery's hash check never gets overwritten."""
    import json
    import os
    import pytest
    from sigma.tooling import governed_bounded_apply as mod

    if os.name != "nt":
        pytest.skip("K1 Win32 recovery compare/write proof requires Windows")

    world, target, proposal, _ = case
    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    foreign = b"K1_V5_RECOVERY_LATE_FOREIGN_CONTENT"
    assert len({original, payload, foreign}) == 3

    ledger = tmp_path / "k1_v5_recovery_lifecycle.jsonl"
    monkeypatch.setattr(mod, "_k1_wal_lifecycle_path", lambda: ledger)
    real_writer = mod._k1_physical_write_bytes

    def crash_after_act(path, content, attestation, worktree):
        result = real_writer(path, content, attestation, worktree)
        if Path(path).resolve() == target.resolve() and content == payload:
            raise SystemExit("K1_V5_CRASH_AFTER_ACT")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(mod, "_k1_physical_write_bytes", crash_after_act)
        with pytest.raises(SystemExit, match="K1_V5_CRASH_AFTER_ACT"):
            _engine(proposal.base_sha).apply_proposal_governed(
                proposal, **_execution_args(world)
            )

    wal = Path(proposal.target_worktree) / ".obsidia_wal" / (
        f"wal_{proposal.proposal_id}.json"
    )
    assert wal.is_file() and target.read_bytes() == payload

    injected = []

    def outside_write_before_pinned_restore(path, content, attestation, worktree):
        if Path(path).resolve() == target.resolve() and content == original:
            target.write_bytes(foreign)
            injected.append(True)
        return real_writer(path, content, attestation, worktree)

    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_physical_write_bytes",
            outside_write_before_pinned_restore,
        )
        recovered = mod.SealedRollbackEvidence.recover_dangling_wal(
            proposal.target_worktree
        )

    states = [
        json.loads(line)["state"]
        for line in ledger.read_text(encoding="utf-8").splitlines()
    ]
    print("K1_TEST108_INJECTED:", injected)
    print("K1_TEST108_RECOVERED:", recovered)
    print("K1_TEST108_FOREIGN_PRESERVED:", target.read_bytes() == foreign)
    assert injected == [True]
    assert recovered == []
    assert target.read_bytes() == foreign
    assert wal.is_file()
    assert states == ["PREPARED", "RECOVERING"]


def test_k1_v5_immediate_rollback_late_edit_never_clobbered(
    case, tmp_path, monkeypatch
):
    """K1 109: post-test rollback cannot overwrite a new outside edit."""
    import json
    import os
    import pytest
    from sigma.tooling import governed_bounded_apply as mod

    if os.name != "nt":
        pytest.skip("K1 Win32 rollback compare/write proof requires Windows")

    world, target, proposal, _ = case
    root = tmp_path.resolve()
    target.resolve().relative_to(root)
    Path(proposal.target_worktree).resolve().relative_to(root)
    before = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    foreign = b"K1_V5_ROLLBACK_LATE_FOREIGN_CONTENT"
    assert len({before, payload, foreign}) == 3

    ledger = tmp_path / "k1_v5_immediate_rollback.jsonl"
    monkeypatch.setattr(mod, "_k1_wal_lifecycle_path", lambda: ledger)
    actual_write = mod._k1_physical_write_bytes
    injected = []

    def outside_edit_before_rollback(path, content, attestation, worktree):
        if Path(path).resolve() == target.resolve() and content == before:
            target.write_bytes(foreign)
            injected.append(True)
        return actual_write(path, content, attestation, worktree)

    kwargs = dict(_execution_args(world))
    kwargs["post_test_runner"] = lambda _: False
    with monkeypatch.context() as patch:
        patch.setattr(
            mod, "_k1_physical_write_bytes",
            outside_edit_before_rollback,
        )
        with pytest.raises(mod.StableHandleRefused):
            _engine(proposal.base_sha).apply_proposal_governed(
                proposal, **kwargs
            )

    wal = Path(proposal.target_worktree) / ".obsidia_wal" / (
        f"wal_{proposal.proposal_id}.json"
    )
    states = [
        json.loads(line)["state"]
        for line in ledger.read_text(encoding="utf-8").splitlines()
    ]
    print("K1_TEST109_INJECTED:", injected)
    print("K1_TEST109_OUTSIDE_BYTES_PRESERVED:", target.read_bytes() == foreign)
    assert injected == [True]
    assert target.read_bytes() == foreign
    assert wal.is_file()
    assert states == ["PREPARED"]
