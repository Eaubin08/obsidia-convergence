"""
sigma/tests/test_kx108_pre_decision_write_safety.py
====================================================
SUITE OFFICIELLE DE VALIDATION DE L'INVARIANT DE SÉCURITÉ :
"AUCUNE ÉCRITURE AVANT DÉCISION KX108 VALIDE" (PHASE 3B)

Vérifie l'ensemble des cas d'inversion, d'anti-rejeu, de TOCTOU et de rollback automatique :
 1. BLOCK : Zéro écriture sur disque.
 2. HOLD : Zéro écriture sur disque.
 3. NO_DECISION : Zéro écriture sur disque.
 4. Ticket absent : Zéro écriture sur disque.
 5. Ticket falsifié : Zéro écriture sur disque.
 6. Ticket expiré : Zéro écriture sur disque.
 7. Scope drift (fichiers non approuvés) : Zéro écriture sur disque.
 8. Fichier protégé ciblé : Zéro écriture sur disque.
 9. TOCTOU Head Drift (HEAD modifié avant écriture) : Abandon immédiat.
10. Patch hash mismatch (Contenu altéré) : Abandon immédiat.
11. Tentative de rejeu de ticket : Rejet par anti-rejeu.
12. Crash avant autorisation : Disque intact.
13. Crash après autorisation avant mutation : Disque intact.
14. Crash pendant mutation : Rollback automatique via SealedRollbackEvidence.
15. Échec des post-tests : Rollback automatique via SealedRollbackEvidence.
16. Nominal ALLOW : Application réussie dans le périmètre autorisé.
17. Concurrence : Deux applications simultanées, une seule réussit.

Tous les tests opèrent sur des répertoires temporaires strictement isolés.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import shutil
import tempfile
import runpy
import secrets
import threading
from pathlib import Path

import pytest

from periphery.world_calls.sovereign_ticket import (
    issue_sovereign_ticket,
    issue_sovereign_ticket_from_decision_record,
    load_decision_store,
)
from sigma.tooling.governed_bounded_apply import (
    GovernedBoundedApply,
    PatchProposal,
    PatchOperation,
    SealedRollbackEvidence,
)


@pytest.fixture
def isolated_worktree():
    """Crée un worktree isolé pour le test."""
    temp_dir = tempfile.mkdtemp(prefix="obsidia_worktree_test_")
    # Création d'un fichier pré-existant
    orig_file = Path(temp_dir) / "src" / "existing.txt"
    orig_file.parent.mkdir(parents=True, exist_ok=True)
    orig_file.write_text("ORIGINAL_CONTENT", encoding="utf-8")
    
    yield temp_dir

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)


# ===========================================================================
# KX108-K1 : l'autorisation d'écrire ne provient que d'une décision KX108 réelle
# (pipeline tooling_build → GuardX108), persistée, authentifiée et vérifiée. Les
# scénarios qui exigent une autorisation l'obtiennent ainsi ; leurs assertions sont
# inchangées.
# ===========================================================================

@pytest.fixture(autouse=True)
def private_k1_runtime(tmp_path, monkeypatch):
    """Private storage and test key; real security checks remain active."""
    from periphery.world_calls import ticket_store as ts
    from periphery.world_calls import sovereign_ticket as st

    monkeypatch.setattr(ts, "_DEFAULT_STORE", str(tmp_path / "tickets.jsonl"))
    monkeypatch.setattr(ts, "_DEFAULT_CONSUMED_STORE", str(tmp_path / "nonces.jsonl"))
    monkeypatch.setenv("OBSIDIA_KEY_KX108_K1", secrets.token_hex(32))
    monkeypatch.setattr(st, "_KEY_REGISTRY", {})


@pytest.fixture
def canonical_case(tmp_path, private_k1_runtime):
    """Reuse the complete PRE world, never transplant only its decision ID."""
    fixture = Path(__file__).resolve().parents[2] / (
        "tests/cli/test_k1_pre_action_binding_positive_v1.py"
    )
    case = runpy.run_path(str(fixture))["_fixture"](tmp_path)
    world, target, proposal, _ = case
    target.resolve().relative_to(tmp_path.resolve())
    assert len(proposal.operations) == 1
    assert proposal.approved_scope == [proposal.operations[0].path]
    store = load_decision_store()
    record = store.load_kx108_decision_record(world["pre_id"], world["dc"])
    assert store.verify_kx108_decision_record_authenticity(record) == (True, None)
    assert record["decision_phase"] == "PRE_EXECUTION"
    assert record["x108_gate"] == "ALLOW"
    return case


def _execution_args(world):
    return dict(
        decision_record_id=world["pre_id"], decision_store_dir=world["dc"],
        execution_dir=world["ex"], pre_execution_context_dir=world["cx"],
        repo_root=world["repo"],
    )


def _k1_allow_ticket(case, **overrides):
    world, _, _, ticket_args = case
    return issue_sovereign_ticket_from_decision_record(
        world["pre_id"], **dict(ticket_args, **overrides)
    )


def _engine(proposal):
    return GovernedBoundedApply(worktree_head_provider=lambda _: proposal.base_sha)


def _wal_entries(proposal):
    directory = Path(proposal.target_worktree) / ".obsidia_wal"
    return sorted(directory.iterdir()) if directory.exists() else []


# ===========================================================================
# 1. TEST 1 : DÉCISION BLOCK -> ZÉRO ÉCRITURE
# ===========================================================================

def test_scenario_1_block_decision_prevents_write(isolated_worktree):
    """Vérifie qu'un ticket ou arbitrage BLOCK n'écrit aucun octet."""
    proposal = PatchProposal(
        proposal_id="prop-block-001",
        base_sha="sha_valid_123",
        target_worktree=isolated_worktree,
        approved_scope=["src/existing.txt"],
        operations=[PatchOperation("src/existing.txt", "MALICIOUS_CONTENT")],
    )
    
    # Injection d'un ticket BLOCK
    block_ticket = issue_sovereign_ticket(
        action_id=proposal.proposal_id,
        os3_ticket_id="os3-block",
        x108_gate="BLOCK",
        scope="bounded_apply",
        autonomy_level=1,
        world_call_class="GOVERNED_WRITE",
        input_hash=proposal.patch_hash,
    )
    
    engine = GovernedBoundedApply(worktree_head_provider=lambda _: "sha_valid_123")
    res = engine.apply_proposal_governed(proposal, injected_ticket=block_ticket)
    
    assert res.status == "REFUSED_PRE_DECISION"
    assert res.disk_written is False
    assert Path(isolated_worktree, "src", "existing.txt").read_text(encoding="utf-8") == "ORIGINAL_CONTENT"


# ===========================================================================
# 2. TEST 2 : DÉCISION HOLD -> ZÉRO ÉCRITURE
# ===========================================================================

def test_scenario_2_hold_decision_prevents_write(isolated_worktree):
    """Vérifie qu'une décision HOLD n'écrit aucun octet."""
    proposal = PatchProposal(
        proposal_id="prop-hold-001",
        base_sha="sha_valid_123",
        target_worktree=isolated_worktree,
        approved_scope=["src/existing.txt"],
        operations=[PatchOperation("src/existing.txt", "HOLD_MUTATION")],
    )
    
    hold_ticket = issue_sovereign_ticket(
        action_id=proposal.proposal_id,
        os3_ticket_id="os3-hold",
        x108_gate="HOLD",
        scope="bounded_apply",
        autonomy_level=1,
        world_call_class="GOVERNED_WRITE",
        input_hash=proposal.patch_hash,
    )
    
    engine = GovernedBoundedApply(worktree_head_provider=lambda _: "sha_valid_123")
    res = engine.apply_proposal_governed(proposal, injected_ticket=hold_ticket)
    
    assert res.status == "REFUSED_PRE_DECISION"
    assert res.disk_written is False
    assert Path(isolated_worktree, "src", "existing.txt").read_text(encoding="utf-8") == "ORIGINAL_CONTENT"


# ===========================================================================
# 3. TEST 3 : NO DECISION / ÉCHEC PRE-CHECK -> ZÉRO ÉCRITURE
# ===========================================================================

def test_scenario_3_no_decision_prevents_write(isolated_worktree):
    """Vérifie que si la pré-validation échoue, aucune écriture n'intervient."""
    proposal = PatchProposal(
        proposal_id="prop-no-dec-001",
        base_sha="sha_expected_123",
        target_worktree=isolated_worktree,
        approved_scope=["src/existing.txt"],
        operations=[PatchOperation("src/existing.txt", "UNAUTHORIZED_CONTENT")],
    )
    # HEAD actuel différent du base_sha
    engine = GovernedBoundedApply(worktree_head_provider=lambda _: "sha_actual_DIFFERENT")
    res = engine.apply_proposal_governed(proposal)
    
    assert res.status == "REFUSED_PRE_DECISION"
    assert "WORKTREE_HEAD_DRIFT" in res.kx108_reason
    assert res.disk_written is False
    assert Path(isolated_worktree, "src", "existing.txt").read_text(encoding="utf-8") == "ORIGINAL_CONTENT"


# ===========================================================================
# 4. TEST 4 : TICKET ABSENT / REFUS SOUVERAIN -> ZÉRO ÉCRITURE
# ===========================================================================

def test_scenario_4_missing_ticket_prevents_write(isolated_worktree):
    """Vérifie qu'un ticket None ou manquant empêche l'écriture."""
    proposal = PatchProposal(
        proposal_id="prop-no-ticket-001",
        base_sha="sha_valid_123",
        target_worktree=isolated_worktree,
        approved_scope=["src/existing.txt"],
        operations=[PatchOperation("src/existing.txt", "NO_TICKET_CONTENT")],
    )
    
    engine = GovernedBoundedApply(worktree_head_provider=lambda _: "sha_valid_123")
    res = engine.apply_proposal_governed(proposal)
    assert res.status == "REFUSED_PRE_DECISION"
    assert res.kx108_reason == "NO_VERIFIED_DECISION_RECORD"
    assert not res.disk_written
    assert Path(isolated_worktree, "src", "existing.txt").read_text(
        encoding="utf-8"
    ) == "ORIGINAL_CONTENT"
    with pytest.raises(AssertionError, match="SOVEREIGN_TICKET_MISSING"):
        from periphery.world_calls.ticket_store import verify_and_consume_sovereign_ticket
        verify_and_consume_sovereign_ticket(None)


# ===========================================================================
# 5. TEST 5 : TICKET FALSIFIÉ -> ZÉRO ÉCRITURE
# ===========================================================================

def test_scenario_5_falsified_ticket_prevents_write(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    ticket = _k1_allow_ticket(canonical_case)
    ticket.authenticator = '0' * 64
    res = _engine(proposal).apply_proposal_governed(
        proposal, injected_ticket=ticket, **_execution_args(world)
    )
    assert res.status == "REFUSED_PRE_DECISION"
    assert "SOVEREIGN_TICKET_AUTHENTICATOR_INVALID" in res.error_detail
    assert not res.disk_written
    assert target.read_bytes() == before
    assert _wal_entries(proposal) == []


# ===========================================================================
# 6. TEST 6 : TICKET EXPIRÉ -> ZÉRO ÉCRITURE
# ===========================================================================

def test_scenario_6_expired_ticket_prevents_write(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    ticket = _k1_allow_ticket(canonical_case, ttl_seconds=-10)
    res = _engine(proposal).apply_proposal_governed(
        proposal, injected_ticket=ticket, **_execution_args(world)
    )
    assert res.status == "REFUSED_PRE_DECISION"
    assert "SOVEREIGN_TICKET_EXPIRED" in res.error_detail
    assert not res.disk_written
    assert target.read_bytes() == before
    assert _wal_entries(proposal) == []


# ===========================================================================
# 7. TEST 7 : SCOPE DRIFT (FICHIERS NON APPROUVÉS) -> ZÉRO ÉCRITURE
# ===========================================================================

def test_scenario_7_scope_drift_prevents_write(isolated_worktree):
    """Vérifie qu'une tentative d'écriture hors approved_scope est bloquée."""
    proposal = PatchProposal(
        proposal_id="prop-drift-001",
        base_sha="sha_valid_123",
        target_worktree=isolated_worktree,
        approved_scope=["src/allowed.txt"],
        operations=[
            PatchOperation("src/allowed.txt", "OK"),
            PatchOperation("src/secret_bypass.txt", "EVIL"),  # Non approuvé !
        ],
    )
    engine = GovernedBoundedApply(worktree_head_provider=lambda _: "sha_valid_123")
    res = engine.apply_proposal_governed(proposal)
    
    assert res.status == "REFUSED_PRE_DECISION"
    assert "SCOPE_DRIFT" in res.kx108_reason
    assert res.disk_written is False
    assert not Path(isolated_worktree, "src", "secret_bypass.txt").exists()


# ===========================================================================
# 8. TEST 8 : FICHIER PROTÉGÉ CIBLÉ -> ZÉRO ÉCRITURE
# ===========================================================================

def test_scenario_8_protected_file_prevents_write(isolated_worktree):
    """Vérifie qu'une tentative de toucher à server.kernel.sealed.cjs est bloquée net."""
    proposal = PatchProposal(
        proposal_id="prop-prot-001",
        base_sha="sha_valid_123",
        target_worktree=isolated_worktree,
        approved_scope=["server.kernel.sealed.cjs"],
        operations=[PatchOperation("server.kernel.sealed.cjs", "HACK_SEALED")],
    )
    engine = GovernedBoundedApply(worktree_head_provider=lambda _: "sha_valid_123")
    res = engine.apply_proposal_governed(proposal)
    
    assert res.status == "REFUSED_PRE_DECISION"
    assert "PROTECTED_SCOPE_VIOLATION" in res.kx108_reason
    assert res.disk_written is False


# ===========================================================================
# 9. TEST 9 : TOCTOU HEAD DRIFT -> ABANDON IMMÉDIAT
# ===========================================================================

def test_scenario_9_toctou_head_drift_prevents_write(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    calls = []

    def shifting_head(_):
        calls.append(True)
        return proposal.base_sha if len(calls) == 1 else "DRIFTED_HEAD"

    res = GovernedBoundedApply(worktree_head_provider=shifting_head).apply_proposal_governed(
        proposal, **_execution_args(world)
    )
    assert calls == [True, True]
    assert res.status == "REFUSED_PRE_DECISION"
    assert res.kx108_pre_gate == "ALLOW"
    assert "TOCTOU_HEAD_DRIFT_DETECTED" in res.kx108_reason
    assert not res.disk_written
    assert target.read_bytes() == before


# ===========================================================================
# 10. TEST 10 : PATCH HASH MISMATCH -> ABANDON IMMÉDIAT
# ===========================================================================

def test_scenario_10_patch_hash_mismatch_prevents_write(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    ticket = _k1_allow_ticket(canonical_case)
    # Issue for verified patch A, then submit different patch B.
    proposal.operations[0].content = 'UNAPPROVED_PATCH_B'
    assert ticket.input_hash != proposal.patch_hash
    res = _engine(proposal).apply_proposal_governed(
        proposal, injected_ticket=ticket, **_execution_args(world)
    )
    assert res.status == "REFUSED_PRE_DECISION"
    assert "SOVEREIGN_TICKET_INPUT_MISMATCH" in res.error_detail
    assert not res.disk_written
    assert target.read_bytes() == before
    assert _wal_entries(proposal) == []


# ===========================================================================
# 11. TEST 11 : REPLAY D'UN TICKET DÉJÀ CONSOMMÉ -> REJET
# ===========================================================================

def test_scenario_11_replayed_ticket_prevents_write(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    from periphery.world_calls import ticket_store as ts

    ticket = _k1_allow_ticket(canonical_case)
    engine = _engine(proposal)
    first = engine.apply_proposal_governed(
        proposal, injected_ticket=ticket, **_execution_args(world)
    )
    assert first.status == "COMMITTED"
    assert target.read_bytes() == proposal.operations[0].content.encode("utf-8")
    ledger = Path(ts._DEFAULT_CONSUMED_STORE)
    consumed = ledger.read_bytes()
    assert ts.load_consumed_nonces()[ticket.nonce]["state"] == "COMMITTED"

    # External reversion of the temporary target restores the PRE precondition.
    # Preserve the consumed ledger to reach the actual replay boundary.
    target.write_bytes(before)
    second = engine.apply_proposal_governed(
        proposal, injected_ticket=ticket, **_execution_args(world)
    )
    assert second.status == "REFUSED_PRE_DECISION"
    assert "SOVEREIGN_TICKET_REPLAY_DETECTED" in second.error_detail
    assert not second.disk_written
    assert target.read_bytes() == before
    assert ledger.read_bytes() == consumed


# ===========================================================================
# 12. TEST 12 : CRASH AVANT AUTORISATION -> DISQUE INTACT
# ===========================================================================

def test_scenario_12_crash_before_auth_clean(isolated_worktree):
    """Une exception levée avant l'autorisation ne laisse aucune trace."""
    proposal = PatchProposal(
        proposal_id="prop-crash-001",
        base_sha="sha_valid_123",
        target_worktree=isolated_worktree,
        approved_scope=["src/existing.txt"],
        operations=[PatchOperation("src/existing.txt", "SHOULD_NOT_BE_WRITTEN")],
    )
    class CrashingEngine(GovernedBoundedApply):
        def pre_check(self, p):
            raise RuntimeError("CRASH_IN_PRECHECK")

    engine = CrashingEngine(worktree_head_provider=lambda _: "sha_valid_123")
    with pytest.raises(RuntimeError, match="CRASH_IN_PRECHECK"):
        engine.apply_proposal_governed(proposal)

    assert Path(isolated_worktree, "src", "existing.txt").read_text(encoding="utf-8") == "ORIGINAL_CONTENT"


# ===========================================================================
# 13. TEST 13 : CRASH JUSTE APRÈS AUTORISATION AVANT MUTATION -> DISQUE INTACT
# ===========================================================================

def test_scenario_13_crash_after_auth_before_mutation_clean(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    with pytest.raises(RuntimeError, match="CRASH_AFTER_AUTHORIZATION_BEFORE_MUTATION"):
        _engine(proposal).apply_proposal_governed(
            proposal, simulate_crash_after_auth=True, **_execution_args(world)
        )
    assert target.read_bytes() == before
    assert _wal_entries(proposal) == []


# ===========================================================================
# 14. TEST 14 : CRASH PENDANT MUTATION -> ROLLBACK AUTOMATIQUE RESTAURÉ
# ===========================================================================

def test_scenario_14_crash_during_mutation_automatic_rollback(canonical_case, monkeypatch):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    # Single-write equivalent: real physical mutation, then an I/O interruption.
    payload = proposal.operations[0].content.encode("utf-8")
    real_write = Path.write_bytes
    writes = []

    def interrupted_write(path, data):
        result = real_write(path, data)
        if path.resolve() == target.resolve() and data == payload:
            assert target.read_bytes() == payload != before
            writes.append(True)
            raise OSError("CRASH_DURING_MUTATION")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "write_bytes", interrupted_write)
        res = _engine(proposal).apply_proposal_governed(proposal, **_execution_args(world))

    assert writes == [True]
    assert res.status == "ROLLED_BACK"
    assert res.rolled_back and not res.disk_written
    assert res.error_detail == "CRASH_DURING_MUTATION"
    assert target.read_bytes() == before
    assert _wal_entries(proposal) == []


# ===========================================================================
# 15. TEST 15 : ÉCHEC DES POST-TESTS -> ROLLBACK AUTOMATIQUE
# ===========================================================================

def test_scenario_15_post_test_failure_automatic_rollback(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    observed = []

    def failing_runner(worktree):
        assert worktree == proposal.target_worktree
        assert target.read_bytes() == proposal.operations[0].content.encode("utf-8")
        assert target.read_bytes() != before
        observed.append(True)
        return False

    res = _engine(proposal).apply_proposal_governed(
        proposal, post_test_runner=failing_runner, **_execution_args(world)
    )
    assert observed == [True]
    assert res.status == "ROLLED_BACK"
    assert res.rolled_back and not res.disk_written
    assert res.error_detail == "POST_APPLY_TESTS_FAILED"
    assert target.read_bytes() == before
    assert _wal_entries(proposal) == []


# ===========================================================================
# 16. TEST 16 : NOMINAL ALLOW -> APPLICATION SÛRE
# ===========================================================================

def test_scenario_16_nominal_allow_executes_safely(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    from periphery.world_calls.ticket_store import load_consumed_nonces

    res = _engine(proposal).apply_proposal_governed(
        proposal, post_test_runner=lambda _: True, **_execution_args(world)
    )
    assert res.status == "COMMITTED"
    assert res.kx108_pre_gate == "ALLOW"
    marker = load_consumed_nonces()[f"kx108-decision-record:{world['pre_id']}"]
    assert marker["state"] == "COMMITTED"
    assert res.disk_written and not res.rolled_back
    assert res.modified_files == proposal.approved_scope
    assert target.read_bytes() == proposal.operations[0].content.encode("utf-8")
    assert target.read_bytes() != before
    assert _wal_entries(proposal) == []


# ===========================================================================
# 17. TEST 17 : DEUX APPLICATIONS CONCURRENTES -> UNE SEULE RÉUSSIT
# ===========================================================================

def test_scenario_17_concurrent_apply_one_succeeds(canonical_case):
    world, target, proposal, _ = canonical_case
    ticket = _k1_allow_ticket(canonical_case)
    start = threading.Barrier(2)

    def try_apply():
        start.wait(timeout=10)
        return _engine(proposal).apply_proposal_governed(
            proposal, injected_ticket=ticket, **_execution_args(world)
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(try_apply) for _ in range(2)]
        results = [future.result(timeout=30) for future in futures]
    assert sorted(r.status for r in results) == ["COMMITTED", "REFUSED_PRE_DECISION"]
    refused = next(r for r in results if r.status == "REFUSED_PRE_DECISION")
    assert any(reason in refused.error_detail for reason in (
        "SOVEREIGN_TICKET_REPLAY_DETECTED", "TARGET_PRECONDITION_DRIFT",
    )), refused.error_detail
    assert not refused.disk_written
    assert target.read_bytes() == proposal.operations[0].content.encode("utf-8")
    assert _wal_entries(proposal) == []


# ===========================================================================
# 18. TEST 18 : CRASH SYSTÈME BRUTAL -> RÉCONCILIATION WAL AU REDÉMARRAGE
# ===========================================================================

def test_scenario_18_system_crash_wal_recovery(isolated_worktree):
    """Forged WAL cannot authorize physical restoration or cleanup."""
    existing_path = Path(isolated_worktree) / "src" / "existing.txt"
    wal_dir = Path(isolated_worktree) / ".obsidia_wal"
    wal_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Simulation d'un crash ayant laissé une mutation corrompue et un WAL orphelin sur disque
    existing_path.write_text("CORRUPTED_POST_CRASH_CONTENT", encoding="utf-8")
    orphan_wal = wal_dir / "wal_prop-crash-sigkill-001.json"
    orphan_wal.write_text(json.dumps({
        "evidence_id": "rollback-sigkill-test",
        "proposal_id": "prop-crash-sigkill-001",
        "created_at": "2026-10-28T10:00:00Z",
        "original_files": {"src/existing.txt": "ORIGINAL_CONTENT"},
        "pre_state_hashes": {"src/existing.txt": "abc"},
        "state": "MUTATION_IN_PROGRESS",
    }), encoding="utf-8")

    # 2. Appel de la procédure de réconciliation au redémarrage
    physical_before = existing_path.read_bytes()
    wal_before = orphan_wal.read_bytes()
    recovered = SealedRollbackEvidence.recover_dangling_wal(isolated_worktree)

    assert recovered == []
    assert existing_path.read_bytes() == physical_before
    assert orphan_wal.read_bytes() == wal_before
    assert sorted(wal_dir.iterdir()) == [orphan_wal]


def test_k1_unresolved_wal_reentry_refused_v1(canonical_case):
    world, target, proposal, _ = canonical_case
    before = target.read_bytes()
    wal_dir = Path(proposal.target_worktree) / ".obsidia_wal"
    wal_dir.mkdir()
    wal = wal_dir / "wal_unresolved_probe.json"
    wal_content = b"UNAUTHENTICATED_PENDING_WAL"
    wal.write_bytes(wal_content)
    result = _engine(proposal).apply_proposal_governed(proposal, **_execution_args(world))
    assert result.status == "REFUSED_PRE_DECISION"
    assert result.kx108_pre_gate == "ALLOW"
    assert result.kx108_reason == "WAL_UNRESOLVED_FAIL_CLOSED"
    assert not result.disk_written
    assert target.read_bytes() == before
    assert wal.read_bytes() == wal_content


def test_scenario_18_authenticated_wal_recovers(canonical_case, monkeypatch):
    """Real PRE -> real WAL -> interrupted physical write -> verified recovery."""
    from sigma.tooling import governed_bounded_apply as mod

    world, target, proposal, _ = canonical_case
    original = target.read_bytes()
    payload = proposal.operations[0].content.encode("utf-8")
    real_write = Path.write_bytes
    writes = []

    def interrupted_write(path, data):
        result = real_write(path, data)
        if path.resolve() == target.resolve() and data == payload:
            writes.append(True)
            raise SystemExit("K1_PHYSICAL_WRITE_THEN_INTERRUPT")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "write_bytes", interrupted_write)
        with pytest.raises(SystemExit, match="K1_PHYSICAL_WRITE_THEN_INTERRUPT"):
            _engine(proposal).apply_proposal_governed(proposal, **_execution_args(world))

    assert writes == [True]
    assert target.read_bytes() == payload != original
    journals = _wal_entries(proposal)
    assert len(journals) == 1
    wal = journals[0]
    data = json.loads(wal.read_text(encoding="utf-8"))
    assert data["decision_record_id"] == world["pre_id"]
    assert mod._k1_wal_current_state(data) == "PREPARED"
    assert SealedRollbackEvidence.recover_dangling_wal(
        proposal.target_worktree
    ) == [proposal.proposal_id]
    assert target.read_bytes() == original
    assert mod._k1_wal_current_state(data) == "RECOVERED"
    assert not wal.exists()
