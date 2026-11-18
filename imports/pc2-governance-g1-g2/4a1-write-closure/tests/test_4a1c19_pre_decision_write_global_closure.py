from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def _text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")
def test_build_direct_target_mutation_is_unreachable_before_fail_closed_return():
    s = _text("scripts/obsidia_build.py")
    block = s.index(
        "BLOCKED_PRE_DECISION_GOVERNED_PATCH_RAIL_REQUIRED"
    )
    stop = s.index("return 2", block)
    mutation = s.index("result = apply_candidate_patch(", stop)
    assert block < stop < mutation
def test_jarvis_operational_state_rejects_canonical_scope():
    s = _text(
        "scripts/obsidia_jarvis_workspace_binding_v0.py"
    )
    assert "CANONICAL_OPERATIONAL_STATE_PATH_REJECTED" in s
    assert "is_canonical_write_root" in s
def test_terminal_operational_state_rejects_canonical_scope_without_subprocess_guard():
    s = _text("scripts/obsidia_terminal.py")
    assert "CANONICAL_WRITE_ROOT_REJECTED" in s
    assert "_is_canonical_terminal_write_path" in s
    assert "_git_common_dir_from_root" in s
    assert "obsidia_governed_write_guard_v0" not in s
def test_local_snapshot_requires_pre_allow_before_git_mutation():
    s = _text(
        "scripts/obsidia_mission_local_snapshot_v0.py"
    )
    pre = s.index("KX108_PRE_GATE_NOT_ALLOW")
    add = s.index("rc, err = _git_add_exact(")
    commit = s.index("rc, err = _git_commit(")
    assert pre < add < commit
def test_sealed_evidence_declares_no_target_mutation():
    s = _text("scripts/obsidia_sealed_evidence_v0.py")
    assert "ne mute AUCUNE cible" in s
    assert "SEALED_ROLLBACK_EVIDENCE_DIR" in s
    assert "SEALED_APPLY_RECEIPT_DIR" in s
def test_kx108_decision_store_is_off_repo_persistence():
    s = _text("scripts/obsidia_kx108_decision_store.py")
    assert "hors dépôt" in s
    assert "Ce module ne DÉCIDE rien" in s
def test_supervised_checkpoint_is_non_authority_state():
    s = _text(
        "scripts/obsidure_supervised_mission_checkpoint_v1.py"
    )
    assert '"approval_created": False' in s
    assert '"kx108_called": False' in s
    assert '"executor_invoked": False' in s
    assert '"checkpoint_kind": "PREPARE_ONLY_SUPERVISED_STATE"' in s
def test_gateway_packet_is_raw_noncanonical_not_memory_write():
    s = _text("scripts/obsidia_gateway.py")
    assert '"status": "RAW_NON_CANONICAL"' in s
    assert '"memory_write": False' in s
def test_batch_execution_refuses_protected_targets():
    s = _text("scripts/obsidia_batch_execution.py")
    assert "REFUSED_PROTECTED_TARGET" in s
    assert 'if child.get("target_path") and _is_protected(' in s
def test_branching_ledger_rejects_protected_target():
    s = _text("scripts/obsidia_branching_ledger.py")
    assert "GIT_TARGET_PROTECTED_REJECTED" in s
    assert "REJECTED_PROTECTED" in s
