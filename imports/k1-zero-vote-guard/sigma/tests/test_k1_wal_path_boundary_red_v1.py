import json

from sigma.tooling.governed_bounded_apply import (
    SealedRollbackEvidence,
)


def test_wal_recovery_must_not_escape_worktree(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    outside = tmp_path / "outside_canary.txt"
    outside.write_bytes(b"ORIGINAL_SAFE")

    wal_dir = worktree / ".obsidia_wal"
    wal_dir.mkdir()
    wal = wal_dir / "wal_probe.json"

    wal.write_text(
        json.dumps({
            "proposal_id": "probe",
            "state": "MUTATION_IN_PROGRESS",
            "original_files": {
                "../outside_canary.txt": "UNAUTHORIZED_CHANGE"
            },
            "pre_state_hashes": {
                "../outside_canary.txt": "0" * 64
            },
        }),
        encoding="utf-8",
    )

    recovered = SealedRollbackEvidence.recover_dangling_wal(
        str(worktree)
    )

    assert outside.read_bytes() == b"ORIGINAL_SAFE"
    assert wal.exists()
    assert recovered == []


def test_direct_rollback_must_not_escape_worktree(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    outside = tmp_path / "outside_canary.txt"
    outside.write_bytes(b"ORIGINAL_SAFE")

    evidence = SealedRollbackEvidence(
        evidence_id="red-probe",
        proposal_id="red-probe",
        created_at="2026-11-12T00:00:00Z",
        original_files={
            "../outside_canary.txt": "UNAUTHORIZED_CHANGE"
        },
        pre_state_hashes={
            "../outside_canary.txt": "0" * 64
        },
    )

    try:
        evidence.execute_rollback(str(worktree))
    except (ValueError, PermissionError):
        pass

    assert outside.read_bytes() == b"ORIGINAL_SAFE"
