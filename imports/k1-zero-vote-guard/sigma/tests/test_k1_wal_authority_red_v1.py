import hashlib
import json

from sigma.tooling.governed_bounded_apply import (
    SealedRollbackEvidence,
)


def test_forged_in_scope_wal_must_not_restore(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    target = worktree / "canary.txt"
    target.write_bytes(b"SAFE_ORIGINAL")

    forged = "ATTACKER_CHOSEN_RESTORE"

    wal_dir = worktree / ".obsidia_wal"
    wal_dir.mkdir()
    wal = wal_dir / "wal_forged_probe.json"

    wal.write_text(
        json.dumps({
            "evidence_id": "forged-evidence",
            "proposal_id": "forged_probe",
            "created_at": "2026-11-12T00:00:00Z",
            "state": "MUTATION_IN_PROGRESS",
            "original_files": {
                "canary.txt": forged
            },
            "pre_state_hashes": {
                "canary.txt": hashlib.sha256(
                    forged.encode("utf-8")
                ).hexdigest()
            },
        }),
        encoding="utf-8",
    )

    recovered = SealedRollbackEvidence.recover_dangling_wal(
        str(worktree)
    )

    assert target.read_bytes() == b"SAFE_ORIGINAL"
    assert wal.exists()
    assert recovered == []
