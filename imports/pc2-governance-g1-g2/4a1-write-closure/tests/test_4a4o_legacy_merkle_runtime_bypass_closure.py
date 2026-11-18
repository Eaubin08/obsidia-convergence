from __future__ import annotations
import hashlib
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
ACTIVE_LEGACY = ROOT / "audit_merkle.py"
ARCHIVED_LEGACY = (
    ROOT
    / "audit"
    / "legacy_root"
    / "audit_merkle.py"
)

ARCHIVED_LEGACY_HISTORICAL = (
    ROOT
    / "audit"
    / "legacy_root"
    / "audit_merkle.py.historical.txt"
)
TERRAIN_KERNEL = (
    ROOT
    / "runtime_terrain_bank_trading_gps"
    / "server.kernel.sealed.cjs"
)
ARCHIVED_LEGACY_SHA256 = (
    "c84d014dee0a8df44035a17619ef35a122085d2c0796ffe8e70a89e5091cf481"
)
def _sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
def test_archived_legacy_writer_is_preserved_exactly():
    assert ARCHIVED_LEGACY.exists()
    assert ARCHIVED_LEGACY_HISTORICAL.exists()

    assert (
        _sha256(
            ARCHIVED_LEGACY_HISTORICAL
        )
        == ARCHIVED_LEGACY_SHA256
    )

    assert (
        _sha256(
            ARCHIVED_LEGACY
        )
        != ARCHIVED_LEGACY_SHA256
    )


def test_active_runtime_legacy_helper_has_no_seal_write():
    source = ACTIVE_LEGACY.read_text(
        encoding="utf-8-sig"
    )
    assert 'open("merkle_seal.json", "w")' not in source
    assert "json.dump(seal" not in source
    assert 'DECISION_AUTHORITY = "NONE"' in source
    assert 'MUTATION_AUTHORITY = "NONE"' in source
    assert 'LEGACY_RUNTIME_MODE = "READ_ONLY"' in source
def test_legacy_helper_preserves_root_hash_interface_without_mutation(
    tmp_path,
):
    data_dir = (
        tmp_path
        / "MonProjet"
        / "allData"
    )
    data_dir.mkdir(
        parents=True
    )
    (data_dir / "decision_001.json").write_text(
        '{"decision":"A"}',
        encoding="utf-8",
    )
    (data_dir / "decision_002.json").write_text(
        '{"decision":"B"}',
        encoding="utf-8",
    )
    seal_path = (
        tmp_path
        / "merkle_seal.json"
    )
    sentinel = (
        b'{"historical":"MUST_REMAIN_UNTOUCHED"}'
    )
    seal_path.write_bytes(
        sentinel
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(ACTIVE_LEGACY),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert (
        seal_path.read_bytes()
        == sentinel
    )
    assert "ROOT HASH :" in proc.stdout
    assert "READ_ONLY" in proc.stdout
    assert "NOT modified" in proc.stdout
def test_terrain_kernel_compatibility_is_preserved():
    source = TERRAIN_KERNEL.read_text(
        encoding="utf-8-sig"
    )
    assert "audit_merkle.py" in source
    assert (
        'exec(`python "${auditMerklePath}"`'
        in source
    )
    assert (
        "ROOT HASH : (.*)"
        in source
    )
