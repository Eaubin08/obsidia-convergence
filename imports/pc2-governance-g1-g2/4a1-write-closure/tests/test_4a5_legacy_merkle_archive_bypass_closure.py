from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

ARCHIVE_STUB = (
    ROOT
    / "audit"
    / "legacy_root"
    / "audit_merkle.py"
)

HISTORICAL_SNAPSHOT = (
    ROOT
    / "audit"
    / "legacy_root"
    / "audit_merkle.py.historical.txt"
)

EXPECTED_HISTORICAL_SHA256 = (
    "c84d014dee0a8df44035a17619ef35a122085d2c0796ffe8e70a89e5091cf481"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def test_historical_writer_bytes_are_preserved_non_executable():
    assert HISTORICAL_SNAPSHOT.exists()

    assert (
        _sha256(HISTORICAL_SNAPSHOT)
        == EXPECTED_HISTORICAL_SHA256
    )

    assert HISTORICAL_SNAPSHOT.suffix == ".txt"


def test_legacy_python_path_contains_no_root_seal_writer():
    src = ARCHIVE_STUB.read_text(
        encoding="utf-8-sig"
    )

    assert 'open("merkle_seal.json", "w")' not in src
    assert "json.dump(seal" not in src
    assert "atomic_replace_with_bytes" not in src

    assert 'DECISION_AUTHORITY = "NONE"' in src
    assert 'MUTATION_AUTHORITY = "NONE"' in src

    assert (
        'LEGACY_RUNTIME_MODE = "EXECUTION_DISABLED"'
        in src
    )


def test_direct_execution_fails_closed_without_touching_seal(
    tmp_path,
):
    seal = tmp_path / "merkle_seal.json"

    sentinel = (
        b'{"historical":"MUST_REMAIN_UNTOUCHED"}'
    )

    seal.write_bytes(sentinel)

    proc = subprocess.run(
        [
            sys.executable,
            str(ARCHIVE_STUB),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode != 0

    combined = (
        proc.stdout
        + proc.stderr
    )

    assert (
        "LEGACY_MERKLE_ARCHIVE_EXECUTION_DISABLED"
        in combined
    )

    assert seal.read_bytes() == sentinel


def test_archive_has_no_forwarding_authority():
    src = ARCHIVE_STUB.read_text(
        encoding="utf-8-sig"
    )

    assert "publish_runtime_seal(" not in src
    assert "obsidia_runtime_merkle_seal_publisher_v1" not in src
