import importlib.util
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "obsidia_runtime_merkle_seal_v1.py"
spec = importlib.util.spec_from_file_location(
    "obsidia_runtime_merkle_seal_v1",
    MODULE_PATH,
)
assert spec is not None
assert spec.loader is not None
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "proofs").mkdir(parents=True)
    (root / "formal").mkdir()
    (root / "sigma").mkdir()
    (root / "runtime_terrain_bank_trading_gps").mkdir()
    (root / "proofs" / "a.txt").write_bytes(b"proof-a")
    (root / "formal" / "b.txt").write_bytes(b"formal-b")
    (root / "sigma" / "c.py").write_bytes(b"sigma-c")
    (
        root
        / "runtime_terrain_bank_trading_gps"
        / "server.kernel.sealed.cjs"
    ).write_bytes(b"terrain-kernel")
    # Explicitly excluded / unrelated surfaces.
    (root / ".claude").mkdir()
    (root / ".claude" / "SCRATCH.md").write_bytes(b"mutable-local")
    (root / "merkle_seal.json").write_bytes(b"historical-seal")
    (root / "server.kernel.sealed.cjs").write_bytes(b"legacy-root-kernel")
    return root
def test_same_bytes_same_paths_same_root(tmp_path):
    root = _repo(tmp_path)
    a = M.compute_runtime_seal(root)
    b = M.compute_runtime_seal(root)
    assert a["merkle_root"] == b["merkle_root"]
    assert a["entries"] == b["entries"]
def test_protected_runtime_byte_change_changes_root(tmp_path):
    root = _repo(tmp_path)
    before = M.compute_runtime_seal(root)["merkle_root"]
    (root / "sigma" / "c.py").write_bytes(b"sigma-c-modified")
    after = M.compute_runtime_seal(root)["merkle_root"]
    assert after != before
def test_path_rename_changes_root_even_when_bytes_identical(tmp_path):
    root = _repo(tmp_path)
    before = M.compute_runtime_seal(root)["merkle_root"]
    source = root / "proofs" / "a.txt"
    target = root / "proofs" / "renamed.txt"
    source.rename(target)
    after = M.compute_runtime_seal(root)["merkle_root"]
    assert after != before
def test_excluded_claude_change_does_not_change_root(tmp_path):
    root = _repo(tmp_path)
    before = M.compute_runtime_seal(root)["merkle_root"]
    (root / ".claude" / "SCRATCH.md").write_bytes(b"different-local-state")
    after = M.compute_runtime_seal(root)["merkle_root"]
    assert after == before
def test_historical_merkle_seal_change_does_not_change_root(tmp_path):
    root = _repo(tmp_path)
    before = M.compute_runtime_seal(root)["merkle_root"]
    (root / "merkle_seal.json").write_bytes(b"changed-historical-seal")
    after = M.compute_runtime_seal(root)["merkle_root"]
    assert after == before
def test_root_legacy_kernel_change_does_not_change_runtime_root(tmp_path):
    root = _repo(tmp_path)
    before = M.compute_runtime_seal(root)["merkle_root"]
    (root / "server.kernel.sealed.cjs").write_bytes(b"legacy-changed")
    after = M.compute_runtime_seal(root)["merkle_root"]
    assert after == before
def test_terrain_kernel_change_changes_runtime_root(tmp_path):
    root = _repo(tmp_path)
    before = M.compute_runtime_seal(root)["merkle_root"]
    (
        root
        / "runtime_terrain_bank_trading_gps"
        / "server.kernel.sealed.cjs"
    ).write_bytes(b"terrain-kernel-modified")
    after = M.compute_runtime_seal(root)["merkle_root"]
    assert after != before
def test_missing_mandatory_scope_fails_closed(tmp_path):
    root = _repo(tmp_path)
    (
        root
        / "runtime_terrain_bank_trading_gps"
        / "server.kernel.sealed.cjs"
    ).unlink()
    with pytest.raises(
        FileNotFoundError,
        match="RUNTIME_SEAL_SCOPE_MISSING",
    ):
        M.compute_runtime_seal(root)
def test_verify_accepts_exact_recomputation(tmp_path):
    root = _repo(tmp_path)
    seal = M.compute_runtime_seal(root)
    result = M.verify_runtime_seal(seal, root)
    assert result["verified"] is True
    assert result["status"] == "RUNTIME_SEAL_VERIFIED"
    assert all(result["checks"].values())
def test_verify_detects_stale_runtime_surface(tmp_path):
    root = _repo(tmp_path)
    seal = M.compute_runtime_seal(root)
    (root / "proofs" / "a.txt").write_bytes(b"tampered")
    result = M.verify_runtime_seal(seal, root)
    assert result["verified"] is False
    assert result["status"] == "RUNTIME_SEAL_MISMATCH"
    assert result["checks"]["root_match"] is False
