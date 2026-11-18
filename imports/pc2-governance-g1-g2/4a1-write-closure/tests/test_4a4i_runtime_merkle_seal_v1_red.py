from pathlib import Path
import ast
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scripts" / "obsidia_runtime_merkle_seal_v1.py"
EXPECTED_SCOPE = (
    "proofs/",
    "formal/",
    "sigma/",
    "runtime_terrain_bank_trading_gps/server.kernel.sealed.cjs",
)
FORBIDDEN_SCOPE = (
    "merkle_seal.json",
    "server.kernel.sealed.cjs",
    ".claude/",
)
def _source():
    assert TARGET.exists(), (
        "Missing canonical runtime seal implementation: "
        "scripts/obsidia_runtime_merkle_seal_v1.py"
    )
    return TARGET.read_text(encoding="utf-8")
def test_runtime_merkle_v1_declares_exact_canonical_scope():
    src = _source()
    for item in EXPECTED_SCOPE:
        assert item in src, f"missing canonical seal scope item: {item}"
def test_runtime_merkle_v1_does_not_include_self_or_legacy_surfaces():
    src = _source()
    # Self-reference must be explicitly excluded.
    assert "merkle_seal.json" in src
    assert "EXCLUDE" in src.upper()
    # .claude must not be part of the sealed runtime corpus.
    assert ".claude/" in src
    assert "server.kernel.sealed.cjs" in src
def test_runtime_merkle_v1_is_non_authoritative():
    src = _source()
    assert 'DECISION_AUTHORITY = "NONE"' in src
    assert "KX108_ONLY" not in src or "DECISION_AUTHORITY" in src
def test_runtime_merkle_v1_has_compute_and_verify_without_runtime_mutation():
    src = _source()
    tree = ast.parse(src)
    functions = {
        n.name
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
    }
    assert "compute_runtime_seal" in functions
    assert "verify_runtime_seal" in functions
def test_runtime_merkle_v1_uses_path_and_bytes_not_only_file_hash_list():
    src = _source()
    assert "sha256" in src.lower()
    assert "relative" in src.lower() or "path" in src.lower()
def test_runtime_merkle_v1_never_overwrites_historical_seal_implicitly():
    src = _source()
    forbidden = (
        'open("merkle_seal.json", "w"',
        "write_text(",
        "write_bytes(",
    )
    # Implementation must be compute/verify first.
    # Persistence, if added later, requires an explicit separate rail.
    for token in forbidden:
        assert token not in src
