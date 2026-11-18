from pathlib import Path
import ast
ROOT = Path(__file__).resolve().parents[1]
TARGET = (
    ROOT
    / "scripts"
    / "obsidia_runtime_merkle_seal_publisher_v1.py"
)
def _source() -> str:
    assert TARGET.exists(), (
        "Missing dedicated governed runtime seal publisher: "
        "scripts/obsidia_runtime_merkle_seal_publisher_v1.py"
    )
    return TARGET.read_text(
        encoding="utf-8-sig"
    )
def test_publisher_exists_as_dedicated_module():
    src = _source()
    assert (
        "OBSIDIA_RUNTIME_MERKLE_SEAL_PUBLISHER_V1"
        in src
    )
def test_publisher_has_no_decision_authority():
    src = _source()
    assert 'DECISION_AUTHORITY = "NONE"' in src
    assert "IS_KX_AUTHORITY = False" in src
def test_publisher_target_is_exactly_merkle_seal_json():
    src = _source()
    assert (
        'TARGET_RELATIVE_PATH = "merkle_seal.json"'
        in src
    )
def test_publisher_binds_exact_candidate_identity():
    src = _source()
    required = (
        "candidate_merkle_root",
        "candidate_manifest_hash",
        "candidate_scope_hash",
        "candidate_total_files",
        "execution_authority_hash",
    )
    for token in required:
        assert token in src
def test_publisher_requires_human_approval_and_kx108_pre():
    src = _source()
    assert "HumanApproval" in src
    assert "KX108_PRE" in src
    assert "approval_id" in src
    assert "execution_authority_hash" in src
def test_publisher_requires_pre_allow_before_physical_write():
    src = _source()
    tree = ast.parse(src)
    fn = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "publish_runtime_seal"
        ),
        None,
    )
    assert fn is not None
    text = ast.unparse(fn)
    assert "KX108_PRE" in text
    assert "ALLOW" in text
def test_publisher_has_atomic_replace_and_post_verify():
    src = _source()
    assert "atomic" in src.lower()
    assert "verify_runtime_seal" in src
    assert "POST_WRITE" in src or "post_write" in src
def test_publisher_preserves_historical_provenance():
    src = _source()
    assert "historical" in src.lower()
    assert (
        "b8a69ce98ee86f3871ef2f75a50bf8ac"
        "b138865adfaba77009bb6e57e569d6b2"
        in src
    )
def test_no_generic_protected_override():
    src = _source()
    forbidden = (
        "allow_protected=True",
        "allow_protected = True",
        "protected_override=True",
        "protected_override = True",
        "REFUSED_PROTECTED_TARGET = None",
    )
    for token in forbidden:
        assert token not in src
def test_publisher_cannot_target_arbitrary_path():
    src = _source()
    forbidden_parameters = (
        "target_path",
        "destination_path",
        "output_path",
    )
    tree = ast.parse(src)
    fn = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "publish_runtime_seal"
        ),
        None,
    )
    assert fn is not None
    params = {
        arg.arg
        for arg in fn.args.args
    }
    for name in forbidden_parameters:
        assert name not in params
