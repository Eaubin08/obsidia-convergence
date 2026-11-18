from pathlib import Path
import ast


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "scripts" / "obsidia_build.py"
CANDIDATE = ROOT / "scripts" / "obsidia_candidate_patch_v1.py"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _function_source(path: Path, name: str) -> str:
    src = _source(path)
    tree = ast.parse(src)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == name:
                lines = src.splitlines()
                return "\n".join(
                    lines[node.lineno - 1 : node.end_lineno]
                )

    raise AssertionError(f"function not found: {name}")


def test_real_candidate_mutation_is_fail_closed_without_governed_patch_rail():
    body = _function_source(BUILD, "cmd_execute")

    guard = "BLOCKED_PRE_DECISION_GOVERNED_PATCH_RAIL_REQUIRED"
    mutation = "apply_candidate_patch("

    assert guard in body
    assert mutation in body

    assert body.find(guard) < body.find(mutation)


def test_synthetic_mutation_is_fail_closed_before_direct_write():
    body = _function_source(BUILD, "cmd_execute")

    guard = "BLOCKED_PRE_DECISION_GOVERNED_PATCH_RAIL_REQUIRED"

    synthetic_primitives = (
        "shutil.copy(src_tgt, tgt)",
        "tgt.write_text(",
        "shutil.copy(src_tst, tst)",
    )

    assert guard in body

    guard_pos = body.find(guard)

    for primitive in synthetic_primitives:
        pos = body.find(primitive)
        if pos >= 0:
            assert guard_pos < pos, (
                f"synthetic mutation reachable before fail-closed guard: {primitive}"
            )


def test_post_mutation_tooling_kx108_is_not_claimed_as_pre():
    body = _function_source(BUILD, "cmd_execute")

    assert "_call_kx108(" in body

    assert "KX108_PRE_DECISION_RECORD_ID" not in body
    assert "FAKE_KX108_PRE" not in body
    assert "FORCED_ALLOW" not in body


def test_candidate_patch_module_remains_non_sovereign():
    src = _source(CANDIDATE)

    forbidden = (
        'DECISION_AUTHORITY = "KX108_ONLY"',
        "IS_KX_AUTHORITY = True",
        "IS_EXECUTION_AUTHORITY = True",
    )

    for marker in forbidden:
        assert marker not in src
