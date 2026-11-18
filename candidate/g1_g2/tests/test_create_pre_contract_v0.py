"""G2 : contrats CREATE avant HumanApproval/KX108_PRE, sans création réelle."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "obsidia_create_pre_contract_v0.py"
spec = importlib.util.spec_from_file_location("create_pre_candidate", MODULE_PATH)
assert spec and spec.loader
CREATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CREATE)

SHA = "a" * 64


def invoke(root: Path, **overrides) -> dict:
    args = {
        "worktree_root": root,
        "operation_type": "CREATE_TARGET_FROM_SOURCE",
        "target_path": "src/feature.py",
        "source_content_sha256": SHA,
        "is_protected": lambda path: False,
    }
    args.update(overrides)
    return CREATE.prepare_create_target_pre_evidence(**args)


def test_create_maps_to_pc2_create_without_authorizing(tmp_path):
    (tmp_path / "src").mkdir()
    result = invoke(tmp_path)
    assert result["status"] == "READY_FOR_CANONICAL_PRE_EVIDENCE"
    assert result["operation_type"] == "CREATE_TARGET_FROM_SOURCE"
    assert result["pc2_adapter_operation_type"] == "CREATE"
    assert result["target_pre_sha256"] is None
    assert result["authorized"] is False
    assert result["target_mutated"] is False
    assert not (tmp_path / "src" / "feature.py").exists()


@pytest.mark.parametrize("operation", [
    "UPDATE_TARGET_FROM_SOURCE", "CREATE", "", "MOVE", "DELETE",
])
def test_no_ambiguous_create_operation(tmp_path, operation):
    assert invoke(tmp_path, operation_type=operation)["status"] == "HOLD_CREATE_PRE"


@pytest.mark.parametrize("path", [
    "../escape.py",
    "src/../escape.py",
    "C:\\Windows\\bad.py",
    "\\\\server\\share\\bad.py",
    "/etc/passwd",
    "src/file.txt:stream",
    "src//file.py",
    "src/./file.py",
    "src/file.py/",
])
def test_path_escapes_and_ambiguous_spellings_fail_closed(tmp_path, path):
    result = invoke(tmp_path, target_path=path)
    assert result["status"] == "HOLD_CREATE_PRE"
    assert result["authorized"] is False


def test_existing_target_is_rejected(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "feature.py").write_text("already here", encoding="utf-8")
    result = invoke(tmp_path)
    assert result["reason"] == "CREATE_TARGET_ALREADY_EXISTS"


def test_existing_file_as_parent_is_rejected(tmp_path):
    (tmp_path / "src").write_text("not a folder", encoding="utf-8")
    assert invoke(tmp_path)["reason"] == "TARGET_PARENT_NOT_DIRECTORY"


def test_parent_symlink_is_rejected(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "src").symlink_to(tmp_path / "real", target_is_directory=True)
    assert invoke(tmp_path)["reason"] == "TARGET_PATH_SYMLINK_COMPONENT"


@pytest.mark.parametrize("bad", ["notsha", "", "a" * 63])
def test_missing_or_invalid_source_hash_fail_closed(tmp_path, bad):
    assert invoke(tmp_path, source_content_sha256=bad)["reason"] == "SOURCE_SHA256_NOT_CANONICAL"


def test_policy_absence_or_rejection_blocks(tmp_path):
    assert invoke(tmp_path, is_protected=None)["reason"] == "CANONICAL_PROTECTION_POLICY_MISSING"
    assert invoke(tmp_path, is_protected=lambda _: True)["reason"] == "CREATE_TARGET_PROTECTED"


def test_policy_failure_blocks(tmp_path):
    def broken_policy(_):
        raise RuntimeError("unavailable")
    assert invoke(tmp_path, is_protected=broken_policy)["reason"] == "CANONICAL_PROTECTION_POLICY_FAILED"


def test_no_writes_to_target_even_when_evidence_ready(tmp_path):
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    result = invoke(tmp_path)
    after = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    assert result["status"] == "READY_FOR_CANONICAL_PRE_EVIDENCE"
    assert before == after
