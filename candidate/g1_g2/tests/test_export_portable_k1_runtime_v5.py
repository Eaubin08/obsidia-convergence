"""Exporter V5: tests purement locaux, aucun Git externe et aucun push."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "export_portable_k1_runtime_v5.py"
spec = importlib.util.spec_from_file_location("portable_export", SCRIPT)
assert spec and spec.loader
EXP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(EXP)


@pytest.fixture
def source(tmp_path):
    for relative in EXP.REQUIRED_SOURCES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# G1G2 source\n", encoding="utf-8")
    return tmp_path


def test_target_is_portable_only_and_explicit_branch():
    assert EXP.EXPECTED_MACHINE == "DESKTOP-Q5MD7J7"
    assert EXP.EXPECTED_SOURCE_BRANCH == "fix/kx108-zero-vote-guard-v1"
    assert EXP.EXPECTED_DEST_BRANCH == "build/g1-g2-contract-merge-v0"
    assert "obsidia-convergence" in EXP.EXPECTED_REMOTE
    assert all("/obsidia_cli.py" not in p for p in EXP.REQUIRED_SOURCES)


def test_source_collection_is_bounded_and_hashed(source):
    selected, discovered = EXP.select_sources(source)
    assert len(selected) == len(EXP.REQUIRED_SOURCES)
    assert discovered == []
    manifest = EXP._manifest(source, selected, discovered, "a" * 40)
    assert manifest["status"] == "SOURCE_ONLY__FUNCTIONAL_HOLD"
    assert manifest["source_machine"] == EXP.EXPECTED_MACHINE
    for item in manifest["files"]:
        assert item["sha256"] == hashlib.sha256(selected[item["path"]]).hexdigest()


def test_create_source_discovered_without_scanning_cli(source):
    candidate = source / "scripts" / "obsidia_create_kernel_v5.py"
    candidate.write_text('ACTION = "CREATE_TARGET_FROM_SOURCE"\n', encoding="utf-8")
    cli = source / "scripts" / "obsidia_cli.py"
    cli.write_text('ACTION = "CREATE_TARGET_FROM_SOURCE"\n', encoding="utf-8")
    selected, discovered = EXP.select_sources(source)
    assert "scripts/obsidia_create_kernel_v5.py" in discovered
    assert "scripts/obsidia_create_kernel_v5.py" in selected
    assert "scripts/obsidia_cli.py" not in selected


def test_missing_required_source_stops(source):
    (source / EXP.REQUIRED_SOURCES[0]).unlink()
    with pytest.raises(EXP.ExportHold, match="REQUIRED_SOURCE_MISSING"):
        EXP.select_sources(source)


def test_private_key_material_stops_before_copy(source):
    file = source / EXP.REQUIRED_SOURCES[0]
    file.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n")
    with pytest.raises(EXP.ExportHold, match="POSSIBLE_SECRET_FOUND"):
        EXP.select_sources(source)


def test_token_marker_stops_before_copy(source):
    file = source / EXP.REQUIRED_SOURCES[0]
    file.write_text("token = 'ghp_" + "a" * 28 + "'\n", encoding="utf-8")
    with pytest.raises(EXP.ExportHold, match="POSSIBLE_SECRET_FOUND"):
        EXP.select_sources(source)


def test_symlink_selected_source_is_rejected(source):
    file = source / EXP.REQUIRED_SOURCES[0]
    assert file.exists()
    real = source / "original.py"
    file.rename(real)
    try:
        file.symlink_to(real)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege unavailable")
        raise
    with pytest.raises(EXP.ExportHold, match="SOURCE_UNREADABLE_OR_REDIRECTED"):
        EXP.select_sources(source)


def test_source_not_utf8_stops(source):
    (source / EXP.REQUIRED_SOURCES[0]).write_bytes(b"\xff\xfe\x03")
    with pytest.raises(EXP.ExportHold, match="SOURCE_NOT_UTF8"):
        EXP.select_sources(source)


def test_wrong_machine_is_a_hard_stop_before_git(source, monkeypatch):
    monkeypatch.setenv("COMPUTERNAME", "DESKTOP-SDOG0EL")
    with pytest.raises(EXP.ExportHold, match="WRONG_MACHINE"):
        EXP._verify_machine_and_repos(source, source)

