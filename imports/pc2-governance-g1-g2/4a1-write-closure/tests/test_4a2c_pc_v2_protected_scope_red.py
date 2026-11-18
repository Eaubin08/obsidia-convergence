from pathlib import Path
import tempfile
import scripts.obsidia_pc_capabilities_v2 as PC
PROTECTED_TARGETS = (
    "proofs/4a2_probe.txt",
    "formal/4a2_probe.txt",
    "merkle_seal.json",
    "runtime_terrain_bank_trading_gps/server.kernel.sealed.cjs",
)
def _base_kwargs(root, stores):
    return dict(
        execution_worktree_path=root,
        main_worktree_path=root.parent / "main-placeholder",
        branch_name="probe-branch",
        base_sha="a" * 40,
        stores_base_dir=stores,
        session_id="4a2-probe",
    )
def test_create_prepare_rejects_all_protected_targets(monkeypatch, tmp_path):
    monkeypatch.setattr(
        PC,
        "_check_isolation",
        lambda *a, **k: {"ok": True},
    )
    stores = tmp_path / "stores"
    for target in PROTECTED_TARGETS:
        out = PC.pc_v2_create_file_prepare(
            target,
            b"probe",
            **_base_kwargs(tmp_path, stores),
        )
        assert out["status"] != PC.PREPARED_AWAITING_HUMAN_APPROVAL, target
        assert "PROTECTED" in str(out), target
def test_move_prepare_rejects_protected_destination(monkeypatch, tmp_path):
    monkeypatch.setattr(
        PC,
        "_check_isolation",
        lambda *a, **k: {"ok": True},
    )
    src = tmp_path / "normal.txt"
    src.write_bytes(b"x")
    out = PC.pc_v2_move_file_prepare(
        "normal.txt",
        "proofs/moved.txt",
        **_base_kwargs(tmp_path, tmp_path / "stores"),
    )
    assert out["status"] != PC.PREPARED_AWAITING_HUMAN_APPROVAL
    assert "PROTECTED" in str(out)
def test_move_prepare_rejects_protected_source(monkeypatch, tmp_path):
    monkeypatch.setattr(
        PC,
        "_check_isolation",
        lambda *a, **k: {"ok": True},
    )
    src = tmp_path / "proofs" / "existing.txt"
    src.parent.mkdir(parents=True)
    src.write_bytes(b"x")
    out = PC.pc_v2_move_file_prepare(
        "proofs/existing.txt",
        "normal.txt",
        **_base_kwargs(tmp_path, tmp_path / "stores"),
    )
    assert out["status"] != PC.PREPARED_AWAITING_HUMAN_APPROVAL
    assert "PROTECTED" in str(out)
def test_apply_patch_prepare_rejects_protected_target(monkeypatch, tmp_path):
    monkeypatch.setattr(
        PC,
        "_check_isolation",
        lambda *a, **k: {"ok": True},
    )
    target = tmp_path / "proofs" / "x.txt"
    target.parent.mkdir(parents=True)
    target.write_text("old\n", encoding="utf-8")
    patch = """diff --git a/proofs/x.txt b/proofs/x.txt
--- a/proofs/x.txt
+++ b/proofs/x.txt
@@ -1 +1 @@
-old
+new
"""
    class Dummy:
        returncode = 0
        stderr = ""
    monkeypatch.setattr(PC.subprocess, "run", lambda *a, **k: Dummy())
    out = PC.pc_v2_apply_patch_prepare(
        patch,
        **_base_kwargs(tmp_path, tmp_path / "stores"),
    )
    assert out["status"] != PC.PREPARED_AWAITING_HUMAN_APPROVAL
    assert "PROTECTED" in str(out)
