from __future__ import annotations

import inspect
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import obsidia_pc_capabilities_v2 as PC2


def _src(fn) -> str:
    return inspect.getsource(fn)


def test_4a1_create_file_has_no_direct_filesystem_mutation():
    src = _src(PC2.pc_v2_create_file_execute)

    banned = (
        "os.replace(",
        ".write_bytes(",
        ".write_text(",
    )

    for primitive in banned:
        assert primitive not in src, (
            "4A1_OPEN: CREATE_FILE still owns direct mutation primitive: "
            + primitive
        )


def test_4a1_move_file_has_no_direct_filesystem_mutation():
    src = _src(PC2.pc_v2_move_file_execute)

    banned = (
        "executor.move_file(",
        "os.replace(",
        "shutil.move(",
        ".rename(",
        ".replace(",
    )

    for primitive in banned:
        assert primitive not in src, (
            "4A1_OPEN: MOVE_FILE still owns direct mutation primitive: "
            + primitive
        )


def test_4a1_apply_patch_has_no_direct_git_apply_mutation():
    src = _src(PC2.pc_v2_apply_patch_execute)

    assert '["git", "apply"' not in src, (
        "4A1_OPEN: APPLY_PATCH still dispatches git apply directly"
    )
    assert "subprocess.run(" not in src or '"git", "apply"' not in src, (
        "4A1_OPEN: APPLY_PATCH still owns physical patch mutation"
    )


def test_4a1_create_dir_has_no_direct_directory_mutation():
    src = _src(PC2.pc_v2_create_dir_execute)

    banned = (
        "executor.create_dir(",
        ".mkdir(",
        "os.mkdir(",
        "os.makedirs(",
    )

    for primitive in banned:
        assert primitive not in src, (
            "4A1_OPEN: CREATE_DIR still owns direct mutation primitive: "
            + primitive
        )


def test_4a1_filesystem_public_capabilities_remain_present():
    required = (
        "pc_v2_create_file_prepare",
        "pc_v2_create_file_execute",
        "pc_v2_move_file_prepare",
        "pc_v2_move_file_execute",
        "pc_v2_apply_patch_prepare",
        "pc_v2_apply_patch_execute",
        "pc_v2_create_dir_prepare",
        "pc_v2_create_dir_execute",
    )

    for name in required:
        assert hasattr(PC2, name), name


def test_4a1_pc_v2_remains_non_authority():
    sc = PC2.self_check_v2()

    assert sc["is_execution_authority"] is False
    assert sc["is_kx_authority"] is False
    assert sc["new_parallel_mutation_engine"] is False
