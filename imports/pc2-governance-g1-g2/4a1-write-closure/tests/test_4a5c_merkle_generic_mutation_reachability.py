from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(ROOT / "scripts"),
)

import obsidia_content_apply as C


def test_root_merkle_seal_exactly_refused_by_generic_content_apply():
    target, reason = C.canonicalize_write_target(
        "merkle_seal.json"
    )

    assert target is None
    assert reason == C.REFUSED_PROTECTED_TARGET


def test_relative_root_merkle_alias_exactly_refused():
    target, reason = C.canonicalize_write_target(
        "./merkle_seal.json"
    )

    assert target is None
    assert reason == C.REFUSED_PROTECTED_TARGET
