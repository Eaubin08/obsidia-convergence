"""P1-C326: D1 refuses structurally valid but unauthenticated KX108 POST."""
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import obsidia_post_execution_disposition_v0 as D

DS = D._DS


def test_unauthenticated_post_cannot_enable_commit_review(tmp_path):
    record_id = "p1-c326-synthetic-post"

    post = {
        "decision_record_schema_version": DS.SCHEMA_VERSION,
        "decision_record_id": record_id,
        "created_at": "2026-11-25T00:00:00+00:00",
        "decision_phase": DS.POST_DECISION_PHASE,
        "decision_authority": DS.DECISION_AUTHORITY,
        "x108_gate": "ALLOW",
        "kx108_pre_decision_record_id": "synthetic-pre",
        "kx108_pre_decision_record_hash": "a" * 64,
    }

    for field in DS._record_bound_fields_for(post):
        post.setdefault(field, None)

    post["decision_record_hash"] = (
        DS.compute_kx108_decision_record_hash(post)
    )

    assert DS.verify_kx108_decision_record(post) == (True, None)
    assert DS.verify_kx108_decision_record_authenticity(post) == (
        False, "DECISION_RECORD_NOT_AUTHENTICATED"
    )

    with patch.object(
        DS, "load_kx108_decision_record", return_value=post
    ):
        original = DS.verify_kx108_decision_record_authenticity

        with patch.object(
            DS,
            "verify_kx108_decision_record_authenticity",
            wraps=original,
        ) as verifier:
            result = D.classify_post_execution_disposition(
                post_decision_record_id=record_id,
                post_decision_store_dir=tmp_path,
            )

            assert verifier.call_count == 1

    assert result["status"] == D.DISPOSITION_CLASSIFIED
    assert result["disposition"] == D.MUST_ROLLBACK
    assert result["reason"] == (
        "KX108_POST_RECORD_INVALID:DECISION_RECORD_NOT_AUTHENTICATED"
    )
    assert result["commit_review_eligible"] is False
    assert result["rollback_required"] is True
    assert result["write_capability"] is False
    assert result["authority"] == "NON_SOVEREIGN"
    assert list(tmp_path.rglob("*")) == []