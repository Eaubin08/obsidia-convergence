"""P1 : Contrats autonomes d'évidence scellée (C2) et de disposition post-exécution (D1)."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT / "scripts", ROOT):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import obsidia_kx108_decision_store as _DS
import obsidia_post_execution_disposition_v0 as _DISP
import obsidia_sealed_evidence_v0 as _SEV


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class P1SealedEvidenceAndDispositionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-p1-sev-disp-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sre_dir = self.root / "sre"
        self.sar_dir = self.root / "sar"
        self.post_dir = self.root / "kx_post"
        self.sre_dir.mkdir()
        self.sar_dir.mkdir()
        self.post_dir.mkdir()

        self.pre_bytes = b"old_line = 1\n"
        self.src_bytes = b"new_line = 2\n"
        self.child = {
            "child_execution_id": "chd-p1-1",
            "target_path": "scripts/tool.py",
            "target_pre_sha256": _sha(self.pre_bytes),
            "source_content_sha256": _sha(self.src_bytes),
            "operation_type": _SEV.OPERATION_TYPE,
            "source_kind": "GIT_BLOB",
            "source_path": "scripts/tool.py",
            "source_git_commit_sha": "a" * 40,
            "source_git_blob_sha": "b" * 40,
            "source_git_historical_path": "scripts/tool.py",
        }

    def test_sealed_rollback_evidence_and_apply_receipt_immutability(self) -> None:
        # 1. Preimage mismatch refusé
        bad_sre, err = _SEV.build_sealed_rollback_evidence(
            batch_execution_id="bex-1",
            child=self.child,
            execution_authority_hash="e" * 64,
            approval_id="apr-1",
            kx108_pre_decision_record_id="kxpre-1",
            kx108_pre_decision_record_hash="f" * 64,
            preimage_bytes=b"wrong_bytes",
        )
        self.assertIsNone(bad_sre)
        self.assertEqual(err, "PREIMAGE_SHA256_NEQ_CHILD_TARGET_PRE")

        # 2. Construction, vérification, stockage idempotent et détection d'immutabilité SRE
        sre, err = _SEV.build_sealed_rollback_evidence(
            batch_execution_id="bex-1",
            child=self.child,
            execution_authority_hash="e" * 64,
            approval_id="apr-1",
            kx108_pre_decision_record_id="kxpre-1",
            kx108_pre_decision_record_hash="f" * 64,
            preimage_bytes=self.pre_bytes,
        )
        self.assertIsNone(err)
        self.assertEqual(_SEV.verify_sealed_rollback_evidence(sre), (True, None))
        self.assertEqual(_SEV.decode_sealed_preimage(sre), (self.pre_bytes, None))
        self.assertEqual(
            _SEV.store_sealed_rollback_evidence(sre, self.sre_dir)["status"],
            _SEV.STATUS_STORED,
        )
        self.assertEqual(
            _SEV.store_sealed_rollback_evidence(sre, self.sre_dir)["status"],
            _SEV.STATUS_IDEMPOTENT,
        )
        mutated_sre = {**sre, "created_at": "2026-11-24T00:00:01+00:00"}
        mutated_sre["sealed_rollback_evidence_hash"] = _SEV.compute_sealed_rollback_evidence_hash(
            mutated_sre
        )
        self.assertEqual(
            _SEV.store_sealed_rollback_evidence(mutated_sre, self.sre_dir)["status"],
            _SEV.STATUS_IMMUTABILITY_VIOLATION,
        )

        # 3. SealedApplyReceipt : refus si target_post_sha256 != source_content_sha256
        bad_sar, err = _SEV.build_sealed_apply_receipt(
            batch_execution_id="bex-1",
            child=self.child,
            execution_authority_hash="e" * 64,
            approval_id="apr-1",
            kx108_pre_decision_record_id="kxpre-1",
            kx108_pre_decision_record_hash="f" * 64,
            sealed_rollback_evidence_id=sre["sealed_rollback_evidence_id"],
            sealed_rollback_evidence_hash=sre["sealed_rollback_evidence_hash"],
            target_pre_sha256=_sha(self.pre_bytes),
            target_post_sha256=_sha(b"divergent"),
            bytes_written=len(self.src_bytes),
        )
        self.assertIsNone(bad_sar)
        self.assertEqual(err, "TARGET_POST_SHA256_NEQ_CHILD_SOURCE_CONTENT_SHA256")

        sar, err = _SEV.build_sealed_apply_receipt(
            batch_execution_id="bex-1",
            child=self.child,
            execution_authority_hash="e" * 64,
            approval_id="apr-1",
            kx108_pre_decision_record_id="kxpre-1",
            kx108_pre_decision_record_hash="f" * 64,
            sealed_rollback_evidence_id=sre["sealed_rollback_evidence_id"],
            sealed_rollback_evidence_hash=sre["sealed_rollback_evidence_hash"],
            target_pre_sha256=_sha(self.pre_bytes),
            target_post_sha256=_sha(self.src_bytes),
            bytes_written=len(self.src_bytes),
        )
        self.assertIsNone(err)
        self.assertEqual(_SEV.verify_sealed_apply_receipt(sar), (True, None))
        self.assertEqual(
            _SEV.store_sealed_apply_receipt(sar, self.sar_dir)["status"],
            _SEV.STATUS_STORED,
        )

    def _write_post_record(
        self,
        *,
        record_id: str,
        gate: str,
        phase: str = _DS.POST_DECISION_PHASE,
        linked_pre: bool = True,
    ) -> dict:
        rec = {
            "decision_record_schema_version": 1,
            "decision_record_id": record_id,
            "created_at": "2026-11-24T00:00:00+00:00",
            "decision_phase": phase,
            "batch_execution_id": "bex-1",
            "child_execution_id": "chd-p1-1",
            "execution_authority_hash": "e" * 64,
            "approval_id": "apr-1",
            "test_contract_hash": "c" * 64,
            "test_result_id": "tcr-1",
            "test_result_record_hash": "d" * 64,
            "kx108_input_translation_hash": "1" * 64,
            "decision_id": "dec-post-1",
            "trace_id": "trc-post-1",
            "domain": "tooling_build",
            "x108_gate": gate,
            "reason_code": "OK" if gate == "ALLOW" else "HOLD_OR_BLOCK",
            "severity": "S0" if gate == "ALLOW" else "S2",
            "market_verdict": "ACT" if gate == "ALLOW" else gate,
            "contradictions": [],
            "unknowns": [],
            "risk_flags": [],
            "decision_authority": "KX108_ONLY",
            "canonical_envelope": {"x108_gate": gate},
        }
        if phase == _DS.PRE_DECISION_PHASE:
            rec.pop("test_result_id")
            rec.pop("test_result_record_hash")
            rec["pre_execution_context_id"] = "pec-1"
            rec["pre_execution_context_record_hash"] = "2" * 64
        if linked_pre:
            rec["kx108_pre_decision_record_id"] = "kxpre-1"
            rec["kx108_pre_decision_record_hash"] = "f" * 64
        rec["decision_record_hash"] = _DS.compute_kx108_decision_record_hash(rec)
        (self.post_dir / f"{record_id}.json").write_text(
            json.dumps(rec, sort_keys=True), encoding="utf-8"
        )
        return rec

    def test_post_execution_disposition_classifier_is_readonly_and_fail_closed(self) -> None:
        # 1. Erreurs d'entrée -> DISPOSITION_HOLD
        self.assertEqual(
            _DISP.classify_post_execution_disposition()["status"], _DISP.DISPOSITION_HOLD
        )
        self.assertEqual(
            _DISP.classify_post_execution_disposition(failure_signal="BAD_SIGNAL")["reason"],
            "UNKNOWN_FAILURE_SIGNAL:BAD_SIGNAL",
        )

        # 2. Signal canonique -> MUST_ROLLBACK
        sig = _DISP.classify_post_execution_disposition(failure_signal="POST_EVIDENCE_UNAVAILABLE")
        self.assertEqual(sig["disposition"], _DISP.MUST_ROLLBACK)
        self.assertIs(sig["write_capability"], False)
        self.assertIs(sig["commit_review_eligible"], False)

        # 3. Record absent -> MUST_ROLLBACK
        missing = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kxpost-missing", post_decision_store_dir=self.post_dir
        )
        self.assertEqual(missing["disposition"], _DISP.MUST_ROLLBACK)
        self.assertEqual(missing["reason"], "KX108_POST_RECORD_NOT_FOUND")

        # 4. Mauvaise phase (PRE_EXECUTION) ou non lié -> DISPOSITION_HOLD
        self._write_post_record(
            record_id="kx-pre-only", gate="ALLOW", phase=_DS.PRE_DECISION_PHASE, linked_pre=False
        )
        self.assertEqual(
            _DISP.classify_post_execution_disposition(
                post_decision_record_id="kx-pre-only", post_decision_store_dir=self.post_dir
            )["disposition"],
            _DISP.MUST_ROLLBACK,
        )
        self._write_post_record(record_id="kx-unlinked", gate="ALLOW", linked_pre=False)
        self.assertEqual(
            _DISP.classify_post_execution_disposition(
                post_decision_record_id="kx-unlinked", post_decision_store_dir=self.post_dir
            )["reason"],
            "KX108_POST_RECORD_INVALID:DECISION_RECORD_NOT_AUTHENTICATED",
        )

        # 5. POST ALLOW lié -> KEEP_ELIGIBLE_FOR_HUMAN_COMMIT_REVIEW ; POST HOLD/BLOCK -> MUST_ROLLBACK
        self._write_post_record(record_id="kx-post-allow", gate="ALLOW", linked_pre=True)
        keep = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kx-post-allow", post_decision_store_dir=self.post_dir
        )
        self.assertEqual(keep["disposition"], _DISP.MUST_ROLLBACK)
        self.assertIs(keep["write_capability"], False)
        self.assertIs(keep["commit_review_eligible"], False)

        self._write_post_record(record_id="kx-post-hold", gate="HOLD", linked_pre=True)
        rb = _DISP.classify_post_execution_disposition(
            post_decision_record_id="kx-post-hold", post_decision_store_dir=self.post_dir
        )
        self.assertEqual(rb["disposition"], _DISP.MUST_ROLLBACK)
        self.assertIs(rb["rollback_required"], True)


if __name__ == "__main__":
    unittest.main()
