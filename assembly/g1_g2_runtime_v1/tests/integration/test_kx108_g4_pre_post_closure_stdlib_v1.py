"""Tests locaux de liaison G4 : records synthétiques et clé de test uniquement."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import obsidia_kx108_decision_store as DS
from obsidia_governance_runtime_v1 import get_runtime


def _envelope(gate: str) -> dict:
    return {
        "x108_gate": gate, "decision_id": "synthetic-dec-1",
        "domain": "tooling_build", "reason_code": "SYNTHETIC_ONLY",
    }


class Kx108G4ReadOnlyClosure(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="obsidia-g4-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.pre_dir = self.base / "pre"
        self.post_dir = self.base / "post"
        self.pre_dir.mkdir()
        self.post_dir.mkdir()
        self.anchors = {
            "batch_execution_id": "batch-synth", "child_execution_id": "child-synth",
            "execution_authority_hash": "a" * 64,
            "approval_id": "approval-synth-not-real", "test_contract_hash": "b" * 64,
        }
        self.pre = {
            "decision_record_schema_version": DS.SCHEMA_VERSION,
            "decision_record_id": "pre-synthetic",
            "created_at": "2026-11-19T00:00:00Z",
            "decision_phase": DS.PRE_DECISION_PHASE,
            **self.anchors,
            "pre_execution_context_id": "context-synth",
            "pre_execution_context_record_hash": "c" * 64,
            "kx108_input_translation_hash": "d" * 64,
            "decision_id": "synthetic-dec-1", "trace_id": "synthetic-trace",
            "domain": "tooling_build", "x108_gate": "ALLOW",
            "reason_code": "SYNTHETIC_ONLY", "severity": "S0",
            "market_verdict": "READY_FOR_COMMIT_REVIEW",
            "contradictions": [], "unknowns": [], "risk_flags": [],
            "decision_authority": "KX108_ONLY",
            "canonical_envelope": _envelope("ALLOW"),
        }
        self.pre["decision_record_hash"] = DS.compute_kx108_decision_record_hash(self.pre)
        self._test_key = b"TEST_ONLY_G4_SYNTHETIC_KEY_NOT_FOR_PRODUCTION"
        self.key_patch = patch.object(DS, "_kernel_key", return_value=self._test_key)
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)
        DS._authenticate_decision_record(self.pre, "run_and_persist_kx108_pre_execution_decision")
        self.post = {
            "decision_record_schema_version": DS.SCHEMA_VERSION,
            "decision_record_id": "post-synthetic", "created_at": "2026-11-19T00:00:01Z",
            "decision_phase": DS.POST_DECISION_PHASE,
            **self.anchors,
            "test_result_id": "tests-synth", "test_result_record_hash": "e" * 64,
            "kx108_input_translation_hash": "f" * 64,
            "decision_id": "synthetic-dec-1", "trace_id": "synthetic-trace",
            "domain": "tooling_build", "x108_gate": "HOLD",
            "reason_code": "SYNTHETIC_ONLY", "severity": "S2",
            "market_verdict": "BUILD_HOLD", "contradictions": [],
            "unknowns": [], "risk_flags": [], "decision_authority": "KX108_ONLY",
            "canonical_envelope": _envelope("HOLD"),
            "kx108_pre_decision_record_id": self.pre["decision_record_id"],
            "kx108_pre_decision_record_hash": self.pre["decision_record_hash"],
            "sealed_apply_receipt_id": "apply-synth",
            "sealed_apply_receipt_hash": "1" * 64,
            "sealed_rollback_evidence_id": "rollback-synth",
            "sealed_rollback_evidence_hash": "2" * 64,
        }
        self._seal_post()
        self._save_records()

    def _seal_post(self):
        self.post["decision_record_hash"] = DS.compute_kx108_decision_record_hash(self.post)

    def _save_records(self):
        (self.pre_dir / "pre-synthetic.json").write_text(json.dumps(self.pre), encoding="utf-8")
        (self.post_dir / "post-synthetic.json").write_text(json.dumps(self.post), encoding="utf-8")

    def _inspect(self, **overrides):
        kwargs = {
            "pre_record_id": "pre-synthetic", "post_record_id": "post-synthetic",
            "pre_store_dir": self.pre_dir, "post_store_dir": self.post_dir,
            "expected_anchors": self.anchors,
        }
        kwargs.update(overrides)
        return get_runtime().inspect_kx108_pre_post_write_closure(**kwargs)

    def test_valid_synthetic_chain_is_still_hold(self):
        before = [(p.name, p.read_bytes()) for d in (self.pre_dir, self.post_dir) for p in d.iterdir()]
        result = self._inspect()
        after = [(p.name, p.read_bytes()) for d in (self.pre_dir, self.post_dir) for p in d.iterdir()]
        self.assertEqual(before, after)
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(result["pre_hmac_verified"])
        self.assertTrue(result["pre_post_record_link_verified"])
        self.assertTrue(result["post_structural_hash_verified"])
        self.assertFalse(result["post_authenticated"])
        self.assertFalse(result["sealed_evidence_verified"])
        self.assertFalse(result["write_closure_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["target_mutated"])

    def test_forged_pre_with_recomputed_hash_cannot_bypass_hmac(self):
        self.pre["approval_id"] = "forged-approval"
        self.pre["decision_record_hash"] = DS.compute_kx108_decision_record_hash(self.pre)
        self.post["kx108_pre_decision_record_hash"] = self.pre["decision_record_hash"]
        self._seal_post()
        self._save_records()
        result = self._inspect()
        self.assertIn("G4_PRE_AUTH_INVALID", result["reason"])

    def test_unavailable_kernel_key_holds(self):
        with patch.object(DS, "_kernel_key", side_effect=RuntimeError("no key")):
            self.assertIn("KERNEL_KEY_UNAVAILABLE", self._inspect()["reason"])

    def test_invalid_pre_gate_holds_even_if_hmac_valid(self):
        self.pre["x108_gate"] = "BLOCK"
        self.pre["canonical_envelope"] = _envelope("BLOCK")
        self.pre["decision_record_hash"] = DS.compute_kx108_decision_record_hash(self.pre)
        DS._authenticate_decision_record(self.pre, "run_and_persist_kx108_pre_execution_decision")
        self._save_records()
        self.assertEqual(self._inspect()["reason"], "G4_PRE_NOT_ALLOW")

    def test_post_mismatched_pre_hash_holds(self):
        self.post["kx108_pre_decision_record_hash"] = "3" * 64
        self._seal_post()
        self._save_records()
        self.assertEqual(self._inspect()["reason"], "G4_POST_PRE_EXACT_RECORD_BINDING_MISMATCH")

    def test_post_mismatched_pre_id_holds(self):
        self.post["kx108_pre_decision_record_id"] = "some-other-pre"
        self._seal_post()
        self._save_records()
        self.assertEqual(self._inspect()["reason"], "G4_POST_PRE_EXACT_RECORD_BINDING_MISMATCH")

    def test_unbound_post_legacy_holds(self):
        del self.post["kx108_pre_decision_record_id"]
        del self.post["kx108_pre_decision_record_hash"]
        self._seal_post()
        self._save_records()
        self.assertEqual(self._inspect()["reason"], "G4_POST_PRE_EXACT_RECORD_BINDING_MISMATCH")

    def test_post_unhashed_mutation_holds(self):
        self.post["approval_id"] = "forged"
        self._save_records()
        self.assertIn("STRUCTURAL_INVALID", self._inspect()["reason"])

    def test_structurally_rehashed_post_forgery_cannot_authorize(self):
        self.post["x108_gate"] = "ALLOW"
        self.post["canonical_envelope"] = _envelope("ALLOW")
        self._seal_post()
        self._save_records()
        result = self._inspect()
        self.assertTrue(result["post_structural_hash_verified"])
        self.assertFalse(result["post_authenticated"])
        self.assertFalse(result["release_authorized"])

    def test_anchor_drift_rejected(self):
        self.post["execution_authority_hash"] = "4" * 64
        self._seal_post()
        self._save_records()
        self.assertEqual(self._inspect()["reason"], "G4_ANCHOR_MISMATCH:execution_authority_hash")

    def test_caller_supplied_invalid_anchor_rejected(self):
        anchors = copy.deepcopy(self.anchors)
        anchors["approval_id"] = "not-the-one"
        self.assertEqual(self._inspect(expected_anchors=anchors)["reason"], "G4_ANCHOR_MISMATCH:approval_id")

    def test_caller_cannot_inject_fake_authority_anchor(self):
        anchors = {**self.anchors, "decision_authority": "ALLOW"}
        self.assertEqual(self._inspect(expected_anchors=anchors)["reason"], "G4_TRUSTED_ANCHORS_REQUIRED_EXACT")

    def test_incomplete_sealed_c2_links_rejected(self):
        # Sans l'ID d'apply, le schéma canonique retombe sur le contrat
        # historique D1 : G4 refuse explicitement cette dégradation C2.
        del self.post["sealed_apply_receipt_id"]
        self._seal_post()
        self._save_records()
        self.assertEqual(self._inspect()["reason"], "G4_C2_SEALED_EVIDENCE_LINK_INCOMPLETE")

    def test_malformed_sealed_hash_rejected(self):
        self.post["sealed_apply_receipt_hash"] = "garbage"
        self._seal_post()
        self._save_records()
        self.assertEqual(self._inspect()["reason"], "G4_C2_SEALED_EVIDENCE_HASH_INVALID")

    def test_missing_record_rejected(self):
        self.assertIn("NOT_FOUND", self._inspect(pre_record_id="missing-pre")["reason"])
        self.assertIn("NOT_FOUND", self._inspect(post_record_id="missing-post")["reason"])

    def test_filename_record_identity_mismatch_rejected(self):
        self.pre["decision_record_id"] = "another-pre"
        self.pre["decision_record_hash"] = DS.compute_kx108_decision_record_hash(self.pre)
        DS._authenticate_decision_record(self.pre, "run_and_persist_kx108_pre_execution_decision")
        self._save_records()
        self.assertEqual(self._inspect()["reason"], "G4_PRE_RECORD_NOT_FOUND_OR_ID_MISMATCH")

    def test_path_traversal_record_id_holds(self):
        self.assertIn("NOT_FOUND", self._inspect(pre_record_id="../outside")["reason"])


if __name__ == "__main__":
    unittest.main()
