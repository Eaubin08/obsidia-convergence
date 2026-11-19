"""G4H : l'intention WAL ne peut être publiée qu'avant mutation C2 test."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

import test_kx108_g4e_post_mutation_exception_stdlib_v1 as _G4E
from c2_write_intent_wal_v1 import STORE_UNAVAILABLE, inspect_intent
from scripts import obsidia_governed_apply_v0 as APPLY


class G4HPrewriteWalBoundary(unittest.TestCase):
    def setUp(self):
        self.fixture = _G4E.G4EPostMutationExceptions("test_receipt_builder_exception_routes_rollback")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.wal_dir = self.fixture.root / "wal-g4h"

    def _wal_ids(self):
        return [p.name.removesuffix(".intent.json") for p in self.wal_dir.glob("*.intent.json")]

    def test_intent_is_stored_and_reloaded_before_first_write(self):
        original = self.fixture._mutate

        def guarded_mutation(*args):
            ids = self._wal_ids()
            self.assertEqual(len(ids), 1)
            wal = inspect_intent(self.wal_dir, ids[0])
            self.assertEqual(wal["reason"], "UNRESOLVED_INTENT")
            self.assertFalse(wal["release_authorized"])
            return original(*args)

        self.fixture._mutate = guarded_mutation
        self.fixture.adp.translate_evidence_to_tooling_build_state.side_effect = RuntimeError("test")
        result = self.fixture._invoke(c2_write_intent_dir=self.wal_dir)
        self.fixture._assert_safe_rollback(result)
        self.assertEqual(len(self._wal_ids()), 1)

    def test_replay_of_identical_intent_is_denied_before_any_second_write(self):
        self.fixture.adp.translate_evidence_to_tooling_build_state.side_effect = RuntimeError("test")
        # Identite temporelle de la preuve SRE fixee pour rejouer exactement
        # le MEME intent et atteindre la barriere WAL, pas une autre preuve.
        with patch.object(_G4E.SEV, "_now", return_value="2026-11-19T00:00:00Z"):
            first = self.fixture._invoke(c2_write_intent_dir=self.wal_dir)
            self.fixture._assert_safe_rollback(first)
            second = self.fixture._invoke(c2_write_intent_dir=self.wal_dir)
        self.assertEqual(second["status"], APPLY.GOVERNED_REMEDIATION_APPLY_REJECTED_NO_MUTATION)
        self.assertIn("G4H_WAL_PREWRITE_HOLD:STORE_NOT_NEW", second["reason"])
        self.assertEqual(self.fixture.mutations, 1)
        self.assertEqual(self.fixture.rollback_calls, 1)

    def test_wal_store_failure_blocks_target_mutation(self):
        self.fixture.adp.translate_evidence_to_tooling_build_state.side_effect = RuntimeError("test")
        with patch("c2_write_intent_wal_v1.store_intent", return_value={"status": STORE_UNAVAILABLE}):
            result = self.fixture._invoke(c2_write_intent_dir=self.wal_dir)
        self.assertEqual(result["status"], APPLY.GOVERNED_REMEDIATION_APPLY_REJECTED_NO_MUTATION)
        self.assertIn("G4H_WAL_PREWRITE_HOLD", result["reason"])
        self.assertEqual(self.fixture.mutations, 0)
        self.assertEqual(self.fixture.target.read_bytes(), self.fixture.old)

    def test_wal_reload_failure_blocks_target_mutation(self):
        with patch("c2_write_intent_wal_v1.inspect_intent", return_value={"reason": "CORRUPTED"}):
            result = self.fixture._invoke(c2_write_intent_dir=self.wal_dir)
        self.assertEqual(result["status"], APPLY.GOVERNED_REMEDIATION_APPLY_REJECTED_NO_MUTATION)
        self.assertIn("INTENT_RELOAD_NOT_VERIFIED", result["reason"])
        self.assertEqual(self.fixture.mutations, 0)

    def test_invalid_explicit_wal_dir_denied(self):
        result = self.fixture._invoke(c2_write_intent_dir="untrusted string")
        self.assertEqual(result["status"], APPLY.GOVERNED_REMEDIATION_APPLY_REJECTED_NO_MUTATION)
        self.assertIn("G4H_WAL_DIR_NOT_EXPLICIT_PATH", result["reason"])
        self.assertEqual(self.fixture.mutations, 0)

    def test_without_opt_in_historical_test_path_keeps_no_wal(self):
        self.fixture.adp.translate_evidence_to_tooling_build_state.side_effect = RuntimeError("test")
        result = self.fixture._invoke()
        self.fixture._assert_safe_rollback(result)
        self.assertFalse(self.wal_dir.exists())


if __name__ == "__main__":
    unittest.main()
