"""G4G — WAL append-only isolé, avec arrêt abrupt d'un sous-processus.

Les seules écritures concernent TemporaryDirectory. Aucun APPLY métier.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from c2_write_intent_wal_v1 import (
    IDEMPOTENT, IMMUTABILITY_VIOLATION, STORED, STORE_UNAVAILABLE,
    build_intent, build_outcome, inspect_intent, store_intent, store_outcome,
    verify_intent, verify_outcome,
)
from obsidia_governance_runtime_v1 import get_runtime


def synthetic_intent():
    return build_intent(
        batch_execution_id="batch-test-only", child_execution_id="child-test-only",
        execution_authority_hash="a" * 64, approval_id="approval-synthetic",
        pre_decision_record_id="pre-test-only",
        pre_decision_record_hash="b" * 64,
        sealed_rollback_evidence_id="sre-test-only",
        sealed_rollback_evidence_hash="c" * 64,
        target_path="targets/synthetic.txt", target_pre_sha256="d" * 64,
        target_post_sha256="e" * 64,
    )


class G4GIntentWal(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="obsidia-g4g-wal-synthetic-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.wal = self.root / "wal"
        self.intent = synthetic_intent()
        self.assertIsNotNone(self.intent)

    def test_deterministic_identity_and_canonical_hash(self):
        self.assertEqual(synthetic_intent(), self.intent)
        self.assertEqual(verify_intent(self.intent), (True, None))
        self.assertFalse(self.intent["producer_authenticated"])
        self.assertFalse(self.intent["release_authorized"])

    def test_append_only_persistence_then_readonly_unresolved(self):
        self.assertEqual(store_intent(self.intent, self.wal)["status"], STORED)
        actual = get_runtime().inspect_c2_write_intent_wal(
            wal_dir=self.wal, intent_id=self.intent["intent_id"])
        self.assertEqual(actual["status"], "HOLD")
        self.assertEqual(actual["reason"], "UNRESOLVED_INTENT")
        self.assertTrue(actual["quarantine_review_required"])
        self.assertFalse(actual["recovery_authorized"])
        self.assertFalse(actual["release_authorized"])

    def test_idempotence_exact_bytes(self):
        self.assertEqual(store_intent(self.intent, self.wal)["status"], STORED)
        self.assertEqual(store_intent(self.intent, self.wal)["status"], IDEMPOTENT)

    def test_conflicting_disk_bytes_never_overwritten(self):
        self.assertEqual(store_intent(self.intent, self.wal)["status"], STORED)
        p = self.wal / (self.intent["intent_id"] + ".intent.json")
        p.write_text("tampered", encoding="utf-8")
        self.assertEqual(store_intent(self.intent, self.wal)["status"], IMMUTABILITY_VIOLATION)
        self.assertEqual(p.read_text(encoding="utf-8"), "tampered")
        self.assertEqual(inspect_intent(self.wal, self.intent["intent_id"])["status"], "HOLD")

    def test_forged_field_and_hash_rejected(self):
        forged = dict(self.intent)
        forged["target_path"] = "targets/forged.txt"
        self.assertFalse(verify_intent(forged)[0])
        self.assertEqual(store_intent(forged, self.wal)["status"], STORE_UNAVAILABLE)
        self.assertFalse(self.wal.exists())

    def test_invalid_path_and_extra_authority_blocked(self):
        for path in ("../escape", "/absolute", "C:\\windows\\temp", "a//b"):
            params = dict(target_path=path)
            from inspect import signature
            original = synthetic_intent()
            values = {name: original[name] for name in signature(build_intent).parameters}
            values.update(params)
            self.assertIsNone(build_intent(**values))
        forged = {**self.intent, "release_authorized": True}
        self.assertFalse(verify_intent(forged)[0])
        forged = {**self.intent, "allow": "ALLOW"}
        self.assertFalse(verify_intent(forged)[0])

    def test_outcome_is_report_only_not_execution_permission(self):
        self.assertEqual(store_intent(self.intent, self.wal)["status"], STORED)
        report = build_outcome(self.intent, reported_status="REPORTED_KEEP",
                               observed_sha256="e" * 64)
        self.assertIsNotNone(report)
        self.assertEqual(verify_outcome(report, self.intent), (True, None))
        self.assertEqual(store_outcome(report, self.intent, self.wal)["status"], STORED)
        self.assertEqual(store_outcome(report, self.intent, self.wal)["status"], IDEMPOTENT)
        observed = inspect_intent(self.wal, self.intent["intent_id"])
        self.assertEqual(observed["reason"], "OUTCOME_REPORTED_NOT_ATTESTED")
        self.assertEqual(observed["status"], "HOLD")
        self.assertFalse(observed["release_authorized"])
        self.assertFalse(observed["physical_mutation_attested"])

    def test_outcome_conflict_or_tampering_holds(self):
        self.assertEqual(store_intent(self.intent, self.wal)["status"], STORED)
        report = build_outcome(self.intent, reported_status="REPORTED_ROLLBACK",
                               observed_sha256="d" * 64)
        self.assertEqual(store_outcome(report, self.intent, self.wal)["status"], STORED)
        other = build_outcome(self.intent, reported_status="REPORTED_KEEP",
                              observed_sha256="e" * 64)
        self.assertEqual(store_outcome(other, self.intent, self.wal)["status"], IMMUTABILITY_VIOLATION)
        p = self.wal / (self.intent["intent_id"] + ".outcome.json")
        obj = json.loads(p.read_text(encoding="utf-8"))
        obj["reported_status"] = "REPORTED_KEEP"
        p.write_text(json.dumps(obj), encoding="utf-8")
        self.assertIn("OUTCOME_UNTRUSTED", inspect_intent(self.wal, self.intent["intent_id"])["reason"])

    def test_wrong_or_unhashable_status_is_not_accepted(self):
        self.assertIsNone(build_outcome(self.intent, reported_status="ALLOW", observed_sha256=None))
        self.assertIsNone(build_outcome(self.intent, reported_status=[], observed_sha256=None))

    def test_invalid_filename_or_missing_intent_holds(self):
        for identity in ("../escape", "no-intent", self.intent["intent_id"]):
            actual = inspect_intent(self.wal, identity)
            self.assertEqual(actual["status"], "HOLD")
            self.assertFalse(actual["recovery_authorized"])

    def test_symlink_store_is_denied(self):
        (self.root / "real").mkdir()
        try:
            self.wal.symlink_to(self.root / "real", target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink unavailable on this account: {exc}")
        self.assertEqual(store_intent(self.intent, self.wal)["status"], STORE_UNAVAILABLE)
        self.assertIn("UNSAFE", inspect_intent(self.wal, self.intent["intent_id"])["reason"])

    def test_concurrent_store_cannot_publish_two_versions(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: store_intent(self.intent, self.wal)["status"], range(16)))
        self.assertEqual(results.count(STORED), 1)
        self.assertEqual(results.count(IDEMPOTENT), 15)
        self.assertEqual(inspect_intent(self.wal, self.intent["intent_id"])["reason"], "UNRESOLVED_INTENT")

    def test_abrupt_process_exit_leaves_visible_unresolved_intent(self):
        # Le sous-processus ne fait AUCUN APPLY : il publie une intention dans
        # le dossier temporaire puis s'arrête sans exécuter de finalizer.
        worker = (
            "import json,os,sys\n"
            "from pathlib import Path\n"
            "from c2_write_intent_wal_v1 import store_intent,STORED\n"
            "x=store_intent(json.loads(sys.argv[2]),Path(sys.argv[1]))\n"
            "os._exit(17 if x['status']==STORED else 18)\n"
        )
        # L'environnement Python de tests est propagé, rien n'est ajouté à
        # un chemin global ni écrit hors de self.wal.
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2]) + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run([sys.executable, "-B", "-c", worker,
                                 str(self.wal), json.dumps(self.intent)],
                                cwd=self.root, env=env,
                                capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 17, result.stderr)
        status = inspect_intent(self.wal, self.intent["intent_id"])
        self.assertEqual(status["reason"], "UNRESOLVED_INTENT")
        self.assertTrue(status["quarantine_review_required"])


if __name__ == "__main__":
    unittest.main()
