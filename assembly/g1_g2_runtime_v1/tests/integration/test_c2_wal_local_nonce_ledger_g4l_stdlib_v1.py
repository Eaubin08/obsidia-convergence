"""G4L : réservation exclusive locale, rejouement refusé, aucun droit KX108."""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from c2_wal_machine_rsa_receipt_v1 import DOMAIN, canonical_payload
from c2_wal_local_nonce_ledger_g4l_v1 import reserve_synthetic_nonce_testonly
from prepare_g4k_synthetic_subprocess_v1 import build_subprocess_fixture
from verify_g4l_local_nonce_v1 import main as verify_cli
from obsidia_governance_runtime_v1 import get_runtime
import test_c2_wal_machine_rsa_g4j_stdlib_v1 as _G4J

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:
    hashes = None


@unittest.skipUnless(hashes is not None, "optional cryptography unavailable")
class G4LLocalReplayLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _G4J.G4JWalMachineRsa.setUpClass()
        cls.private = _G4J.G4JWalMachineRsa.private
        cls.cert64 = _G4J.G4JWalMachineRsa.cert64
        cls.pin = _G4J.G4JWalMachineRsa.pin

    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="obsidia-g4l-ledger-")
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name) / "new-root"
        self.fixture = build_subprocess_fixture(
            repo_root=self.root, machine_id="DESKTOP-Q5MD7J7",
            public_cert_pin=self.pin, source_git_head="b" * 40)
        signature = self.private.sign(
            DOMAIN + canonical_payload(self.fixture["payload"]),
            padding.PKCS1v15(), hashes.SHA256())
        self.input = {
            "wal_dir": self.fixture["wal_dir"], "repo_root": str(self.root),
            "intent_id": self.fixture["intent_id"],
            "receipt": {"payload": self.fixture["payload"],
                        "signature_base64": base64.b64encode(signature).decode("ascii")},
            "public_certificate_der_base64": self.cert64,
            "pinned_certificate_sha256": self.pin,
            "expected_machine_id": "DESKTOP-Q5MD7J7",
        }

    def _reserve(self, input_data=None):
        d = self.input if input_data is None else input_data
        return reserve_synthetic_nonce_testonly(
            wal_dir=Path(d["wal_dir"]), repo_root=Path(d["repo_root"]),
            intent_id=d["intent_id"], receipt=d["receipt"],
            public_certificate_der_base64=d["public_certificate_der_base64"],
            pinned_certificate_sha256=d["pinned_certificate_sha256"],
            expected_machine_id=d["expected_machine_id"])

    def _ledger_paths(self):
        return list((self.root / "wal" / "g4l-local-testonly-ledger").glob("nonce-*.json"))

    def _assert_no_authority(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        for key in (
            "ledger_is_trusted", "replay_prevented", "producer_identity_attested",
            "process_execution_attested", "responsible_person_authenticated",
            "certificate_enrollment_approved", "human_approval_verified",
            "kx108_ticket_issued", "execution_authorized", "recovery_authorized",
            "release_authorized", "target_mutated",
        ):
            self.assertIs(result[key], False, key)

    def test_first_reservation_persists_but_is_not_sovereign(self):
        res = self._reserve()
        self._assert_no_authority(res)
        self.assertEqual(res["reason"], "G4L_NONCE_RESERVED_LOCAL_UNTRUSTED")
        self.assertTrue(res["local_nonce_reserved"])
        self.assertEqual(len(self._ledger_paths()), 1)

    def test_second_reservation_is_refused_without_modifying_record(self):
        self.assertTrue(self._reserve()["local_nonce_reserved"])
        path = self._ledger_paths()[0]
        original = path.read_bytes()
        res = self._reserve()
        self._assert_no_authority(res)
        self.assertEqual(res["reason"], "G4L_LOCAL_REPLAY_DUPLICATE_DENIED")
        self.assertTrue(res["local_duplicate_denied"])
        self.assertEqual(path.read_bytes(), original)

    def test_independent_python_processes_reject_replay(self):
        cli = ROOT / "tools" / "verify_g4l_local_nonce_v1.py"
        cmd = [sys.executable, "-B", str(cli)]
        payload = json.dumps(self.input)
        first = subprocess.run(cmd + ["--reserve"], input=payload, text=True,
                               capture_output=True, timeout=15)
        second = subprocess.run(cmd + ["--deny-replay"], input=payload, text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("LOCAL_REPLAY_DENIAL_PASS=True", second.stdout)

    def test_parallel_reservations_only_one_wins(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _x: self._reserve(), range(6)))
        self.assertEqual(sum(r["local_nonce_reserved"] for r in results), 1)
        self.assertEqual(sum(r["local_duplicate_denied"] for r in results), 5)
        self.assertEqual(len(self._ledger_paths()), 1)

    def test_partially_written_file_remains_quarantined(self):
        self._reserve()
        self._ledger_paths()[0].write_bytes(b'{"incomplete":')
        res = self._reserve()
        self._assert_no_authority(res)
        self.assertEqual(res["reason"], "G4L_NONCE_FILE_CORRUPT_QUARANTINE")
        self.assertTrue(res["local_duplicate_denied"])

    def test_modified_record_hash_quarantined(self):
        self._reserve()
        path = self._ledger_paths()[0]
        record = json.loads(path.read_text(encoding="utf-8"))
        record["outcome_record_hash"] = "e" * 64
        path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")))
        self.assertEqual(self._reserve()["reason"], "G4L_NONCE_FILE_CORRUPT_QUARANTINE")

    def test_reformatted_record_quarantined(self):
        self._reserve()
        path = self._ledger_paths()[0]
        record = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps(record, indent=2))
        self.assertEqual(self._reserve()["reason"], "G4L_NONCE_FILE_CORRUPT_QUARANTINE")

    def test_duplicate_fields_in_local_ledger_quarantined(self):
        self._reserve()
        path = self._ledger_paths()[0]
        raw = path.read_text(encoding="utf-8").replace(
            '"schema":', '"schema":"forged","schema":', 1)
        path.write_text(raw)
        self.assertEqual(self._reserve()["reason"], "G4L_NONCE_FILE_CORRUPT_QUARANTINE")

    def test_untrusted_local_ledger_deletion_can_reenable_nonce(self):
        self._reserve()
        self._ledger_paths()[0].unlink()  # uniquement scénario tempfile
        result = self._reserve()
        self.assertTrue(result["local_nonce_reserved"])
        self.assertFalse(result["replay_prevented"])
        self.assertFalse(result["ledger_is_trusted"])

    def test_wrong_machine_rejected_before_reservation(self):
        data = copy.deepcopy(self.input)
        data["expected_machine_id"] = "DESKTOP-SDOG0EL"
        res = self._reserve(data)
        self.assertIn("G4K_G4J_SIGNATURE_REQUIRED", res["reason"])
        self.assertFalse(self._ledger_paths())

    def test_wrong_certificate_pin_rejected(self):
        data = copy.deepcopy(self.input)
        data["pinned_certificate_sha256"] = "0" * 64
        self.assertFalse(self._reserve(data)["local_nonce_reserved"])
        self.assertFalse(self._ledger_paths())

    def test_tampered_signature_rejected_without_file(self):
        data = copy.deepcopy(self.input)
        data["receipt"]["payload"]["nonce"] = "1" * 64
        self.assertFalse(self._reserve(data)["local_nonce_reserved"])
        self.assertFalse(self._ledger_paths())

    def test_current_target_drift_denies_new_reservation(self):
        target = self.root / "targets" / "synthetic.txt"
        target.write_bytes(b"POSTIMAGE_CHANGED")
        self.assertFalse(self._reserve()["local_nonce_reserved"])
        self.assertFalse(self._ledger_paths())

    def test_noncanonical_root_rejected(self):
        data = copy.deepcopy(self.input)
        data["wal_dir"] = str(self.root / "different-wal")
        res = self._reserve(data)
        self.assertFalse(res["local_nonce_reserved"])

    def test_cli_rejects_duplicate_json_fields(self):
        data = json.dumps(self.input).replace('"wal_dir":', '"wal_dir":"bad","wal_dir":', 1)
        with patch("sys.argv", ["verify", "--reserve"]), \
                patch("sys.stdin", io.StringIO(data)), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(verify_cli(), 2)
        self.assertIn("INPUT_JSON_INVALID", out.getvalue())

    def test_runtime_does_not_expose_ledger_mutation(self):
        runtime = get_runtime()
        self.assertFalse(hasattr(runtime, "reserve_synthetic_nonce_testonly"))
        self.assertEqual(runtime.capabilities()["apply"], "HOLD")
        self.assertFalse(runtime.capabilities()["target_mutated"])


if __name__ == "__main__":
    unittest.main()
