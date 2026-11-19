"""G4K : processus synthétique réellement lancé, mais jamais attesté KX108."""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from c2_wal_machine_rsa_receipt_v1 import DOMAIN, canonical_payload
from c2_wal_runner_observation_g4k_v1 import (
    CHILD_BYTES, build_runner_observation, inspect_c2_wal_synthetic_runner_observation,
    verify_runner_observation,
)
from prepare_g4k_synthetic_subprocess_v1 import build_subprocess_fixture
from verify_g4k_synthetic_runner_v1 import main as verify_cli
from obsidia_governance_runtime_v1 import get_runtime
import test_c2_wal_machine_rsa_g4j_stdlib_v1 as _G4J

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:
    hashes = None


@unittest.skipUnless(hashes is not None, "optional cryptography unavailable")
class G4KSyntheticRunnerObservation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _G4J.G4JWalMachineRsa.setUpClass()
        cls.private = _G4J.G4JWalMachineRsa.private
        cls.pin = _G4J.G4JWalMachineRsa.pin
        cls.cert64 = _G4J.G4JWalMachineRsa.cert64

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="obsidia-g4k-runner-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "new-repo"
        self.fixture = build_subprocess_fixture(
            repo_root=self.root, machine_id="DESKTOP-Q5MD7J7",
            public_cert_pin=self.pin, source_git_head="f" * 40,
        )
        self.trace_path = Path(self.fixture["runner_trace_path"])
        self.source_path = self.root / "runner" / "g4k_synthetic_child_v1.py"
        self.input = {
            "wal_dir": self.fixture["wal_dir"],
            "repo_root": str(self.root),
            "intent_id": self.fixture["intent_id"],
            "receipt": self._signed(self.fixture["payload"]),
            "public_certificate_der_base64": self.cert64,
            "pinned_certificate_sha256": self.pin,
            "expected_machine_id": "DESKTOP-Q5MD7J7",
        }

    def _signed(self, payload):
        signature = self.private.sign(
            DOMAIN + canonical_payload(payload), padding.PKCS1v15(), hashes.SHA256())
        return {"payload": payload,
                "signature_base64": base64.b64encode(signature).decode("ascii")}

    def _inspect(self, data=None):
        args = self.input if data is None else data
        return get_runtime().inspect_c2_wal_synthetic_runner_observation(
            wal_dir=Path(args["wal_dir"]), repo_root=Path(args["repo_root"]),
            intent_id=args["intent_id"], receipt=args["receipt"],
            public_certificate_der_base64=args["public_certificate_der_base64"],
            pinned_certificate_sha256=args["pinned_certificate_sha256"],
            expected_machine_id=args["expected_machine_id"],
        )

    def _no_authority(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        for field in (
            "machine_identity_attested", "certificate_enrollment_approved",
            "producer_identity_attested", "responsible_person_authenticated",
            "process_execution_attested", "test_transcript_attested",
            "source_git_head_attested", "replay_prevented", "human_approval_verified",
            "kx108_ticket_issued", "execution_authorized", "recovery_authorized",
            "release_authorized", "target_mutated",
        ):
            self.assertIs(result[field], False, field)

    def test_real_synthetic_subprocess_capture_and_rsa_binds_without_authority(self):
        result = self._inspect()
        self._no_authority(result)
        self.assertTrue(result["machine_signature_verified"])
        self.assertTrue(result["synthetic_runner_record_verified"])
        self.assertTrue(result["synthetic_runner_live_source_hash_verified"])
        self.assertGreater(result["observed_child_pid"], 0)
        self.assertEqual(result["reason"], "G4K_SYNTHETIC_SUBPROCESS_TRACE_MATCH_NOT_ATTESTED")
        self.assertEqual(self.source_path.read_bytes(), CHILD_BYTES)

    def test_python_cli_pass_stays_hold(self):
        with patch("sys.stdin", io.StringIO(json.dumps(self.input))), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = verify_cli()
        self.assertEqual(rc, 0, output.getvalue())
        self.assertIn("REAL_RUNNER_EXECUTION_ATTESTED=False", output.getvalue())
        self.assertIn("RELEASE=HOLD", output.getvalue())

    def test_duplicate_json_keys_denied(self):
        text = json.dumps(self.input).replace('"wal_dir":', '"wal_dir":"fake","wal_dir":', 1)
        with patch("sys.stdin", io.StringIO(text)), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(verify_cli(), 2)
        self.assertIn("INPUT_JSON_INVALID", output.getvalue())

    def test_trace_mutation_to_invalid_json_denied(self):
        self.trace_path.write_text("BROKEN", encoding="utf-8")
        result = self._inspect()
        self._no_authority(result)
        self.assertIn("G4K_TRACE_OR_SOURCE_INVALID", result["reason"])

    def test_trace_semantic_tamper_denied(self):
        record = json.loads(self.trace_path.read_text(encoding="utf-8"))
        record["child_pid_observed"] += 1
        self.trace_path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")))
        self.assertIn("G4K_RUNNER_RECORD_CONTENT_OR_HASH_INVALID", self._inspect()["reason"])

    def test_reencoded_trace_rejected_even_if_identical_fields(self):
        record = json.loads(self.trace_path.read_text(encoding="utf-8"))
        self.trace_path.write_text(json.dumps(record, indent=1))
        self.assertIn("G4K_TRACE_NONCANONICAL", self._inspect()["reason"])

    def test_duplicate_trace_field_denied(self):
        raw = self.trace_path.read_text(encoding="utf-8").replace(
            '"schema":', '"schema":"fake","schema":', 1)
        self.trace_path.write_text(raw, encoding="utf-8")
        self.assertIn("G4K_TRACE_OR_SOURCE_INVALID", self._inspect()["reason"])

    def test_nonfinite_json_trace_is_fail_closed(self):
        self.trace_path.write_text('{"schema":NaN}', encoding="utf-8")
        self.assertIn("G4K_TRACE_OR_SOURCE_INVALID", self._inspect()["reason"])

    def test_live_runner_source_drift_denied(self):
        self.source_path.write_bytes(b"print('replacement')\n")
        self.assertIn("G4K_LIVE_SYNTHETIC_RUNNER_DRIFT", self._inspect()["reason"])

    def test_missing_trace_denied(self):
        self.trace_path.unlink()
        self.assertIn("G4K_TRACE_OR_SOURCE_UNAVAILABLE", self._inspect()["reason"])

    def test_missing_runner_denied(self):
        self.source_path.unlink()
        self.assertIn("G4K_TRACE_OR_SOURCE_UNAVAILABLE", self._inspect()["reason"])

    def test_replaced_signed_hash_denied(self):
        forged = copy.deepcopy(self.input)
        forged["receipt"] = self._signed({
            **forged["receipt"]["payload"], "tests_transcript_sha256": "d" * 64})
        self.assertIn("G4K_SIGNED_RUNNER_TRACE_BINDING_MISMATCH",
                      self._inspect(forged)["reason"])

    def test_signature_tamper_denied(self):
        forged = copy.deepcopy(self.input)
        forged["receipt"]["payload"]["source_git_head"] = "a" * 40
        self.assertIn("SIGNATURE_MISMATCH", self._inspect(forged)["reason"])

    def test_other_machine_denied_even_with_same_signature(self):
        forged = copy.deepcopy(self.input)
        forged["expected_machine_id"] = "DESKTOP-SDOG0EL"
        self.assertIn("SCOPE_OR_IDENTITY_INVALID", self._inspect(forged)["reason"])

    def test_wrong_certificate_pin_denied(self):
        forged = copy.deepcopy(self.input)
        forged["pinned_certificate_sha256"] = "0" * 64
        self.assertIn("PUBLIC_CERTIFICATE_PIN_MISMATCH", self._inspect(forged)["reason"])

    def test_second_inspection_does_not_prove_replay_prevention(self):
        self.assertTrue(self._inspect()["machine_signature_verified"])
        again = self._inspect()
        self.assertTrue(again["machine_signature_verified"])
        self.assertFalse(again["replay_prevented"])

    def test_untrusted_process_pid_is_not_attested(self):
        data = json.loads(self.trace_path.read_text(encoding="utf-8"))
        self.assertGreater(data["child_pid_observed"], 0)
        self.assertFalse(self._inspect()["process_execution_attested"])

    def test_reuse_existing_root_refused(self):
        with self.assertRaises(ValueError):
            build_subprocess_fixture(repo_root=self.root, machine_id="DESKTOP-Q5MD7J7",
                                     public_cert_pin=self.pin, source_git_head="f" * 40)

    def test_fabricated_synthetic_stdout_rejected_by_builder(self):
        from c2_write_intent_wal_v1 import load_verified_intent, load_verified_outcome
        intent = load_verified_intent(Path(self.input["wal_dir"]), self.input["intent_id"])
        outcome = load_verified_outcome(Path(self.input["wal_dir"]), intent)
        self.assertIsNone(build_runner_observation(
            intent=intent, outcome=outcome, machine_id="DESKTOP-Q5MD7J7",
            run_nonce="c" * 64, child_pid=42, child_exit_code=0,
            stdout=b"FAKE", stderr=b""))

    def test_nonzero_child_exit_not_accepted(self):
        from c2_write_intent_wal_v1 import load_verified_intent, load_verified_outcome
        intent = load_verified_intent(Path(self.input["wal_dir"]), self.input["intent_id"])
        outcome = load_verified_outcome(Path(self.input["wal_dir"]), intent)
        self.assertIsNone(build_runner_observation(
            intent=intent, outcome=outcome, machine_id="DESKTOP-Q5MD7J7",
            run_nonce="c" * 64, child_pid=42, child_exit_code=1,
            stdout=b"OBSIDIA_G4K_SYNTHETIC_RESULT_V1|" + b"c" * 64 + b"\n", stderr=b""))

    def test_runtime_has_one_readonly_inspector_not_executor(self):
        self.assertTrue(callable(get_runtime().inspect_c2_wal_synthetic_runner_observation))
        self.assertEqual(get_runtime().capabilities()["apply"], "HOLD")
        self.assertFalse(get_runtime().capabilities()["target_mutated"])


if __name__ == "__main__":
    unittest.main()
