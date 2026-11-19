"""Contrat du scénario WAL Windows/G4J : clés RSA purement synthétiques."""
from __future__ import annotations

import base64
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

from prepare_g4j_wal_synthetic_fixture_v1 import build_fixture
from verify_g4j_wal_receipt_v1 import main as verify_cli
import test_c2_wal_machine_rsa_g4j_stdlib_v1 as _G4J

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:
    hashes = None


@unittest.skipUnless(hashes is not None, "optional cryptography unavailable")
class G4JWindowsFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _G4J.G4JWalMachineRsa.setUpClass()
        cls.private = _G4J.G4JWalMachineRsa.private
        cls.cert64 = _G4J.G4JWalMachineRsa.cert64
        cls.pin = _G4J.G4JWalMachineRsa.pin

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="obsidia-g4j-windows-fixture-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "synthetic-new-root"
        self.fixture = build_fixture(
            repo_root=self.root, machine_id="DESKTOP-Q5MD7J7",
            public_cert_pin=self.pin, source_git_head="a" * 40)
        message = base64.b64decode(self.fixture["signing_message_base64"])
        signature = self.private.sign(message, padding.PKCS1v15(), hashes.SHA256())
        self.envelope = {
            "wal_dir": self.fixture["wal_dir"],
            "repo_root": self.fixture["repo_root"],
            "intent_id": self.fixture["intent_id"],
            "receipt": {
                "payload": self.fixture["payload"],
                "signature_base64": base64.b64encode(signature).decode("ascii"),
            },
            "public_certificate_der_base64": self.cert64,
            "pinned_certificate_sha256": self.pin,
            "expected_machine_id": "DESKTOP-Q5MD7J7",
        }

    def _run(self, text):
        with patch("sys.stdin", io.StringIO(text)), \
                patch("sys.stdout", new_callable=io.StringIO) as stdout:
            status = verify_cli()
        return status, stdout.getvalue()

    def test_synthetic_wal_and_key_proof_end_to_end_no_release(self):
        code, output = self._run(json.dumps(self.envelope))
        self.assertEqual(code, 0, output)
        self.assertIn("OBSIDIA_G4J_WAL_MACHINE_RSA_PASS=True", output)
        self.assertIn("PRODUCER_ORIGIN_ATTESTED=False", output)
        self.assertIn("RELEASE=HOLD", output)

    def test_signing_message_is_domain_separated(self):
        raw = base64.b64decode(self.fixture["signing_message_base64"])
        self.assertTrue(raw.startswith(b"OBSIDIA_G4J_C2_WAL_MACHINE_RSA_V1\x00"))
        self.assertEqual(self.root.joinpath("targets", "synthetic.txt").read_bytes(),
                         b"G4J_SYNTHETIC_POSTIMAGE")

    def test_rejects_duplicate_json_fields(self):
        raw = json.dumps(self.envelope).replace('"wal_dir":',
                                                '"wal_dir":"fake","wal_dir":', 1)
        code, output = self._run(raw)
        self.assertEqual(code, 2)
        self.assertIn("INPUT_JSON_INVALID", output)

    def test_signature_tamper_still_fails_via_cli(self):
        data = json.loads(json.dumps(self.envelope))
        data["receipt"]["payload"]["nonce"] = "f" * 64
        code, output = self._run(json.dumps(data))
        self.assertEqual(code, 2)
        self.assertIn("SIGNATURE_MISMATCH", output)

    def test_fixture_builder_refuses_to_overwrite_existing_root(self):
        with self.assertRaises(ValueError):
            build_fixture(repo_root=self.root, machine_id="DESKTOP-Q5MD7J7",
                          public_cert_pin=self.pin, source_git_head="a" * 40)


if __name__ == "__main__":
    unittest.main()
