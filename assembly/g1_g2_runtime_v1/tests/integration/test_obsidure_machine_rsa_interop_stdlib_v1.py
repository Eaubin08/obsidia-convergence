"""Contrat Windows/.NET -> Python, avec une clé RSA uniquement synthétique."""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts", ROOT / "tools"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from obsidure_machine_rsa_interop_v1 import (
    _DOMAIN, inspect_machine_rsa_interop_challenge,
)
from verify_obsidure_machine_challenge_v1 import main as cli_main

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None

MACHINE = "DESKTOP-Q5MD7J7"


@unittest.skipUnless(x509 is not None, "optional cryptography unavailable")
class MachineRsaWindowsPythonInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                             "OBSIDIA-OBSIDURE-" + MACHINE)])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(cls.private.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ), critical=True).sign(cls.private, hashes.SHA256()))
        cls.der = cert.public_bytes(serialization.Encoding.DER)
        cls.pin = hashlib.sha256(cls.der).hexdigest()

    def setUp(self):
        self.challenge = _DOMAIN + MACHINE.encode("ascii") + b"|" + b"a" * 32
        self.envelope = self._build(self.challenge)

    def _build(self, message):
        signature = self.private.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return {
            "schema": "OBSIDURE_WINDOWS_RSA_INTEROP_CHALLENGE_V1",
            "expected_machine_id": MACHINE,
            "public_certificate_der_base64": base64.b64encode(self.der).decode("ascii"),
            "pinned_certificate_sha256": self.pin,
            "challenge_base64": base64.b64encode(message).decode("ascii"),
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }

    def test_in_memory_signature_matches_but_release_remains_hold(self):
        result = inspect_machine_rsa_interop_challenge(self.envelope)
        self.assertEqual(result["status"], "MACHINE_RSA_INTEROP_VERIFIED_NOT_C278_PROVENANCE")
        self.assertTrue(result["machine_signature_verified"])
        self.assertTrue(result["tampered_challenge_rejected"])
        for field in ("producer_identity_attested", "machine_identity_attested",
                      "certificate_enrollment_approved", "test_process_attested",
                      "execution_authorized", "release_authorized", "action_ticket_issued",
                      "human_approval_verified", "replay_prevented", "target_mutated"):
            self.assertIs(result[field], False, field)

    def test_modified_nonce_with_original_signature_is_hold(self):
        changed = copy.deepcopy(self.envelope)
        changed["challenge_base64"] = base64.b64encode(
            _DOMAIN + MACHINE.encode("ascii") + b"|" + b"b" * 32,
        ).decode("ascii")
        self.assertEqual(inspect_machine_rsa_interop_challenge(changed)["reason"],
                         "MACHINE_RSA_INTEROP:C278_MACHINE_RSA_SIGNATURE_MISMATCH")

    def test_wrong_cert_pin_is_hold(self):
        changed = copy.deepcopy(self.envelope)
        changed["pinned_certificate_sha256"] = "0" * 64
        self.assertEqual(inspect_machine_rsa_interop_challenge(changed)["reason"],
                         "MACHINE_RSA_INTEROP_CERTIFICATE_PIN_MISMATCH")

    def test_declared_other_machine_is_hold(self):
        changed = copy.deepcopy(self.envelope)
        changed["expected_machine_id"] = "DESKTOP-SDOG0EL"
        self.assertEqual(inspect_machine_rsa_interop_challenge(changed)["reason"],
                         "MACHINE_RSA_INTEROP_CHALLENGE_DOMAIN_INVALID")

    def test_extra_authority_field_is_hold(self):
        changed = copy.deepcopy(self.envelope)
        changed["release_authorized"] = True
        self.assertEqual(inspect_machine_rsa_interop_challenge(changed)["reason"],
                         "MACHINE_RSA_INTEROP_ENVELOPE_INVALID")

    def test_invalid_domain_is_hold_even_when_resigned(self):
        changed = self._build(b"other domain\x00" + MACHINE.encode() + b"|" + b"a" * 32)
        self.assertEqual(inspect_machine_rsa_interop_challenge(changed)["reason"],
                         "MACHINE_RSA_INTEROP_CHALLENGE_DOMAIN_INVALID")

    def test_repeated_challenge_does_not_pretend_anti_replay(self):
        a = inspect_machine_rsa_interop_challenge(self.envelope)
        b = inspect_machine_rsa_interop_challenge(self.envelope)
        self.assertTrue(a["machine_signature_verified"])
        self.assertFalse(b["replay_prevented"])

    def test_invalid_signature_is_hold(self):
        changed = copy.deepcopy(self.envelope)
        changed["signature_base64"] = base64.b64encode(b"0" * 384).decode("ascii")
        self.assertEqual(inspect_machine_rsa_interop_challenge(changed)["reason"],
                         "MACHINE_RSA_INTEROP:C278_MACHINE_RSA_SIGNATURE_MISMATCH")

    def test_cli_main_is_readonly_and_refuses_duplicate_json_fields(self):
        with patch("sys.stdin", io.StringIO(json.dumps(self.envelope))), \
                patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(cli_main(), 0)
            self.assertIn("OBSIDURE_WINDOWS_PYTHON_RSA_INTEROP_PASS=True", stdout.getvalue())
            self.assertIn("RELEASE=HOLD", stdout.getvalue())
        dup = json.dumps(self.envelope).replace('"schema":', '"schema":"FAKE","schema":', 1)
        with patch("sys.stdin", io.StringIO(dup)), \
                patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(cli_main(), 2)
            self.assertIn("INPUT_JSON_INVALID", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
