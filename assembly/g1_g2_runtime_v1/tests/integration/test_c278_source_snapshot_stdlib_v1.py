"""Preuves et refus du snapshot C278, avec clé éphémère de test uniquement."""
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
TOOLS = ROOT / "tools"
for path in (ROOT, TOOLS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import obsidure_c278_source_snapshot_v1 as snapshot
import sign_and_verify_c278_source_portable_v1 as cli

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def observed():
    return {
        "status": "C278_STATIC_SOURCE_PROFILE_ONLY",
        "machine": snapshot.MACHINE,
        "required_symbols_present": True,
        "git_head": snapshot.OBSERVED_HEAD,
        "git_branch": "feat/gencoin-world-bus-dryrun-v1",
        "files": {name: {"sha256": sha, "bytes": 42} for name, sha in snapshot.EXPECTED_SOURCES.items()},
        "test_process_attested": False,
    }


class C278SnapshotStatic(unittest.TestCase):
    def test_prepare_has_exact_fields_and_no_authority(self):
        result = snapshot.prepare_snapshot(observed(), nonce="f" * 32)
        self.assertEqual(result["status"], "READY_FOR_LOCAL_KEY_SIGNING")
        self.assertEqual(set(result["payload"]), snapshot._FIELDS)
        self.assertFalse(result["payload"]["test_process_attested"])
        self.assertFalse(result["payload"]["execution_authorized"])
        self.assertTrue(base64.b64decode(result["message_base64"]).startswith(snapshot.DOMAIN))

    def test_reject_changed_source_or_unknown_source(self):
        bad = observed()
        bad["files"]["periphery/agents/obsidure_repair_bridge.py"]["sha256"] = "a" * 64
        self.assertEqual(snapshot.prepare_snapshot(bad, nonce="f" * 32)["status"], "HOLD")
        bad = observed()
        bad["files"]["extra.py"] = {}
        self.assertEqual(snapshot.prepare_snapshot(bad, nonce="f" * 32)["status"], "HOLD")

    def test_bad_git_metadata_or_nonce_holds(self):
        bad = observed()
        bad["git_head"] = "NO_HEAD"
        self.assertEqual(snapshot.prepare_snapshot(bad, nonce="f" * 32)["status"], "HOLD")
        self.assertEqual(snapshot.prepare_snapshot(observed(), nonce="not-a-nonce")["status"], "HOLD")

    def test_broken_envelope_and_untrusted_authority_hold(self):
        self.assertEqual(snapshot.verify_snapshot({}, observed())["status"], "HOLD")
        self.assertEqual(snapshot.verify_snapshot({"payload": {"decision_authority": "KX108"}}, observed())["status"], "HOLD")

    def test_cli_duplicate_keys_refused(self):
        with patch("sys.stdin", io.StringIO('{"a":1,"a":2}')), patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(cli.main(["--verify"]), 2)
            self.assertIn("HOLD", out.getvalue())

    def test_cli_never_inspects_wrong_machine_as_success(self):
        with patch.object(cli, "inspect_portable_fix", return_value={"status": "HOLD"}), \
                patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(cli.main(["--prepare"]), 2)


@unittest.skipUnless(CRYPTO_AVAILABLE, "cryptography unavailable: real RSA checks not executed")
class C278SnapshotRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                            "OBSIDIA-OBSIDURE-" + snapshot.MACHINE)])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(cls.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ), critical=True).sign(cls.key, hashes.SHA256()))
        cls.cert = cert.public_bytes(serialization.Encoding.DER)
        cls.cert_sha = hashlib.sha256(cls.cert).hexdigest()

    def setUp(self):
        p = patch.object(snapshot, "PUBLIC_SHA256", self.cert_sha)
        p.start()
        self.addCleanup(p.stop)
        self.source = observed()
        self.prepared = snapshot.prepare_snapshot(self.source, nonce="a" * 32)
        message = base64.b64decode(self.prepared["message_base64"])
        signature = self.key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        self.envelope = {
            "payload": self.prepared["payload"],
            "message_base64": self.prepared["message_base64"],
            "signature_base64": base64.b64encode(signature).decode("ascii"),
            "public_certificate_der_base64": base64.b64encode(self.cert).decode("ascii"),
        }

    def test_real_rsa_verification_proves_only_source(self):
        result = snapshot.verify_snapshot(self.envelope, self.source)
        self.assertEqual(result["status"], "C278_SOURCE_SNAPSHOT_RSA_MATCH_NO_TEST_PROVENANCE")
        self.assertTrue(result["source_hashes_match"])
        for field in ("test_process_attested", "test_isolation_certified", "enrollment_approved",
                      "execution_authorized", "release_authorized", "replay_prevented"):
            self.assertFalse(result[field])

    def test_modified_test_authority_flag_rejected_even_if_original_signed(self):
        for field in ("test_process_attested", "execution_authorized", "release_authorized"):
            bad = copy.deepcopy(self.envelope)
            bad["payload"][field] = True
            self.assertEqual(snapshot.verify_snapshot(bad, self.source)["status"], "HOLD")

    def test_replaced_message_and_signature_rejected(self):
        bad = copy.deepcopy(self.envelope)
        bad["message_base64"] = base64.b64encode(b"forged").decode("ascii")
        self.assertEqual(snapshot.verify_snapshot(bad, self.source)["status"], "HOLD")
        bad = copy.deepcopy(self.envelope)
        bad["signature_base64"] = base64.b64encode(b"0" * 384).decode("ascii")
        self.assertEqual(snapshot.verify_snapshot(bad, self.source)["status"], "HOLD")

    def test_source_or_head_drift_rejected_after_signing(self):
        changed = observed()
        changed["files"]["periphery/agents/obsidure_repair_contract.py"]["sha256"] = "0" * 64
        self.assertEqual(snapshot.verify_snapshot(self.envelope, changed)["status"], "HOLD")
        changed = observed()
        changed["git_head"] = "0" * 40
        self.assertEqual(snapshot.verify_snapshot(self.envelope, changed)["status"], "HOLD")

    def test_certificate_pin_and_extra_fields_rejected(self):
        bad = copy.deepcopy(self.envelope)
        bad["payload"]["public_certificate_sha256"] = "0" * 64
        self.assertEqual(snapshot.verify_snapshot(bad, self.source)["status"], "HOLD")
        bad = copy.deepcopy(self.envelope)
        bad["payload"]["sovereign_ticket"] = "ALLOW"
        self.assertEqual(snapshot.verify_snapshot(bad, self.source)["status"], "HOLD")

    def test_cli_verification_with_mock_source_and_real_rsa(self):
        with patch.object(cli, "inspect_portable_fix", return_value=self.source), \
                patch("sys.stdin", io.StringIO(json.dumps(self.envelope))), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(cli.main(["--verify"]), 0)
            self.assertIn("NO_TEST_PROVENANCE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
