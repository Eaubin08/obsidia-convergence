"""G4O : vérification anti-réemploi de clé et script Windows sans effet implicite."""
from __future__ import annotations

import base64
import copy
import hashlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from obsidia_governance_runtime_v1 import get_runtime
from verify_g4n_admin_modes_v1 import build_fixture, synthetic_founder

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None


@unittest.skipUnless(x509 is not None, "optional cryptography unavailable")
class FounderKeySeparationG4O(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = build_fixture(members=1)

    def setUp(self):
        self.plan, self.registry, _ = copy.deepcopy(self.source)
        self.runtime = get_runtime()

    def check(self):
        return self.runtime.inspect_obsidure_admin_bootstrap(
            plan=self.plan, machine_registry=self.registry)

    def test_verified_public_founder_key_is_not_independent_approval(self):
        result = self.check()
        self.assertTrue(result["founder_key_registry_conflict_absent"])
        self.assertIs(result["founder_key_separate_from_pc"], False)
        self.assertIs(result["founder_trust_anchor_verified"], False)
        self.assertIs(result["machine_enrollment_approved"], False)

    def test_same_rsa_key_reissued_in_different_certificate_is_denied(self):
        key, cert64, pin = synthetic_founder()
        self.plan["founder"]["public_certificate_der_base64"] = cert64
        self.plan["founder"]["public_certificate_sha256"] = pin
        # Nouveau certificat avec nom/serial différents, mais MÊME clé RSA.
        subject = x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, "OBSIDIA-OBSIDURE-DESKTOP-Q5MD7J7")])
        now = datetime.now(timezone.utc)
        machine_cert = (x509.CertificateBuilder()
                        .subject_name(subject).issuer_name(subject)
                        .public_key(key.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(now - timedelta(days=1))
                        .not_valid_after(now + timedelta(days=10))
                        .sign(key, hashes.SHA256()))
        machine_der = machine_cert.public_bytes(serialization.Encoding.DER)
        machine_pin = hashlib.sha256(machine_der).hexdigest()
        self.assertNotEqual(machine_pin, pin)
        entry = self.registry["machine_identities"][0]
        entry["enrollment_state"] = "ENROLLED_AWAITING_REVIEW"
        entry["public_certificate_der_base64"] = base64.b64encode(machine_der).decode("ascii")
        entry["public_certificate_sha256"] = machine_pin
        result = self.check()
        self.assertEqual(result["reason"],
                         "G4O_FOUNDER_REISSUED_CERTIFICATE_SAME_PC_KEY_DENIED")
        self.assertIs(result["founder_key_separate_from_pc"], False)

    def test_unparseable_certificate_for_enrolled_machine_fails_closed(self):
        entry = self.registry["machine_identities"][0]
        fake_der = b"not-an-x509-certificate" * 25
        entry["enrollment_state"] = "ENROLLED_AWAITING_REVIEW"
        entry["public_certificate_der_base64"] = base64.b64encode(fake_der).decode("ascii")
        entry["public_certificate_sha256"] = hashlib.sha256(fake_der).hexdigest()
        self.assertIn("G4O_MACHINE_CERTIFICATE_NOT_CRYPTO_VERIFIABLE", self.check()["reason"])

    def test_unparseable_founder_certificate_fails_closed(self):
        fake_der = b"not-an-x509-certificate" * 25
        self.plan["founder"]["public_certificate_der_base64"] = base64.b64encode(fake_der).decode("ascii")
        self.plan["founder"]["public_certificate_sha256"] = hashlib.sha256(fake_der).hexdigest()
        self.assertIn("G4O_FOUNDER_CERTIFICATE_NOT_CRYPTO_VERIFIABLE", self.check()["reason"])

    def test_windows_enroll_requires_explicit_switch(self):
        source = (ROOT / "tools" / "enroll_obsidure_founder_admin_windows_g4o_v1.ps1").read_text(encoding="utf-8")
        self.assertIn("[switch]$Enroll", source)
        self.assertIn("if (-not $Enroll)", source)
        self.assertIn("MODE=CHECK_ONLY", source)
        self.assertIn("return", source)
        self.assertIn("New-SelfSignedCertificate @params", source)
        self.assertIn("KeyExportPolicy = 'NonExportable'", source)
        self.assertIn("FOUNDER_INDEPENDENTLY_APPROVED=False", source)

    def test_windows_provision_has_distinct_subject_and_root_guard(self):
        source = (ROOT / "tools" / "enroll_obsidure_founder_admin_windows_g4o_v1.ps1").read_text(encoding="utf-8")
        self.assertIn("CN=OBSIDIA-ADMIN-FOUNDER-ETIENNE", source)
        self.assertIn("CN=OBSIDIA-OBSIDURE-DESKTOP-Q5MD7J7", source)
        self.assertIn("DESKTOP-Q5MD7J7", source)
        self.assertIn("Get-RsaPublicMaterial", source)
        self.assertIn("G4O_FOUNDER_PC_RSA_KEY_REUSE_DENIED", source)
        self.assertIn("PUBLIC_PROPOSAL_EXISTS_NO_OVERWRITE", source)

    def test_no_new_activate_or_approve_api(self):
        self.assertFalse(hasattr(self.runtime, "activate_team_mode"))
        self.assertFalse(hasattr(self.runtime, "enroll_founder"))
        self.assertEqual(self.runtime.capabilities()["apply"], "HOLD")


if __name__ == "__main__":
    unittest.main()
