"""Un MAC C278 synthétique n'est pas une attestation du runner Obsidure.

Clé exclusivement dans la fixture ; aucun secret KX108 ou test réel.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
import test_obsidure_c278_sandbox_observation_stdlib_v1 as _fixture_module

KEY = b"unit-only-not-a-real-issuer-key-32-bytes-2026"
ISSUER = "synthetic-obsidure-runner"
KEY_ID = "synthetic-independent-key-v1"
DOMAIN = b"OBSIDIA_OBSIDURE_C278_RECEIPT_V1\x00"


def digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()


def sign(payload, key=KEY):
    body = json.dumps(
        payload, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hmac.new(key, DOMAIN + body, hashlib.sha256).hexdigest()


class C278SignedReceiptContract(unittest.TestCase):
    def setUp(self):
        self.fixture = _fixture_module.C278SandboxObservation(
            "test_c278_canonical_replay_and_sandbox_bytes_are_only_observed"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.runtime = ObsidiaGovernanceRuntime()
        f = self.fixture
        self.kwargs = dict(
            r10_inspection=f.r10, repair_request=f.request,
            repair_proposal=f.proposal, c278_evidence=f.c278,
            repair_verdict=f.verdict, repo_root=f.root,
            trusted_issuer_id=ISSUER, trusted_key_id=KEY_ID,
            verifier_key=KEY,
        )
        self.payload = dict(
            schema="OBSIDURE_C278_DETACHED_HMAC_RECEIPT_V1",
            issuer_id=ISSUER, key_id=KEY_ID,
            receipt_id="receipt-synthetic-001", nonce="f" * 64,
            request_id=f.request["request_id"],
            proposal_id=f.proposal["proposal_id"],
            verdict_id=f.verdict["verdict_id"],
            repair_request_sha256=digest(f.request),
            repair_proposal_sha256=digest(f.proposal),
            c278_evidence_sha256=digest(f.c278),
            repair_verdict_sha256=digest(f.verdict),
            candidate_artifact_sha256={f.target: hashlib.sha256(f.content.encode()).hexdigest()},
            source_git_head="1" * 40, runner_code_sha256="2" * 64,
            tests_transcript_sha256="3" * 64,
        )

    def verify(self, payload=None, signature=None, **kwargs):
        data = self.payload if payload is None else payload
        envelope = {"payload": data, "hmac_sha256": sign(data) if signature is None else signature}
        return self.runtime.inspect_obsidure_c278_signed_receipt(
            **{**self.kwargs, **kwargs}, receipt=envelope,
        )

    def test_matching_synthetic_mac_remains_unattested_and_readonly(self):
        f = self.fixture
        paths = [f.root / f.target, f.sandbox / f.target]
        before = [p.read_bytes() for p in paths]
        result = self.verify()
        self.assertEqual(result["status"], "C278_RECEIPT_HMAC_MATCH_ORIGIN_UNATTESTED")
        self.assertTrue(result["receipt_hmac_verified"])
        for field in (
            "producer_identity_attested", "sandbox_origin_attested",
            "test_process_attested", "test_isolation_certified",
            "live_git_head_verified", "replay_prevented", "provenance_verified",
            "human_approval_verified", "execution_authorized", "release_authorized",
            "action_ticket_issued", "target_mutated", "executor_invoked",
        ):
            self.assertIs(result[field], False, field)
        self.assertEqual(before, [p.read_bytes() for p in paths])

    def test_no_separate_trust_key_is_hold(self):
        result = self.verify(verifier_key=None)
        self.assertEqual(result["reason"], "C278_INDEPENDENT_TRUST_KEY_MISSING")
        self.assertFalse(result["receipt_hmac_verified"])

    def test_forged_or_truncated_mac_is_hold(self):
        self.assertEqual(self.verify(signature="0" * 64)["reason"], "C278_RECEIPT_MAC_MISMATCH")
        self.assertEqual(self.verify(signature="0" * 12)["reason"], "C278_RECEIPT_FIELDS_INVALID")
        self.assertEqual(self.verify(verifier_key=b"different-secret-not-valid-for-receipt")['reason'],
                         "C278_RECEIPT_MAC_MISMATCH")

    def test_lineage_or_artifact_substitution_is_hold_even_when_resigned(self):
        forged = copy.deepcopy(self.payload)
        forged["proposal_id"] = "other-proposal"
        self.assertEqual(self.verify(forged)["reason"], "C278_RECEIPT_LINEAGE_MISMATCH")
        forged = copy.deepcopy(self.payload)
        forged["candidate_artifact_sha256"][self.fixture.target] = "a" * 64
        self.assertEqual(self.verify(forged)["reason"], "C278_RECEIPT_SANDBOX_ARTIFACT_MISMATCH")

    def test_c278_evidence_or_verdict_change_is_hold(self):
        forged = copy.deepcopy(self.payload)
        forged["c278_evidence_sha256"] = "0" * 64
        self.assertEqual(self.verify(forged)["reason"], "C278_RECEIPT_SOURCE_DIGEST_MISMATCH")
        self.fixture.verdict["tests_executed"][0]["status"] = "FAIL"
        self.assertTrue(self.verify()["reason"].startswith("C278_SANDBOX_OBSERVATION_REQUIRED:"))

    def test_sandbox_drift_after_receipt_is_hold(self):
        (self.fixture.sandbox / self.fixture.target).write_bytes(b"tampered\n")
        self.assertEqual(
            self.verify()["reason"],
            "C278_SANDBOX_OBSERVATION_REQUIRED:C278_SANDBOX_BYTES_DIFFER_FROM_VERDICT",
        )

    def test_wrong_issuer_or_kernel_key_id_is_hold(self):
        self.assertEqual(self.verify(trusted_issuer_id="other")["reason"],
                         "C278_RECEIPT_ISSUER_OR_SCHEMA_MISMATCH")
        self.assertEqual(self.verify(trusted_key_id="KX108_KERNEL_KEY")["reason"],
                         "C278_OBSIDURE_TRUST_IDENTITY_INVALID")

    def test_unknown_authority_fields_fail_closed(self):
        forged = copy.deepcopy(self.payload)
        forged["execution_authorized"] = True
        self.assertEqual(self.verify(forged)["reason"], "C278_RECEIPT_FIELDS_INVALID")
        forged = copy.deepcopy(self.payload)
        forged["schema"] = "KX108_SOVEREIGN_ALLOW"
        self.assertEqual(self.verify(forged)["reason"], "C278_RECEIPT_ISSUER_OR_SCHEMA_MISMATCH")

    def test_unverified_head_transcript_and_reused_nonce_do_not_grant_origin(self):
        result1 = self.verify()
        result2 = self.verify()
        self.assertTrue(result1["receipt_hmac_verified"])
        self.assertTrue(result2["receipt_hmac_verified"])
        self.assertFalse(result2["replay_prevented"])
        self.assertFalse(result2["live_git_head_verified"])
        self.assertFalse(result2["producer_identity_attested"])
        self.assertEqual(self.runtime.execute(operation_type="C278_TEST_RELEASE")["status"], "HOLD")

    def test_public_runtime_remains_single_and_non_authorizing(self):
        capabilities = self.runtime.capabilities()
        self.assertEqual(capabilities["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertEqual(capabilities["apply"], "HOLD")
        self.assertEqual(self.verify()["decision_authority"], "KX108_ONLY")


if __name__ == "__main__":
    unittest.main()
