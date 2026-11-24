"""C263-C267 : Rejeu P1 — NOOP, Provenance C278/F7, HumanApproval, KX108 PRE/POST, Clôture."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / "scripts", ROOT / "periphery" / "world_calls"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import obsidia_canonical_receipt_envelope_v1 as _CRE
import obsidia_realized_state_reconciliation_v1 as _R8_RECON


def _sha(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


class P1C263NoopReconciliationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-c263-noop-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for sub in ("v2exec", "approval", "kxpre", "receipts"):
            (self.root / sub).mkdir()
        self.target = "scripts/tool.py"
        self.before_sha = _sha(b"old\n")
        self.patch_sha = _sha(b"--- a/scripts/tool.py\n+++ b/scripts/tool.py\n@@ -1 +1 @@\n-old\n+new\n")
        desc = {
            "patch_sha256": self.patch_sha,
            "target_paths": [self.target],
            "before_digests": {self.target: self.before_sha},
            "base_sha": "a" * 40,
            "session_id": "c263-noop-session",
            "operation_type": "V2_APPLY_PATCH",
        }
        self.eah = _sha(
            json.dumps(
                {
                    "v2_schema": "PC_CAPABILITIES_V2_EAH_V0",
                    "operation_type": "V2_APPLY_PATCH",
                    "action_descriptor": desc,
                },
                sort_keys=True,
            )
        )
        self.v2id = "v2x-" + _sha(self.eah + "a" * 40 + desc["session_id"])[:32]
        record = {
            "v2_exec_id": self.v2id,
            "operation_type": "V2_APPLY_PATCH",
            "eah": self.eah,
            "descriptor": desc,
            "decision_authority": "KX108_ONLY",
        }
        raw_desc = json.dumps(record, sort_keys=True, ensure_ascii=False)
        (self.root / "v2exec" / f"{self.v2id}.json").write_text(raw_desc, encoding="utf-8")
        self.desc_hash = _sha(raw_desc)

    def _store_noop_envelope(self, *, after_digests: dict[str, str], case: str) -> str:
        exec_input = {"v2_exec_id": self.v2id, "case": case}
        post_state = {"target_paths": [self.target], "after_digests": after_digests}
        env = _CRE.build_canonical_receipt_envelope(
            capability="G1_G2_PATCH",
            operation_type="V2_APPLY_PATCH",
            request_ref={"public_action": "APPLY_PATCH"},
            session_ref={"v2_exec_id": self.v2id},
            prepare={"descriptor_ref": self.v2id, "descriptor_hash": self.desc_hash},
            authorization={
                "execution_authority_hash": self.eah,
                "approval_id": "NOT_REACHED",
                "kx108_pre_decision_record_id": "NOT_REACHED",
                "kx108_verdict": "ALLOW",
                "binder_verdict_status": "NOT_REACHED",
            },
            execution={
                "executor_kind": "GOVERNED_PATCH",
                "executor_operation": "V2_APPLY_PATCH",
                "executor_status": "NOOP",
                "executor_input_ref": exec_input,
                "executor_input_hash": _CRE.compute_ref_hash(exec_input),
                "physical_effect_dispatched": True,
                "mutation_performed": False,
            },
            realized_state={
                "outcome": _CRE.OUTCOME_NOOP,
                "physical_effect_dispatched": True,
                "mutation_performed": False,
                "realized_state_verified": True,
                "proof_strength": "STRONG",
                "post_state_ref": post_state,
                "post_state_hash": _CRE.compute_ref_hash(post_state),
            },
            receipt={"source": "SYNTHETIC_C263"},
        )
        res = _CRE.store_canonical_receipt_envelope(env, self.root / "receipts")
        self.assertEqual(res["status"], _CRE.STATUS_STORED)
        return env["action_evidence_id"]

    def test_c263_apply_patch_outcome_noop_with_unchanged_digests(self) -> None:
        aev_noop = self._store_noop_envelope(
            after_digests={self.target: self.before_sha}, case="noop_unchanged"
        )
        recon = _R8_RECON.reconcile_action_evidence(aev_noop, stores_base_dir=self.root)
        self.assertEqual(recon["reconciliation_status"], _R8_RECON.STATUS_NOOP_CONFIRMED)

    def test_c263_apply_patch_outcome_noop_with_mutated_digests_is_mismatch(self) -> None:
        aev_mutated = self._store_noop_envelope(
            after_digests={self.target: _sha(b"mutated\n")}, case="noop_contradiction"
        )
        recon = _R8_RECON.reconcile_action_evidence(aev_mutated, stores_base_dir=self.root)
        self.assertEqual(recon["reconciliation_status"], _R8_RECON.STATUS_MISMATCH)


if __name__ == "__main__":
    unittest.main()


# ======================================================================
# C264 : Provenance Obsidure C278/F7
# ======================================================================
import hmac as _hmac
import obsidia_batch_execution as _BATCH
import obsidia_canonical_receipt_replay_v1 as _R8_REPLAY
import obsidia_kx108_decision_store as _KX_STORE
from obsidia_governance_runtime_v1 import ObsidiaGovernanceRuntime
from obsidure_builder_proposal_v1 import BuilderPatchRef, ObsidureBuilderProposalV1
from obsidure_c278_signed_receipt_v1 import inspect_c278_detached_hmac_receipt
from obsidure_governance_handoff_v1 import build_governance_handoff
from obsidure_proposal_manifest_v1 import (
    ArtifactRef,
    EvidenceRecord,
    build_proposal_manifest,
)
from obsidure_proposal_validation_v1 import (
    ValidationObligation,
    ValidationPolicy,
    validate_obsidure_proposal,
)
from obsidure_r10_repair_intake_v1 import _BOUNDARY
from periphery.world_calls import sovereign_ticket as _ST
from periphery.world_calls import ticket_store as _TS
from scripts.proposal_meaning_validator import validate_proposal_meaning


def _canon_json(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


class P1C264ObsidureProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-c264-prov-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo_root = self.root / "repo"
        self.target = "scripts/tool.py"
        (self.repo_root / "scripts").mkdir(parents=True)
        (self.repo_root / self.target).write_bytes(b"old\n")
        self.sb = self.repo_root / "_EPHEMERAL_REPAIR_SANDBOX_C264"
        (self.sb / "scripts").mkdir(parents=True)
        (self.sb / self.target).write_bytes(b"new\n")
        self.runtime = ObsidiaGovernanceRuntime()

        self.ids = {
            "repair_request_id": "req-c264-1",
            "repair_proposal_id": "prop-c264-1",
            "repair_verdict_id": "verd-c264-1",
        }
        self.request = {
            "request_id": self.ids["repair_request_id"],
            "repo_targets": [self.target],
            "objective": "Repair tool",
            "summary": "tool broken",
            "error_contexts": [
                {"target_path": self.target, "error_type": "TOOL", "raw_details": "broken"}
            ],
            "target_excerpts": {self.target: "old\n"},
            "tests_hint": ["tests/test_tool.py"],
            "boundary": dict(_BOUNDARY),
        }
        self.proposal = {
            "proposal_id": self.ids["repair_proposal_id"],
            "request_id": self.ids["repair_request_id"],
            "rationale": "Repair tool",
            "candidate_files": [
                {
                    "path": self.target,
                    "change_kind": "MODIFY",
                    "full_content": "new\n",
                    "base_sha256": _sha(b"old\n"),
                    "rationale": "Fix",
                }
            ],
            "tests_to_run": ["tests/test_tool.py"],
            "confidence": "HIGH",
            "boundary": dict(_BOUNDARY),
        }
        self.c278 = validate_proposal_meaning(request=self.request, proposal=self.proposal)
        self.verdict = {
            "verdict_id": self.ids["repair_verdict_id"],
            "request_id": self.ids["repair_request_id"],
            "proposal_id": self.ids["repair_proposal_id"],
            "status": "PASS",
            "compiled_files": [self.target],
            "sandbox_dir": str(self.sb),
            "errors": [],
            "boundary": dict(_BOUNDARY),
            "tested_artifacts": [{"path": self.target, "sha256": _sha(b"new\n")}],
            "tests_executed": [
                {"test": "tests/test_tool.py", "status": "PASS", "returncode": 0, "isolation": "FULL"}
            ],
        }
        self.r10 = self.runtime.inspect_obsidure_r10_repair(
            repair_request=self.request,
            repair_proposal=self.proposal,
            c278_evidence=self.c278,
            repair_verdict=self.verdict,
            worktree_root=self.repo_root,
            declared_targets=[self.target],
        )
        self.assertEqual(self.r10["status"], "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY")

        self.trust_key = b"obsidure-c264-test-trust-key-0123456789abcdef"
        self.issuer = "obsidure-runner-test"
        self.key_id = "obsidure-key-1"
        payload = {
            "schema": "OBSIDURE_C278_DETACHED_HMAC_RECEIPT_V1",
            "issuer_id": self.issuer,
            "key_id": self.key_id,
            "receipt_id": "rcpt-c264-1",
            "nonce": "1" * 64,
            "request_id": self.ids["repair_request_id"],
            "proposal_id": self.ids["repair_proposal_id"],
            "verdict_id": self.ids["repair_verdict_id"],
            "repair_request_sha256": _sha(_canon_json(self.request)),
            "repair_proposal_sha256": _sha(_canon_json(self.proposal)),
            "c278_evidence_sha256": _sha(_canon_json(self.c278)),
            "repair_verdict_sha256": _sha(_canon_json(self.verdict)),
            "candidate_artifact_sha256": {self.target: _sha(b"new\n")},
            "source_git_head": "a" * 40,
            "runner_code_sha256": "2" * 64,
            "tests_transcript_sha256": "3" * 64,
        }
        mac = _hmac.new(
            self.trust_key,
            b"OBSIDIA_OBSIDURE_C278_RECEIPT_V1\x00" + _canon_json(payload),
            hashlib.sha256,
        ).hexdigest()
        self.receipt = {"payload": payload, "hmac_sha256": mac}

    def test_c264_valid_hmac_still_keeps_provenance_unattested(self) -> None:
        res = inspect_c278_detached_hmac_receipt(
            r10_inspection=self.r10,
            repair_request=self.request,
            repair_proposal=self.proposal,
            c278_evidence=self.c278,
            repair_verdict=self.verdict,
            repo_root=self.repo_root,
            receipt=self.receipt,
            trusted_issuer_id=self.issuer,
            trusted_key_id=self.key_id,
            verifier_key=self.trust_key,
        )
        self.assertEqual(res["status"], "C278_RECEIPT_HMAC_MATCH_ORIGIN_UNATTESTED")
        self.assertIs(res["receipt_hmac_verified"], True)
        self.assertIs(res["producer_identity_attested"], False)
        self.assertIs(res["sandbox_origin_attested"], False)
        self.assertIs(res["test_process_attested"], False)
        self.assertIs(res["provenance_verified"], False)
        self.assertIs(res["human_approval_verified"], False)
        self.assertIs(res["execution_authorized"], False)
        self.assertIs(res["release_authorized"], False)

    def test_c264_provenance_falsifications_rejected(self) -> None:
        # 1. Mauvaise clé HMAC
        bad_key = inspect_c278_detached_hmac_receipt(
            r10_inspection=self.r10,
            repair_request=self.request,
            repair_proposal=self.proposal,
            c278_evidence=self.c278,
            repair_verdict=self.verdict,
            repo_root=self.repo_root,
            receipt=self.receipt,
            trusted_issuer_id=self.issuer,
            trusted_key_id=self.key_id,
            verifier_key=b"wrong-key-" + b"0" * 32,
        )
        self.assertEqual(bad_key["status"], "HOLD")
        self.assertEqual(bad_key["reason"], "C278_RECEIPT_MAC_MISMATCH")

        # 2. Clé KX108 interdite comme clé de confiance Obsidure
        kx_key = inspect_c278_detached_hmac_receipt(
            r10_inspection=self.r10,
            repair_request=self.request,
            repair_proposal=self.proposal,
            c278_evidence=self.c278,
            repair_verdict=self.verdict,
            repo_root=self.repo_root,
            receipt=self.receipt,
            trusted_issuer_id=self.issuer,
            trusted_key_id="KX108_KEY",
            verifier_key=self.trust_key,
        )
        self.assertEqual(kx_key["status"], "HOLD")
        self.assertEqual(kx_key["reason"], "C278_OBSIDURE_TRUST_IDENTITY_INVALID")

        # 3. Digest source altéré
        bad_payload = {**self.receipt["payload"], "repair_verdict_sha256": "f" * 64}
        bad_rcpt = {"payload": bad_payload, "hmac_sha256": self.receipt["hmac_sha256"]}
        bad_digest = inspect_c278_detached_hmac_receipt(
            r10_inspection=self.r10,
            repair_request=self.request,
            repair_proposal=self.proposal,
            c278_evidence=self.c278,
            repair_verdict=self.verdict,
            repo_root=self.repo_root,
            receipt=bad_rcpt,
            trusted_issuer_id=self.issuer,
            trusted_key_id=self.key_id,
            verifier_key=self.trust_key,
        )
        self.assertEqual(bad_digest["status"], "HOLD")
        self.assertEqual(bad_digest["reason"], "C278_RECEIPT_SOURCE_DIGEST_MISMATCH")


# ======================================================================
# C265 : HumanApproval (intégrité, liaison, périmètre, révocation)
# ======================================================================
class P1C265HumanApprovalTest(unittest.TestCase):
    def _make_envelope_and_approval(self, *, approved_by: str = "HUMAN") -> tuple[dict, dict]:
        envelope = {
            "batch_execution_id": "bex-c265-1",
            "batch_id": "batch-c265-1",
            "batch_hash": "a" * 64,
            "candidate_scope_hash": "b" * 64,
            "execution_authority_hash": "c" * 64,
        }
        approval = {
            "approval_schema_version": _BATCH.SCHEMA_VERSION,
            "approval_id": "apr-c265-1",
            "batch_execution_id": envelope["batch_execution_id"],
            "batch_id": envelope["batch_id"],
            "batch_hash": envelope["batch_hash"],
            "candidate_scope_hash": envelope["candidate_scope_hash"],
            "execution_authority_hash": envelope["execution_authority_hash"],
            "approval_status": _BATCH.APPROVED_FOR_BOUNDED_EXECUTION,
            "approved_by": approved_by,
            "decision_authority": "KX108_ONLY",
            "created_at": "2026-11-24T00:00:00+00:00",
        }
        if approved_by == _BATCH.APPROVED_BY_HUMAN_MISSION_AUTHORITY_DERIVED:
            approval.update(
                {
                    "approval_kind": _BATCH.APPROVAL_KIND_DERIVED_MISSION_AUTHORITY_EVIDENCE_V0,
                    "derived_mission_approval_evidence_id": "dmae-1",
                    "embedded_authority_locator": {"mission_id": "m-1", "hma_id": "hma-1"},
                }
            )
        approval["approval_record_hash"] = _BATCH.compute_approval_record_hash(approval)
        return envelope, approval

    def test_c265_approval_integrity_binding_scope_and_derived_fail_closed(self) -> None:
        env, apr = self._make_envelope_and_approval()
        ok, reason = _BATCH.verify_approval_artifact(apr)
        self.assertTrue(ok, reason)
        ok_v, reason_v = _BATCH._validate_approval(apr, env)
        self.assertTrue(ok_v, reason_v)

        # 1. Absente / hash altéré
        self.assertEqual(_BATCH.verify_approval_artifact(None), (False, "APPROVAL_MISSING"))
        tampered = {**apr, "approval_record_hash": "0" * 64}
        self.assertEqual(
            _BATCH.verify_approval_artifact(tampered), (False, "APPROVAL_RECORD_HASH_MISMATCH")
        )

        # 2. Liaison à l'action exacte & périmètre
        self.assertEqual(
            _BATCH._validate_approval(apr, {**env, "batch_execution_id": "other"}),
            (False, "APPROVAL_WRONG_EXECUTION_ID"),
        )
        self.assertEqual(
            _BATCH._validate_approval(apr, {**env, "execution_authority_hash": "9" * 64}),
            (False, "APPROVAL_EXECUTION_CONTENT_MISMATCH"),
        )
        self.assertEqual(
            _BATCH._validate_approval(apr, {**env, "candidate_scope_hash": "8" * 64}),
            (False, "APPROVAL_WRONG_SCOPE_HASH"),
        )

        # 3. Approbation dérivée sans contexte canonique -> fail-closed
        env_d, apr_d = self._make_envelope_and_approval(
            approved_by=_BATCH.APPROVED_BY_HUMAN_MISSION_AUTHORITY_DERIVED
        )
        ok_d, why_d = _BATCH._validate_approval(apr_d, env_d, derived_authority_context=None)
        self.assertFalse(ok_d)
        self.assertIn("DERIVED_APPROVAL_", str(why_d))
        # 4. Statut non approuvé refusé
        bad_status = {**apr, "approval_status": "HOLD"}
        bad_status["approval_record_hash"] = _BATCH.compute_approval_record_hash(bad_status)
        self.assertEqual(
            _BATCH._validate_approval(bad_status, env),
            (False, "APPROVAL_STATUS_INVALID"),
        )


# ======================================================================
# C266 : KX108 PRE/POST (magasins temporaires + clé de test)
# ======================================================================
class P1C266Kx108PrePostTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-c266-kx108-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.decisions_dir = self.root / "kx_decisions"
        self.decisions_dir.mkdir()
        self.nonces_path = str(self.root / "consumed_nonces.jsonl")
        self.action_id = "act-c266-1"
        self.payload = [{"path": "scripts/tool.py", "type": "WRITE"}]
        self.input_hash = _sha(_canon_json(self.payload))

        _ST.reset_kernel_keys()
        _ST.register_kernel_key(_ST._DEFAULT_KEY_ID, b"c266-ephemeral-test-key-0123456789abcdef")
        self.addCleanup(_ST.reset_kernel_keys)

    def _make_pre_record(
        self,
        *,
        gate: str = "ALLOW",
        phase: str = "PRE_EXECUTION",
        producer: str = "run_and_persist_kx108_pre_execution_decision",
        record_id: str = "kxdec-c266-1",
    ) -> dict:
        rec = {
            "decision_record_schema_version": 1,
            "decision_record_id": record_id,
            "created_at": "2026-11-24T00:00:00+00:00",
            "decision_phase": phase,
            "decision_record_producer": producer,
            "batch_execution_id": "bex-c266",
            "child_execution_id": "chd-c266",
            "execution_authority_hash": "a" * 64,
            "approval_id": "apr-c266",
            "pre_execution_context_id": "prectx-c266",
            "pre_execution_context_record_hash": "b" * 64,
            "test_contract_hash": "c" * 64,
            "kx108_input_translation_hash": "d" * 64,
            "decision_id": "dec-c266-1",
            "trace_id": "trc-c266-1",
            "domain": "tooling_build",
            "x108_gate": gate,
            "reason_code": "OK" if gate == "ALLOW" else "HOLD_REASON",
            "severity": "S0" if gate == "ALLOW" else "S2",
            "market_verdict": "ACT" if gate == "ALLOW" else "HOLD",
            "contradictions": [],
            "unknowns": [],
            "risk_flags": [],
            "decision_authority": "KX108_ONLY",
            "canonical_envelope": {
                "decision_id": "dec-c266-1",
                "trace_id": "trc-c266-1",
                "domain": "tooling_build",
                "x108_gate": gate,
                "reason_code": "OK" if gate == "ALLOW" else "HOLD_REASON",
                "severity": "S0" if gate == "ALLOW" else "S2",
                "market_verdict": "ACT" if gate == "ALLOW" else "HOLD",
                "contradictions": [],
                "unknowns": [],
                "risk_flags": [],
            },
        }
        rec["decision_record_hash"] = _KX_STORE.compute_kx108_decision_record_hash(rec)
        rec["decision_record_auth_version"] = _KX_STORE.DECISION_RECORD_AUTH_VERSION
        rec["decision_record_key_id"] = _ST._DEFAULT_KEY_ID
        key = _ST.get_kernel_key(_ST._DEFAULT_KEY_ID)
        rec["decision_record_authenticator"] = _hmac.new(
            key, _KX_STORE._record_auth_message(rec), hashlib.sha256
        ).hexdigest()
        return rec

    def test_c266_kx108_decision_and_ticket_adversarial_matrix(self) -> None:
        # 1. Décision HOLD -> impossible d'émettre un ALLOW direct sans décision vérifiée
        with self.assertRaisesRegex(AssertionError, "ALLOW_REQUIRES_VERIFIED_DECISION_RECORD"):
            _ST.issue_sovereign_ticket(
                action_id=self.action_id,
                os3_ticket_id="os3-1",
                x108_gate="ALLOW",
                scope="bounded_apply",
                autonomy_level=1,
                world_call_class="GOVERNED_WRITE",
                input_hash=self.input_hash,
            )

        hold_ticket = _ST.issue_sovereign_ticket(
            action_id=self.action_id,
            os3_ticket_id="os3-hold",
            x108_gate="HOLD",
            scope="bounded_apply",
            autonomy_level=1,
            world_call_class="GOVERNED_WRITE",
            input_hash=self.input_hash,
        )
        with self.assertRaisesRegex(AssertionError, "SOVEREIGN_TICKET_NOT_ALLOW:HOLD"):
            _TS.verify_and_consume_sovereign_ticket(
                hold_ticket,
                required_scope="bounded_apply",
                expected_action_id=self.action_id,
                action_payload=self.payload,
                decision_store_dir=self.decisions_dir,
                consumed_store_path=self.nonces_path,
            )

        # 2. Décision absente
        with self.assertRaisesRegex(AssertionError, "DECISION_RECORD_MISSING"):
            _ST.issue_sovereign_ticket_from_decision_record(
                "kxdec-missing",
                action_id=self.action_id,
                scope="bounded_apply",
                input_hash=self.input_hash,
                decision_store_dir=self.decisions_dir,
            )

        # 3. Authentificateur de décision invalide
        bad_auth = self._make_pre_record(record_id="kxdec-bad-auth")
        bad_auth["decision_record_authenticator"] = "0" * 64
        self.assertEqual(
            _KX_STORE.verify_kx108_decision_record_authenticity(bad_auth),
            (False, "DECISION_RECORD_AUTHENTICATOR_INVALID"),
        )

        # 4. Décision falsifiée (hash mismatch)
        bad_hash = self._make_pre_record(record_id="kxdec-bad-hash")
        bad_hash["x108_gate"] = "HOLD"
        self.assertEqual(
            _KX_STORE.verify_kx108_decision_record(bad_hash),
            (False, "DECISION_RECORD_HASH_MISMATCH"),
        )

        # 5. Producteur non éligible
        bad_prod = self._make_pre_record(
            record_id="kxdec-bad-prod", producer="untrusted_caller"
        )
        (self.decisions_dir / "kxdec-bad-prod.json").write_text(
            json.dumps(bad_prod), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            AssertionError, "SOVEREIGN_TICKET_DECISION_PRODUCER_NOT_ELIGIBLE"
        ):
            _ST.issue_sovereign_ticket_from_decision_record(
                "kxdec-bad-prod",
                action_id=self.action_id,
                scope="bounded_apply",
                input_hash=self.input_hash,
                decision_store_dir=self.decisions_dir,
            )

        # 6. Mauvaise phase PRE (POST_EXECUTION au lieu de PRE_EXECUTION)
        bad_phase = self._make_pre_record(
            record_id="kxdec-bad-phase", phase="POST_EXECUTION"
        )
        bad_phase.update({"test_result_id": "tcr-1", "test_result_record_hash": "e" * 64})
        bad_phase["decision_record_hash"] = _KX_STORE.compute_kx108_decision_record_hash(bad_phase)
        bad_phase["decision_record_authenticator"] = _hmac.new(
            _ST.get_kernel_key(_ST._DEFAULT_KEY_ID),
            _KX_STORE._record_auth_message(bad_phase),
            hashlib.sha256,
        ).hexdigest()
        (self.decisions_dir / "kxdec-bad-phase.json").write_text(
            json.dumps(bad_phase), encoding="utf-8"
        )
        with self.assertRaisesRegex(AssertionError, "SOVEREIGN_TICKET_PRE_EXECUTION_REQUIRED"):
            _ST.issue_sovereign_ticket_from_decision_record(
                "kxdec-bad-phase",
                action_id=self.action_id,
                scope="bounded_apply",
                input_hash=self.input_hash,
                decision_store_dir=self.decisions_dir,
            )

        # 7. Anti-rejeu atomique du nonce (réservation + refus de réutilisation)
        self.assertTrue(
            _TS.reserve_ticket_nonce("nonce-c266-1", "tkt-1", store_path=self.nonces_path)
        )
        self.assertFalse(
            _TS.reserve_ticket_nonce("nonce-c266-1", "tkt-1", store_path=self.nonces_path)
        )


# ======================================================================
# C267 : Rejeu intégré complet Handoff -> R9 -> R12/R8 -> Réconciliation -> KX108
# ======================================================================
class P1C267IntegratedReplayClosureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obsidia-c267-closure-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for sub in ("v2exec", "approval", "kxpre", "receipts"):
            (self.root / sub).mkdir()
        self.runtime = ObsidiaGovernanceRuntime()
        self.target = "scripts/tool.py"
        self.repo_ref = "synthetic-closure-repo"
        self.patch = "--- a/scripts/tool.py\n+++ b/scripts/tool.py\n@@ -1 +1 @@\n-old\n+new\n"
        self.patch_sha = _sha(self.patch)
        self.base_sha = "a" * 40
        self.ids = {
            "repair_request_id": "r10-c267-req",
            "repair_proposal_id": "r10-c267-prop",
            "repair_verdict_id": "r10-c267-verd",
        }
        self.r10 = {"status": "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY", **self.ids}
        self.proposal = ObsidureBuilderProposalV1(
            objective="C267 closure",
            proposal_kind="REPAIR",
            base_commit_sha=self.base_sha,
            target_scope=(self.target,),
            files_touched=(self.target,),
            candidate_patch_ref=BuilderPatchRef("repair.patch", self.patch_sha),
            tests_proposed=("repair-sandbox-verdict",),
            source_context_refs=(self.ids["repair_request_id"],),
            declared_evidence={"c278_evidence": "CONTINUOUS", **self.ids},
        )
        patch_art = ArtifactRef(
            artifact_kind="CANDIDATE_PATCH",
            logical_ref="repair.patch",
            content_sha256=self.patch_sha,
            artifact_format="REAL_UNIFIED_DIFF_V1",
        )
        test_art = ArtifactRef(
            artifact_kind="TEST_RESULT",
            logical_ref=self.ids["repair_verdict_id"],
            content_sha256=_sha("c267-verdict"),
        )
        ev = EvidenceRecord(
            evidence_kind="TEST_RESULT_EVIDENCE",
            subject_ref=self.proposal.proposal_id,
            producer_ref="SYNTHETIC_TEST",
            verification_status="VERIFIED",
            artifact_ref=test_art,
            scope=(self.target,),
            result="PASS",
            provenance={"base_commit_sha": self.base_sha},
        )
        self.manifest = build_proposal_manifest(
            self.proposal,
            candidate_artifacts=(patch_art, test_art),
            evidence_records=(ev,),
            verification_obligations=("repair-sandbox-verdict",),
            repo_identity_ref=self.repo_ref,
        )
        policy = ValidationPolicy(
            obligations=(
                ValidationObligation(
                    obligation_kind="UNIT_TEST",
                    target="repair-sandbox-verdict",
                    scope=(self.target,),
                    required=True,
                    expected_evidence_kind="TEST_RESULT_EVIDENCE",
                    allow_observed=False,
                ),
            )
        )
        self.validation = validate_obsidure_proposal(
            self.proposal, self.manifest, validation_policy=policy
        )
        self.handoff = build_governance_handoff(
            self.proposal,
            self.manifest,
            self.validation,
            source_metadata={**self.ids, "c278_evidence": "CONTINUOUS"},
        )
        self.lineage = {
            "lineage_schema_version": "OBSIDURE_GOVERNED_PATCH_PREPARE_ADAPTER_V1",
            "builder_proposal_id": self.proposal.proposal_id,
            "builder_manifest_id": self.manifest.manifest_id,
            "builder_validation_id": self.validation.validation_id,
            "builder_handoff_id": self.handoff.handoff_id,
        }
        before = {self.target: _sha(b"old\n")}
        desc = {
            "patch_sha256": self.patch_sha,
            "target_paths": [self.target],
            "before_digests": before,
            "execution_worktree": str(self.root / "iso"),
            "main_worktree": str(self.root / "main"),
            "branch_name": "synthetic/c267",
            "base_sha": self.base_sha,
            "session_id": "c267-sess",
            "operation_type": "V2_APPLY_PATCH",
            "descriptor_lineage": self.lineage,
        }
        eah = _sha(
            json.dumps(
                {
                    "v2_schema": "PC_CAPABILITIES_V2_EAH_V0",
                    "operation_type": "V2_APPLY_PATCH",
                    "action_descriptor": desc,
                },
                sort_keys=True,
            )
        )
        self.v2id = "v2x-" + _sha(eah + self.base_sha + desc["session_id"])[:32]
        record = {
            "v2_exec_id": self.v2id,
            "operation_type": "V2_APPLY_PATCH",
            "eah": eah,
            "descriptor": desc,
            "decision_authority": "KX108_ONLY",
        }
        raw_desc = json.dumps(record, sort_keys=True, ensure_ascii=False)
        (self.root / "v2exec" / f"{self.v2id}.json").write_text(raw_desc, encoding="utf-8")
        (self.root / "v2exec" / f"{self.v2id}.patch").write_bytes(self.patch.encode("utf-8"))
        self.desc_hash = _sha(raw_desc)
        self.r9 = {
            "status": "R10_REPAIR_PREPARED",
            "r9_proposal": self.proposal,
            "r9_manifest": self.manifest,
            "r9_validation": self.validation,
            "r9_handoff": self.handoff,
            "prepared_action": {
                "status": "PREPARED_AWAITING_HUMAN_APPROVAL",
                "j5_phase": "PREPARE",
                "operation_type": "V2_APPLY_PATCH",
                "decision_authority": "KX108_ONLY",
                "execution_authority_hash": eah,
                "patch_sha256": self.patch_sha,
                "target_paths": [self.target],
                "before_digests": before,
                "v2_exec_id": self.v2id,
                "child_id": "chd-" + _sha(eah + self.patch_sha)[:32],
                "manifest_hash": _sha(json.dumps(desc, sort_keys=True))[:16],
                "desc_hash": self.desc_hash,
                "builder_lineage": dict(self.lineage),
                "approval_created": False,
                "binder_runtime_called": False,
                "kx108_called": False,
                "executor_invoked": False,
                "physical_mutation": False,
                "action_evidence_id_created": False,
                "validation_equals_approval": False,
                "handoff_equals_authorization": False,
                "prepare_equals_authorization": False,
            },
            "patch_content": self.patch,
            "tested_patch_hash": self.patch_sha,
            "repair_lineage": self.ids,
            "prepared": True,
            "approval_created": False,
            "kx108_called": False,
            "executor_invoked": False,
            "physical_mutation": False,
            "commit_created": False,
            "push_performed": False,
            "merge_performed": False,
        }
        exec_input = {"v2_exec_id": self.v2id, "patch_sha256": self.patch_sha}
        self.receipt_env = _CRE.build_canonical_receipt_envelope(
            capability="G1_G2_PATCH",
            operation_type="V2_APPLY_PATCH",
            request_ref={"public_action": "APPLY_PATCH", "builder_lineage": dict(self.lineage)},
            session_ref={"v2_exec_id": self.v2id},
            prepare={
                "descriptor_ref": self.v2id,
                "descriptor_hash": self.desc_hash,
                "builder_lineage": dict(self.lineage),
            },
            authorization={
                "execution_authority_hash": eah,
                "approval_id": "NOT_REACHED",
                "kx108_pre_decision_record_id": "NOT_REACHED",
                "kx108_verdict": "HOLD",
                "binder_verdict_status": "NOT_REACHED",
            },
            execution={
                "executor_kind": "GOVERNED_PATCH",
                "executor_operation": "V2_APPLY_PATCH",
                "executor_status": "NOT_REACHED",
                "executor_input_ref": exec_input,
                "executor_input_hash": _CRE.compute_ref_hash(exec_input),
                "physical_effect_dispatched": False,
                "mutation_performed": False,
            },
            realized_state={
                "outcome": _CRE.OUTCOME_KX108_HOLD,
                "physical_effect_dispatched": False,
                "mutation_performed": False,
                "realized_state_verified": False,
                "proof_strength": "NONE",
                "post_state_ref": {"status": "NOT_REACHED"},
                "post_state_hash": _CRE.compute_ref_hash({"status": "NOT_REACHED"}),
            },
            receipt={"source": "SYNTHETIC_C267"},
        )
        _CRE.store_canonical_receipt_envelope(self.receipt_env, self.root / "receipts")

    def test_c267_end_to_end_coherent_chain_holds_with_exact_separation(self) -> None:
        # 1. Handoff
        h = self.runtime.inspect_obsidure_governance_handoff(
            proposal=self.proposal,
            manifest=self.manifest,
            validation=self.validation,
            handoff=self.handoff,
        )
        self.assertEqual(h["status"], "OBSIDURE_HANDOFF_VERIFIED_READONLY")
        self.assertIs(h["execution_authorized"], False)

        # 2. R9
        r9 = self.runtime.inspect_obsidure_r9_preparation(
            r10_inspection=self.r10,
            r9_result=self.r9,
            stores_base_dir=self.root,
            expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(r9["status"], "R9_PREPARE_BINDING_MATCH_UNATTESTED")
        self.assertIs(r9["artifact_binding_verified"], True)
        self.assertIs(r9["provenance_verified"], False)

        # 3. R12 / R8
        aev = self.receipt_env["action_evidence_id"]
        r12 = self.runtime.inspect_obsidure_r9_r12_outcome(
            action_evidence_id=aev,
            stores_base_dir=self.root,
            r10_inspection=self.r10,
            r9_result=self.r9,
            expected_repo_identity_ref=self.repo_ref,
        )
        self.assertEqual(r12["derived_outcome_classification"], "PRE_DISPATCH_FAILURE")
        self.assertIs(r12["release_authorized"], False)
        self.assertIs(r12["execution_authorized"], False)

        # 4. Rejeu & Réconciliation R8
        replay = _R8_REPLAY.replay_action_evidence(aev, stores_base_dir=self.root)
        self.assertEqual(replay["replay_verdict"], _R8_REPLAY.VERDICT_VERIFIED)
        recon = _R8_RECON.reconcile_action_evidence(aev, stores_base_dir=self.root)
        self.assertEqual(recon["reconciliation_status"], _R8_RECON.STATUS_NOT_REALIZED)

        # 5. Vérification KX108 : aucune décision souveraine absente n'est fabriquée
        self.assertEqual(
            _KX_STORE.verify_kx108_decision_record_authenticity(None),
            (False, "DECISION_RECORD_MISSING"),
        )
