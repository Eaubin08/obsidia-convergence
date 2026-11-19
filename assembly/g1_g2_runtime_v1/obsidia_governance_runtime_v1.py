"""OBSIDIA Gouvernance G1/G2 — point d'entrée logique unique.

Ce candidat assemble K1 V5, Sigma GuardX108, le contrat CREATE et le journal
WORLD_ACTION. Les chemins d'écriture métier restent volontairement en HOLD
jusqu'à la clôture du pipeline canonique sur Windows (PRE/POST, HMAC, TOCTOU).

Ce module n'ouvre pas de serveur, n'exécute aucun connecteur et ne crée
jamais de décision souveraine de substitution.
"""
from __future__ import annotations

import dataclasses
import math
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent
_SCRIPTS = _ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from scripts.obsidia_create_pre_contract_v0 import prepare_create_target_pre_evidence
from obsidure_governed_boundary_v1 import admit_obsidure_bridge_pre
from obsidure_r10_repair_intake_v1 import inspect_obsidure_r10_repair
from obsidure_c278_sandbox_observation_v1 import (
    inspect_obsidure_c278_sandbox_observation,
    reconstruct_r9_patch_without_execution,
)
from obsidure_c278_signed_receipt_v1 import inspect_c278_detached_hmac_receipt
from obsidure_c278_machine_rsa_receipt_v1 import inspect_c278_machine_rsa_receipt
from obsidure_machine_identity_registry_v1 import inspect_machine_identity_registry
from obsidure_r9_prepare_provenance_v1 import inspect_obsidure_r9_prepare_provenance
from obsidure_r12_r8_outcome_v1 import inspect_obsidure_r12_r8_outcome
from kx108_pre_post_closure_readonly_v1 import inspect_pre_post_write_closure
from kx108_c2_receipts_readonly_v1 import inspect_c2_actual_receipts
from kx108_c2_signed_post_readonly_v1 import inspect_c2_signed_post_receipts
from kx108_c2_crash_window_readonly_v1 import inspect_c2_crash_window
from c2_write_intent_wal_v1 import inspect_intent as inspect_c2_write_intent_wal
from c2_wal_outcome_observer_v1 import inspect_c2_wal_outcome_state
from c2_wal_machine_rsa_receipt_v1 import inspect_wal_machine_rsa_receipt
from c2_wal_runner_observation_g4k_v1 import inspect_c2_wal_synthetic_runner_observation
from obsidure_machine_role_proposal_g4m_v1 import inspect_obsidure_machine_role_proposal
from obsidure_admin_bootstrap_g4n_v1 import inspect_obsidure_admin_bootstrap
from scripts.obsidia_kx108_decision_store import (
    persist_kx108_world_action_pre_execution_decision,
)
from proofs.audit_merkle_readonly_4a1 import build_merkle_root
from sigma.aggregation import aggregate_tooling_build
from sigma.contracts import AgentVote, AuthorityLevel, Domain, DomainAggregate
from sigma.guard import GuardX108


class ObsidiaGovernanceRuntime:
    """Une seule façade, des rails spécialisés sous autorité KX108_ONLY.

    Le statut d'un rail ne doit jamais être interprété comme une autorisation
    d'écriture. Le rail d'exécution est coupé à cette étape de convergence.
    """

    authority = "KX108_ONLY"
    release = "G1_G2_RUNTIME_CANDIDATE_V1"

    def capabilities(self) -> dict[str, Any]:
        return {
            "runtime": self.release,
            "decision_authority": self.authority,
            "engine": "OBSIDIA_GOUVERNANCE_UNIFIED",
            "sigma_aggregation": "K1_GUARD_AVAILABLE",
            "sigma_tooling_advisory": "BOUNDED_FOUR_VOTE_INTAKE_NO_TICKET",
            "obsidure_proposal": "C2_BRIDGE_READONLY_PRE_ADMISSION_NO_EXECUTION",
            "obsidure_r10_repair": "F7_REPAIR_CANDIDATES_READONLY_INSPECTION_NO_EXECUTION",
            "obsidure_c278_sandbox": "CANONICAL_C278_REPLAY_AND_SANDBOX_BYTES_UNATTESTED",
            "obsidure_c278_signed_receipt": "DETACHED_HMAC_VERIFICATION_ONLY_ORIGIN_UNATTESTED",
            "obsidure_c278_machine_rsa_receipt": "PER_MACHINE_RSA_PUBLIC_VERIFICATION_ONLY_ORIGIN_UNATTESTED",
            "obsidure_machine_identity": "PER_MACHINE_PUBLIC_KEY_ENROLLED_ON_PORTABLE_AWAITING_REVIEW_NO_AUTHORITY",
            "obsidure_r9_prepare": "CANONICAL_V2_DESCRIPTOR_AND_PATCH_REPLAY_UNATTESTED",
            "obsidure_r9_r12_link": "R9_TO_R8_HISTORICAL_READONLY_HOLD",
            "obsidure_r12_r8_outcome": "CANONICAL_HISTORICAL_REPLAY_READONLY_NO_RETRY",
            "kx108_k1_pre_post": "G4_PRE_HMAC_POST_STRUCTURAL_BINDING_INSPECTOR_READONLY",
            "global_write_closure": "G4B_C2_CANONICAL_RECEIPTS_RELOAD_AND_STRUCTURAL_LINK_RELEASE_HOLD",
            "kx108_c2_signed_post": "G4D_POST_K1_HMAC_WITH_C2_STRUCTURE_READONLY_RELEASE_HOLD",
            "kx108_c2_crash_window": "G4F_PREIMAGE_HMAC_LINKED_LIVE_OBSERVATION_READONLY_NO_RESTORE",
            "c2_write_intent_wal": "G4H_OPTIN_PREWRITE_G4I_READONLY_OUTCOME_INSPECTION_NO_RESTORE",
            "c2_wal_machine_receipt": "G4J_PER_MACHINE_RSA_PINNED_VERIFICATION_ONLY_NO_TRUST_ROOT",
            "c2_runner_observation": "G4K_SYNTHETIC_SUBPROCESS_TRACE_HASH_BINDING_READONLY_NO_PRODUCER_TRUST",
            "machine_role_boundary": "G4M_PER_MACHINE_ROLE_PROPOSAL_PINNED_NOT_ENROLLED_OR_AUTHORIZED",
            "obsidure_admin_bootstrap": "G4N_FOUNDER_ONLY_TEAM_PREPARED_FOUNDER_SIGNED_PROPOSAL_NOT_ACTIVE",
            "update": "K1_PREPARE_AVAILABLE_EXECUTION_HOLD",
            "create": "PREFLIGHT_ONLY",
            "world_action": "EVIDENCE_ONLY",
            "merkle": "READ_ONLY_COMPUTE",
            "apply": "HOLD",
            "rollback": "SOURCE_ASSEMBLED_VALIDATION_PENDING",
            "ragnarok": "NOT_CONNECTED",
            "target_mutated": False,
        }

    def evaluate(self, aggregate: DomainAggregate) -> dict[str, Any]:
        """Retourne un avis GuardX108 ; même ALLOW n'ouvre aucun droit d'APPLY."""
        if not isinstance(aggregate, DomainAggregate):
            return self._hold("SIGMA_AGGREGATE_INVALID")
        envelope = GuardX108().decide(aggregate)
        return {
            "status": "EVALUATED_NOT_AUTHORIZED",
            "decision_authority": self.authority,
            "envelope": dataclasses.asdict(envelope),
            "execution_authorized": False,
            "target_mutated": False,
        }

    def evaluate_tooling_build_advisory(self, votes: list[AgentVote]) -> dict[str, Any]:
        """Relie quatre observations Sigma a K1 sans creer de droit d'action.

        Ce point d'entree prend des votes deja produits, non leurs origines
        attestées. Il n'appelle pas le pipeline Sigma dependants de sigma.base,
        ne fabrique pas de HumanApproval et ne retourne jamais de ticket.
        """
        if not isinstance(votes, list):
            return self._hold("SIGMA_VOTES_LIST_REQUIRED")
        if not votes:
            # Le chemin zero-vote canonique doit encore passer par GuardX108.
            aggregate = aggregate_tooling_build([])
        else:
            if len(votes) != 4:
                return self._hold("SIGMA_TOOLING_FOUR_DISTINCT_VOTES_REQUIRED")
            agent_ids: set[str] = set()
            for vote in votes:
                if type(vote) is not AgentVote:
                    return self._hold("SIGMA_VOTE_TYPE_INVALID")
                domain = vote.domain.value if isinstance(vote.domain, Domain) else vote.domain
                if domain != Domain.TOOLING_BUILD.value:
                    return self._hold("SIGMA_VOTE_DOMAIN_MISMATCH")
                if not isinstance(vote.agent_id, str) or not vote.agent_id.strip() or vote.agent_id in agent_ids:
                    return self._hold("SIGMA_VOTE_AGENT_ID_INVALID_OR_DUPLICATE")
                agent_ids.add(vote.agent_id)
                # Le transport d'avis n'a pas le droit d'usurper une regle
                # contractuelle ou une autorite mandatory/non resolue.
                if vote.rule_id or vote.authority_level != AuthorityLevel.ADVISORY:
                    return self._hold("SIGMA_VOTE_AUTHORITY_NOT_ADVISORY")
                if not isinstance(vote.confidence, (int, float)) or not math.isfinite(vote.confidence) or not 0 <= vote.confidence <= 1:
                    return self._hold("SIGMA_VOTE_CONFIDENCE_INVALID")
                if not isinstance(vote.claim, str) or not isinstance(vote.proposed_verdict, str):
                    return self._hold("SIGMA_VOTE_CONTENT_INVALID")
                for field in (vote.contradictions, vote.unknowns, vote.risk_flags):
                    if not isinstance(field, list) or not all(isinstance(item, str) for item in field):
                        return self._hold("SIGMA_VOTE_SIGNALS_INVALID")
            aggregate = aggregate_tooling_build(votes)

        evaluation = self.evaluate(aggregate)
        if evaluation["status"] != "EVALUATED_NOT_AUTHORIZED":
            return self._hold("SIGMA_ADVISORY_EVALUATION_UNAVAILABLE")
        envelope = evaluation["envelope"]
        # Pas d'enveloppe souveraine complete vers les consommateurs : les
        # ids de ticket produits par GuardX108 ne sont pas des preuves HMAC.
        return {
            "status": "SIGMA_ADVISORY_ONLY",
            "decision_authority": self.authority,
            "advisory": {
                "domain": Domain.TOOLING_BUILD.value,
                "market_verdict": aggregate.market_verdict,
                "guard_gate_observed": envelope["x108_gate"],
                "reason_code": envelope["reason_code"],
                "vote_count": len(votes),
                "unknowns": list(aggregate.unknowns),
                "contradictions": list(aggregate.contradictions),
                "risk_flags": list(aggregate.risk_flags),
            },
            "action_ticket_issued": False,
            "execution_authorized": False,
            "target_mutated": False,
        }

    def prepare_create(
        self,
        *,
        worktree_root: Path,
        operation_type: str,
        target_path: str,
        source_content_sha256: str,
    ) -> dict[str, Any]:
        """Réutilise obligatoirement la politique canonique de K1."""
        try:
            from scripts.obsidia_batch_execution import _is_protected
        except (ImportError, AttributeError):
            return self._hold("CANONICAL_PROTECTION_POLICY_UNAVAILABLE")
        return prepare_create_target_pre_evidence(
            worktree_root=worktree_root,
            operation_type=operation_type,
            target_path=target_path,
            source_content_sha256=source_content_sha256,
            is_protected=_is_protected,
        )

    def admit_obsidure_bridge(
        self, *, bridge_result: Any, worktree_root: Path, approved_scope: list[str],
    ) -> dict[str, Any]:
        """Frontiere C2 lecture seule ; aucune HumanApproval ni KX108 PRE ici.

        ``bridge_result`` provient du pont existant, sans executer ce pont
        dans ce runtime. ``approved_scope`` borne des chemins, mais ne
        constitue PAS une preuve d'approbation humaine.
        """
        return admit_obsidure_bridge_pre(
            bridge_result=bridge_result,
            worktree_root=worktree_root,
            approved_scope=approved_scope,
        )

    def inspect_obsidure_r10_repair(
        self, *, repair_request: dict[str, Any], repair_proposal: dict[str, Any],
        c278_evidence: dict[str, Any], repair_verdict: dict[str, Any],
        worktree_root: Path, declared_targets: list[str],
    ) -> dict[str, Any]:
        """Lit la proposition native F7/R10 et ses preuves declarees.

        Les donnees ne valent ni attestation de sandbox, ni HumanApproval.
        Aucun adaptateur R9/F7 n'est execute a cette frontiere.
        """
        return inspect_obsidure_r10_repair(
            repair_request=repair_request,
            repair_proposal=repair_proposal,
            c278_evidence=c278_evidence,
            repair_verdict=repair_verdict,
            worktree_root=worktree_root,
            declared_targets=declared_targets,
        )

    def inspect_obsidure_r12_r8_outcome(
        self, *, action_evidence_id: str, stores_base_dir: Path,
        r10_inspection: dict[str, Any], prepared_repair: dict[str, Any],
    ) -> dict[str, Any]:
        """R12 : confronte R10/R9 aux vraies preuves R8 persistées, sans APPLY.

        Pas de reprise automatique ni de HumanApproval simulée. Une preuve
        historique positive n'ouvre jamais d'autorité d'exécution future.
        """
        return inspect_obsidure_r12_r8_outcome(
            action_evidence_id=action_evidence_id,
            stores_base_dir=stores_base_dir,
            r10_inspection=r10_inspection,
            prepared_repair=prepared_repair,
        )

    def inspect_obsidure_r9_preparation(
        self, *, r10_inspection: dict[str, Any], r9_result: dict[str, Any],
        stores_base_dir: Path, expected_repo_identity_ref: str,
    ) -> dict[str, Any]:
        """Controle les preuves R9/V2 persistées ; ne lance pas PREPARE."""
        return inspect_obsidure_r9_prepare_provenance(
            r10_inspection=r10_inspection,
            r9_result=r9_result,
            stores_base_dir=stores_base_dir,
            expected_repo_identity_ref=expected_repo_identity_ref,
        )

    def inspect_obsidure_c278_sandbox(
        self, *, r10_inspection: dict[str, Any], repair_request: dict[str, Any],
        repair_proposal: dict[str, Any], c278_evidence: dict[str, Any],
        repair_verdict: dict[str, Any], repo_root: Path,
    ) -> dict[str, Any]:
        """Relit C278 et la sandbox existante, sans réexécuter les tests."""
        return inspect_obsidure_c278_sandbox_observation(
            r10_inspection=r10_inspection, repair_request=repair_request,
            repair_proposal=repair_proposal, c278_evidence=c278_evidence,
            repair_verdict=repair_verdict, repo_root=repo_root,
        )

    def inspect_obsidure_c278_signed_receipt(
        self, *, r10_inspection: dict[str, Any], repair_request: dict[str, Any],
        repair_proposal: dict[str, Any], c278_evidence: dict[str, Any],
        repair_verdict: dict[str, Any], repo_root: Path,
        receipt: dict[str, Any], trusted_issuer_id: str,
        trusted_key_id: str, verifier_key: bytes | None,
    ) -> dict[str, Any]:
        """Vérifie un MAC Obsidure sans accorder d'autorité ni attester le runner.

        La clé doit être indépendante du secret souverain KX108 K1.
        Aucun producteur ou magasin de confiance n'est provisionné ici.
        """
        return inspect_c278_detached_hmac_receipt(
            r10_inspection=r10_inspection, repair_request=repair_request,
            repair_proposal=repair_proposal, c278_evidence=c278_evidence,
            repair_verdict=repair_verdict, repo_root=repo_root,
            receipt=receipt, trusted_issuer_id=trusted_issuer_id,
            trusted_key_id=trusted_key_id, verifier_key=verifier_key,
        )

    def inspect_obsidure_machine_identity_registry(self, registry: Any) -> dict[str, Any]:
        """Valide l'inventaire des PC et rôles, sans approuver de clé ni ticket."""
        return inspect_machine_identity_registry(registry)

    def inspect_obsidure_c278_machine_rsa_receipt(
        self, *, r10_inspection: dict[str, Any], repair_request: dict[str, Any],
        repair_proposal: dict[str, Any], c278_evidence: dict[str, Any],
        repair_verdict: dict[str, Any], repo_root: Path,
        receipt: dict[str, Any], public_certificate_der_base64: str | None,
        pinned_certificate_sha256: str, expected_machine_id: str,
    ) -> dict[str, Any]:
        """Vérifie une signature RSA par PC ; jamais une admission KX108.

        Le pin de certificat fourni ne constitue pas en lui-même un
        enrôlement approuvé et aucun certificat privé n'est manipulé.
        """
        return inspect_c278_machine_rsa_receipt(
            r10_inspection=r10_inspection, repair_request=repair_request,
            repair_proposal=repair_proposal, c278_evidence=c278_evidence,
            repair_verdict=repair_verdict, repo_root=repo_root,
            receipt=receipt,
            public_certificate_der_base64=public_certificate_der_base64,
            pinned_certificate_sha256=pinned_certificate_sha256,
            expected_machine_id=expected_machine_id,
        )

    def inspect_obsidure_c278_r9_r12_outcome(
        self, *, action_evidence_id: str, stores_base_dir: Path,
        r10_inspection: dict[str, Any], r9_result: dict[str, Any],
        expected_repo_identity_ref: str, repair_request: dict[str, Any],
        repair_proposal: dict[str, Any], c278_evidence: dict[str, Any],
        repair_verdict: dict[str, Any], repo_root: Path,
        execution_worktree_root: Path,
    ) -> dict[str, Any]:
        """C278 et sandbox observés → R9 → R12, sans créer de provenance.

        Le verdict et la sandbox ne sont pas signés par un producteur fiable.
        Même une concordance complète ne libère donc jamais l'exécution.
        """
        observation = self.inspect_obsidure_c278_sandbox(
            r10_inspection=r10_inspection, repair_request=repair_request,
            repair_proposal=repair_proposal, c278_evidence=c278_evidence,
            repair_verdict=repair_verdict, repo_root=repo_root,
        )
        if observation["status"] != "C278_SANDBOX_BYTES_MATCH_UNATTESTED":
            return {
                **self._hold(observation["reason"]),
                "schema_version": "OBSIDURE_C278_R9_R12_OBSERVATION_JOIN_V1",
                "c278_observation": observation, "readonly": True,
                "sandbox_origin_attested": False, "release_authorized": False,
            }
        r9 = self.inspect_obsidure_r9_preparation(
            r10_inspection=r10_inspection, r9_result=r9_result,
            stores_base_dir=stores_base_dir,
            expected_repo_identity_ref=expected_repo_identity_ref,
        )
        if r9["status"] != "R9_PREPARE_BINDING_MATCH_UNATTESTED":
            return {
                **self._hold(r9["reason"]),
                "schema_version": "OBSIDURE_C278_R9_R12_OBSERVATION_JOIN_V1",
                "c278_observation": observation, "r9_prepare": r9,
                "readonly": True, "sandbox_origin_attested": False,
                "release_authorized": False,
            }
        proposal = r9_result.get("r9_proposal")
        declared = getattr(proposal, "declared_evidence", None)
        if (not isinstance(declared, Mapping)
                or declared.get("tested_artifact_hashes") != observation["candidate_artifact_sha256"]
                or declared.get("c278_evidence") != "CONTINUOUS"):
            return {
                **self._hold("C278_R9_TESTED_ARTIFACTS_LINEAGE_MISMATCH"),
                "schema_version": "OBSIDURE_C278_R9_R12_OBSERVATION_JOIN_V1",
                "c278_observation": observation, "r9_prepare": r9,
                "readonly": True, "sandbox_origin_attested": False,
                "release_authorized": False,
            }
        expected_patch, patch_error = reconstruct_r9_patch_without_execution(
            repair_proposal=repair_proposal,
            repo_root=execution_worktree_root,
        )
        if patch_error is not None or expected_patch != r9_result.get("patch_content"):
            return {
                **self._hold(patch_error or "C278_R9_PATCH_CONTENT_DIVERGES"),
                "schema_version": "OBSIDURE_C278_R9_R12_OBSERVATION_JOIN_V1",
                "c278_observation": observation, "r9_prepare": r9,
                "readonly": True, "sandbox_origin_attested": False,
                "release_authorized": False,
            }
        outcome = self.inspect_obsidure_r9_r12_outcome(
            action_evidence_id=action_evidence_id,
            stores_base_dir=stores_base_dir, r10_inspection=r10_inspection,
            r9_result=r9_result,
            expected_repo_identity_ref=expected_repo_identity_ref,
        )
        return {
            **outcome,
            "join_schema_version": "OBSIDURE_C278_R9_R12_OBSERVATION_JOIN_V1",
            "c278_observation": observation,
            "sandbox_bytes_observed": True,
            "sandbox_origin_attested": False,
            "test_process_attested": False,
            "release_authorized": False, "execution_authorized": False,
            "target_mutated": False,
        }

    def inspect_obsidure_r9_r12_outcome(
        self, *, action_evidence_id: str, stores_base_dir: Path,
        r10_inspection: dict[str, Any], r9_result: dict[str, Any],
        expected_repo_identity_ref: str,
    ) -> dict[str, Any]:
        """R9 canonique -> R12 historique, sans elever une provenance declaree."""
        r9 = self.inspect_obsidure_r9_preparation(
            r10_inspection=r10_inspection,
            r9_result=r9_result,
            stores_base_dir=stores_base_dir,
            expected_repo_identity_ref=expected_repo_identity_ref,
        )
        if r9["status"] != "R9_PREPARE_BINDING_MATCH_UNATTESTED":
            return {
                "schema_version": "OBSIDURE_R9_R12_READONLY_JOIN_V1",
                "status": "HOLD", "reason": r9["reason"],
                "derived_outcome_classification": "EVIDENCE_INCOMPLETE",
                "recommendation": "ESCALATE", "r9_prepare": r9,
                "readonly": True, "authority": "NON_SOVEREIGN",
                "decision_authority": "KX108_ONLY", "execution_authorized": False,
                "human_approval_verified": False, "action_ticket_issued": False,
                "executor_invoked": False, "target_mutated": False, "automatic_retry": False,
            }
        r12 = self.inspect_obsidure_r12_r8_outcome(
            action_evidence_id=action_evidence_id,
            stores_base_dir=stores_base_dir,
            r10_inspection=r10_inspection,
            prepared_repair={
                "repair_lineage": r9["repair_lineage"],
                "prepared_action": {
                    "builder_lineage": r9["builder_lineage"],
                    "v2_exec_id": r9["v2_exec_id"],
                },
            },
        )
        # La concordance des hashes R9 ne prouve pas une sandbox authentique.
        # Meme un SUCCESS historique R8 ne donne donc aucun droit d'execution.
        if r12.get("derived_outcome_classification") == "HISTORICAL_EXECUTION_EVIDENCE_MATCHED":
            r12 = {**r12, "derived_outcome_classification": "EVIDENCE_INCOMPLETE",
                   "recommendation": "ESCALATE", "reason": "R9_SANDBOX_ORIGIN_NOT_AUTHENTICATED"}
        return {
            **r12,
            "join_schema_version": "OBSIDURE_R9_R12_READONLY_JOIN_V1",
            "r9_prepare": r9,
            "r9_artifact_binding_verified": True,
            "r9_provenance_verified": False,
            "release_authorized": False,
            "execution_authorized": False,
            "human_approval_verified": False,
            "action_ticket_issued": False,
            "executor_invoked": False,
            "target_mutated": False,
            "automatic_retry": False,
        }

    def prepare_existing_update(self, **canonical_inputs: Any) -> dict[str, Any]:
        """Préparation K1 d'une cible EXISTANTE, sans APPLY ni HumanApproval.

        Le producteur canonique peut créer des artefacts de préparation dans
        les répertoires fournis par l'appelant. Il ne mute pas la cible.
        """
        try:
            from scripts.obsidia_governed_execution_driver_v0 import (
                prepare_governed_execution,
            )
            result = prepare_governed_execution(**canonical_inputs)
        except (ImportError, AttributeError, OSError, KeyError, TypeError, ValueError) as exc:
            return self._hold(f"K1_PREPARE_UNAVAILABLE:{type(exc).__name__}")
        if not isinstance(result, dict):
            return self._hold("K1_PREPARE_INVALID_RESULT")
        # Même PREPARED_AWAITING_HUMAN_APPROVAL n'est pas une autorisation.
        if result.get("target_mutated") is not False:
            return self._hold("K1_PREPARE_MUTATION_UNVERIFIED")
        return {**result, "execution_authorized": False}

    def inspect_kx108_pre_post_write_closure(
        self, *, pre_record_id: str, post_record_id: str,
        pre_store_dir: Path, post_store_dir: Path,
        expected_anchors: dict[str, str],
    ) -> dict[str, Any]:
        """G4 : relit les records PRE/POST, sans produire ni exécuter de décision.

        Un POST structurel ne prouve pas l'identité de son producteur ;
        les liens C2 ne prouvent pas les octets des reçus. Toujours HOLD.
        """
        return inspect_pre_post_write_closure(
            pre_record_id=pre_record_id, post_record_id=post_record_id,
            pre_store_dir=pre_store_dir, post_store_dir=post_store_dir,
            expected_anchors=expected_anchors,
        )

    def inspect_kx108_c2_actual_receipts(self, **canonical_inputs: Any) -> dict[str, Any]:
        """G4B : vrai rechargement structurel des reçus scellés, toujours HOLD."""
        return inspect_c2_actual_receipts(**canonical_inputs)

    def inspect_kx108_c2_signed_post_receipts(self, **canonical_inputs: Any) -> dict[str, Any]:
        """G4D : joint POST HMAC K1 et reçus C2, sans attester une écriture."""
        return inspect_c2_signed_post_receipts(**canonical_inputs)

    def inspect_kx108_c2_crash_window(self, **canonical_inputs: Any) -> dict[str, Any]:
        """G4F : observe une préimage C2 et la cible, sans reprise automatique."""
        return inspect_c2_crash_window(**canonical_inputs)

    def inspect_c2_write_intent_wal(self, *, wal_dir: Path, intent_id: str) -> dict[str, Any]:
        """G4G : inspecte un intent isolé, sans jamais autoriser une reprise."""
        return inspect_c2_write_intent_wal(wal_dir=wal_dir, intent_id=intent_id)

    def inspect_c2_wal_outcome_state(self, *, wal_dir: Path, intent_id: str,
                                     repo_root: Path) -> dict[str, Any]:
        """G4I : observe les octets C2 + le claim WAL, sans exécuter."""
        return inspect_c2_wal_outcome_state(
            wal_dir=wal_dir, intent_id=intent_id, repo_root=repo_root)

    def inspect_c2_wal_machine_rsa_receipt(self, **canonical_inputs: Any) -> dict[str, Any]:
        """G4J : vérifie la possession de clé sur un WAL, sans ticket souverain."""
        return inspect_wal_machine_rsa_receipt(**canonical_inputs)

    def inspect_c2_wal_synthetic_runner_observation(self, **canonical_inputs: Any) -> dict[str, Any]:
        """G4K : rapproche trace synthétique et RSA G4J, sans exécuter."""
        return inspect_c2_wal_synthetic_runner_observation(**canonical_inputs)

    def inspect_obsidure_machine_role_proposal(self, **canonical_inputs: Any) -> dict[str, Any]:
        """G4M : compare registre/rôle et signature, sans approuver l'enrôlement."""
        return inspect_obsidure_machine_role_proposal(**canonical_inputs)

    def inspect_obsidure_admin_bootstrap(self, **canonical_inputs: Any) -> dict[str, Any]:
        """G4N : V1 fondateur et V2 équipe préparée, aucune activation automatique."""
        return inspect_obsidure_admin_bootstrap(**canonical_inputs)

    def record_world_action_evidence(
        self,
        *,
        decision_envelope: Any,
        binding_context: dict[str, Any],
        store_dir: Path,
    ) -> dict[str, Any]:
        """Archive une preuve structurelle, jamais une permission de connecteur."""
        if store_dir is None:
            return self._hold("WORLD_ACTION_STORE_REQUIRED")
        return persist_kx108_world_action_pre_execution_decision(
            decision_envelope,
            binding_context,
            store_dir=Path(store_dir),
        )

    def compute_proof_root(self, sha256_digests: list[str]) -> dict[str, Any]:
        """Calcul 4A1 sans écrire merkle_seal.json ni créer d'attestation."""
        if not isinstance(sha256_digests, list) or not sha256_digests:
            return self._hold("MERKLE_DIGESTS_REQUIRED")
        if any(
            not isinstance(value, str) or
            re.fullmatch(r"[0-9a-fA-F]{64}", value) is None
            for value in sha256_digests
        ):
            return self._hold("MERKLE_DIGEST_INVALID")
        return {
            "status": "MERKLE_ROOT_COMPUTED_READ_ONLY",
            "root": build_merkle_root([digest.lower() for digest in sha256_digests]),
            "count": len(sha256_digests),
            "decision_authority": self.authority,
            "execution_authorized": False,
            "target_mutated": False,
        }

    def execute(self, *, operation_type: str, **_ignored: Any) -> dict[str, Any]:
        """Verrou G1/G2 : activation des écritures seulement après tests de clôture."""
        return self._hold(f"G1_G2_EXECUTION_NOT_RELEASED:{operation_type}")

    @classmethod
    def _hold(cls, reason: str) -> dict[str, Any]:
        return {
            "status": "HOLD",
            "reason": reason,
            "decision_authority": cls.authority,
            "execution_authorized": False,
            "target_mutated": False,
        }


def get_runtime() -> ObsidiaGovernanceRuntime:
    """Entrée unique pour le candidat G1/G2."""
    return ObsidiaGovernanceRuntime()
