"""OBSIDIA Gouvernance G1/G2 — point d'entrée logique unique.

Ce candidat assemble K1 V5, Sigma GuardX108, le contrat CREATE et le journal
WORLD_ACTION. Les chemins d'écriture métier restent volontairement en HOLD
jusqu'à la clôture du pipeline canonique sur Windows (PRE/POST, HMAC, TOCTOU).

Ce module n'ouvre pas de serveur, n'exécute aucun connecteur et ne crée
jamais de décision souveraine de substitution.
"""
from __future__ import annotations

import dataclasses
import re
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent
_SCRIPTS = _ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from scripts.obsidia_create_pre_contract_v0 import prepare_create_target_pre_evidence
from scripts.obsidia_kx108_decision_store import (
    persist_kx108_world_action_pre_execution_decision,
)
from proofs.audit_merkle_readonly_4a1 import build_merkle_root
from sigma.contracts import DomainAggregate
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
            "kx108_k1_pre_post": "SOURCE_ASSEMBLED_VALIDATION_PENDING",
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
