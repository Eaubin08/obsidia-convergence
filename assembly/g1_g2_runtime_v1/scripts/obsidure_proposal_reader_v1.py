"""Lecteur autonome de propositions Obsidure ? sans moteur APPLY.

Aucune autorit? d'ex?cution. Aucune ?criture de cible.
Les r?gles ci-dessous proviennent des sources P1/G575 v?rifi?es.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROPOSALS_DIR = Path(__file__).resolve().parent.parent / "_PATCH_PROPOSALS"


MAX_FILES_V1 = 20

PROTECTED_PATHS_V1 = (
    "server.kernel.sealed.cjs",
    "proofs/",
    "formal/",
    "merkle_seal.json",
)

PROTECTED_INFIXES: Tuple[str, ...] = (
    "server.kernel.sealed.cjs",
    "proofs/V18_",
    "proofs/lean/57_preuves",
    "merkle_seal.json",
    "rfc3161",
)

def _is_protected(path_str: str) -> bool:
    normalized = path_str.replace("\\", "/")
    return any(infx.replace("\\", "/") in normalized for infx in PROTECTED_INFIXES)


@dataclass
class GateTestEvidence:
    """Artefact attesté d'exécution de tests — jamais un booléen injecté."""
    command: str
    test_identity: str
    exit_code: int
    status: str          # "PASS" | "FAIL" | "ERROR"
    timestamp: str
    results_summary: str
    receipt_hash: str = ""

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and self.status == "PASS"


@dataclass
class BoundedApplySession:
    """Session d'application bornée — contrat spec §7."""
    session_id: str
    proposal_id: str
    objective: str
    base_sha: str
    worktree_path: str
    approved_scope: List[str]
    proposal_files: List[str]
    operations: List[Dict[str, Any]]
    protected_paths_check: str = "UNKNOWN"
    proposal_hash: str = ""
    apply_status: str = "PENDING"
    dryrun_status: str = "PENDING"
    scope_verification: str = "PENDING"
    actual_modified_files: List[str] = field(default_factory=list)
    test_evidence: Optional[GateTestEvidence] = None
    gate_evidence: Optional[GateTestEvidence] = None
    kx108_decision: str = "UNKNOWN"
    kx108_raw: Dict[str, Any] = field(default_factory=dict)
    commit_status: str = "NOT_COMMITTED"
    push_status: str = "NOT_PUSHED"
    merge_status: str = "NOT_MERGED"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _validate_proposal_id(proposal_id: str) -> None:
    if not proposal_id or "/" in proposal_id or "\\" in proposal_id or ".." in proposal_id:
        raise ValueError(f"proposal_id invalide : {proposal_id!r}")


def _proposal_json_path(proposal_id: str) -> Path:
    _validate_proposal_id(proposal_id)
    return PROPOSALS_DIR / proposal_id / "proposal.json"


def _compute_proposal_hash(data: dict) -> str:
    canonical = json.dumps(
        {k: data[k] for k in sorted(data.keys()) if k not in ("human_approved", "status", "proposal_hash")},
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _check_protected_in_list(files: List[str]) -> List[str]:
    return [f for f in files if _is_protected(f) or any(p in f.replace("\\", "/") for p in PROTECTED_PATHS_V1)]


def load_and_validate_proposal(
    proposal_id: str,
    session_id: str,
    base_sha: str,
    worktree: str,
    approved_scope: List[str],
) -> BoundedApplySession:
    """
    Charge la proposal et applique toutes les vérifications de cohérence.
    Retourne un BoundedApplySession avec dryrun_status positionné.
    Lève ValueError avec le code de blocage si une vérification échoue.
    """
    p = _proposal_json_path(proposal_id)
    if not p.exists():
        raise ValueError(f"BLOCK_PROPOSAL_NOT_FOUND: {proposal_id}")

    with p.open(encoding="utf-8") as f:
        data = json.load(f)

    # Vérification session_id
    if data.get("session_id") and data["session_id"] != session_id:
        raise ValueError(
            f"HOLD_PROPOSAL_MISMATCH: session_id attendu={session_id!r} "
            f"dans proposal={data['session_id']!r}"
        )

    # Vérification base_sha
    if data.get("base_sha") and data["base_sha"] != base_sha:
        raise ValueError(
            f"HOLD_PROPOSAL_MISMATCH: base_sha attendu={base_sha!r} "
            f"dans proposal={data['base_sha']!r}"
        )

    # Vérification worktree
    if data.get("worktree") and data["worktree"] != worktree:
        raise ValueError(
            f"BLOCK: worktree attendu={worktree!r} dans proposal={data['worktree']!r}"
        )

    # Vérification proposal_hash si présente
    stored_hash = data.get("proposal_hash", "")
    computed = _compute_proposal_hash(data)
    if stored_hash and stored_hash != computed:
        raise ValueError(
            f"HOLD_PROPOSAL_MISMATCH: proposal_hash corrompu "
            f"stored={stored_hash!r} computed={computed!r}"
        )

    proposal_files: List[str] = data.get("proposal_files", [
        p.get("path", "") for p in data.get("patches", [])
    ])

    # proposition_files ⊆ approved_scope
    out_of_scope = sorted(set(proposal_files) - set(approved_scope))
    if out_of_scope:
        raise ValueError(
            f"BLOCK_SCOPE_DRIFT: fichiers hors scope approuvé : {out_of_scope}"
        )

    if len(approved_scope) > MAX_FILES_V1:
        raise ValueError(
            f"BLOCK: scope dépasse MAX_FILES_V1={MAX_FILES_V1} "
            f"(reçu {len(approved_scope)} fichiers)"
        )

    # Protected paths dans la proposal
    blocked = _check_protected_in_list(proposal_files)
    if blocked:
        raise ValueError(
            f"BLOCK: protected paths dans la proposal : {blocked}"
        )

    return BoundedApplySession(
        session_id=session_id,
        proposal_id=proposal_id,
        objective=data.get("objective", ""),
        base_sha=base_sha,
        worktree_path=worktree,
        approved_scope=approved_scope,
        proposal_files=proposal_files,
        operations=data.get("operations", []),
        protected_paths_check="CLEAN",
        proposal_hash=computed,
        dryrun_status="PENDING",
    )

