"""Entrée Obsidure F7/R10 dans le runtime unique, sans execution.

Contrat provenant des objets RepairRequest / RepairProposal / RepairVerdict
(`periphery/agents/obsidure_repair_contract.py`) et du chemin R10-B1
(`scripts/obsidure_repair_r9_adapter_v1.py`). Seuls leurs dictionnaires
serialises sont inspectes ; aucun module F7 ni executeur n'est importe.

Un PASS/CONTINUOUS declare par l'appelant n'atteste pas la provenance des
tests ou de C278. La sortie n'est donc ni PRE, ni HumanApproval, ni ticket.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from obsidure_governed_boundary_v1 import _relative_path
from scripts.obsidia_batch_execution import _is_protected
from scripts.obsidia_create_pre_contract_v0 import prepare_create_target_pre_evidence
from scripts.obsidia_governed_write_guard_v0 import verify_path_reparse_safe

_BOUNDARY = {
    "decision_authority": "KX108_ONLY",
    "emits_act": False, "emits_verdict": False, "kernel_mutation": False,
    "memory_write": False, "canonical_write": False, "auto_apply": False,
    "auto_commit": False, "auto_push": False,
    "sandbox_mode": "HUMAN_APPROVED_WRITE",
    "external_engine_role": "PROPOSE_ONLY",
}
_REPAIR_PREFIXES = (
    "periphery/", "apps/obsidia_api/", "scripts/", "tests/",
    "connectors/", "domains/", "sigma/",
)
_REPAIR_EXTS = frozenset((".py", ".json", ".md", ".yaml", ".yml", ".toml"))
_REPAIR_PROTECTED = (
    "server.kernel.sealed.cjs", "proofs/v18_", "proofs/lean/57_preuves",
    "merkle_seal.json", "rfc3161",
)
_MAX_CANDIDATES = 64
_REQUEST_KEYS = frozenset({
    "request_id", "created_at", "origin", "objective", "failure_mode",
    "summary", "error_contexts", "repo_targets", "target_excerpts",
    "attempts_spent", "sandbox_dir", "tests_hint", "boundary",
})
_PROPOSAL_KEYS = frozenset({
    "proposal_id", "request_id", "engine", "created_at", "rationale",
    "candidate_files", "tests_to_run", "confidence", "boundary",
})
_VERDICT_KEYS = frozenset({
    "verdict_id", "request_id", "proposal_id", "status", "created_at",
    "errors", "compiled_files", "sandbox_dir", "tests_executed",
    "resume_objective", "tested_artifacts", "boundary",
})


def _hold(reason: str) -> dict[str, Any]:
    return {
        "status": "HOLD", "reason": reason, "decision_authority": "KX108_ONLY",
        "execution_authorized": False, "action_ticket_issued": False,
        "human_approval_verified": False, "kx108_pre_invoked": False,
        "target_mutated": False,
    }


def _is_valid_boundary(data: Any) -> bool:
    return type(data) is dict and data == _BOUNDARY


def inspect_obsidure_r10_repair(
    *, repair_request: Any, repair_proposal: Any, c278_evidence: Any,
    repair_verdict: Any, worktree_root: Path, declared_targets: Any,
) -> dict[str, Any]:
    """Inspecte les vrais objets F7 serialises, sans creer d'artefact.

    Le controle des SHA cible reste un preflight (non atomique). Le point
    d'ecriture canonique devra refaire le controle sous verrou, puis passer
    HumanApproval et KX108 PRE/POST. Un resultat positif ne prouve PAS que
    le RepairVerdict et les tests proviennent d'une sandbox authentique.
    """
    if any(type(item) is not dict for item in (
        repair_request, repair_proposal, c278_evidence, repair_verdict,
    )):
        return _hold("R10_SERIALIZED_EVIDENCE_DICTS_REQUIRED")
    if (set(repair_request) - _REQUEST_KEYS
            or set(repair_proposal) - _PROPOSAL_KEYS
            or set(repair_verdict) - _VERDICT_KEYS
            or any(k in c278_evidence for k in (
                "human_approved", "execution_authorized", "approval_created",
                "ticket_id", "x108_gate", "kx108_decision",
            ))):
        return _hold("R10_UNKNOWN_OR_AUTHORIZING_FIELDS")
    if not all(_is_valid_boundary(item.get("boundary")) for item in (
        repair_request, repair_proposal, repair_verdict,
    )):
        return _hold("R10_NON_SOVEREIGN_BOUNDARY_INVALID")

    request_id = repair_request.get("request_id")
    proposal_id = repair_proposal.get("proposal_id")
    verdict_id = repair_verdict.get("verdict_id")
    if any(type(v) is not str or not v or v != v.strip() for v in (
        request_id, proposal_id, verdict_id,
    )):
        return _hold("R10_REPAIR_ID_MISSING")
    if (repair_proposal.get("request_id") != request_id
            or repair_verdict.get("request_id") != request_id
            or repair_verdict.get("proposal_id") != proposal_id
            or c278_evidence.get("request_id") != request_id
            or c278_evidence.get("proposal_id") != proposal_id):
        return _hold("R10_REPAIR_LINEAGE_MISMATCH")
    if (c278_evidence.get("evidence") != "CONTINUOUS"
            or repair_verdict.get("status") != "PASS"):
        return _hold("R10_C278_OR_SANDBOX_VERDICT_NOT_PASS")

    candidates = repair_proposal.get("candidate_files")
    tested = repair_verdict.get("tested_artifacts")
    if (type(candidates) is not list or not 0 < len(candidates) <= _MAX_CANDIDATES
            or type(tested) is not list or len(tested) != len(candidates)):
        return _hold("R10_CANDIDATES_OR_TESTED_ARTIFACTS_INCOMPLETE")
    if (type(declared_targets) is not list or not declared_targets
            or any(_relative_path(item) is None for item in declared_targets)
            or len({item.casefold() for item in declared_targets}) != len(declared_targets)):
        return _hold("R10_DECLARED_SCOPE_INVALID")
    request_targets = repair_request.get("repo_targets")
    if (type(request_targets) is not list
            or any(_relative_path(item) is None for item in request_targets)
            or set(request_targets) != set(declared_targets)
            or len(request_targets) != len(declared_targets)):
        return _hold("R10_REQUEST_TARGET_SCOPE_MISMATCH")

    try:
        root = Path(worktree_root)
        if root.is_symlink() or root.is_junction() or not root.is_dir():
            return _hold("R10_WORKTREE_ROOT_UNVERIFIED")
        root = root.resolve(strict=True)
    except (OSError, TypeError, ValueError):
        return _hold("R10_WORKTREE_ROOT_UNVERIFIED")

    observed_artifacts: dict[str, str] = {}
    artifact_aliases: set[str] = set()
    for item in tested:
        if type(item) is not dict:
            return _hold("R10_TESTED_ARTIFACT_MALFORMED")
        rel = _relative_path(item.get("path"))
        digest = item.get("sha256")
        if (rel is None or type(digest) is not str or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
                or rel.casefold() in artifact_aliases):
            return _hold("R10_TESTED_ARTIFACT_IDENTITY_INVALID")
        observed_artifacts[rel] = digest
        artifact_aliases.add(rel.casefold())

    checked: list[dict[str, Any]] = []
    paths: set[str] = set()
    path_aliases: set[str] = set()
    for candidate in candidates:
        if type(candidate) is not dict:
            return _hold("R10_CANDIDATE_MALFORMED")
        if set(candidate) - {"path", "full_content", "change_kind", "base_sha256", "rationale"}:
            return _hold("R10_CANDIDATE_UNKNOWN_FIELDS")
        rel = _relative_path(candidate.get("path"))
        if rel is None or rel.casefold() in path_aliases:
            return _hold("R10_CANDIDATE_PATH_INVALID_OR_DUPLICATE")
        paths.add(rel)
        path_aliases.add(rel.casefold())
        lower = rel.casefold()
        if (not lower.startswith(_REPAIR_PREFIXES)
                or Path(rel).suffix.casefold() not in _REPAIR_EXTS
                or any(bad in lower for bad in _REPAIR_PROTECTED)
                or _is_protected(rel) or _is_protected(lower)):
            return _hold("R10_TARGET_OUTSIDE_F7_K1_POLICY")
        if rel not in declared_targets:
            return _hold("R10_CANDIDATE_NOT_IN_DECLARED_SCOPE")
        op = candidate.get("change_kind")
        if op not in ("MODIFY", "CREATE"):
            return _hold("R10_CANDIDATE_CHANGE_KIND_NOT_SUPPORTED")
        content = candidate.get("full_content")
        if type(content) is not str or not content.strip():
            return _hold("R10_CANDIDATE_CONTENT_MISSING")
        candidate_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if observed_artifacts.get(rel) != candidate_sha:
            return _hold("R10_TESTED_ARTIFACT_HASH_MISMATCH")
        target = root.joinpath(*rel.split("/"))
        try:
            ok, _ = verify_path_reparse_safe(root, target, kind="R10_TARGET")
            if not ok:
                return _hold("R10_TARGET_REPARSE_UNSAFE")
            if op == "MODIFY":
                if not target.is_file():
                    return _hold("R10_MODIFY_TARGET_MISSING")
                before = target.read_bytes()
                base_sha = candidate.get("base_sha256")
                if (type(base_sha) is not str
                        or len(base_sha) != 64
                        or any(c not in "0123456789abcdef" for c in base_sha)
                        or hashlib.sha256(before).hexdigest() != base_sha):
                    return _hold("R10_MODIFY_BASE_SHA_DRIFT_OR_MISSING")
                if before == content.encode("utf-8"):
                    return _hold("R10_NO_EFFECTIVE_REPAIR_DIFF")
            else:
                if candidate.get("base_sha256") not in ("", None):
                    return _hold("R10_CREATE_PREIMAGE_MUST_BE_NULL")
                pre = prepare_create_target_pre_evidence(
                    worktree_root=root, operation_type="CREATE_TARGET_FROM_SOURCE",
                    target_path=rel, source_content_sha256=candidate_sha,
                    is_protected=_is_protected,
                )
                if pre.get("status") != "READY_FOR_CANONICAL_PRE_EVIDENCE":
                    return _hold("R10_CREATE_K1_PREFLIGHT_HOLD")
        except (OSError, ValueError, TypeError, UnicodeError):
            return _hold("R10_CANDIDATE_TARGET_UNVERIFIED")
        checked.append({
            "target_path": rel, "operation": op,
            "candidate_content_sha256": candidate_sha,
            "target_pre_sha256": candidate.get("base_sha256") if op == "MODIFY" else None,
        })

    if paths != set(declared_targets) or paths != set(observed_artifacts):
        return _hold("R10_TARGET_SET_BINDING_MISMATCH")
    return {
        "status": "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY",
        "decision_authority": "KX108_ONLY",
        "repair_request_id": request_id, "repair_proposal_id": proposal_id,
        "repair_verdict_id": verdict_id, "candidates": checked,
        "evidence_provenance_verified": False,
        "r9_prepare_executed": False,
        "next_gate": "R9_OR_G2_PREPARE_THEN_HUMAN_APPROVAL_KX108_PRE",
        "execution_authorized": False, "action_ticket_issued": False,
        "human_approval_verified": False, "kx108_pre_invoked": False,
        "target_mutated": False,
    }
