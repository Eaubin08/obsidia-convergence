"""Admission en lecture seule du pont Obsidure C2 vers le runtime unique.

Consomme la sortie EXISTANTE de
``obsidia_family_wiring_apply_bridge_v0.build_child_execution_from_obsidure_proposal``.
Le pont lui-meme n'est pas importe : sa fermeture de dependances est toujours
HOLD. Un objet fourni par l'appelant est une proposition, jamais une preuve
d'autorisation KX108, meme si ses champs disent ALLOW ou APPROVED.

Aucune ecriture, aucun APPLY, aucun ticket, aucun service et aucun appel KX108.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path, PureWindowsPath
from typing import Any

from scripts.obsidia_batch_execution import _is_protected
from scripts.obsidia_content_apply import resolve_source_bytes
from scripts.obsidia_create_pre_contract_v0 import (
    _WINDOWS_FORBIDDEN,
    _WINDOWS_RESERVED,
    prepare_create_target_pre_evidence,
)
from scripts.obsidia_governed_write_guard_v0 import verify_path_reparse_safe

AUTHORITY = "KX108_ONLY"
_SHA = re.compile(r"^[0-9a-fA-F]{64}$")
_CHILD_KEYS = frozenset({
    "candidate_entry_id", "child_execution_id", "source_kind",
    "source_path", "source_hash", "source_content_sha256",
    "source_repository_identity", "source_git_commit_sha",
    "source_git_blob_sha", "source_git_historical_path", "target_path",
    "target_pre_hash", "target_pre_sha256", "operation_type",
    "operation_reason", "execution_status", "provenance_refs",
})
_BRIDGE_KEYS = frozenset({
    "status", "reason", "child", "proposal_id", "proposal_hash",
    "source_content_sha256", "bridge_report", "authority",
    "write_capability",
})
_REPORT_KEYS = frozenset({
    "target_path", "operation_type", "source_kind", "source_path",
    "source_bytes", "target_pre_state", "family_provenance_keys",
})


def _hold(reason: str) -> dict[str, Any]:
    return {
        "status": "HOLD", "reason": reason,
        "decision_authority": AUTHORITY,
        "execution_authorized": False,
        "action_ticket_issued": False,
        "target_mutated": False,
    }


def _relative_path(raw: Any) -> str | None:
    """Un chemin litteral, sans alias Windows ni normalisation silencieuse."""
    if type(raw) is not str or not raw or raw != raw.strip():
        return None
    if "\\" in raw or "\x00" in raw or PureWindowsPath(raw).drive:
        return None
    if raw.startswith("/") or raw.startswith("//"):
        return None
    parts = raw.split("/")
    if any(p in ("", ".", "..") or ":" in p for p in parts):
        return None
    if any(
        p != p.strip() or p.endswith(".") or "~" in p
        or any(c in _WINDOWS_FORBIDDEN or ord(c) < 32 for c in p)
        or p.split(".", 1)[0].upper() in _WINDOWS_RESERVED
        for p in parts
    ):
        return None
    return raw


def admit_obsidure_bridge_pre(
    *, bridge_result: Any, worktree_root: Path, approved_scope: Any,
) -> dict[str, Any]:
    """Reverifie le child C2 : provenance du contenu et etat de la cible.

    La validation canonique du proposal par Obsidure et toute HumanApproval
    restent des etapes separees NON REALISEES ici. Le resultat positif est
    seulement une admission read-only vers le PRE KX108 a construire.
    """
    if type(bridge_result) is not dict or set(bridge_result) - _BRIDGE_KEYS:
        return _hold("OBSIDURE_BRIDGE_SHAPE_INVALID_OR_UNKNOWN_FIELDS")
    if (bridge_result.get("status") != "BRIDGE_CHILD_READY"
            or bridge_result.get("authority") != "NON_SOVEREIGN"
            or bridge_result.get("write_capability") is not False):
        return _hold("OBSIDURE_BRIDGE_NOT_NON_SOVEREIGN_READY")
    child = bridge_result.get("child")
    report = bridge_result.get("bridge_report")
    if type(child) is not dict or set(child) - _CHILD_KEYS:
        return _hold("OBSIDURE_CHILD_SHAPE_INVALID_OR_UNKNOWN_FIELDS")
    if type(report) is not dict or set(report) - _REPORT_KEYS:
        return _hold("OBSIDURE_REPORT_SHAPE_INVALID_OR_UNKNOWN_FIELDS")
    if (not isinstance(bridge_result.get("proposal_id"), str)
            or not bridge_result["proposal_id"].strip()
            or not isinstance(child.get("child_execution_id"), str)
            or not child["child_execution_id"].strip()
            or child.get("execution_status") != "PLANNED"):
        return _hold("OBSIDURE_PROPOSAL_ID_OR_STATUS_INVALID")

    target_rel = _relative_path(child.get("target_path"))
    source_rel = _relative_path(child.get("source_path"))
    if target_rel is None or source_rel is None or source_rel == target_rel:
        return _hold("OBSIDURE_TARGET_OR_SOURCE_PATH_INVALID")
    if (type(approved_scope) is not list or not approved_scope
            or any(_relative_path(p) is None for p in approved_scope)
            or len(set(approved_scope)) != len(approved_scope)
            or target_rel not in approved_scope):
        return _hold("OBSIDURE_SCOPE_NOT_BOUNDED")
    if _is_protected(target_rel) or _is_protected(target_rel.casefold()):
        return _hold("OBSIDURE_TARGET_PROTECTED")

    op = child.get("operation_type")
    if op not in {"CREATE_TARGET_FROM_SOURCE", "UPDATE_TARGET_FROM_SOURCE"}:
        return _hold("OBSIDURE_OPERATION_NOT_CANONICAL")
    if child.get("source_kind") != "FILESYSTEM_FILE":
        return _hold("OBSIDURE_SOURCE_KIND_NOT_SUPPORTED")
    if any(child.get(k) for k in (
        "source_git_commit_sha", "source_git_blob_sha", "source_git_historical_path"
    )):
        return _hold("OBSIDURE_FILESYSTEM_SOURCE_GIT_FIELDS_PRESENT")
    full_sha = child.get("source_content_sha256")
    if type(full_sha) is not str or not _SHA.fullmatch(full_sha):
        return _hold("OBSIDURE_SOURCE_SHA256_INVALID")
    if (bridge_result.get("source_content_sha256") != full_sha
            or child.get("source_hash") != full_sha[:16]):
        return _hold("OBSIDURE_SOURCE_IDENTITY_MISMATCH")
    if (report.get("target_path") != target_rel
            or report.get("operation_type") != op
            or report.get("source_kind") != "FILESYSTEM_FILE"
            or report.get("source_path") != source_rel):
        return _hold("OBSIDURE_BRIDGE_REPORT_BINDING_MISMATCH")

    try:
        root = Path(worktree_root)
        if root.is_symlink() or root.is_junction() or not root.is_dir():
            return _hold("OBSIDURE_WORKTREE_ROOT_UNVERIFIED")
        root = root.resolve(strict=True)
        if child.get("source_repository_identity") != str(root):
            return _hold("OBSIDURE_SOURCE_REPOSITORY_IDENTITY_MISMATCH")
        source = root.joinpath(*source_rel.split("/"))
        target = root.joinpath(*target_rel.split("/"))
        for path, kind in ((source, "SOURCE"), (target, "TARGET")):
            ok, _reason = verify_path_reparse_safe(root, path, kind=kind)
            if not ok:
                return _hold(f"OBSIDURE_{kind}_REPARSE_UNSAFE")
        if not source.is_file():
            return _hold("OBSIDURE_SOURCE_FILE_MISSING")
        # Delegation au resolveur K1 reel, pas de second resolveur de contenu.
        source_bytes, source_error = resolve_source_bytes(child, root)
        if source_error is not None or source_bytes is None:
            return _hold("OBSIDURE_SOURCE_CANONICAL_RESOLVE_FAILED")
        if type(report.get("source_bytes")) is not int or report["source_bytes"] != len(source_bytes):
            return _hold("OBSIDURE_SOURCE_SIZE_MISMATCH")

        target_present = target.exists() or target.is_symlink()
        reported_pre = child.get("target_pre_sha256")
        if op == "CREATE_TARGET_FROM_SOURCE":
            if reported_pre is not None or child.get("target_pre_hash") is not None:
                return _hold("OBSIDURE_CREATE_PREIMAGE_MUST_BE_NULL")
            if report.get("target_pre_state") != "ABSENT":
                return _hold("OBSIDURE_CREATE_REPORT_PRESTATE_MISMATCH")
            # Le preflight K1 comprend la politique des cibles protegees.
            pre = prepare_create_target_pre_evidence(
                worktree_root=root, operation_type=op, target_path=target_rel,
                source_content_sha256=full_sha, is_protected=_is_protected,
            )
            if pre.get("status") != "READY_FOR_CANONICAL_PRE_EVIDENCE":
                return _hold(f"OBSIDURE_CREATE_K1_PRE_HOLD:{pre.get('reason', 'UNKNOWN')}")
        else:
            if not target_present or not target.is_file():
                return _hold("OBSIDURE_UPDATE_TARGET_MISSING")
            if type(reported_pre) is not str or not _SHA.fullmatch(reported_pre):
                return _hold("OBSIDURE_UPDATE_BASE_SHA256_REQUIRED")
            if child.get("target_pre_hash") != reported_pre[:16]:
                return _hold("OBSIDURE_UPDATE_BASE_PREFIX_MISMATCH")
            if report.get("target_pre_state") != "EXISTS":
                return _hold("OBSIDURE_UPDATE_REPORT_PRESTATE_MISMATCH")
            if hashlib.sha256(target.read_bytes()).hexdigest() != reported_pre.lower():
                return _hold("OBSIDURE_UPDATE_BASE_DRIFT")
    except (OSError, ValueError, TypeError):
        return _hold("OBSIDURE_PRE_ADMISSION_IO_UNVERIFIED")

    return {
        "status": "OBSIDURE_PRE_ADMISSION_READONLY",
        "proposal_id": bridge_result["proposal_id"],
        "child_execution_id": child["child_execution_id"],
        "operation_type": op,
        "target_path": target_rel,
        "source_content_sha256": full_sha.lower(),
        "target_pre_sha256": reported_pre,
        "next_gate": "CANONICAL_HUMAN_APPROVAL_AND_KX108_PRE_NOT_INVOKED",
        "decision_authority": AUTHORITY,
        "execution_authorized": False,
        "action_ticket_issued": False,
        "target_mutated": False,
    }
