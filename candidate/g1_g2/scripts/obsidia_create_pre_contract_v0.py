"""G2 — normalisation PRE de CREATE_TARGET_FROM_SOURCE, sans mutation.

Pont de contrat K1/Jarvis -> adaptateur PRE 4A1/X108-CREATE.
Ce module NE crée pas de fichier, n'approuve pas une action et ne peut
jamais retourner ALLOW : la décision appartient au pipeline KX108 réel.

Ce contrôle est une étape PRE de préparation, PAS la protection anti-TOCTOU
au point d'écriture. Le runtime gouverné doit recontrôler la cible et
l'identité de l'action sous son propre verrou avant la mutation.
"""
from __future__ import annotations

import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_CANONICAL_CREATE = "CREATE_TARGET_FROM_SOURCE"
_PC2_ADAPTER_CREATE = "CREATE"


def _is_link_or_junction(path: Path) -> bool:
    """Refuse aussi les jonctions NTFS (pas toujours des symlinks Windows)."""
    return path.is_symlink() or path.is_junction()


def _reject(reason: str) -> dict:
    return {
        "status": "HOLD_CREATE_PRE",
        "reason": reason,
        "authorized": False,
        "target_mutated": False,
        "decision_authority": "KX108_ONLY",
    }


def prepare_create_target_pre_evidence(
    *,
    worktree_root: Path,
    operation_type: str,
    target_path: str,
    source_content_sha256: str,
    is_protected: Callable[[str], bool] | None = None,
) -> dict:
    """Contrôle lecture seule de CREATE avant les vérificateurs canoniques.

    Le callback is_protected DOIT être celui de la politique de protection
    du moteur réel (absent -> HOLD). Aucune valeur d'approbation ni x108_gate
    fournie par l'appelant n'est acceptée.
    """
    if operation_type != _CANONICAL_CREATE:
        return _reject("CREATE_OPERATION_NOT_CANONICAL")
    if not isinstance(source_content_sha256, str) or not _SHA256.fullmatch(source_content_sha256):
        return _reject("SOURCE_SHA256_NOT_CANONICAL")
    if not isinstance(target_path, str) or not target_path.strip():
        return _reject("TARGET_PATH_MISSING")
    if not callable(is_protected):
        return _reject("CANONICAL_PROTECTION_POLICY_MISSING")

    raw_path = target_path.strip()
    if "\x00" in raw_path or PureWindowsPath(raw_path).drive:
        return _reject("TARGET_PATH_ABSOLUTE_OR_DRIVE")
    normalized = raw_path.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return _reject("TARGET_PATH_ABSOLUTE_OR_DRIVE")
    parts = normalized.split("/")
    if any(part in ("", ".", "..") or ":" in part for part in parts):
        return _reject("TARGET_PATH_TRAVERSAL_OR_ADS")
    relative = PurePosixPath(normalized)
    if relative.is_absolute():
        return _reject("TARGET_PATH_ABSOLUTE_OR_DRIVE")

    root = Path(worktree_root)
    if _is_link_or_junction(root) or not root.is_dir():
        return _reject("WORKTREE_ROOT_UNVERIFIED")
    root = root.resolve(strict=True)

    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if _is_link_or_junction(candidate):
            return _reject("TARGET_PATH_SYMLINK_COMPONENT")
        if candidate != root / Path(*relative.parts) and candidate.exists() and not candidate.is_dir():
            return _reject("TARGET_PARENT_NOT_DIRECTORY")

    if candidate.exists() or _is_link_or_junction(candidate):
        return _reject("CREATE_TARGET_ALREADY_EXISTS")

    try:
        if bool(is_protected(normalized)):
            return _reject("CREATE_TARGET_PROTECTED")
    except Exception:
        return _reject("CANONICAL_PROTECTION_POLICY_FAILED")

    return {
        "status": "READY_FOR_CANONICAL_PRE_EVIDENCE",
        "operation_type": _CANONICAL_CREATE,
        "pc2_adapter_operation_type": _PC2_ADAPTER_CREATE,
        "target_path": normalized,
        "target_pre_sha256": None,
        "source_content_sha256": source_content_sha256.lower(),
        "authorized": False,
        "target_mutated": False,
        "decision_authority": "KX108_ONLY",
        "next_gate": "HUMAN_APPROVAL_VERIFIED_THEN_KX108_PRE",
    }
