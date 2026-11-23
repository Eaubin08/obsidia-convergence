"""Observation indépendante du couple C278/RepairVerdict/F7, sans APPLY.

Le code source du producteur historique ``test_repair_proposal`` a été audité :
il écrit des candidats dans une sandbox et émet un verdict de tests non signé.
Ce rail vérifie seulement la continuité sémantique canonique et l'état actuel
des octets sur disque. Un PASS déclaré ne constitue PAS une attestation du
processus qui a exécuté les tests, de son isolation ou de son origine.
"""
from __future__ import annotations

import difflib
import hashlib
from pathlib import Path
from typing import Any

from scripts.proposal_meaning_validator import validate_proposal_meaning
from obsidure_governed_boundary_v1 import _relative_path

_PREFIX = "_EPHEMERAL_REPAIR_SANDBOX_"
_MAX_CANDIDATES = 64
_MAX_FILE_BYTES = 1_000_000


def _hold(reason: str, **extra: Any) -> dict[str, Any]:
    return _result("HOLD", reason, **extra)


def _result(status: str, reason: str | None, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "OBSIDURE_C278_SANDBOX_OBSERVATION_READONLY_V1",
        "status": status, "reason": reason,
        "readonly": True, "authority": "NON_SOVEREIGN",
        "decision_authority": "KX108_ONLY",
        "c278_replayed": status != "HOLD",
        "sandbox_bytes_observed": status != "HOLD",
        "producer_identity_attested": False,
        "sandbox_origin_attested": False,
        "test_process_attested": False,
        "test_isolation_certified": False,
        "live_git_head_verified": False,
        "provenance_verified": False,
        "human_approval_verified": False,
        "execution_authorized": False,
        "action_ticket_issued": False,
        "kx108_pre_invoked": False,
        "executor_invoked": False,
        "target_mutated": False,
        "automatic_retry": False,
        **extra,
    }


def _no_reparse(path: Path, stop: Path) -> bool:
    """Refuse les reparse points jusqu'à la racine, sans suivre les liens."""
    current = path
    while True:
        if current.is_symlink() or current.is_junction():
            return False
        if current == stop:
            return True
        if current == current.parent:
            return False
        current = current.parent


def inspect_obsidure_c278_sandbox_observation(
    *, r10_inspection: dict[str, Any], repair_request: dict[str, Any],
    repair_proposal: dict[str, Any], c278_evidence: dict[str, Any],
    repair_verdict: dict[str, Any], repo_root: Path,
) -> dict[str, Any]:
    """Ne relance ni C278 externe, ni les tests, ni le producteur de verdict.

    ``repo_root`` doit être une racine existante. Aucune création d'objet.
    Le verdict peut avoir été forgé : le rapport ne prétend jamais le contraire.
    """
    if (type(r10_inspection) is not dict
            or r10_inspection.get("status") != "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY"):
        return _hold("R10_INSPECTION_REQUIRED")
    if any(type(v) is not dict for v in (
        repair_request, repair_proposal, c278_evidence, repair_verdict,
    )):
        return _hold("C278_SERIALIZED_INPUTS_REQUIRED")
    if (type(c278_evidence.get("checks")) is not dict
            or c278_evidence.get("schema") != "BRODY_PROPOSAL_MEANING_VALIDATOR_V2"):
        return _hold("C278_FULL_CANONICAL_RECORD_REQUIRED")

    for field, expected in (
        ("repair_request_id", repair_request.get("request_id")),
        ("repair_proposal_id", repair_proposal.get("proposal_id")),
        ("repair_verdict_id", repair_verdict.get("verdict_id")),
    ):
        if type(expected) is not str or not expected or r10_inspection.get(field) != expected:
            return _hold("C278_R10_REPAIR_LINEAGE_MISMATCH")
    if (repair_proposal.get("request_id") != repair_request.get("request_id")
            or repair_verdict.get("request_id") != repair_request.get("request_id")
            or repair_verdict.get("proposal_id") != repair_proposal.get("proposal_id")
            or repair_verdict.get("status") != "PASS"
            or repair_verdict.get("errors") != []):
        return _hold("C278_REPAIR_VERDICT_NOT_BOUND_PASS")

    try:
        replayed_c278 = validate_proposal_meaning(
            request=repair_request, proposal=repair_proposal,
        )
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return _hold("C278_CANONICAL_REPLAY_FAILED")
    if replayed_c278.get("evidence") != "CONTINUOUS" or replayed_c278 != c278_evidence:
        return _hold("C278_CANONICAL_RECORD_DIVERGES")

    candidates = repair_proposal.get("candidate_files")
    artifacts = repair_verdict.get("tested_artifacts")
    if (type(candidates) is not list or not 0 < len(candidates) <= _MAX_CANDIDATES
            or type(artifacts) is not list or len(artifacts) != len(candidates)):
        return _hold("C278_CANDIDATE_ARTIFACTS_INCOMPLETE")
    paths = []
    hashes = {}
    for candidate, artifact in zip(candidates, artifacts):
        if type(candidate) is not dict or type(artifact) is not dict:
            return _hold("C278_CANDIDATE_OR_ARTIFACT_INVALID")
        rel = _relative_path(candidate.get("path"))
        content = candidate.get("full_content")
        if (rel is None or rel in paths or type(content) is not str
                or not content.strip() or len(content.encode("utf-8")) > _MAX_FILE_BYTES
                or artifact.get("path") != rel):
            return _hold("C278_SANDBOX_TARGET_INVALID")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if artifact.get("sha256") != digest:
            return _hold("C278_TESTED_ARTIFACT_HASH_DIVERGES")
        paths.append(rel)
        hashes[rel] = digest

    observed = r10_inspection.get("candidates")
    if (type(observed) is not list or len(observed) != len(paths)
            or any(type(x) is not dict or type(x.get("target_path")) is not str
                   for x in observed)):
        return _hold("C278_R10_CANDIDATE_HASH_DIVERGES")
    if (len({x["target_path"] for x in observed}) != len(paths)
            or {x["target_path"]: x.get("candidate_content_sha256") for x in observed} != hashes):
        return _hold("C278_R10_CANDIDATE_HASH_DIVERGES")
    if repair_verdict.get("compiled_files") != paths:
        return _hold("C278_COMPILED_FILES_NOT_BOUND")

    expected_tests = repair_proposal.get("tests_to_run") or repair_request.get("tests_hint")
    executed = repair_verdict.get("tests_executed")
    if (type(expected_tests) is not list or not expected_tests or len(expected_tests) > 10
            or type(executed) is not list or len(executed) != len(expected_tests)):
        return _hold("C278_DECLARED_TEST_RESULTS_MISSING")
    isolations = []
    for expected, test in zip(expected_tests, executed):
        if (type(expected) is not str or type(test) is not dict
                or test.get("test") != expected or test.get("status") != "PASS"
                or type(test.get("returncode")) is not int or test["returncode"] != 0
                or test.get("isolation") not in ("FULL", "PARTIAL")):
            return _hold("C278_DECLARED_TEST_RESULT_INCONSISTENT")
        isolations.append(test["isolation"])

    try:
        root = Path(repo_root)
        sandbox = Path(repair_verdict.get("sandbox_dir"))
        if (not root.is_absolute() or not root.is_dir() or not sandbox.is_absolute()
                or not sandbox.name.startswith(_PREFIX)
                or not sandbox.is_dir() or not _no_reparse(root, Path(root.anchor))
                or not _no_reparse(sandbox, root)):
            return _hold("C278_SANDBOX_ROOT_UNTRUSTED")
        if sandbox.parent != root:
            return _hold("C278_SANDBOX_OUTSIDE_EXPECTED_REPO")
        for rel in paths:
            file = sandbox.joinpath(*rel.split("/"))
            if not _no_reparse(file, sandbox) or not file.is_file():
                return _hold("C278_SANDBOX_FILE_UNSAFE_OR_MISSING")
            if file.stat().st_size > _MAX_FILE_BYTES:
                return _hold("C278_SANDBOX_FILE_TOO_LARGE")
            raw = file.read_bytes()
            if len(raw) > _MAX_FILE_BYTES or file.read_bytes() != raw:
                return _hold("C278_SANDBOX_FILE_CHANGED_DURING_OBSERVATION")
            if hashlib.sha256(raw).hexdigest() != hashes[rel]:
                return _hold("C278_SANDBOX_BYTES_DIFFER_FROM_VERDICT")
    except (OSError, TypeError, ValueError, UnicodeError):
        return _hold("C278_SANDBOX_OBSERVATION_FAILED")

    return _result(
        "C278_SANDBOX_BYTES_MATCH_UNATTESTED", None,
        repair_lineage={
            "repair_request_id": repair_request["request_id"],
            "repair_proposal_id": repair_proposal["proposal_id"],
            "repair_verdict_id": repair_verdict["verdict_id"],
        },
        candidate_artifact_sha256=hashes,
        sandbox_test_isolation_observed=isolations,
        evidence_limits=[
            "VERDICT_AND_TEST_STATUSES_ARE_UNSIGNED",
            "SANDBOX_BYTES_CAN_BE_REWRITTEN_AFTER_TESTS",
            "C278_IS_SEMANTIC_CONTINUITY_NOT_RUNNER_ATTESTATION",
            "NO_GIT_HEAD_OR_SIGNED_EXECUTION_ORIGIN",
        ],
    )


def reconstruct_r9_patch_without_execution(
    *, repair_proposal: dict[str, Any], repo_root: Path,
) -> tuple[str | None, str | None]:
    """Rejoue EXACTEMENT le diff R9 des candidats F7, seulement en mémoire.

    Le producteur R9 `_build_patch_from_repair` accepte MODIFY existant et
    utilise `difflib.unified_diff` avec `lt=\\n` et `splitlines(keepends=True)`.
    Rejouer ces octets referme la liaison entre le contenu candidat réellement
    observé dans la sandbox et le patch du descripteur R9.
    """
    if type(repair_proposal) is not dict:
        return None, "R9_PATCH_SOURCE_PROPOSAL_MISSING"
    candidates = repair_proposal.get("candidate_files")
    if type(candidates) is not list or not 0 < len(candidates) <= _MAX_CANDIDATES:
        return None, "R9_PATCH_SOURCE_CANDIDATES_INVALID"
    try:
        root = Path(repo_root)
        if not root.is_absolute() or not root.is_dir() or not _no_reparse(root, Path(root.anchor)):
            return None, "R9_PATCH_SOURCE_ROOT_UNSAFE"
        chunks = []
        visited = set()
        for candidate in candidates:
            if type(candidate) is not dict:
                return None, "R9_PATCH_SOURCE_CANDIDATE_INVALID"
            rel = _relative_path(candidate.get("path"))
            content = candidate.get("full_content")
            digest = candidate.get("base_sha256")
            if (rel is None or rel in visited or candidate.get("change_kind") != "MODIFY"
                    or type(content) is not str or not content.strip()
                    or len(content.encode("utf-8")) > _MAX_FILE_BYTES):
                return None, "R9_PATCH_SOURCE_MODIFY_ONLY"
            visited.add(rel)
            file = root.joinpath(*rel.split("/"))
            if not _no_reparse(file, root) or not file.is_file():
                return None, "R9_PATCH_SOURCE_TARGET_UNSAFE"
            if file.stat().st_size > _MAX_FILE_BYTES:
                return None, "R9_PATCH_SOURCE_TARGET_TOO_LARGE"
            before = file.read_bytes()
            if len(before) > _MAX_FILE_BYTES or file.read_bytes() != before:
                return None, "R9_PATCH_SOURCE_BASE_DRIFT"
            if (type(digest) is not str
                    or hashlib.sha256(before).hexdigest() != digest):
                return None, "R9_PATCH_SOURCE_PREIMAGE_DRIFT"
            diff = "".join(difflib.unified_diff(
                before.decode("utf-8").splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile="a/" + rel, tofile="b/" + rel,
                lineterm="\n",
            ))
            if not diff:
                return None, "R9_PATCH_SOURCE_NO_EFFECTIVE_CHANGE"
            if not diff.endswith("\n"):
                diff += "\n"
            chunks.append(diff)
        return "".join(chunks), None
    except (OSError, TypeError, ValueError, UnicodeError):
        return None, "R9_PATCH_SOURCE_REPLAY_FAILED"
