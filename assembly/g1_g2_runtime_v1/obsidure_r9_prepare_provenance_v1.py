"""R9 -> R12 : verifier de PREPARE existant, en lecture seule.

Ce module ne lance jamais l'adaptateur R9, git apply ou un executeur. Il
recontrole les objets canoniques R9 et les deux artefacts V2 DEJA persistés.
L'integrite structurale n'atteste pas la provenance reelle de la sandbox.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from obsidure_builder_proposal_v1 import (
    ObsidureBuilderProposalV1, verify_builder_proposal,
)
from obsidure_proposal_manifest_v1 import (
    ObsidureProposalManifestV1, verify_proposal_manifest,
)
from obsidure_proposal_validation_v1 import (
    ProposalValidationResultV1, ValidationObligation, ValidationPolicy,
    validate_obsidure_proposal,
)
from obsidure_governance_handoff_v1 import (
    ObsidureGovernanceHandoffV1, verify_governance_handoff,
)


_R9_STATUS = "R10_REPAIR_PREPARED"
_V2_PREPARED = "PREPARED_AWAITING_HUMAN_APPROVAL"
_OP = "V2_APPLY_PATCH"
_ID = re.compile(r"^v2x-[a-f0-9]{32}$")
_HEX40 = re.compile(r"^[a-f0-9]{40}$")
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_REPAIR = ("repair_request_id", "repair_proposal_id", "repair_verdict_id")
_BUILDER = ("builder_proposal_id", "builder_manifest_id", "builder_validation_id", "builder_handoff_id")
_MAX_PATCH = 1_000_000
_MAX_DESC = 64_000
_MAX_TARGETS = 20
_FORBIDDEN = ("approval_created", "kx108_called", "executor_invoked", "physical_mutation")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _result(reason: str | None, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "OBSIDURE_R9_PREPARE_PROVENANCE_READONLY_V1",
        "status": "R9_PREPARE_BINDING_MATCH_UNATTESTED" if reason is None else "HOLD",
        "reason": reason,
        "readonly": True,
        "authority": "NON_SOVEREIGN",
        "decision_authority": "KX108_ONLY",
        "artifact_binding_verified": reason is None,
        "provenance_verified": False,
        "sandbox_origin_attested": False,
        "live_git_head_verified": False,
        "human_approval_verified": False,
        "execution_authorized": False,
        "action_ticket_issued": False,
        "kx108_pre_invoked": False,
        "executor_invoked": False,
        "target_mutated": False,
        "automatic_retry": False,
        **extra,
    }


def _jload_no_duplicates(raw: bytes) -> dict:
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("DUPLICATE_JSON_KEY")
            out[key] = value
        return out

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError("DESCRIPTOR_NOT_DICT")
    return value


def _read_store(base: Path, filename: str, maximum: int) -> bytes:
    if (base.is_symlink() or base.is_junction() or not base.is_dir()
            or any(p.is_symlink() or p.is_junction() for p in base.parents)):
        raise ValueError("UNSAFE_STORE_ROOT")
    store = base / "v2exec"
    if not store.is_dir() or store.is_symlink() or store.is_junction():
        raise ValueError("UNSAFE_V2_STORE")
    file = store / filename
    if not file.is_file() or file.is_symlink() or file.is_junction():
        raise ValueError("UNSAFE_OR_MISSING_V2_FILE")
    if file.stat().st_size > maximum:
        raise ValueError("V2_FILE_TOO_LARGE")
    raw = file.read_bytes()
    if len(raw) > maximum or file.read_bytes() != raw:
        raise ValueError("V2_FILE_CHANGED_DURING_READ")
    return raw


def _safe_target(path: str) -> bool:
    if type(path) is not str or not path or len(path) > 250 or "\\" in path or ":" in path:
        return False
    parts = path.split("/")
    if any(not p or p in (".", "..") or p.endswith((" ", "."))
           or p.lower().startswith(".git") or any(c in p for c in '<>"|?*')
           for p in parts):
        return False
    reserved = {"CON", "PRN", "AUX", "NUL"} | {"COM" + str(i) for i in range(1, 10)} | {"LPT" + str(i) for i in range(1, 10)}
    return all(p.split(".")[0].upper() not in reserved for p in parts)


def _patch_targets(raw: bytes) -> list[str] | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return None
    if "--- " not in text or "@@ " not in text or "GIT binary patch" in text:
        return None
    targets = []
    for line in text.split("\n"):
        if line.startswith("+++ "):
            name = line[4:].strip()
            if name.startswith("b/"):
                name = name[2:]
            if not _safe_target(name) or name in targets:
                return None
            targets.append(name)
    return targets if 0 < len(targets) <= _MAX_TARGETS else None


def inspect_obsidure_r9_prepare_provenance(
    *, r10_inspection: dict[str, Any], r9_result: dict[str, Any],
    stores_base_dir: Path, expected_repo_identity_ref: str,
) -> dict[str, Any]:
    """Rejoue la logique de liaison R9, sans appeler PREPARE ni APPLY."""
    if type(r10_inspection) is not dict or r10_inspection.get("status") != "OBSIDURE_R10_CANDIDATES_INSPECTED_READONLY":
        return _result("R10_INSPECTION_REQUIRED")
    if type(r9_result) is not dict or r9_result.get("status") != _R9_STATUS:
        return _result("R9_PREPARED_RESULT_REQUIRED")
    if type(expected_repo_identity_ref) is not str or not expected_repo_identity_ref.strip():
        return _result("EXPECTED_REPO_IDENTITY_REQUIRED")
    if any(r9_result.get(key) is not False for key in (
        "approval_created", "kx108_called", "executor_invoked", "physical_mutation",
        "commit_created", "push_performed", "merge_performed",
    )):
        return _result("R9_RESULT_CLAIMS_EXECUTION_AUTHORITY")
    if r9_result.get("prepared") is not True:
        return _result("R9_PREPARE_NOT_CONFIRMED")

    proposal = r9_result.get("r9_proposal")
    manifest = r9_result.get("r9_manifest")
    validation = r9_result.get("r9_validation")
    handoff = r9_result.get("r9_handoff")
    if not (type(proposal) is ObsidureBuilderProposalV1
            and type(manifest) is ObsidureProposalManifestV1
            and type(validation) is ProposalValidationResultV1
            and type(handoff) is ObsidureGovernanceHandoffV1):
        return _result("R9_CANONICAL_TYPED_ARTIFACTS_REQUIRED")
    try:
        for verify, args in (
            (verify_builder_proposal, (proposal,)),
            (verify_proposal_manifest, (manifest, proposal)),
            (verify_governance_handoff, (handoff, proposal, manifest, validation)),
        ):
            ok, why = verify(*args)
            if not ok:
                return _result("R9_CANONICAL_BINDING_INVALID:" + str(why))
        if validation.validation_verdict != "VALID":
            return _result("R9_VALIDATION_NOT_VALID")
        p = proposal.to_dict()
        m = manifest.to_dict()
        v = validation.to_dict()
        h = handoff.to_dict()
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        return _result("R9_CANONICAL_REPLAY_ERROR:" + type(exc).__name__)

    repair = r9_result.get("repair_lineage")
    if type(repair) is not dict or any(
        type(repair.get(key)) is not str or repair[key] != r10_inspection.get(key)
        for key in _REPAIR
    ):
        return _result("R9_R10_REPAIR_LINEAGE_MISMATCH")
    if any(h.get("source_metadata", {}).get(key) != repair[key] for key in _REPAIR):
        return _result("R9_HANDOFF_REPAIR_LINEAGE_MISMATCH")
    if h["repo_identity_ref"] != expected_repo_identity_ref or m["repo_identity_ref"] != expected_repo_identity_ref:
        return _result("R9_REPO_IDENTITY_MISMATCH")

    prepared = r9_result.get("prepared_action")
    if type(prepared) is not dict or prepared.get("status") != _V2_PREPARED or prepared.get("j5_phase") != "PREPARE":
        return _result("R9_V2_PREPARE_RECORD_REQUIRED")
    if any(prepared.get(key) is not False for key in _FORBIDDEN) or prepared.get("decision_authority") != "KX108_ONLY":
        return _result("R9_PREPARE_CLAIMS_EXECUTION_AUTHORITY")
    if any(prepared.get(key) is not False for key in (
        "action_evidence_id_created", "validation_equals_approval", "handoff_equals_authorization", "prepare_equals_authorization",
    )):
        return _result("R9_PREPARE_PRIVILEGE_ESCALATION")
    lineage = {
        "lineage_schema_version": "OBSIDURE_GOVERNED_PATCH_PREPARE_ADAPTER_V1",
        **dict(zip(_BUILDER, (p["proposal_id"], m["manifest_id"], v["validation_id"], h["handoff_id"]))),
    }
    if prepared.get("builder_lineage") != lineage or prepared.get("operation_type") != _OP:
        return _result("R9_BUILDER_LINEAGE_OR_OPERATION_MISMATCH")
    v2id = prepared.get("v2_exec_id")
    if type(v2id) is not str or not _ID.fullmatch(v2id):
        return _result("R9_V2_EXEC_ID_INVALID")

    try:
        base = Path(stores_base_dir)
        raw_descriptor = _read_store(base, v2id + ".json", _MAX_DESC)
        raw_patch = _read_store(base, v2id + ".patch", _MAX_PATCH)
        record = _jload_no_duplicates(raw_descriptor)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        return _result("R9_V2_STORED_ARTIFACT_INVALID:" + str(exc)[:100])
    desc = record.get("descriptor")
    if type(desc) is not dict:
        return _result("R9_V2_DESCRIPTOR_MISSING")
    patch = r9_result.get("patch_content")
    if type(patch) is not str or len(patch.encode("utf-8")) > _MAX_PATCH or raw_patch != patch.encode("utf-8"):
        return _result("R9_PATCH_ARTIFACT_DRIFT")
    targets = _patch_targets(raw_patch)
    if (targets is None or sorted(targets) != list(prepared.get("target_paths") or ())
            or sorted(targets) != list(p["target_scope"])
            or sorted(targets) != list(p["files_touched"])):
        return _result("R9_TARGET_SCOPE_OR_PATCH_FORMAT_MISMATCH")
    try:
        # L'adaptateur R9 signe l'ordre des candidats dans l'obligation :
        # cet ordre est celui du patch, pas le scope trie de la proposition.
        policy = ValidationPolicy(obligations=(ValidationObligation(
            obligation_kind="UNIT_TEST", target="repair-sandbox-verdict",
            scope=tuple(targets), required=True,
            expected_evidence_kind="TEST_RESULT_EVIDENCE", allow_observed=False,
        ),))
        replayed_validation = validate_obsidure_proposal(proposal, manifest, validation_policy=policy)
        if replayed_validation.to_dict() != validation.to_dict():
            return _result("R9_VALIDATION_REPLAY_MISMATCH")
    except (ValueError, TypeError, KeyError, AttributeError):
        return _result("R9_VALIDATION_REPLAY_UNAVAILABLE")
    patch_sha = _sha(raw_patch)
    if (patch_sha != p["candidate_patch_ref"]["sha256"]
            or patch_sha != prepared.get("patch_sha256")
            or patch_sha != desc.get("patch_sha256")
            or patch_sha != r9_result.get("tested_patch_hash")):
        return _result("R9_PATCH_HASH_MISMATCH")
    if (desc.get("descriptor_lineage") != lineage
            or desc.get("operation_type") != _OP
            or desc.get("target_paths") != sorted(targets)
            or desc.get("base_sha") != p["base_commit_sha"]
            or desc.get("before_digests") != prepared.get("before_digests")):
        return _result("R9_PERSISTED_DESCRIPTOR_BINDING_MISMATCH")
    if (type(desc.get("before_digests")) is not dict
            or set(desc["before_digests"]) != set(targets)
            or any(type(x) is not str or not _HEX64.fullmatch(x) for x in desc["before_digests"].values())
            or not _HEX40.fullmatch(str(desc.get("base_sha") or ""))):
        return _result("R9_PERSISTED_PREIMAGE_INVALID")
    eah = _sha(json.dumps({"v2_schema": "PC_CAPABILITIES_V2_EAH_V0", "operation_type": _OP,
                           "action_descriptor": desc}, sort_keys=True).encode("utf-8"))
    dh = _sha(raw_descriptor)
    mh = _sha(json.dumps(desc, sort_keys=True).encode("utf-8"))[:16]
    expected_v2id = "v2x-" + _sha((eah + desc["base_sha"] + str(desc.get("session_id") or "")).encode("utf-8"))[:32]
    expected_child = "chd-" + _sha((eah + patch_sha).encode("utf-8"))[:32]
    if (record.get("v2_exec_id") != v2id or record.get("eah") != eah
            or record.get("operation_type") != _OP or record.get("decision_authority") != "KX108_ONLY"
            or prepared.get("execution_authority_hash") != eah
            or prepared.get("desc_hash") != dh or prepared.get("manifest_hash") != mh
            or prepared.get("child_id") != expected_child or v2id != expected_v2id):
        return _result("R9_V2_DESCRIPTOR_AUTHORITY_BINDING_MISMATCH")
    return _result(
        None,
        repair_lineage={key: repair[key] for key in _REPAIR},
        builder_lineage={key: lineage[key] for key in _BUILDER},
        v2_exec_id=v2id,
        descriptor_hash=dh,
        patch_sha256=patch_sha,
        repo_identity_ref=expected_repo_identity_ref,
        evidence_limits=["R9_SANDBOX_ORIGIN_NOT_AUTHENTICATED", "PREPARE_IS_NOT_HUMAN_APPROVAL",
                         "CURRENT_WORKTREE_STATE_NOT_ATTESTED", "NO_KX108_PRE_OR_POST"],
    )
