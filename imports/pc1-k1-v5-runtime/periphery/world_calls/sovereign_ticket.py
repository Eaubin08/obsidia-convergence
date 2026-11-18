from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

# Format versioning
TICKET_VERSION_V1 = "obsidia.kx108.ticket.v1"
# KX108-K1 : seul format porteur d'un ALLOW ; la liaison à la décision vérifiée est couverte par le HMAC.
TICKET_VERSION_V2 = "obsidia.kx108.ticket.v2"
# Périmètres qu'une décision d'un domaine souverain peut adosser (aucun domaine ni périmètre nouveau).
TICKET_SCOPES_BY_DOMAIN: Dict[str, tuple] = {"tooling_build": ("bounded_apply",)}

# Default Key ID and In-Memory Registry for Key Rotation
_DEFAULT_KEY_ID = "kx108-k1"
_KEY_REGISTRY: Dict[str, bytes] = {}


def get_kernel_key(key_id: str = _DEFAULT_KEY_ID) -> bytes:
    """
    Récupère la clé secrète associée à un key_id.
    - En production (OBSIDIA_ENV=production|prod) : la clé est STRICTEMENT OBLIGATOIRE via variable
      d'environnement et doit mesurer au minimum 32 octets (256 bits). Aucune génération silencieuse.
    - En environnement de test/dev local : génération sécurisée 256 bits en RAM sans fuite Git.
    """
    if key_id not in _KEY_REGISTRY:
        env_var = f"OBSIDIA_KEY_{key_id.upper().replace('-', '_')}"
        env_key = os.environ.get(env_var) or os.environ.get("OBSIDIA_KX108_SECRET_KEY")
        is_production = os.environ.get("OBSIDIA_ENV", "").strip().lower() in ("production", "prod")

        # K1: reuse a provisioned Windows DPAPI key when no
        # explicit environment key was provided.
        if not env_key and os.name == "nt":
            from periphery.world_calls.k1_dpapi_bootstrap import (
                load_k1_dpapi_key_text,
            )
            env_key = load_k1_dpapi_key_text()

        if env_key:
            key_bytes = env_key.encode("utf-8") if isinstance(env_key, str) else env_key
            if is_production and len(key_bytes) < 32:
                raise ValueError(
                    f"OBSIDIA_KEY_SAFETY_ERROR: Secret key for '{key_id}' in production must have "
                    f"at least 32 bytes (256 bits) of entropy, got {len(key_bytes)}."
                )
            _KEY_REGISTRY[key_id] = key_bytes
        else:
            if is_production:
                raise RuntimeError(
                    f"OBSIDIA_PRODUCTION_FAIL_CLOSED: Secret key for '{key_id}' is mandatory in production. "
                    f"Set {env_var} or OBSIDIA_KX108_SECRET_KEY."
                )
            # Environnement de test/dev local : clé cryptographique 256 bits en mémoire
            _KEY_REGISTRY[key_id] = secrets.token_bytes(32)
    return _KEY_REGISTRY[key_id]

def require_persistent_kernel_keys(key_ids):
    """
    Physical K1 execution requires externally configured key material.

    A cached ephemeral key is not evidence of provenance.
    This function never generates replacement key material.
    """
    import hmac

    accepted = {}

    for key_id in dict.fromkeys(key_ids):
        if not isinstance(key_id, str) or not key_id:
            raise RuntimeError("K1_PERSISTENT_KEY_INVALID")

        env_var = (
            f"OBSIDIA_KEY_{key_id.upper().replace('-', '_')}"
        )

        configured = (
            os.environ.get(env_var)
            or os.environ.get("OBSIDIA_KX108_SECRET_KEY")
        )

        if not configured and os.name == "nt":
            from periphery.world_calls.k1_dpapi_bootstrap import (
                load_k1_dpapi_key_text,
            )
            configured = load_k1_dpapi_key_text()

        if not configured:
            raise RuntimeError("K1_PERSISTENT_KEY_REQUIRED")

        if isinstance(configured, str):
            key_bytes = configured.encode("utf-8")
        elif isinstance(configured, bytes):
            key_bytes = configured
        else:
            raise RuntimeError("K1_PERSISTENT_KEY_INVALID")

        if len(key_bytes) < 32:
            raise RuntimeError("K1_PERSISTENT_KEY_INVALID")

        cached = _KEY_REGISTRY.get(key_id)

        if cached is not None and not hmac.compare_digest(
            cached, key_bytes
        ):
            raise RuntimeError("K1_KEY_PROVENANCE_MISMATCH")

        accepted[key_id] = key_bytes

    # Only update the registry when every requested key has
    # passed provenance validation.
    _KEY_REGISTRY.update(accepted)



def reset_kernel_keys() -> None:
    """Réinitialise le registre de clés pour tests hermétiques."""
    global _KEY_REGISTRY
    _KEY_REGISTRY.clear()


def register_kernel_key(key_id: str, key_bytes: bytes) -> None:
    """Enregistre ou fait pivoter une clé d'autorité pour tests ou rotation officielle."""
    _KEY_REGISTRY[key_id] = key_bytes


def canonical_ticket_bytes(
    version: str,
    ticket_id: str,
    decision_id: str,
    action_id: str,
    os3_ticket_id: str,
    scope: str,
    x108_gate: str,
    autonomy_level: int,
    world_call_class: str,
    dry_run_only: bool,
    input_hash: str,
    action_hash: str,
    issued_at: str,
    expires_at: str,
    nonce: str,
    key_id: str,
    decision_record_id: str = "",
    decision_record_hash: str = "",
    decision_domain: str = "",
) -> bytes:
    """Sérialisation canonique, versionnée et déterministe pour authentification HMAC.
    v2 couvre en plus la liaison à l'enregistrement de décision ; v1 reste octet pour octet inchangé."""
    canonical_dict = {
        "action_hash": str(action_hash),
        "action_id": str(action_id),
        "autonomy_level": int(autonomy_level),
        "decision_id": str(decision_id),
        "dry_run_only": bool(dry_run_only),
        "expires_at": str(expires_at),
        "input_hash": str(input_hash),
        "issued_at": str(issued_at),
        "key_id": str(key_id),
        "nonce": str(nonce),
        "os3_ticket_id": str(os3_ticket_id),
        "scope": str(scope),
        "ticket_id": str(ticket_id),
        "version": str(version),
        "world_call_class": str(world_call_class),
        "x108_gate": str(x108_gate),
    }
    if str(version) == TICKET_VERSION_V2:
        canonical_dict.update({
            "decision_domain": str(decision_domain),
            "decision_record_hash": str(decision_record_hash),
            "decision_record_id": str(decision_record_id),
        })
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_authenticator(raw_bytes: bytes, key_id: str = _DEFAULT_KEY_ID) -> str:
    """Calcule le HMAC-SHA256 de la sérialisation canonique."""
    key = get_kernel_key(key_id)
    return hmac.new(key, raw_bytes, hashlib.sha256).hexdigest()


@dataclass
class SovereignTicket:
    ticket_id: str
    action_id: str
    os3_ticket_id: str
    scope: str
    issued_at: str
    expires_at: str
    x108_gate: str
    autonomy_level: int
    dry_run_only: bool = True
    world_call_class: str = "NO_WORLD_CALL"
    hash: str = ""
    # Nouveaux champs d'autorité Phase 2G :
    decision_id: str = ""
    input_hash: str = ""
    action_hash: str = ""
    nonce: str = ""
    key_id: str = _DEFAULT_KEY_ID
    authenticator: str = ""
    version: str = TICKET_VERSION_V1
    # KX108-K1 : liaison à l'enregistrement de décision vérifié (tickets v2)
    decision_record_id: str = ""
    decision_record_hash: str = ""
    decision_domain: str = ""

    @property
    def kernel_signature(self) -> str:
        """Alias documentaire pour conformité de contrat."""
        return self.authenticator

    def is_expired(self) -> bool:
        if not self.expires_at:
            return True
        now = datetime.now(timezone.utc).isoformat()
        return now > self.expires_at

    def is_valid_scope(self, required_scope: str) -> bool:
        return self.scope == required_scope or self.scope == "*"

    def assert_not_expired(self) -> None:
        if self.is_expired():
            raise AssertionError(f"SOVEREIGN_TICKET_EXPIRED:{self.ticket_id}")

    def assert_scope(self, required_scope: str) -> None:
        if not self.is_valid_scope(required_scope):
            raise AssertionError(f"SOVEREIGN_TICKET_INVALID_SCOPE:{self.scope}!={required_scope}")

    def assert_dry_run(self) -> None:
        if not self.dry_run_only:
            raise AssertionError("SOVEREIGN_TICKET_NOT_DRY_RUN")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "action_id": self.action_id,
            "os3_ticket_id": self.os3_ticket_id,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "x108_gate": self.x108_gate,
            "autonomy_level": self.autonomy_level,
            "dry_run_only": self.dry_run_only,
            "world_call_class": self.world_call_class,
            "hash": self.hash,
            "decision_id": self.decision_id,
            "input_hash": self.input_hash,
            "action_hash": self.action_hash,
            "nonce": self.nonce,
            "key_id": self.key_id,
            "authenticator": self.authenticator,
            "version": self.version,
            "decision_record_id": self.decision_record_id,
            "decision_record_hash": self.decision_record_hash,
            "decision_domain": self.decision_domain,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SovereignTicket:
        return cls(
            ticket_id=str(data.get("ticket_id", "")),
            action_id=str(data.get("action_id", "")),
            os3_ticket_id=str(data.get("os3_ticket_id", "")),
            scope=str(data.get("scope", "")),
            issued_at=str(data.get("issued_at", "")),
            expires_at=str(data.get("expires_at", "")),
            x108_gate=str(data.get("x108_gate", "UNKNOWN")),
            autonomy_level=int(data.get("autonomy_level", 0)),
            dry_run_only=bool(data.get("dry_run_only", True)),
            world_call_class=str(data.get("world_call_class", "NO_WORLD_CALL")),
            hash=str(data.get("hash", "")),
            decision_id=str(data.get("decision_id", "")),
            input_hash=str(data.get("input_hash", "")),
            action_hash=str(data.get("action_hash", "")),
            nonce=str(data.get("nonce", "")),
            key_id=str(data.get("key_id", _DEFAULT_KEY_ID)),
            authenticator=str(data.get("authenticator", "")),
            version=str(data.get("version", "")),
            decision_record_id=str(data.get("decision_record_id", "")),
            decision_record_hash=str(data.get("decision_record_hash", "")),
            decision_domain=str(data.get("decision_domain", "")),
        )


def verify_authenticator(ticket: SovereignTicket) -> bool:
    """Vérification en temps constant du HMAC d'autorité."""
    if not ticket.authenticator or not ticket.nonce or not ticket.expires_at:
        return False
    try:
        key = get_kernel_key(ticket.key_id)
    except KeyError:
        return False

    raw_bytes = canonical_ticket_bytes(
        version=ticket.version or TICKET_VERSION_V1,
        ticket_id=ticket.ticket_id,
        decision_id=ticket.decision_id,
        action_id=ticket.action_id,
        os3_ticket_id=ticket.os3_ticket_id,
        scope=ticket.scope,
        x108_gate=ticket.x108_gate,
        autonomy_level=ticket.autonomy_level,
        world_call_class=ticket.world_call_class,
        dry_run_only=ticket.dry_run_only,
        input_hash=ticket.input_hash,
        action_hash=ticket.action_hash,
        issued_at=ticket.issued_at,
        expires_at=ticket.expires_at,
        nonce=ticket.nonce,
        key_id=ticket.key_id,
        decision_record_id=ticket.decision_record_id,
        decision_record_hash=ticket.decision_record_hash,
        decision_domain=ticket.decision_domain,
    )
    expected = hmac.new(key, raw_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(ticket.authenticator, expected)


# ── KX108-K1 — liaison aux décisions vérifiées ──────────────────────────────

def load_decision_store():
    """Rail canonique scripts/obsidia_kx108_decision_store.py, sous une identité de module unique."""
    module = sys.modules.get("obsidia_kx108_decision_store")
    if module is None:
        path = Path(__file__).resolve().parents[2] / "scripts" / "obsidia_kx108_decision_store.py"
        spec = importlib.util.spec_from_file_location("obsidia_kx108_decision_store", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["obsidia_kx108_decision_store"] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop("obsidia_kx108_decision_store", None)
            raise
    return module


def _verified_decision_record(decision_record_id: str, decision_store_dir: Any = None) -> dict:
    """Charge l'enregistrement depuis le magasin canonique (jamais fourni par l'appelant) et le vérifie :
    structure, authentificateur du noyau, cohérence avec l'enveloppe GuardX108, producteur éligible."""
    try:
        store = load_decision_store()
        record = store.load_kx108_decision_record(
            str(decision_record_id or ""), Path(decision_store_dir) if decision_store_dir else None)
    except Exception as exc:
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_STORE_UNAVAILABLE:{type(exc).__name__}")
    ok, reason = store.verify_kx108_decision_record_authenticity(record)
    if not ok:
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_RECORD_INVALID:{reason}")
    if record.get("decision_record_producer") not in store.TICKET_ELIGIBLE_PRODUCERS:
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_PRODUCER_NOT_ELIGIBLE:{record.get('decision_record_producer')}")
    return record




def _assert_pre_action_binding(
    record: dict, *, action_id: str, input_hash: str, action_hash: str,
    action_payload: Any, target_worktree: Any, base_sha: str, approved_scope: Any,
    execution_dir: Any, pre_execution_context_dir: Any,
    repo_root: Any = None, derived_authority_context: Any = None,
) -> None:
    """Fail-closed K1 binding: one canonical PRE child to one exact WRITE payload.

    Only FILESYSTEM_FILE / UPDATE_TARGET_FROM_SOURCE, one target, is supported.
    Unknown representations are not converted into implied authorization.
    """
    from pathlib import PurePosixPath
    from scripts import obsidia_batch_execution as _execution
    from scripts import obsidia_pre_execution_context as _context
    from scripts.obsidia_kx108_pre_execution_evidence_adapter_v0 import (
        translate_pre_execution_evidence_to_tooling_build_state as _translate_pre,
    )

    def refuse(reason: str) -> None:
        raise AssertionError("SOVEREIGN_TICKET_PRE_ACTION_BINDING:" + reason)

    if not execution_dir or not pre_execution_context_dir:
        refuse("CANONICAL_EVIDENCE_LOCATIONS_REQUIRED")
    if not isinstance(action_id, str) or not action_id:
        refuse("ACTION_ID_REQUIRED")
    if not isinstance(base_sha, str) or not base_sha or not target_worktree:
        refuse("WORKTREE_BASE_REQUIRED")
    if not isinstance(action_payload, list) or len(action_payload) != 1:
        refuse("SINGLE_WRITE_PAYLOAD_REQUIRED")
    op = action_payload[0]
    if not isinstance(op, dict) or set(op) != {"path", "content", "type"}:
        refuse("OPERATION_SHAPE_INVALID")
    target = op.get("path")
    if not isinstance(target, str) or not target or "\\" in target or ":" in target:
        refuse("TARGET_PATH_INVALID")
    path = PurePosixPath(target)
    if path.is_absolute() or path.as_posix() != target or any(p in (".", "..") for p in target.split("/")):
        refuse("TARGET_PATH_NOT_CANONICAL")
    if not isinstance(op.get("content"), str) or op.get("type") != "WRITE":
        refuse("WRITE_ONLY_CONTRACT")
    if approved_scope != [target]:
        refuse("APPROVED_SCOPE_MISMATCH")

    content_hash = hashlib.sha256(op["content"].encode("utf-8")).hexdigest()
    payload_hash = hashlib.sha256(json.dumps(
        action_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(str(input_hash), payload_hash):
        refuse("PATCH_HASH_MISMATCH")
    expected_action_hash = hashlib.sha256(
        f"{target_worktree}:{base_sha}".encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(str(action_hash), expected_action_hash):
        refuse("WORKTREE_BASE_ACTION_HASH_MISMATCH")

    child_id = record.get("child_execution_id")
    expected_child_id = "child-" + hashlib.sha256(
        "|".join((action_id, target, content_hash)).encode("utf-8")
    ).hexdigest()[:24]
    if child_id != expected_child_id:
        refuse("PROPOSAL_CHILD_ID_MISMATCH")

    try:
        tr = _translate_pre(
            batch_execution_id=record.get("batch_execution_id"),
            child_execution_id=child_id,
            approval_id=record.get("approval_id"),
            execution_dir=Path(execution_dir),
            pre_execution_context_dir=Path(pre_execution_context_dir),
            repo_root=Path(repo_root) if repo_root else None,
            derived_authority_context=derived_authority_context,
        )
    except Exception as exc:
        refuse("CANONICAL_VERIFIER_UNAVAILABLE:" + type(exc).__name__)
    if tr.get("status") != "READY_FOR_KX108_PRE_SUBMISSION":
        refuse("CANONICAL_EVIDENCE_INVALID:" + str(tr.get("reason")))
    bound = tr.get("pre_binding_context") or {}
    store = load_decision_store()
    if any(record.get(k) != bound.get(k) for k in store._PRE_BINDING_CONTEXT_FIELDS):
        refuse("SIGNED_PRE_RECORD_EVIDENCE_MISMATCH")

    try:
        env = _execution._load_execution(record["batch_execution_id"], Path(execution_dir))
        children = [c for c in env["children"] if c.get("child_execution_id") == child_id]
        ctx = _context.load_pre_execution_context_record(
            record["pre_execution_context_id"], Path(pre_execution_context_dir),
        )
    except Exception as exc:
        refuse("CANONICAL_ACTION_LOAD_FAILED:" + type(exc).__name__)
    if len(children) != 1 or not isinstance(ctx, dict):
        refuse("CANONICAL_ACTION_AMBIGUOUS")
    child = children[0]
    if child.get("source_kind") != "FILESYSTEM_FILE" or child.get("operation_type") != "UPDATE_TARGET_FROM_SOURCE":
        refuse("UNSUPPORTED_CANONICAL_OPERATION")
    if child.get("target_path") != target or child.get("source_content_sha256") != content_hash:
        refuse("CHILD_TARGET_OR_SOURCE_MISMATCH")
    if ctx.get("source_kind") != "FILESYSTEM_FILE" or ctx.get("source_sha256") != content_hash:
        refuse("CONTEXT_SOURCE_MISMATCH")
    if child.get("source_path") != ctx.get("source_path"):
        refuse("CANONICAL_SOURCE_PATH_MISMATCH")
    if ctx.get("base_sha") != base_sha or ctx.get("approved_scope") != [target]:
        refuse("CONTEXT_BASE_OR_SCOPE_MISMATCH")
    if ctx.get("operation") not in ("REPLACE", "UPDATE", "UPDATE_TARGET_FROM_SOURCE"):
        refuse("CONTEXT_OPERATION_NOT_MAPPED_TO_WRITE")
    if os.path.normcase(str(Path(ctx.get("execution_worktree_path") or "").resolve())) != os.path.normcase(str(Path(target_worktree).resolve())):
        refuse("EXECUTION_WORKTREE_MISMATCH")

    root = Path(ctx.get("repository_root") or "").resolve()
    source_path = ctx.get("source_path")
    if not source_path or Path(source_path).is_absolute():
        refuse("SOURCE_PATH_INVALID")
    source_file = (root / source_path).resolve()
    if not source_file.is_relative_to(root) or not source_file.is_file():
        refuse("SOURCE_NOT_CONFIRMED_WITHIN_REPOSITORY")
    try:
        current_source_hash = hashlib.sha256(source_file.read_bytes()).hexdigest()
    except OSError:
        refuse("SOURCE_READ_FAILED")
    if current_source_hash != content_hash:
        refuse("SOURCE_CONTENT_DRIFT")

    worktree = Path(target_worktree).resolve()
    target_file = (worktree / target).resolve()
    if not target_file.is_relative_to(worktree) or not target_file.is_file():
        refuse("TARGET_NOT_REGULAR_FILE")
    try:
        target_current_hash = hashlib.sha256(target_file.read_bytes()).hexdigest()
    except OSError:
        refuse("TARGET_READ_FAILED")
    if not hmac.compare_digest(str(child.get("target_pre_sha256")), target_current_hash):
        refuse("TARGET_PRECONDITION_DRIFT")


def verify_ticket_decision_binding(
    ticket: "SovereignTicket", decision_store_dir: Any = None, *,
    action_payload: Any = None, target_worktree: Any = None, base_sha: str = "",
    approved_scope: Any = None, execution_dir: Any = None,
    pre_execution_context_dir: Any = None, repo_root: Any = None,
    derived_authority_context: Any = None,
) -> dict:
    """Un ticket ALLOW n'a d'autorité que par la décision vérifiée qu'il désigne ; renvoie cet enregistrement."""
    if ticket.version != TICKET_VERSION_V2 or not ticket.decision_record_id or not ticket.decision_record_hash:
        raise AssertionError(f"SOVEREIGN_TICKET_NO_DECISION_BINDING:{ticket.ticket_id}")
    record = _verified_decision_record(ticket.decision_record_id, decision_store_dir)
    if ticket.scope == "bounded_apply" or ticket.world_call_class == "GOVERNED_WRITE":
        if record.get("decision_phase") != "PRE_EXECUTION":
            raise AssertionError("SOVEREIGN_TICKET_PRE_EXECUTION_REQUIRED")
        if record.get("decision_record_producer") != "run_and_persist_kx108_pre_execution_decision":
            raise AssertionError("SOVEREIGN_TICKET_PRE_PRODUCER_REQUIRED")

    if record.get("x108_gate") != "ALLOW":
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_NOT_ALLOW:{record.get('x108_gate')}")
    if record.get("decision_record_hash") != ticket.decision_record_hash:
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_RECORD_HASH_MISMATCH:{ticket.ticket_id}")
    if record.get("decision_id") != ticket.decision_id:
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_ID_MISMATCH:{ticket.ticket_id}")
    if record.get("domain") != ticket.decision_domain:
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_DOMAIN_MISMATCH:{ticket.decision_domain}")
    if ticket.scope not in TICKET_SCOPES_BY_DOMAIN.get(str(record.get("domain")), ()):
        raise AssertionError(f"SOVEREIGN_TICKET_SCOPE_NOT_PERMITTED_FOR_DOMAIN:{ticket.scope}")
    if ticket.scope == "bounded_apply" or ticket.world_call_class == "GOVERNED_WRITE":
        _assert_pre_action_binding(
            record, action_id=ticket.action_id, input_hash=ticket.input_hash,
            action_hash=ticket.action_hash, action_payload=action_payload,
            target_worktree=target_worktree, base_sha=base_sha,
            approved_scope=approved_scope, execution_dir=execution_dir,
            pre_execution_context_dir=pre_execution_context_dir, repo_root=repo_root,
            derived_authority_context=derived_authority_context,
        )
    return record


def issue_sovereign_ticket(
    action_id: str,
    os3_ticket_id: str,
    x108_gate: str,
    scope: str,
    autonomy_level: int,
    world_call_class: str,
    input_hash: str = "",
    action_hash: str = "",
    decision_id: str = "",
    key_id: str = _DEFAULT_KEY_ID,
    nonce: str = "",
    ttl_seconds: int = 300,
) -> SovereignTicket:
    """
    Émet un ticket souverain authentifié cryptographiquement par le kernel KX108.

    KX108-K1 : un ALLOW n'est jamais accepté de l'appelant. Il n'est émis que par
    issue_sovereign_ticket_from_decision_record, à partir d'une décision vérifiée.
    Les tickets HOLD/BLOCK (chemins de refus) restent émissibles ici.
    """
    if str(x108_gate).strip().upper() == "ALLOW":
        raise AssertionError("SOVEREIGN_TICKET_ALLOW_REQUIRES_VERIFIED_DECISION_RECORD")
    now = datetime.now(timezone.utc)
    issued_at = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat() if ttl_seconds > 0 else (now + timedelta(seconds=ttl_seconds)).isoformat()
    ticket_id = uuid.uuid4().hex
    
    if not decision_id:
        decision_id = f"dec-{uuid.uuid4().hex[:12]}"
    if not nonce:
        nonce = secrets.token_hex(16)
    if not action_hash:
        action_hash = hashlib.sha256(action_id.encode("utf-8")).hexdigest()

    raw_bytes = canonical_ticket_bytes(
        version=TICKET_VERSION_V1,
        ticket_id=ticket_id,
        decision_id=decision_id,
        action_id=action_id,
        os3_ticket_id=os3_ticket_id,
        scope=scope,
        x108_gate=x108_gate,
        autonomy_level=autonomy_level,
        world_call_class=world_call_class,
        dry_run_only=True,
        input_hash=input_hash,
        action_hash=action_hash,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        key_id=key_id,
    )
    authenticator = compute_authenticator(raw_bytes, key_id=key_id)

    # Condensat SHA-256 historique préservé pour compatibilité
    legacy_payload = {
        "ticket_id": ticket_id,
        "action_id": action_id,
        "os3_ticket_id": os3_ticket_id,
        "scope": scope,
        "issued_at": issued_at,
        "x108_gate": x108_gate,
    }
    legacy_hash = hashlib.sha256(
        json.dumps(legacy_payload, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()

    return SovereignTicket(
        ticket_id=ticket_id,
        action_id=action_id,
        os3_ticket_id=os3_ticket_id,
        scope=scope,
        issued_at=issued_at,
        expires_at=expires_at,
        x108_gate=x108_gate,
        autonomy_level=autonomy_level,
        dry_run_only=True,
        world_call_class=world_call_class,
        hash=legacy_hash,
        decision_id=decision_id,
        input_hash=input_hash,
        action_hash=action_hash,
        nonce=nonce,
        key_id=key_id,
        authenticator=authenticator,
        version=TICKET_VERSION_V1,
    )


def issue_sovereign_ticket_from_decision_record(
    decision_record_id: str,
    *,
    action_id: str,
    scope: str,
    input_hash: str,
    decision_store_dir: Any = None,
    autonomy_level: int = 1,
    world_call_class: str = "GOVERNED_WRITE",
    action_hash: str = "",
    key_id: str = _DEFAULT_KEY_ID,
    ttl_seconds: int = 300,
    action_payload: Any = None,
    target_worktree: Any = None,
    base_sha: str = "",
    approved_scope: Any = None,
    execution_dir: Any = None,
    pre_execution_context_dir: Any = None,
    repo_root: Any = None,
    derived_authority_context: Any = None,
) -> SovereignTicket:
    """
    KX108-K1 — seul émetteur d'un ticket ALLOW. L'enregistrement est chargé depuis le
    magasin canonique et vérifié (structure, authentificateur du noyau, cohérence avec
    l'enveloppe GuardX108, producteur éligible) ; x108_gate, decision_id et domaine en
    sont copiés, jamais reçus de l'appelant. Aucune décision de remplacement.
    """
    record = _verified_decision_record(decision_record_id, decision_store_dir)
    if scope == "bounded_apply" or world_call_class == "GOVERNED_WRITE":
        if record.get("decision_phase") != "PRE_EXECUTION":
            raise AssertionError("SOVEREIGN_TICKET_PRE_EXECUTION_REQUIRED")
        if record.get("decision_record_producer") != "run_and_persist_kx108_pre_execution_decision":
            raise AssertionError("SOVEREIGN_TICKET_PRE_PRODUCER_REQUIRED")

    gate = str(record.get("x108_gate"))
    if gate != "ALLOW":
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_NOT_ALLOW:{gate}")
    domain = str(record.get("domain"))
    if scope not in TICKET_SCOPES_BY_DOMAIN.get(domain, ()):
        raise AssertionError(f"SOVEREIGN_TICKET_SCOPE_NOT_PERMITTED_FOR_DOMAIN:{domain}:{scope}")
    if not input_hash:
        raise AssertionError("SOVEREIGN_TICKET_INPUT_BINDING_REQUIRED")

    if scope == "bounded_apply" or world_call_class == "GOVERNED_WRITE":
        _assert_pre_action_binding(
            record, action_id=action_id, input_hash=input_hash,
            action_hash=action_hash, action_payload=action_payload,
            target_worktree=target_worktree, base_sha=base_sha,
            approved_scope=approved_scope, execution_dir=execution_dir,
            pre_execution_context_dir=pre_execution_context_dir, repo_root=repo_root,
            derived_authority_context=derived_authority_context,
        )

    now = datetime.now(timezone.utc)
    issued_at = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    fields = {
        "version": TICKET_VERSION_V2, "ticket_id": uuid.uuid4().hex, "decision_id": str(record.get("decision_id")),
        "action_id": action_id, "os3_ticket_id": "", "scope": scope, "x108_gate": gate,
        "autonomy_level": autonomy_level, "world_call_class": world_call_class, "dry_run_only": True,
        "input_hash": input_hash, "action_hash": action_hash or hashlib.sha256(action_id.encode("utf-8")).hexdigest(),
        "issued_at": issued_at, "expires_at": expires_at, "nonce": secrets.token_hex(16), "key_id": key_id,
        "decision_record_id": str(record.get("decision_record_id")),
        "decision_record_hash": str(record.get("decision_record_hash")), "decision_domain": domain,
    }
    authenticator = compute_authenticator(canonical_ticket_bytes(**fields), key_id=key_id)
    return SovereignTicket(
        ticket_id=fields["ticket_id"], action_id=action_id, os3_ticket_id="", scope=scope, issued_at=issued_at,
        expires_at=expires_at, x108_gate=gate, autonomy_level=autonomy_level, dry_run_only=True,
        world_call_class=world_call_class, hash="", decision_id=fields["decision_id"], input_hash=input_hash,
        action_hash=fields["action_hash"], nonce=fields["nonce"], key_id=key_id, authenticator=authenticator,
        version=TICKET_VERSION_V2, decision_record_id=fields["decision_record_id"],
        decision_record_hash=fields["decision_record_hash"], decision_domain=domain,
    )


def require_ticket_or_block(ticket: SovereignTicket | None) -> None:
    if ticket is None:
        raise AssertionError("NO_SOVEREIGN_TICKET_NO_WORLD_CALL")
    ticket.assert_not_expired()
    ticket.assert_dry_run()
    if not verify_authenticator(ticket):
        raise AssertionError(f"SOVEREIGN_TICKET_AUTHENTICATOR_INVALID:{ticket.ticket_id}")
