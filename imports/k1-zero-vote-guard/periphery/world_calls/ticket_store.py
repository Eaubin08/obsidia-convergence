from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from .sovereign_ticket import (
    SovereignTicket,
    verify_authenticator,
    verify_ticket_decision_binding,
    TICKET_VERSION_V1,
    TICKET_VERSION_V2,
)

_DEFAULT_STORE = os.path.join(
    os.path.dirname(__file__), "..", "..", "audit", "sovereign_tickets.jsonl"
)
_DEFAULT_CONSUMED_STORE = os.path.join(
    os.path.dirname(__file__), "..", "..", "audit", "consumed_nonces.jsonl"
)


class FileLock:
    """Verrou de fichier atomique compatible Windows et multi-processus."""
    def __init__(self, lock_path: str, timeout_s: float = 5.0, poll_interval_s: float = 0.01):
        self.lock_path = lock_path
        self.timeout_s = timeout_s
        self.poll_interval_s = poll_interval_s
        self.fd: Optional[int] = None

    def __enter__(self):
        start = time.monotonic()
        while True:
            try:
                self.fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                return self
            except (FileExistsError, PermissionError):
                if time.monotonic() - start > self.timeout_s:
                    # Sécurité lock stale (> 10s)
                    try:
                        mtime = os.path.getmtime(self.lock_path)
                        if time.time() - mtime > 10.0:
                            os.remove(self.lock_path)
                            continue
                    except OSError:
                        pass
                    raise TimeoutError(f"LOCK_TIMEOUT:{self.lock_path}")
                time.sleep(self.poll_interval_s)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            try:
                os.remove(self.lock_path)
            except OSError:
                pass


def store_ticket(ticket: SovereignTicket, store_path: str | None = None) -> None:
    path = store_path or _DEFAULT_STORE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(ticket.to_dict(), ensure_ascii=False) + "\n")


def load_tickets(store_path: str | None = None) -> list[dict[str, Any]]:
    path = store_path or _DEFAULT_STORE
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def load_consumed_nonces(store_path: str | None = None) -> dict[str, dict[str, Any]]:
    """Charge l'ensemble des nonces consommés et leur état."""
    path = store_path or _DEFAULT_CONSUMED_STORE
    if not os.path.exists(path):
        return {}
    records = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    nonce = data.get("nonce")
                    if nonce:
                        records[nonce] = data
                except json.JSONDecodeError:
                    continue
    return records


def reserve_ticket_nonce(nonce: str, ticket_id: str, store_path: str | None = None) -> bool:
    """Réserve atomiquement un nonce. Échoue si le nonce est déjà réservé ou consommé."""
    if not nonce:
        return False
    path = store_path or _DEFAULT_CONSUMED_STORE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock_path = path + ".lock"

    with FileLock(lock_path):
        records = load_consumed_nonces(path)
        if nonce in records:
            current_state = records[nonce].get("state")
            if current_state in ("RESERVED", "COMMITTED"):
                return False

        with open(path, "a", encoding="utf-8") as fh:
            entry = {
                "nonce": nonce,
                "ticket_id": ticket_id,
                "state": "RESERVED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return True


def commit_ticket_nonce(nonce: str, ticket_id: str, store_path: str | None = None) -> None:
    """Marque définitivement un nonce comme COMMITTED après exécution réussie."""
    if not nonce:
        return
    path = store_path or _DEFAULT_CONSUMED_STORE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock_path = path + ".lock"

    with FileLock(lock_path):
        with open(path, "a", encoding="utf-8") as fh:
            entry = {
                "nonce": nonce,
                "ticket_id": ticket_id,
                "state": "COMMITTED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def fail_ticket_nonce(nonce: str, ticket_id: str, reason: str = "", store_path: str | None = None) -> None:
    """Marque un nonce comme FAILED en cas d'erreur opérationnelle."""
    if not nonce:
        return
    path = store_path or _DEFAULT_CONSUMED_STORE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock_path = path + ".lock"

    with FileLock(lock_path):
        with open(path, "a", encoding="utf-8") as fh:
            entry = {
                "nonce": nonce,
                "ticket_id": ticket_id,
                "state": "FAILED",
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def verify_and_consume_sovereign_ticket(
    ticket: SovereignTicket | dict[str, Any] | None,
    required_scope: str | None = None,
    expected_action_id: str | None = None,
    action_payload: Any = None,
    store_path: str | None = None,
    consumed_store_path: str | None = None,
    decision_store_dir: Any = None,
    target_worktree: Any = None,
    base_sha: str = "",
    approved_scope: Any = None,
    execution_dir: Any = None,
    pre_execution_context_dir: Any = None,
    repo_root: Any = None,
    derived_authority_context: Any = None,
) -> SovereignTicket:
    """
    Validateur canonique unique des tickets souverains (Phase 2G).
    Exécute tous les contrôles d'authenticité, d'intégrité, de fraîcheur et d'anti-rejeu.

    KX108-K1 : la signature ne suffit pas. Avant toute réservation de nonce, la décision
    liée est rechargée depuis le magasin canonique et vérifiée (authentificateur du noyau,
    verdict ALLOW, identifiants, domaine, périmètre) ; la liaison d'entrée est obligatoire ;
    une décision n'adosse qu'une seule exécution.
    """
    if ticket is None:
        raise AssertionError("SOVEREIGN_TICKET_MISSING")

    if isinstance(ticket, dict):
        ticket = SovereignTicket.from_dict(ticket)

    # 1. Vérification de version
    if not ticket.version or ticket.version not in (TICKET_VERSION_V1, TICKET_VERSION_V2):
        raise AssertionError(f"SOVEREIGN_TICKET_UNSUPPORTED_VERSION:{ticket.version}")

    # 2. Vérification d'expiration & horodatage
    if not ticket.expires_at:
        raise AssertionError(f"SOVEREIGN_TICKET_NO_EXPIRATION:{ticket.ticket_id}")
    if ticket.is_expired():
        raise AssertionError(f"SOVEREIGN_TICKET_EXPIRED:{ticket.ticket_id}")

    # 3. Vérification de la porte décisionnelle
    if ticket.x108_gate != "ALLOW":
        raise AssertionError(f"SOVEREIGN_TICKET_NOT_ALLOW:{ticket.x108_gate}")

    # 4. Vérification du périmètre / scope
    if required_scope:
        if not ticket.is_valid_scope(required_scope):
            raise AssertionError(f"SOVEREIGN_TICKET_INVALID_SCOPE:{ticket.scope}!={required_scope}")

    # 5. Vérification de l'identifiant d'action
    if expected_action_id and ticket.action_id != expected_action_id:
        raise AssertionError(f"SOVEREIGN_TICKET_ACTION_MISMATCH:{ticket.action_id}!={expected_action_id}")

    # 6. Vérification du payload d'entrée (Input binding) — rendue obligatoire à l'étape 8 (K1)
    if action_payload is not None:
        if isinstance(action_payload, (dict, list)):
            calc_input_hash = hashlib.sha256(
                json.dumps(action_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest()
        elif isinstance(action_payload, str):
            calc_input_hash = hashlib.sha256(action_payload.encode("utf-8")).hexdigest()
        elif isinstance(action_payload, bytes):
            calc_input_hash = hashlib.sha256(action_payload).hexdigest()
        else:
            calc_input_hash = hashlib.sha256(str(action_payload).encode("utf-8")).hexdigest()

        if not ticket.input_hash or ticket.input_hash != calc_input_hash:
            raise AssertionError(f"SOVEREIGN_TICKET_INPUT_MISMATCH:{ticket.input_hash}!={calc_input_hash}")

    # 7. Vérification de l'authenticité cryptographique (HMAC)
    if not verify_authenticator(ticket):
        raise AssertionError(f"SOVEREIGN_TICKET_AUTHENTICATOR_INVALID:{ticket.ticket_id}")

    # 8. Provenance souveraine (K1) : décision vérifiée et liaison d'entrée exigée AVANT toute réservation de nonce
    record = verify_ticket_decision_binding(
        ticket, decision_store_dir=decision_store_dir,
        action_payload=action_payload, target_worktree=target_worktree,
        base_sha=base_sha, approved_scope=approved_scope,
        execution_dir=execution_dir,
        pre_execution_context_dir=pre_execution_context_dir, repo_root=repo_root,
        derived_authority_context=derived_authority_context,
    )
    if action_payload is None:
        raise AssertionError(f"SOVEREIGN_TICKET_INPUT_BINDING_REQUIRED:{ticket.ticket_id}")

    # 9. Anti-rejeu atomique (Vérification et réservation du nonce)
    if not ticket.nonce:
        raise AssertionError(f"SOVEREIGN_TICKET_MISSING_NONCE:{ticket.ticket_id}")

    claimed = reserve_ticket_nonce(ticket.nonce, ticket.ticket_id, store_path=consumed_store_path)
    if not claimed:
        raise AssertionError(f"SOVEREIGN_TICKET_REPLAY_DETECTED:{ticket.nonce}")

    # 10. Une décision n'adosse qu'une seule exécution (K1)
    decision_marker = f"kx108-decision-record:{record['decision_record_id']}"
    if not reserve_ticket_nonce(decision_marker, ticket.ticket_id, store_path=consumed_store_path):
        fail_ticket_nonce(ticket.nonce, ticket.ticket_id, reason="DECISION_ALREADY_USED",
                          store_path=consumed_store_path)
        raise AssertionError(f"SOVEREIGN_TICKET_DECISION_ALREADY_USED:{record['decision_record_id']}")

    commit_ticket_nonce(ticket.nonce, ticket.ticket_id, store_path=consumed_store_path)
    commit_ticket_nonce(decision_marker, ticket.ticket_id, store_path=consumed_store_path)
    return ticket
