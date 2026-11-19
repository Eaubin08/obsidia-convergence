"""Fabrique un WAL G4J entièrement SYNTHÉTIQUE dans un dossier neuf.

Aucune écriture métier, aucun KX108 appelé, aucune clé privée lue.
Le message exact à signer est renvoyé sur stdout (JSON).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import c2_write_intent_wal_v1 as WAL
from c2_wal_outcome_observer_v1 import report_c2_wal_outcome_testonly
from c2_wal_machine_rsa_receipt_v1 import DOMAIN, build_claim_payload, canonical_payload


def build_fixture(*, repo_root: Path, machine_id: str,
                  public_cert_pin: str, source_git_head: str) -> dict:
    if not isinstance(repo_root, Path) or not repo_root.is_absolute() or repo_root.exists():
        raise ValueError("G4J_SYNTHETIC_ROOT_MUST_BE_NEW_ABSOLUTE")
    # Création exclusive d'un dossier nouveau ; jamais une source utilisateur.
    repo_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    targets = repo_root / "targets"
    targets.mkdir()
    old, new = b"G4J_SYNTHETIC_PREIMAGE", b"G4J_SYNTHETIC_POSTIMAGE"
    target = targets / "synthetic.txt"
    target.write_bytes(new)  # Préparation du scénario, PAS APPLY C2
    wal_dir = repo_root / "wal"
    intent = WAL.build_intent(
        batch_execution_id="g4j-synthetic-only",
        child_execution_id="g4j-synthetic-child",
        execution_authority_hash="a" * 64,
        approval_id="synthetic-no-human-approval",
        pre_decision_record_id="synthetic-no-real-pre",
        pre_decision_record_hash="b" * 64,
        sealed_rollback_evidence_id="synthetic-no-real-sre",
        sealed_rollback_evidence_hash="c" * 64,
        target_path="targets/synthetic.txt",
        target_pre_sha256=hashlib.sha256(old).hexdigest(),
        target_post_sha256=hashlib.sha256(new).hexdigest(),
    )
    if intent is None or WAL.store_intent(intent, wal_dir).get("status") != WAL.STORED:
        raise ValueError("G4J_SYNTHETIC_INTENT_STORE_HOLD")
    view = report_c2_wal_outcome_testonly(
        wal_dir=wal_dir, intent_id=intent["intent_id"],
        repo_root=repo_root, reported_status="REPORTED_KEEP")
    if not view.get("wal_outcome_recorded") or view.get("reason") != "OUTCOME_REPORTED_NOT_ATTESTED":
        raise ValueError("G4J_SYNTHETIC_OUTCOME_HOLD")
    outcome = WAL.load_verified_outcome(wal_dir, intent)
    payload = build_claim_payload(
        machine_id=machine_id, public_certificate_sha256=public_cert_pin,
        intent=intent, outcome=outcome, nonce=secrets.token_hex(32),
        source_git_head=source_git_head,
        runner_code_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        tests_transcript_sha256=hashlib.sha256(
            b"G4J_SYNTHETIC_FIXTURE_NOT_ACTUAL_RUNNER_PROVENANCE").hexdigest(),
    )
    if payload is None:
        raise ValueError("G4J_SYNTHETIC_PAYLOAD_INVALID")
    return {
        "repo_root": str(repo_root), "wal_dir": str(wal_dir),
        "intent_id": intent["intent_id"], "payload": payload,
        "signing_message_base64": base64.b64encode(
            DOMAIN + canonical_payload(payload)).decode("ascii"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="G4J WAL fixture, test only")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--machine", required=True)
    parser.add_argument("--pin", required=True)
    parser.add_argument("--source-head", required=True)
    args = parser.parse_args()
    try:
        result = build_fixture(
            repo_root=args.root, machine_id=args.machine,
            public_cert_pin=args.pin, source_git_head=args.source_head)
    except (OSError, ValueError, TypeError) as exc:
        print("G4J_SYNTHETIC_FIXTURE_HOLD=" + type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
