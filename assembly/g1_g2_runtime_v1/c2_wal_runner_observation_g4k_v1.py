"""G4K — rapproche une observation de processus avec un WAL signé G4J.

La trace est produite dans un bac à sable SYNTHÉTIQUE ; elle est une preuve
d'observation locale, pas une attestation de la provenance d'un runner réel.
La façade publique ne lance aucun processus et n'accorde aucun pouvoir.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import c2_write_intent_wal_v1 as WAL
from c2_wal_machine_rsa_receipt_v1 import inspect_wal_machine_rsa_receipt

SCHEMA = "OBSIDIA_G4K_C2_SYNTHETIC_RUNNER_OBSERVATION_V1"
RUNNER_LABEL = "G4K_FIXED_PYTHON_ISOLATED_SYNTHETIC_V1"
SCRIPT_REL = "runner/g4k_synthetic_child_v1.py"
CHILD_BYTES = (
    b'"""G4K fixed synthetic-only child: stdout only, no imports beyond sys."""\n'
    b'import sys\n'
    b'if len(sys.argv) != 2 or len(sys.argv[1]) != 64 or '\
    b'any(c not in "0123456789abcdef" for c in sys.argv[1]):\n'
    b'    sys.exit(2)\n'
    b'sys.stdout.buffer.write(b"OBSIDIA_G4K_SYNTHETIC_RESULT_V1|" + '\
    b'sys.argv[1].encode("ascii") + b"\\n")\n'
)
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MACHINE = re.compile(r"[A-Z0-9][A-Z0-9-]{2,63}\Z")
_FIELDS = frozenset({
    "schema", "runner_label", "machine_id", "intent_id",
    "intent_record_hash", "outcome_record_hash", "runner_relpath",
    "runner_code_sha256", "run_nonce", "child_pid_observed",
    "child_exit_code_observed", "stdout_base64", "stderr_base64",
    "stdout_sha256", "stderr_sha256", "record_hash",
})


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _decode(value: Any) -> bytes | None:
    if type(value) is not str or len(value) > 8192:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(raw) > 4096 or base64.b64encode(raw).decode("ascii") != value:
        return None
    return raw


def build_runner_observation(*, intent: dict, outcome: dict,
                             machine_id: str, run_nonce: str, child_pid: int,
                             child_exit_code: int, stdout: bytes,
                             stderr: bytes) -> dict | None:
    valid_i, _ = WAL.verify_intent(intent)
    valid_o, _ = WAL.verify_outcome(outcome, intent)
    if (not valid_i or not valid_o or type(machine_id) is not str
            or _MACHINE.fullmatch(machine_id) is None
            or type(run_nonce) is not str or _SHA.fullmatch(run_nonce) is None
            or type(child_pid) is not int or child_pid <= 0
            or type(child_exit_code) is not int or child_exit_code != 0
            or type(stdout) is not bytes or type(stderr) is not bytes
            or len(stdout) > 4096 or stderr != b""):
        return None
    expected_stdout = b"OBSIDIA_G4K_SYNTHETIC_RESULT_V1|" + run_nonce.encode("ascii") + b"\n"
    if stdout != expected_stdout:
        return None
    record = {
        "schema": SCHEMA, "runner_label": RUNNER_LABEL,
        "machine_id": machine_id, "intent_id": intent["intent_id"],
        "intent_record_hash": intent["record_hash"],
        "outcome_record_hash": outcome["record_hash"],
        "runner_relpath": SCRIPT_REL,
        "runner_code_sha256": hashlib.sha256(CHILD_BYTES).hexdigest(),
        "run_nonce": run_nonce, "child_pid_observed": child_pid,
        "child_exit_code_observed": child_exit_code,
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    record["record_hash"] = hashlib.sha256(_canonical(record)).hexdigest()
    return record


def verify_runner_observation(record: Any, *, intent: dict, outcome: dict,
                              expected_machine_id: str) -> tuple[bool, str]:
    if type(record) is not dict or set(record) != _FIELDS:
        return False, "RUNNER_RECORD_FIELDS_INVALID"
    if (record.get("schema") != SCHEMA
            or record.get("runner_label") != RUNNER_LABEL
            or record.get("runner_relpath") != SCRIPT_REL
            or record.get("machine_id") != expected_machine_id):
        return False, "RUNNER_RECORD_SCOPE_INVALID"
    stdout, stderr = _decode(record.get("stdout_base64")), _decode(record.get("stderr_base64"))
    if stdout is None or stderr is None:
        return False, "RUNNER_CAPTURE_ENCODING_INVALID"
    rebuilt = build_runner_observation(
        intent=intent, outcome=outcome, machine_id=expected_machine_id,
        run_nonce=record.get("run_nonce"), child_pid=record.get("child_pid_observed"),
        child_exit_code=record.get("child_exit_code_observed"),
        stdout=stdout, stderr=stderr,
    )
    return (True, "RUNNER_RECORD_STRUCTURAL_MATCH") if rebuilt == record else (
        False, "RUNNER_RECORD_CONTENT_OR_HASH_INVALID")


def _hold(reason: str, **extra: Any) -> dict:
    return {
        "schema_version": SCHEMA, "status": "HOLD", "reason": reason,
        "readonly": True, "decision_authority": "KX108_ONLY",
        "machine_signature_verified": False,
        "synthetic_runner_record_verified": False,
        "synthetic_runner_live_source_hash_verified": False,
        "machine_identity_attested": False,
        "certificate_enrollment_approved": False,
        "producer_identity_attested": False,
        "responsible_person_authenticated": False,
        "process_execution_attested": False,
        "test_transcript_attested": False,
        "source_git_head_attested": False,
        "replay_prevented": False,
        "human_approval_verified": False,
        "kx108_ticket_issued": False,
        "execution_authorized": False,
        "recovery_authorized": False,
        "release_authorized": False,
        "target_mutated": False,
        **extra,
    }


def inspect_c2_wal_synthetic_runner_observation(
    *, wal_dir: Path, intent_id: str, repo_root: Path, receipt: Any,
    public_certificate_der_base64: str,
    pinned_certificate_sha256: str, expected_machine_id: str,
) -> dict:
    """Vérification en lecture seule, aucun runner démarré par ce chemin."""
    signed = inspect_wal_machine_rsa_receipt(
        wal_dir=wal_dir, intent_id=intent_id, repo_root=repo_root,
        receipt=receipt, public_certificate_der_base64=public_certificate_der_base64,
        pinned_certificate_sha256=pinned_certificate_sha256,
        expected_machine_id=expected_machine_id)
    if not signed.get("machine_signature_verified"):
        return _hold("G4K_G4J_SIGNATURE_REQUIRED:" + str(signed.get("reason")))
    intent = WAL.load_verified_intent(wal_dir, intent_id)
    outcome = WAL.load_verified_outcome(wal_dir, intent) if intent is not None else None
    if intent is None or outcome is None:
        return _hold("G4K_WAL_CHANGED")
    if not WAL._store_path_safe(wal_dir) or not WAL._store_path_safe(repo_root):
        return _hold("G4K_ROOT_OR_WAL_PATH_UNSAFE")
    trace_path = wal_dir / (intent_id + ".runner.json")
    source_path = repo_root / "runner" / "g4k_synthetic_child_v1.py"
    try:
        if (trace_path.is_symlink() or source_path.is_symlink()
                or source_path.parent.is_symlink()
                or (hasattr(source_path.parent, "is_junction")
                    and source_path.parent.is_junction())
                or not trace_path.is_file() or not source_path.is_file()):
            return _hold("G4K_TRACE_OR_SOURCE_UNAVAILABLE")
        raw_trace = trace_path.read_bytes()
        live_source = source_path.read_bytes()
        if len(raw_trace) > 16384 or len(live_source) > 8192:
            return _hold("G4K_TRACE_OR_SOURCE_TOO_LARGE")
        def no_duplicates(pairs):
            d = {}
            for key, value in pairs:
                if key in d:
                    raise ValueError("DUPLICATE_RECORD_KEY")
                d[key] = value
            return d
        record = json.loads(raw_trace, object_pairs_hook=no_duplicates)
        if type(record) is not dict or raw_trace != _canonical(record):
            return _hold("G4K_TRACE_NONCANONICAL")
    except (OSError, UnicodeError, ValueError, TypeError):
        return _hold("G4K_TRACE_OR_SOURCE_INVALID")
    valid, reason = verify_runner_observation(
        record, intent=intent, outcome=outcome,
        expected_machine_id=expected_machine_id)
    if not valid:
        return _hold("G4K_" + reason)
    if live_source != CHILD_BYTES:
        return _hold("G4K_LIVE_SYNTHETIC_RUNNER_DRIFT")
    payload = receipt["payload"]
    if (payload["runner_code_sha256"] != record["runner_code_sha256"]
            or payload["tests_transcript_sha256"] != hashlib.sha256(raw_trace).hexdigest()
            or payload["nonce"] != record["run_nonce"]):
        return _hold("G4K_SIGNED_RUNNER_TRACE_BINDING_MISMATCH")
    return _hold(
        "G4K_SYNTHETIC_SUBPROCESS_TRACE_MATCH_NOT_ATTESTED",
        machine_signature_verified=True,
        synthetic_runner_record_verified=True,
        synthetic_runner_live_source_hash_verified=True,
        observed_child_pid=record["child_pid_observed"],
        limits=[
            "SUBPROCESS_CAPTURED_BY_LOCAL_UNATTESTED_LAUNCHER",
            "SIGNED_TRANSCRIPT_CANNOT_ESTABLISH_HISTORICAL_PRODUCER_ORIGIN",
            "G4J_MACHINE_KEY_NOT_KX108_AUTHORIZATION",
            "NO_TRUSTED_REPLAY_LEDGER_OR_RECOVERY_OR_RELEASE",
        ],
    )
