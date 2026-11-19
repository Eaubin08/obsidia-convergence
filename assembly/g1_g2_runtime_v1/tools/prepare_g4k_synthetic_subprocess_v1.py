"""G4K: lance UNIQUEMENT un enfant Python fixe dans un répertoire neuf.

Cet outil de test ne touche ni le FIX, ni les fichiers Obsidia réels. La
trace a une provenance locale observée, non un statut de confiance souveraine.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import c2_write_intent_wal_v1 as WAL
from c2_wal_machine_rsa_receipt_v1 import DOMAIN, canonical_payload
from c2_wal_runner_observation_g4k_v1 import (
    CHILD_BYTES, build_runner_observation, _canonical,
)
from prepare_g4j_wal_synthetic_fixture_v1 import build_fixture


def build_subprocess_fixture(*, repo_root: Path, machine_id: str,
                             public_cert_pin: str, source_git_head: str) -> dict:
    """Un processus réel, mais code/entrée/cible strictement synthétiques."""
    fixture = build_fixture(
        repo_root=repo_root, machine_id=machine_id,
        public_cert_pin=public_cert_pin, source_git_head=source_git_head)
    runner_dir = repo_root / "runner"
    runner_dir.mkdir(mode=0o700)
    child = runner_dir / "g4k_synthetic_child_v1.py"
    with child.open("xb") as stream:
        stream.write(CHILD_BYTES)
        stream.flush()
        os.fsync(stream.fileno())
    nonce = secrets.token_hex(32)
    # N'utilise jamais un exécutable ou script arbitraire transmis par l'appelant.
    # -I: interpréteur isolé; -B: aucun .pyc; shell=False, cwd temporaire.
    proc = subprocess.Popen(
        [sys.executable, "-I", "-B", str(child), nonce],
        cwd=runner_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, shell=False,
    )
    try:
        stdout, stderr = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.communicate()
        raise ValueError("G4K_SYNTHETIC_CHILD_TIMEOUT") from exc
    intent = WAL.load_verified_intent(Path(fixture["wal_dir"]), fixture["intent_id"])
    outcome = WAL.load_verified_outcome(Path(fixture["wal_dir"]), intent)
    observation = build_runner_observation(
        intent=intent, outcome=outcome, machine_id=machine_id,
        run_nonce=nonce, child_pid=proc.pid, child_exit_code=proc.returncode,
        stdout=stdout, stderr=stderr,
    )
    if observation is None:
        raise ValueError("G4K_SYNTHETIC_CHILD_OBSERVATION_INVALID")
    raw = _canonical(observation)
    trace_path = Path(fixture["wal_dir"]) / (fixture["intent_id"] + ".runner.json")
    with trace_path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if trace_path.read_bytes() != raw:
        raise ValueError("G4K_SYNTHETIC_TRACE_RELOAD_FAILED")
    payload = {
        **fixture["payload"],
        "nonce": nonce,
        "runner_code_sha256": observation["runner_code_sha256"],
        "tests_transcript_sha256": hashlib.sha256(raw).hexdigest(),
    }
    canonical = canonical_payload(payload)
    if canonical is None:
        raise ValueError("G4K_SYNTHETIC_SIGNED_PAYLOAD_INVALID")
    return {
        **fixture,
        "payload": payload,
        "runner_trace_path": str(trace_path),
        "signing_message_base64": base64.b64encode(DOMAIN + canonical).decode("ascii"),
        "synthetic_process_observed": True,
        "process_origin_attested": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="G4K fixed subprocess + WAL synthetic fixture")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--machine", required=True)
    parser.add_argument("--pin", required=True)
    parser.add_argument("--source-head", required=True)
    args = parser.parse_args()
    try:
        result = build_subprocess_fixture(
            repo_root=args.root, machine_id=args.machine,
            public_cert_pin=args.pin, source_git_head=args.source_head)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        print("G4K_SYNTHETIC_SUBPROCESS_HOLD=" + type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
