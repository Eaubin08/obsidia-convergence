"""G4K : vérifie stdin JSON + WAL/G4J RSA + trace de child synthétique."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from c2_wal_runner_observation_g4k_v1 import inspect_c2_wal_synthetic_runner_observation


def _no_duplicate_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("G4K_DUPLICATE_JSON_KEY")
        data[key] = value
    return data


def main() -> int:
    raw = sys.stdin.read(65537)
    if not raw or len(raw) > 65536:
        print("G4K_RUNNER_HOLD=INPUT_MISSING_OR_TOO_LONG")
        return 2
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
        if type(data) is not dict or set(data) != {
            "wal_dir", "repo_root", "intent_id", "receipt",
            "public_certificate_der_base64", "pinned_certificate_sha256",
            "expected_machine_id",
        }:
            raise ValueError("G4K_INPUT_SCOPE_INVALID")
        view = inspect_c2_wal_synthetic_runner_observation(
            wal_dir=Path(data["wal_dir"]), repo_root=Path(data["repo_root"]),
            intent_id=data["intent_id"], receipt=data["receipt"],
            public_certificate_der_base64=data["public_certificate_der_base64"],
            pinned_certificate_sha256=data["pinned_certificate_sha256"],
            expected_machine_id=data["expected_machine_id"],
        )
    except (ValueError, TypeError, KeyError, UnicodeError):
        print("G4K_RUNNER_HOLD=INPUT_JSON_INVALID")
        return 2
    if not (view["machine_signature_verified"] and
            view["synthetic_runner_record_verified"] and
            view["synthetic_runner_live_source_hash_verified"]):
        print("G4K_RUNNER_HOLD=" + str(view["reason"]))
        return 2
    print("OBSIDIA_G4K_SYNTHETIC_SUBPROCESS_RSA_PASS=True")
    print("MACHINE=" + data["expected_machine_id"])
    print("SYNTHETIC_RUNNER_TRACE_MATCH=True")
    print("REAL_C278_PRODUCER_ATTESTED=False")
    print("REAL_RUNNER_EXECUTION_ATTESTED=False")
    print("REPLAY_PREVENTION_ATTESTED=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
