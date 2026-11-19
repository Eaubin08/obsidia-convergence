"""Vérifie via STDIN une signature RSA G4J sur un WAL synthétique existant."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from c2_wal_machine_rsa_receipt_v1 import inspect_wal_machine_rsa_receipt


def _reject_duplicate_keys(pairs):
    result = {}
    for key, val in pairs:
        if key in result:
            raise ValueError("G4J_JSON_DUPLICATE_KEY")
        result[key] = val
    return result


def main() -> int:
    raw = sys.stdin.read(65537)
    if not raw or len(raw) > 65536:
        print("G4J_WAL_RSA_HOLD=INPUT_MISSING_OR_TOO_LONG")
        return 2
    try:
        data = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        if type(data) is not dict or set(data) != {
            "wal_dir", "repo_root", "intent_id", "receipt",
            "public_certificate_der_base64", "pinned_certificate_sha256",
            "expected_machine_id",
        }:
            raise ValueError("G4J_ENVELOPE_FIELDS_INVALID")
        result = inspect_wal_machine_rsa_receipt(
            wal_dir=Path(data["wal_dir"]), repo_root=Path(data["repo_root"]),
            intent_id=data["intent_id"], receipt=data["receipt"],
            public_certificate_der_base64=data["public_certificate_der_base64"],
            pinned_certificate_sha256=data["pinned_certificate_sha256"],
            expected_machine_id=data["expected_machine_id"],
        )
    except (ValueError, TypeError, UnicodeError, KeyError):
        print("G4J_WAL_RSA_HOLD=INPUT_JSON_INVALID")
        return 2
    if not result["machine_signature_verified"] or result["reason"] != "G4J_RSA_SIGNATURE_MATCH_ORIGIN_UNATTESTED":
        print("G4J_WAL_RSA_HOLD=" + str(result["reason"]))
        return 2
    print("OBSIDIA_G4J_WAL_MACHINE_RSA_PASS=True")
    print("MACHINE=" + result["machine_id"])
    print("PUBLIC_CERTIFICATE_SHA256=" + result["public_certificate_sha256"])
    print("PRODUCER_ORIGIN_ATTESTED=False")
    print("RUNNER_EXECUTION_ATTESTED=False")
    print("CERTIFICATE_ENROLLMENT_APPROVED=False")
    print("PRIVATE_KEY_EXPORTED=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
