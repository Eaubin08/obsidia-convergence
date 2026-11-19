"""G4M : vérifie via stdin une proposition de rôle machine, sans l'activer."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obsidure_machine_role_proposal_g4m_v1 import inspect_obsidure_machine_role_proposal


def _no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("G4M_DUPLICATE_JSON_KEY")
        d[k] = v
    return d


def main() -> int:
    raw = sys.stdin.read(65537)
    if not raw or len(raw) > 65536:
        print("G4M_MACHINE_ROLE_HOLD=INPUT_MISSING_OR_TOO_LONG")
        return 2
    try:
        obj = json.loads(raw, object_pairs_hook=_no_duplicates)
        if type(obj) is not dict or set(obj) != {
            "registry", "wal_dir", "repo_root", "intent_id", "receipt",
            "public_certificate_der_base64", "expected_public_certificate_sha256",
            "expected_machine_id",
        }:
            raise ValueError("G4M_FIELDS_INVALID")
        view = inspect_obsidure_machine_role_proposal(
            registry=obj["registry"], wal_dir=Path(obj["wal_dir"]),
            repo_root=Path(obj["repo_root"]), intent_id=obj["intent_id"],
            receipt=obj["receipt"],
            expected_machine_id=obj["expected_machine_id"],
            expected_public_certificate_sha256=obj["expected_public_certificate_sha256"],
            public_certificate_der_base64=obj["public_certificate_der_base64"],
        )
    except (TypeError, ValueError, UnicodeError, KeyError):
        print("G4M_MACHINE_ROLE_HOLD=INPUT_JSON_INVALID")
        return 2
    if (not view["synthetic_machine_signature_verified"]
            or not view["synthetic_runner_trace_verified"]
            or view["reason"] != "G4M_MACHINE_ROLE_PROPOSED_CRYPTO_BOUND_NOT_APPROVED"):
        print("G4M_MACHINE_ROLE_HOLD=" + str(view["reason"]))
        return 2
    print("OBSIDIA_G4M_MACHINE_ROLE_PROPOSAL_PASS=True")
    print("MACHINE=" + obj["expected_machine_id"])
    print("ROLE_PROPOSAL=OBSIDURE_TEST_EVIDENCE_PRODUCER")
    print("PUBLIC_CERTIFICATE_PIN_MATCH=True")
    print("CERTIFICATE_ENROLLMENT_APPROVED=False")
    print("RESPONSIBLE_PERSON_AUTHENTICATED=False")
    print("REAL_C278_PRODUCER_ATTESTED=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
