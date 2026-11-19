"""Entrée STDIN, sans fichier ni clé privée, du challenge signé sur Windows."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obsidure_machine_rsa_interop_v1 import inspect_machine_rsa_interop_challenge


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def main() -> int:
    raw = sys.stdin.read(32769)
    if not raw or len(raw) > 32768:
        print("MACHINE_RSA_INTEROP_HOLD=INPUT_MISSING_OR_TOO_LONG")
        return 2
    try:
        envelope = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (ValueError, UnicodeError):
        print("MACHINE_RSA_INTEROP_HOLD=INPUT_JSON_INVALID")
        return 2
    result = inspect_machine_rsa_interop_challenge(envelope)
    if result["status"] != "MACHINE_RSA_INTEROP_VERIFIED_NOT_C278_PROVENANCE":
        print("MACHINE_RSA_INTEROP_HOLD=" + str(result["reason"]))
        return 2
    print("OBSIDURE_WINDOWS_PYTHON_RSA_INTEROP_PASS=True")
    print("MACHINE=" + result["machine_id"])
    print("PUBLIC_CERTIFICATE_SHA256=" + result["public_certificate_sha256"])
    print("CHALLENGE_TAMPER_DENIAL_PASS=True")
    print("C278_RUNNER_ATTESTED=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
