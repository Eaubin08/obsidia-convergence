"""G4L — vérifie/réserve un nonce LOCAL de fixture G4K sur STDIN JSON.

Deux processus indépendants : --reserve une première fois, --deny-replay
une seconde fois. Aucun chemin de mutation du runtime unifié.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from c2_wal_local_nonce_ledger_g4l_v1 import reserve_synthetic_nonce_testonly


def _no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("G4L_DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--reserve", action="store_true")
    group.add_argument("--deny-replay", action="store_true")
    args = parser.parse_args()
    text = sys.stdin.read(65537)
    if not text or len(text) > 65536:
        print("G4L_NONCE_HOLD=INPUT_MISSING_OR_TOO_LONG")
        return 2
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicates)
        if type(data) is not dict or set(data) != {
            "wal_dir", "repo_root", "intent_id", "receipt",
            "public_certificate_der_base64", "pinned_certificate_sha256",
            "expected_machine_id",
        }:
            raise ValueError("G4L_INPUT_SCOPE_INVALID")
        result = reserve_synthetic_nonce_testonly(
            wal_dir=Path(data["wal_dir"]), repo_root=Path(data["repo_root"]),
            intent_id=data["intent_id"], receipt=data["receipt"],
            public_certificate_der_base64=data["public_certificate_der_base64"],
            pinned_certificate_sha256=data["pinned_certificate_sha256"],
            expected_machine_id=data["expected_machine_id"])
    except (ValueError, TypeError, KeyError, UnicodeError):
        print("G4L_NONCE_HOLD=INPUT_JSON_INVALID")
        return 2
    if args.reserve:
        if (not result["local_nonce_reserved"] or
                result["reason"] != "G4L_NONCE_RESERVED_LOCAL_UNTRUSTED"):
            print("G4L_NONCE_HOLD=" + result["reason"])
            return 2
        print("OBSIDIA_G4L_LOCAL_NONCE_RESERVATION_PASS=True")
    else:
        if (not result["local_duplicate_denied"] or
                result["reason"] != "G4L_LOCAL_REPLAY_DUPLICATE_DENIED"):
            print("G4L_NONCE_HOLD=" + result["reason"])
            return 2
        print("OBSIDIA_G4L_LOCAL_REPLAY_DENIAL_PASS=True")
    print("MACHINE=" + data["expected_machine_id"])
    print("LOCAL_LEDGER_TRUSTED=False")
    print("DISTRIBUTED_REPLAY_PREVENTED=False")
    print("PRODUCER_ORIGIN_ATTESTED=False")
    print("KX108_AUTHORITY=UNCHANGED")
    print("RELEASE=HOLD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
