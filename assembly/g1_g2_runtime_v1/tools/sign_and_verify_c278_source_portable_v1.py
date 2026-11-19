"""Interface JSON STDIN/STDOUT pour un instantané C278 signé sur le portable.

--prepare : lit le FIX local sans importer son code, prépare des octets.
--verify  : relit le FIX, vérifie le certificat et la signature RSA fournis.
Aucun mode ne lance C278, ne signe avec une clé privée ni n'écrit de fichier.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from inspect_c278_producer_portable_readonly_v1 import inspect_portable_fix
from obsidure_c278_source_snapshot_v1 import prepare_snapshot, verify_snapshot


def _no_duplicate_keys(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON field")
        output[key] = value
    return output


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv not in (["--prepare"], ["--verify"]):
        print(json.dumps({"status": "HOLD", "reason": "C278_SNAPSHOT_MODE_INVALID"}))
        return 2
    try:
        if argv == ["--prepare"]:
            result = prepare_snapshot(inspect_portable_fix(), nonce=secrets.token_hex(16))
        else:
            raw = sys.stdin.read(32769)
            if not raw or len(raw) > 32768:
                raise ValueError("input invalid or oversized")
            envelope = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
            result = verify_snapshot(envelope, inspect_portable_fix())
    except (OSError, ValueError, TypeError, UnicodeError):
        result = {"status": "HOLD", "reason": "C278_SNAPSHOT_INPUT_OR_RECHECK_FAILED"}
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    return 0 if result["status"] in (
        "READY_FOR_LOCAL_KEY_SIGNING", "C278_SOURCE_SNAPSHOT_RSA_MATCH_NO_TEST_PROVENANCE",
    ) else 2


if __name__ == "__main__":
    sys.exit(main())
