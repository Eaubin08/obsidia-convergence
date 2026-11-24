"""Candidate-only HMA revocation checkpoint integrity.

No authority issuance, no trusted-key management, no KX108 modification.
A caller-provided reference is NOT independently trusted by this module.
"""

import hashlib
import json


CHECKPOINT_SCHEMA = "obsidia.hma.revocation.checkpoint.candidate.v1"


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def registry_digest(mission_id, records):
    if type(mission_id) is not str or not mission_id:
        raise ValueError("MISSION_ID_INVALID")

    if type(records) is not list:
        raise ValueError("REVOCATION_RECORDS_INVALID")

    entries = []
    seen = set()

    for record in records:
        if type(record) is not dict:
            raise ValueError("REVOCATION_NOT_OBJECT")

        rev_id = record.get("mission_authority_revocation_id")
        rev_hash = record.get("revocation_record_hash")

        if type(rev_id) is not str or not rev_id.startswith("rev-"):
            raise ValueError("REVOCATION_ID_INVALID")

        if (
            type(rev_hash) is not str
            or len(rev_hash) != 64
            or any(c not in "0123456789abcdef" for c in rev_hash)
        ):
            raise ValueError("REVOCATION_HASH_INVALID")

        if record.get("mission_id") != mission_id:
            raise ValueError("REVOCATION_MISSION_MISMATCH")

        if rev_id in seen:
            raise ValueError("REVOCATION_DUPLICATE_ID")

        seen.add(rev_id)
        entries.append([rev_id, rev_hash])

    entries.sort()

    return hashlib.sha256(
        _canonical({
            "mission_id": mission_id,
            "entries": entries,
        })
    ).hexdigest()


def verify_checkpoint_structure(mission_id, records, checkpoint):
    """Integrity comparison only. Never grants execution authority."""

    if type(checkpoint) is not dict:
        return False, "CHECKPOINT_MISSING"

    if checkpoint.get("schema") != CHECKPOINT_SCHEMA:
        return False, "CHECKPOINT_SCHEMA_UNSUPPORTED"

    if checkpoint.get("mission_id") != mission_id:
        return False, "CHECKPOINT_MISSION_MISMATCH"

    sequence = checkpoint.get("sequence")

    if type(sequence) is not int or sequence < 0:
        return False, "CHECKPOINT_SEQUENCE_INVALID"

    try:
        actual_hash = registry_digest(mission_id, records)
    except (ValueError, TypeError, OverflowError) as exc:
        return False, str(exc)

    if checkpoint.get("revocation_count") != len(records):
        return False, "CHECKPOINT_COUNT_MISMATCH"

    if checkpoint.get("registry_sha256") != actual_hash:
        return False, "CHECKPOINT_REGISTRY_HASH_MISMATCH"

    return True, None


def authorization_qualification(*args, **kwargs):
    """No independent authenticator or monotonic anchor exists yet."""
    return False, "INDEPENDENT_CHECKPOINT_ATTESTATION_REQUIRED"
