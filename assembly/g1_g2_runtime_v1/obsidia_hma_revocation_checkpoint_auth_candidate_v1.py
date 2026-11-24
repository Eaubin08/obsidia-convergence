"""Candidate-only cryptographic authentication for HMA checkpoints.

No key generation, no production key access, no authority promotion.
The verifier key and monotonic floor MUST originate outside untrusted input.
"""

import hashlib
import hmac
import json

AUTH_SCHEMA = "obsidia.hma.revocation.checkpoint.auth.candidate.v1"

BOUND_FIELDS = (
    "schema",
    "mission_id",
    "sequence",
    "revocation_count",
    "registry_sha256",
    "key_id",
)


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def authenticate_checkpoint(checkpoint, key, key_id):
    """Test-oriented signer. Does not register any trust anchor."""

    if type(checkpoint) is not dict:
        raise ValueError("CHECKPOINT_NOT_OBJECT")

    if type(key) is not bytes or len(key) < 32:
        raise ValueError("KEY_INVALID")

    if type(key_id) is not str or not key_id:
        raise ValueError("KEY_ID_INVALID")

    if checkpoint.get("schema") != AUTH_SCHEMA:
        raise ValueError("CHECKPOINT_SCHEMA_INVALID")

    if checkpoint.get("key_id") != key_id:
        raise ValueError("KEY_ID_MISMATCH")

    if any(field not in checkpoint for field in BOUND_FIELDS):
        raise ValueError("CHECKPOINT_FIELD_MISSING")

    body = {
        field: checkpoint[field]
        for field in BOUND_FIELDS
    }

    return hmac.new(
        key,
        _canonical(body),
        hashlib.sha256,
    ).hexdigest()


def verify_checkpoint_authenticator(
    checkpoint,
    *,
    trusted_key_id,
    verifier_key,
    trusted_sequence_floor,
):
    """Authentication only. Never grants execution authority."""

    if type(checkpoint) is not dict:
        return False, "CHECKPOINT_MISSING"

    if checkpoint.get("schema") != AUTH_SCHEMA:
        return False, "CHECKPOINT_SCHEMA_UNSUPPORTED"

    if (
        type(trusted_key_id) is not str
        or not trusted_key_id
        or checkpoint.get("key_id") != trusted_key_id
    ):
        return False, "CHECKPOINT_KEY_ID_NOT_TRUSTED"

    if type(verifier_key) is not bytes or len(verifier_key) < 32:
        return False, "TRUSTED_VERIFIER_KEY_UNAVAILABLE"

    if any(field not in checkpoint for field in BOUND_FIELDS):
        return False, "CHECKPOINT_FIELD_MISSING"

    sequence = checkpoint.get("sequence")

    if type(sequence) is not int or sequence < 0:
        return False, "CHECKPOINT_SEQUENCE_INVALID"

    if (
        type(trusted_sequence_floor) is not int
        or trusted_sequence_floor < 0
    ):
        return False, "TRUSTED_SEQUENCE_FLOOR_UNAVAILABLE"

    try:
        expected = authenticate_checkpoint(
            checkpoint,
            verifier_key,
            trusted_key_id,
        )
    except (ValueError, TypeError, OverflowError):
        return False, "CHECKPOINT_CANONICALIZATION_INVALID"

    actual = checkpoint.get("authenticator")

    if (
        type(actual) is not str
        or len(actual) != 64
        or not hmac.compare_digest(actual, expected)
    ):
        return False, "CHECKPOINT_AUTHENTICATOR_INVALID"

    if sequence < trusted_sequence_floor:
        return False, "CHECKPOINT_ROLLBACK"

    if sequence > trusted_sequence_floor:
        return False, "CHECKPOINT_AHEAD_OF_TRUSTED_FLOOR"

    return True, None


def authorization_qualification(*args, **kwargs):
    return False, "INDEPENDENT_TRUST_ANCHOR_REQUIRED"
