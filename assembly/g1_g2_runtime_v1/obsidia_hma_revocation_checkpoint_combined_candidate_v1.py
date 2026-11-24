"""Combined candidate-only HMA checkpoint verifier.

Integrity + test-key authentication + supplied monotonic floor.
No independently established trust anchor. No authorization authority.
"""

import obsidia_hma_revocation_checkpoint_candidate_v1 as integrity
import obsidia_hma_revocation_checkpoint_auth_candidate_v1 as authentication


def verify_checkpoint_candidate(
    mission_id,
    records,
    checkpoint,
    *,
    trusted_key_id,
    verifier_key,
    trusted_sequence_floor,
):
    if type(checkpoint) is not dict:
        return False, "CHECKPOINT_MISSING"

    if checkpoint.get("schema") != authentication.AUTH_SCHEMA:
        return False, "CHECKPOINT_SCHEMA_UNSUPPORTED"

    # Candidate schemas are distinct. This projection contains
    # exactly the structural fields shared by both contracts.
    structural = {
        "schema": integrity.CHECKPOINT_SCHEMA,
        "mission_id": checkpoint.get("mission_id"),
        "sequence": checkpoint.get("sequence"),
        "revocation_count": checkpoint.get("revocation_count"),
        "registry_sha256": checkpoint.get("registry_sha256"),
    }

    ok, reason = integrity.verify_checkpoint_structure(
        mission_id,
        records,
        structural,
    )

    if not ok:
        return False, "INTEGRITY:" + str(reason)

    ok, reason = authentication.verify_checkpoint_authenticator(
        checkpoint,
        trusted_key_id=trusted_key_id,
        verifier_key=verifier_key,
        trusted_sequence_floor=trusted_sequence_floor,
    )

    if not ok:
        return False, "AUTHENTICATION:" + str(reason)

    return True, None


def authorization_qualification(*args, **kwargs):
    return False, "INDEPENDENT_TRUST_ANCHOR_REQUIRED"
