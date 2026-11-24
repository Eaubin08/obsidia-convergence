import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import obsidia_hma_revocation_checkpoint_candidate_v1 as integrity
import obsidia_hma_revocation_checkpoint_auth_candidate_v1 as auth
import obsidia_hma_revocation_checkpoint_combined_candidate_v1 as combined


class TestHmaRevocationCheckpointFloor(unittest.TestCase):

    KEY = b"P1-C226-EPHEMERAL-TEST-KEY-0000000001"
    KEY_ID = "p1-c226-test"
    MISSION = "p1-c226-synthetic-mission"

    def _checkpoint(self, sequence):
        record = {
            "schema": auth.AUTH_SCHEMA,
            "mission_id": self.MISSION,
            "sequence": sequence,
            "revocation_count": 0,
            "registry_sha256": integrity.registry_digest(
                self.MISSION, []
            ),
            "key_id": self.KEY_ID,
        }

        record["authenticator"] = auth.authenticate_checkpoint(
            record,
            self.KEY,
            self.KEY_ID,
        )

        return record

    def _verify(self, sequence, floor):
        return combined.verify_checkpoint_candidate(
            self.MISSION,
            [],
            self._checkpoint(sequence),
            trusted_key_id=self.KEY_ID,
            verifier_key=self.KEY,
            trusted_sequence_floor=floor,
        )

    def test_equal_floor_accepted(self):
        self.assertEqual(
            self._verify(2, 2),
            (True, None),
        )

    def test_old_checkpoint_rejected(self):
        self.assertEqual(
            self._verify(1, 2),
            (
                False,
                "AUTHENTICATION:CHECKPOINT_ROLLBACK",
            ),
        )

    def test_ahead_checkpoint_rejected(self):
        self.assertEqual(
            self._verify(3, 2),
            (
                False,
                "AUTHENTICATION:CHECKPOINT_AHEAD_OF_TRUSTED_FLOOR",
            ),
        )

    def test_zero_floor_baseline(self):
        self.assertEqual(
            self._verify(0, 0),
            (True, None),
        )

    def test_zero_floor_ahead_rejected(self):
        self.assertEqual(
            self._verify(1, 0),
            (
                False,
                "AUTHENTICATION:CHECKPOINT_AHEAD_OF_TRUSTED_FLOOR",
            ),
        )

    def test_missing_floor_rejected(self):
        self.assertEqual(
            self._verify(2, None),
            (
                False,
                "AUTHENTICATION:TRUSTED_SEQUENCE_FLOOR_UNAVAILABLE",
            ),
        )

    def test_caller_cannot_promote_authority(self):
        self.assertEqual(
            combined.authorization_qualification(),
            (
                False,
                "INDEPENDENT_TRUST_ANCHOR_REQUIRED",
            ),
        )


if __name__ == "__main__":
    unittest.main()
