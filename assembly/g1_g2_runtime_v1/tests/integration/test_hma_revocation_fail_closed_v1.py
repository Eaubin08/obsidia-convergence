import hashlib
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
EXTERNAL = Path(
    r"C:\Users\User\Desktop\OBSIDIA_WORK\obsidia-x108-proofs"
)

DEPENDENCY = EXTERNAL / "scripts/obsidia_isolated_work_unit_v0.py"

EXPECTED_SHA256 = (
    "e65460ac6b8225717e77a11051821c13c37a9"
    "c2c98a6395d9d75e5b0b087a0a9"
)

if not DEPENDENCY.is_file():
    raise RuntimeError("HMA_TEST_DEPENDENCY_MISSING")

if hashlib.sha256(DEPENDENCY.read_bytes()).hexdigest() != EXPECTED_SHA256:
    raise RuntimeError("HMA_TEST_DEPENDENCY_HASH_MISMATCH")

for directory in (
    EXTERNAL,
    EXTERNAL / "scripts",
    ROOT,
    ROOT / "scripts",
):
    value = str(directory)
    if value not in sys.path:
        sys.path.insert(0, value)

import obsidia_mission_authority_v0 as hma
import obsidia_mission_authority_integration_v0 as integration
import obsidia_mission_authority_pre_adapter_v0 as pre


def registry_error(*args, **kwargs):
    raise RuntimeError("HMA_REVOCATION_RECORD_UNREADABLE")


class HMARevocationFailClosedV1(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(
            prefix="OBSIDIA_HMA_REVOCATION_TEST_"
        )
        self.addCleanup(self.tmp.cleanup)

        self.store = Path(self.tmp.name)
        self.mission = "synthetic-hma-test"
        self.directory = hma._revocations_dir(
            self.mission, self.store
        )

    def load(self):
        return hma.list_mission_authority_revocations(
            self.mission, self.store
        )

    def test_absent_registry_legacy_empty(self):
        self.assertEqual(self.load(), [])

    def test_empty_registry(self):
        self.directory.mkdir(parents=True)
        self.assertEqual(self.load(), [])

    def test_corrupted_json_rejected(self):
        self.directory.mkdir(parents=True)
        (self.directory / "rev-corrupt.json").write_text(
            '{"broken":', encoding="utf-8"
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "HMA_REVOCATION_RECORD_UNREADABLE",
        ):
            self.load()

    def test_array_rejected(self):
        self.directory.mkdir(parents=True)
        (self.directory / "rev-array.json").write_text(
            "[]", encoding="utf-8"
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "HMA_REVOCATION_RECORD_NOT_OBJECT",
        ):
            self.load()

    def test_invalid_structure_rejected(self):
        self.directory.mkdir(parents=True)
        (self.directory / "rev-invalid.json").write_text(
            json.dumps({"actor": "HUMAN"}),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "HMA_REVOCATION_RECORD_INVALID",
        ):
            self.load()

    def test_unexpected_entry_rejected(self):
        self.directory.mkdir(parents=True)
        (self.directory / "unexpected.txt").write_text(
            "synthetic", encoding="utf-8"
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "HMA_REVOCATION_REGISTRY_UNEXPECTED_ENTRY",
        ):
            self.load()

    def test_initial_binding_denied_on_registry_error(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(
                integration._M, "project_mission",
                return_value={
                    "status": integration._M.STATUS_PROJECTION_OK,
                    "current_state": integration._M.S_WORKTREE_BOUND,
                    "active_plan_id": "plan-synthetic",
                }
            ))
            stack.enter_context(patch.object(
                integration._MA,
                "bind_human_mission_authorization",
                return_value={
                    "status": integration._MA.HMA_BOUND,
                    "human_mission_authorization_id": "hma-synthetic",
                }
            ))
            stack.enter_context(patch.object(
                integration._M, "load_mission_genesis",
                return_value={"mission_id": self.mission}
            ))
            stack.enter_context(patch.object(
                integration._M, "load_mission_plan",
                return_value={"plan_id": "plan-synthetic"}
            ))
            stack.enter_context(patch.object(
                integration._MA, "load_human_mission_authorization",
                return_value={"human_mission_authorization_id": "hma-synthetic"}
            ))
            stack.enter_context(patch.object(
                integration._MA, "list_mission_authority_revocations",
                side_effect=registry_error
            ))

            result = integration.bind_mission_authority_from_human_reference(
                mission_id=self.mission,
                human_authorization_reference="synthetic",
                mission_store_dir=str(self.store),
            )

        self.assertEqual(
            result["status"],
            integration.MISSION_AUTHORITY_BIND_REJECTED,
        )
        self.assertTrue(
            result["reason"].startswith("HMA_REVOCATION_REGISTRY_HOLD:")
        )

    def test_daaw_derivation_hold_on_registry_error(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(
                integration._M, "project_mission",
                return_value={
                    "status": integration._M.STATUS_PROJECTION_OK,
                    "current_state": integration._M.S_ACTION_PREPARED,
                    "active_hma_id": "hma-synthetic",
                    "active_hma_plan_id": "plan-synthetic",
                    "plan_completed": False,
                    "last_prepared_evidence": {
                        "action_id": "action-synthetic",
                        "ordinal": 0,
                        "batch_execution_id": "execution-synthetic",
                        "execution_authority_hash": "a" * 64,
                    },
                    "derived_witnesses": [],
                }
            ))
            stack.enter_context(patch.object(
                integration._M, "load_mission_genesis",
                return_value={"mission_id": self.mission}
            ))
            stack.enter_context(patch.object(
                integration._M, "load_mission_plan",
                return_value={"plan_id": "plan-synthetic"}
            ))
            stack.enter_context(patch.object(
                integration._MA, "load_human_mission_authorization",
                return_value={"human_mission_authorization_id": "hma-synthetic"}
            ))
            stack.enter_context(patch.object(
                integration._MA, "list_mission_authority_revocations",
                side_effect=registry_error
            ))

            result = integration.derive_and_record_action_authority_witness(
                mission_id=self.mission,
                work_unit=None,
                execution_dir=str(self.store),
                mission_store_dir=str(self.store),
            )

        self.assertEqual(
            result["status"],
            "ACTION_AUTHORITY_WITNESS_DERIVATION_HOLD",
        )
        self.assertTrue(result["hma_invalid"])
        self.assertFalse(result["daaw_is_execution_authority"])
        self.assertFalse(result["kx_pre_semantics_changed"])

    def test_pre_adapter_denied_on_registry_error(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(
                pre._E, "_load_execution",
                return_value={"execution_authority_hash": "a" * 64}
            ))
            stack.enter_context(patch.object(
                pre._E, "compute_execution_authority_hash",
                return_value="a" * 64
            ))
            stack.enter_context(patch.object(
                pre._M, "project_mission",
                return_value={
                    "status": pre._M.STATUS_PROJECTION_OK,
                    "current_state": pre._M.S_ACTION_PREPARED,
                    "active_hma_id": "hma-synthetic",
                    "active_hma_plan_id": "plan-synthetic",
                    "plan_completed": False,
                    "last_prepared_evidence": {
                        "action_id": "action-synthetic",
                        "ordinal": 0,
                        "child_execution_id": "child-synthetic",
                        "batch_execution_id": "execution-synthetic",
                        "execution_authority_hash": "a" * 64,
                    },
                }
            ))
            stack.enter_context(patch.object(
                pre._M, "load_mission_genesis",
                return_value={"mission_id": self.mission}
            ))
            stack.enter_context(patch.object(
                pre._M, "load_mission_plan",
                return_value={"plan_id": "plan-synthetic"}
            ))
            stack.enter_context(patch.object(
                pre._MA, "load_human_mission_authorization",
                return_value={
                    "human_mission_authorization_id": "hma-synthetic",
                    "human_authorization_reference": "synthetic",
                }
            ))
            stack.enter_context(patch.object(
                pre._MA, "list_mission_authority_revocations",
                side_effect=registry_error
            ))

            result = pre._verify_chain(
                mission_id=self.mission,
                store_dir=str(self.store),
                execution_dir=str(self.store),
                batch_execution_id="execution-synthetic",
            )

        self.assertIsNone(result[0])
        self.assertTrue(
            result[1].startswith("HMA_REVOCATION_REGISTRY_HOLD:")
        )


if __name__ == "__main__":
    unittest.main()
