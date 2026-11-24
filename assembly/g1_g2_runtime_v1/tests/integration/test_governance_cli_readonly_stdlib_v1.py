"""Contrats du premier terminal unifié OBSIDIA Gouvernance : zéro APPLY."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import obsidia_governance_cli_v1 as cli
import sigma_registry_descriptor_v1 as descriptors


def payload(count: int = 4):
    return {
        "schema": "OBSIDIA_SIGMA_TOOLING_ADVISORY_INPUT_V1",
        "votes": [{
            "agent_id": f"agent-{i}", "domain": "tooling_build",
            "proposed_verdict": "ACT", "claim": "test synthetic caller observation",
            "confidence": 0.95,
        } for i in range(count)],
    }


class GovernanceCLIContract(unittest.TestCase):
    def assert_non_authorizing(self, result):
        self.assertEqual(result["decision_authority"], "KX108_ONLY")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["target_mutated"])

    def test_status_is_one_runtime_not_release(self):
        result = cli.dispatch_command("status")
        self.assertEqual(result["capabilities"]["engine"], "OBSIDIA_GOUVERNANCE_UNIFIED")
        self.assertEqual(result["capabilities"]["apply"], "HOLD")
        self.assertEqual(result["full_functional_regression"], "HOLD")
        self.assert_non_authorizing(result)

    def test_sigma_domains_is_static_without_agent_runtime_claim(self):
        registry_imported_before = "sigma.registry" in sys.modules
        result = cli.dispatch_command("sigma-domains")
        self.assertEqual("sigma.registry" in sys.modules, registry_imported_before)
        self.assertEqual(result["status"], "SIGMA_DOMAINS_DESCRIBED_NOT_EXECUTED")
        self.assertEqual(len(result["registry"]["domains"]), 4)
        self.assertFalse(result["registry"]["agent_runtime_imported"])
        self.assertEqual(result["registry"]["dependency_closure"], "HOLD_NOT_CLAIMED")
        self.assert_non_authorizing(result)

    def test_zero_votes_goes_through_guard_with_blocked_gate(self):
        result = cli.dispatch_command("sigma-tooling", payload=payload(0))
        self.assertEqual(result["status"], "SIGMA_ADVISORY_ONLY")
        self.assertEqual(result["advisory"]["market_verdict"], "BUILD_BLOCK")
        self.assertNotEqual(result["advisory"]["guard_gate_observed"], "ALLOW")
        self.assert_non_authorizing(result)

    def test_four_positive_votes_are_advice_not_kx108_ticket(self):
        result = cli.dispatch_command("sigma-tooling", payload=payload())
        self.assertEqual(result["status"], "SIGMA_ADVISORY_ONLY")
        self.assertEqual(result["advisory"]["guard_gate_observed"], "HOLD")
        self.assertFalse(result["source_attested"])
        self.assertEqual(result["input_provenance"], "CALLER_SUPPLIED_UNATTESTED")
        self.assertFalse(result["action_ticket_issued"])
        self.assertNotIn("ticket_id", str(result))
        self.assert_non_authorizing(result)

    def test_unknown_and_contradictions_are_propagated(self):
        raw = payload()
        raw["votes"][0]["unknowns"] = ["NO_REAL_SOURCE"]
        self.assertEqual(cli.dispatch_command("sigma-tooling", payload=raw)["advisory"]["market_verdict"], "BUILD_HOLD")
        raw["votes"][1]["contradictions"] = ["UNRESOLVED"]
        self.assertEqual(cli.dispatch_command("sigma-tooling", payload=raw)["advisory"]["market_verdict"], "BUILD_BLOCK")

    def test_quorum_and_duplicate_agent_denied(self):
        for count in (1, 2, 3, 5):
            with self.subTest(count=count):
                self.assertEqual(cli.dispatch_command("sigma-tooling", payload=payload(count))["status"], "HOLD")
        raw = payload()
        raw["votes"][0]["agent_id"] = raw["votes"][1]["agent_id"]
        self.assertEqual(cli.dispatch_command("sigma-tooling", payload=raw)["status"], "HOLD")

    def test_unknown_authority_human_approval_and_ticket_fields_denied(self):
        for forbidden in ("authority_level", "rule_id", "human_approval", "ticket_id", "decision_authority"):
            with self.subTest(field=forbidden):
                raw = payload()
                raw["votes"][0][forbidden] = "ALLOW"
                self.assertEqual(cli.dispatch_command("sigma-tooling", payload=raw)["status"], "HOLD")

    def test_type_confidence_nonfinite_and_unknown_signals_denied(self):
        for value in (True, "0.8", -0.1, 1.01, float("nan"), float("inf"), 10 ** 10000):
            with self.subTest(confidence=value):
                raw = payload()
                raw["votes"][0]["confidence"] = value
                self.assertEqual(cli.dispatch_command("sigma-tooling", payload=raw)["status"], "HOLD")
        raw = payload()
        raw["votes"][0]["proposed_verdict"] = {"ACT": True}
        self.assertEqual(cli.dispatch_command("sigma-tooling", payload=raw)["status"], "HOLD")
        raw = payload()
        raw["votes"][0]["unknowns"] = "hidden"
        self.assertEqual(cli.dispatch_command("sigma-tooling", payload=raw)["status"], "HOLD")

    def test_unknown_wrapper_fields_denied(self):
        raw = payload()
        raw["x108_gate"] = "ALLOW"
        self.assertEqual(cli.dispatch_command("sigma-tooling", payload=raw)["status"], "HOLD")

    def test_all_execute_commands_hold_including_forged_allow(self):
        for operation in (*cli._EXECUTION_OPERATIONS, "DANGEROUS_UNKNOWN"):
            with self.subTest(operation=operation):
                result = cli.dispatch_command("execute", operation=operation)
                self.assertEqual(result["status"], "HOLD")
                self.assert_non_authorizing(result)

    def test_merkle_pure_compute_and_invalid_input(self):
        with tempfile.TemporaryDirectory(prefix="obsidia-cli-") as d:
            result = cli.dispatch_command("merkle", sha256_digests=["a" * 64, "b" * 64])
            self.assertEqual(result["status"], "MERKLE_ROOT_COMPUTED_READ_ONLY")
            self.assertEqual(len(result["root"]), 64)
            self.assertFalse((Path(d) / "merkle_seal.json").exists())
            self.assert_non_authorizing(result)
            for bad in ([], ["x"], ["a" * 64] * 513):
                self.assertEqual(cli.dispatch_command("merkle", sha256_digests=bad)["status"], "HOLD")

    def test_duplicate_stdin_keys_and_nan_are_denied(self):
        for raw in (b'{"schema":"x","schema":"x","votes":[]}', b'{"schema":"x","votes":[NaN]}'):
            inp = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
            with patch("sys.stdin", inp):
                _, error = cli._read_stdin_json()
                self.assertEqual(error, "SIGMA_STDIN_JSON_INVALID")

    def test_stdin_size_bounded(self):
        inp = io.TextIOWrapper(io.BytesIO(b"a" * (cli._MAX_STDIN_BYTES + 1)), encoding="utf-8")
        with patch("sys.stdin", inp):
            _, error = cli._read_stdin_json()
            self.assertEqual(error, "SIGMA_STDIN_MISSING_OR_OVERSIZED")

    def test_subprocess_cli_status_and_execution_hold(self):
        target = ROOT / "obsidia_governance_cli_v1.py"
        proc = subprocess.run([sys.executable, "-B", str(target), "status"],
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assert_non_authorizing(json.loads(proc.stdout))
        denied = subprocess.run([sys.executable, "-B", str(target), "execute", "--operation", "WORLD_ACTION"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(denied.returncode, 2)
        self.assertEqual(json.loads(denied.stdout)["status"], "HOLD")

    def test_subprocess_sigma_advisory(self):
        target = ROOT / "obsidia_governance_cli_v1.py"
        proc = subprocess.run([sys.executable, "-B", str(target), "sigma-tooling", "--stdin"],
                              input=json.dumps(payload()), capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assert_non_authorizing(json.loads(proc.stdout))

    def test_registry_ast_source_mutation_is_hold(self):
        with tempfile.TemporaryDirectory(prefix="obsidia-sigma-registry-") as d:
            f = Path(d) / "registry.py"
            f.write_text('_CANONICAL_DOMAINS = ("bank", "trading")', encoding="utf-8")
            self.assertEqual(descriptors.inspect_sigma_registry_descriptor(f)["status"], "HOLD")
            f.write_text('_CANONICAL_DOMAINS = ("bank",', encoding="utf-8")
            self.assertEqual(descriptors.inspect_sigma_registry_descriptor(f)["status"], "HOLD")
            original = (ROOT / "sigma" / "registry.py").read_text(encoding="utf-8")
            f.write_text(original + "\n# injected\n", encoding="utf-8")
            self.assertEqual(descriptors.inspect_sigma_registry_descriptor(f)["reason"],
                             "SIGMA_REGISTRY_SOURCE_SHA_MISMATCH")


if __name__ == "__main__":
    unittest.main()
