"""CLI unique de démonstration technique OBSIDIA Gouvernance (lecture seule).

Un seul runtime. SIGMA reste consultatif, KX108 garde l'autorité, et toute
mutation reste HOLD. Aucune connexion réseau, aucun lancement d'agent,
aucune copie/import du FIX, aucun serveur, aucune écriture de preuve.

Exemples :
  python -B obsidia_governance_cli_v1.py status
  python -B obsidia_governance_cli_v1.py sigma-domains
  python -B obsidia_governance_cli_v1.py sigma-tooling --stdin
  python -B obsidia_governance_cli_v1.py merkle --sha256 <64hex> --sha256 <64hex>
  python -B obsidia_governance_cli_v1.py execute --operation WORLD_ACTION
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Any

from obsidia_governance_runtime_v1 import get_runtime
from sigma_registry_descriptor_v1 import inspect_sigma_registry_descriptor
from sigma.contracts import AgentVote

_MAX_STDIN_BYTES = 65536
_SCHEMA = "OBSIDIA_SIGMA_TOOLING_ADVISORY_INPUT_V1"
_REQUIRED = frozenset({"agent_id", "domain", "claim", "proposed_verdict", "confidence"})
_OPTIONAL = frozenset({"unknowns", "contradictions", "risk_flags"})
_VERDICTS = frozenset({"ACT", "HOLD", "BLOCK"})
_EXECUTION_OPERATIONS = (
    "CREATE_TARGET_FROM_SOURCE", "UPDATE_TARGET_FROM_SOURCE", "WORLD_ACTION",
)


def _hold(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "OBSIDIA_GOVERNANCE_CLI_V1",
        "status": "HOLD", "reason": reason,
        "decision_authority": "KX108_ONLY", "readonly": True,
        "action_ticket_issued": False, "execution_authorized": False,
        "target_mutated": False, "release_authorized": False,
    }


def _unique_object_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate field")
        output[key] = value
    return output


def _no_nonfinite(value: str) -> None:
    raise ValueError("nonfinite JSON value")


def _str_field(value: Any, *, limit: int) -> bool:
    return type(value) is str and 0 < len(value) <= limit and bool(value.strip())


def _signals(raw: dict[str, Any], key: str) -> list[str] | None:
    value = raw.get(key, [])
    if (type(value) is not list or len(value) > 20
            or any(not _str_field(item, limit=200) for item in value)):
        return None
    return value


def parse_tooling_advisory_input(value: Any) -> tuple[list[AgentVote] | None, str | None]:
    """Strict : jamais de rule_id, authority_level ou approbation importée."""
    if type(value) is not dict or set(value) != {"schema", "votes"} or value.get("schema") != _SCHEMA:
        return None, "SIGMA_INPUT_ENVELOPE_INVALID"
    raw_votes = value["votes"]
    if type(raw_votes) is not list or len(raw_votes) not in (0, 4):
        return None, "SIGMA_TOOLING_QUORUM_INVALID"
    votes = []
    seen: set[str] = set()
    for entry in raw_votes:
        if type(entry) is not dict or not _REQUIRED <= set(entry) or not set(entry) <= _REQUIRED | _OPTIONAL:
            return None, "SIGMA_VOTE_FIELDS_INVALID"
        agent_id = entry["agent_id"]
        if not _str_field(agent_id, limit=100) or agent_id in seen:
            return None, "SIGMA_AGENT_ID_INVALID_OR_DUPLICATE"
        if (entry["domain"] != "tooling_build"
                or not _str_field(entry["claim"], limit=4096)
                or type(entry["proposed_verdict"]) is not str
                or entry["proposed_verdict"] not in _VERDICTS):
            return None, "SIGMA_VOTE_SCOPE_OR_CONTENT_INVALID"
        confidence = entry["confidence"]
        if (type(confidence) not in (int, float) or not 0.0 <= confidence <= 1.0
                or not math.isfinite(float(confidence))):
            return None, "SIGMA_VOTE_CONFIDENCE_INVALID"
        signal_values = {key: _signals(entry, key) for key in _OPTIONAL}
        if any(signal is None for signal in signal_values.values()):
            return None, "SIGMA_VOTE_SIGNALS_INVALID"
        seen.add(agent_id)
        votes.append(AgentVote(
            agent_id=agent_id, domain="tooling_build",
            claim=entry["claim"], confidence=confidence,
            proposed_verdict=entry["proposed_verdict"],
            **signal_values,
        ))
    return votes, None


def _read_stdin_json() -> tuple[Any | None, str | None]:
    raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES + 1)
    if not raw or len(raw) > _MAX_STDIN_BYTES:
        return None, "SIGMA_STDIN_MISSING_OR_OVERSIZED"
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object_fields,
                          parse_constant=_no_nonfinite), None
    except (UnicodeError, ValueError):
        return None, "SIGMA_STDIN_JSON_INVALID"


def dispatch_command(command: str, *, payload: Any = None,
                     sha256_digests: list[str] | None = None,
                     operation: str | None = None) -> dict[str, Any]:
    """Tous les chemins utilisent la même façade gouvernée."""
    runtime = get_runtime()
    if command == "status":
        info = runtime.capabilities()
        return {
            "schema_version": "OBSIDIA_GOVERNANCE_CLI_V1",
            "status": "RUNTIME_AVAILABLE_READONLY_CANDIDATE",
            "capabilities": info,
            "decision_authority": "KX108_ONLY", "readonly": True,
            "action_ticket_issued": False, "execution_authorized": False,
            "target_mutated": False, "release_authorized": False,
            "full_functional_regression": "HOLD",
        }
    if command == "sigma-domains":
        descriptor = inspect_sigma_registry_descriptor()
        if descriptor["status"] != "SIGMA_DOMAINS_DECLARED_ONLY_NOT_RUNTIME_VERIFIED":
            return _hold("SIGMA_REGISTRY_DESCRIPTOR_HOLD")
        return {
            "schema_version": "OBSIDIA_GOVERNANCE_CLI_V1",
            "status": "SIGMA_DOMAINS_DESCRIBED_NOT_EXECUTED",
            "registry": descriptor, "decision_authority": "KX108_ONLY",
            "readonly": True, "action_ticket_issued": False,
            "execution_authorized": False, "target_mutated": False,
            "release_authorized": False,
        }
    if command == "sigma-tooling":
        votes, reason = parse_tooling_advisory_input(payload)
        if reason is not None:
            return _hold(reason)
        result = runtime.evaluate_tooling_build_advisory(votes)
        if result.get("status") != "SIGMA_ADVISORY_ONLY":
            return _hold("SIGMA_ADVISORY_BOUNDARY_HOLD")
        return {
            "schema_version": "OBSIDIA_GOVERNANCE_CLI_V1",
            **result,
            "source_attested": False,
            "input_provenance": "CALLER_SUPPLIED_UNATTESTED",
            "readonly": True, "release_authorized": False,
        }
    if command == "os4-evaluate":
        if not isinstance(payload, dict):
            return _hold("OS4_INPUT_NOT_OBJECT")
        try:
            import contextlib
            import io
            from obsidia_os4_sigma_adapter_v1 import (
                evaluate_domain_observation_readonly,
            )
            # GuardX108 emits diagnostic traces; preserve JSON stdout.
            with contextlib.redirect_stdout(io.StringIO()):
                result = evaluate_domain_observation_readonly(payload)
        except Exception:
            return _hold("OS4_EVALUATION_FAILED")
        if (
            not isinstance(result, dict)
            or result.get("kx108_gate") != "HOLD"
            or result.get("execution_authorized") is not False
            or result.get("decision_authority") != "KX108_ONLY"
            or result.get("readonly") is not True
        ):
            return _hold("OS4_BOUNDARY_VIOLATION")
        return {
            "schema_version": "OBSIDIA_GOVERNANCE_CLI_V1",
            "status": "HOLD",
            "reason": "OS4_READONLY_UNATTESTED_OBSERVATION",
            "os4_result": result,
            "input_provenance": "CALLER_SUPPLIED_UNATTESTED",
            "decision_authority": "KX108_ONLY",
            "readonly": True,
            "action_ticket_issued": False,
            "execution_authorized": False,
            "target_mutated": False,
            "release_authorized": False,
        }
    if command == "os4-registry-evaluate":
        if type(payload) is not dict or set(payload) != {"observation", "registry"}:
            return _hold("OS4_REGISTRY_INPUT_SCHEMA_INVALID")
        if type(payload["observation"]) is not dict or type(payload["registry"]) is not dict:
            return _hold("OS4_REGISTRY_INPUT_TYPES_INVALID")
        try:
            import contextlib
            import io
            from obsidia_os4_registry_sigma_bridge_v1 import (
                evaluate_os4_registry_sigma_readonly,
            )
            with contextlib.redirect_stdout(io.StringIO()):
                result = evaluate_os4_registry_sigma_readonly(
                    payload["observation"],
                    payload["registry"],
                )
        except Exception:
            return _hold("OS4_REGISTRY_EVALUATION_FAILED")
        if (
            type(result) is not dict
            or result.get("kx108_gate") != "HOLD"
            or result.get("execution_authorized") is not False
            or result.get("decision_authority") != "KX108_ONLY"
            or result.get("readonly") is not True
            or result.get("trust_verified") is not False
            or result.get("measure_valid") is not False
            or result.get("action_ticket_issued") is not False
        ):
            return _hold("OS4_REGISTRY_BOUNDARY_INVALID")
        return {
            "schema_version": "OBSIDIA_GOVERNANCE_CLI_V1",
            "status": "HOLD",
            "reason": "OS4_REGISTRY_UNATTESTED_READONLY",
            "os4_result": result,
            "input_provenance": "CALLER_SUPPLIED_UNATTESTED",
            "decision_authority": "KX108_ONLY",
            "readonly": True,
            "action_ticket_issued": False,
            "execution_authorized": False,
            "target_mutated": False,
            "release_authorized": False,
        }
    if command == "merkle":
        if (type(sha256_digests) is not list or not 1 <= len(sha256_digests) <= 512):
            return _hold("MERKLE_DIGESTS_COUNT_INVALID")
        result = runtime.compute_proof_root(sha256_digests)
        return {"schema_version": "OBSIDIA_GOVERNANCE_CLI_V1", **result,
                "readonly": True, "release_authorized": False}
    if command == "execute":
        if operation not in _EXECUTION_OPERATIONS:
            return _hold("EXECUTION_OPERATION_UNRECOGNIZED")
        result = runtime.execute(operation_type=operation)
        if result.get("status") != "HOLD":
            return _hold("EXECUTION_BOUNDARY_CONTRACT_VIOLATION")
        return {"schema_version": "OBSIDIA_GOVERNANCE_CLI_V1", **result,
                "readonly": True, "release_authorized": False,
                "action_ticket_issued": False}
    return _hold("CLI_COMMAND_UNKNOWN")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="obsidia-gouvernance",
                                     description="Runtime unifié OBSIDIA — lecture seule / RELEASE HOLD")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("status", help="État des rails du runtime unique")
    subs.add_parser("sigma-domains", help="Contrats des domaines Sigma sans lancer d'agents")
    sigma = subs.add_parser("sigma-tooling", help="Avis Sigma tooling_build; aucune autorisation")
    sigma.add_argument("--stdin", action="store_true", required=True,
                       help="Lire un JSON strict depuis STDIN")
    os4 = subs.add_parser("os4-evaluate", help="Observation OS4 consultative, HOLD")
    os4.add_argument("--stdin", action="store_true", required=True,
                     help="Lire une observation JSON stricte depuis STDIN")
    os4_registry = subs.add_parser(
        "os4-registry-evaluate",
        help="Registre OS4 vers Sigma, candidat non atteste, HOLD",
    )
    os4_registry.add_argument(
        "--stdin", action="store_true", required=True,
        help="Lire {observation, registry} en JSON strict depuis STDIN",
    )
    merkle = subs.add_parser("merkle", help="Calcule une racine Merkle sans sceller")
    merkle.add_argument("--sha256", action="append", required=True)
    execute = subs.add_parser("execute", help="Vérifie que l'exécution reste HOLD")
    execute.add_argument("--operation", choices=_EXECUTION_OPERATIONS, required=True)
    args = parser.parse_args(argv)
    payload = None
    if args.command in ("sigma-tooling", "os4-evaluate", "os4-registry-evaluate"):
        payload, error = _read_stdin_json()
        if error is not None:
            if args.command in ("os4-evaluate", "os4-registry-evaluate"):
                error = "OS4_" + error
            result = _hold(error)
            print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
            return 2
    result = dispatch_command(
        args.command, payload=payload,
        sha256_digests=getattr(args, "sha256", None),
        operation=getattr(args, "operation", None),
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                     allow_nan=False))
    return 2 if result["status"] == "HOLD" else 0


if __name__ == "__main__":
    sys.exit(main())
