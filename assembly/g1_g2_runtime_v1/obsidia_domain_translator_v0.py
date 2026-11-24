"""OS4 V0 — Conservative domain observation canonicalization.

Preserves declared observations. Does not establish semantic truth,
rule authority, evidence authenticity, or execution permission.
"""

from __future__ import annotations

import math
from typing import Any


def _hold(reason: str) -> dict[str, Any]:
    return {
        "status": "HOLD",
        "reason": reason,
        "translation_status": "REFUSED",
        "kernel_ready": False,
        "decision_authority": "KX108_ONLY",
        "execution_authorized": False,
        "readonly": True,
    }


def translate_domain_observation(
    observation: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        return _hold("OBSERVATION_INVALID")

    required = {
        "domain",
        "metric",
        "value",
        "unit",
        "evidence_ref",
    }

    if not required.issubset(observation):
        return _hold("OBSERVATION_FIELDS_MISSING")

    if set(observation) != required:
        return _hold("OBSERVATION_FIELDS_UNRECOGNIZED")

    for field in ("domain", "metric", "unit", "evidence_ref"):
        value = observation[field]
        if not isinstance(value, str) or not value.strip():
            return _hold(f"INVALID_{field.upper()}")

    value = observation["value"]

    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        return _hold("INVALID_MEASUREMENT")

    canonical = {
        "domain": observation["domain"],
        "metric": observation["metric"],
        "observed_value": value,
        "unit": observation["unit"],
        "evidence_refs": [observation["evidence_ref"]],
        "unknowns": ["DOMAIN_RULE_NOT_VERIFIED"],
        "contradictions": [],
        "rule_id": None,
        "measure_valid": None,
    }

    return {
        "status": "CANDIDATE_ONLY",
        "reason": "OBSERVATION_CANONICALIZED_UNVERIFIED",
        "translation_status": "STRUCTURAL_ONLY",
        "canonical_observation": canonical,
        "kernel_ready": False,
        "decision_authority": "KX108_ONLY",
        "execution_authorized": False,
        "readonly": True,
    }
