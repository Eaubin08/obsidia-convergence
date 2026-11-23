"""OS4-V2 — Deterministic, non-sovereign dimensional binding.

A caller-supplied mapping is never trusted authority.
No rule registration, no attestation, no execution.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any


_REQUIRED = {
    "domain",
    "metric",
    "dimension",
    "source_unit",
    "canonical_unit",
    "scale",
    "mapping_ref",
}

_OBSERVATION_FIELDS = {
    "domain",
    "metric",
    "dimension",
    "value",
    "unit",
    "evidence_ref",
}


def _hold(reason: str) -> dict[str, Any]:
    return {
        "status": "HOLD",
        "reason": reason,
        "structurally_valid": False,
        "trust_verified": False,
        "measure_valid": False,
        "kernel_ready": False,
        "execution_authorized": False,
        "decision_authority": "KX108_ONLY",
        "readonly": True,
    }


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def bind_dimension_readonly(
    observation: dict[str, Any],
    mapping: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        return _hold("OBSERVATION_INVALID")

    if not isinstance(mapping, dict):
        return _hold("MAPPING_INVALID")

    if set(observation) != _OBSERVATION_FIELDS:
        return _hold("OBSERVATION_SCHEMA_INVALID")

    if set(mapping) != _REQUIRED:
        return _hold("MAPPING_SCHEMA_INVALID")

    for field in ("domain", "metric", "dimension", "unit", "evidence_ref"):
        if not _nonempty(observation[field]):
            return _hold("OBSERVATION_FIELD_INVALID:" + field)

    for field in (
        "domain",
        "metric",
        "dimension",
        "source_unit",
        "canonical_unit",
        "mapping_ref",
    ):
        if not _nonempty(mapping[field]):
            return _hold("MAPPING_FIELD_INVALID:" + field)

    for field in ("domain", "metric", "dimension"):
        if observation[field] != mapping[field]:
            return _hold("MAPPING_BINDING_MISMATCH:" + field)

    if observation["unit"] != mapping["source_unit"]:
        return _hold("SOURCE_UNIT_MISMATCH")

    if type(observation["value"]) not in (int, float):
        return _hold("VALUE_NOT_NUMERIC")

    if not isinstance(mapping["scale"], str):
        return _hold("SCALE_NOT_DECIMAL_STRING")

    try:
        value = Decimal(str(observation["value"]))
        scale = Decimal(mapping["scale"])
    except InvalidOperation:
        return _hold("DECIMAL_INVALID")

    if not value.is_finite() or not scale.is_finite():
        return _hold("NONFINITE_VALUE")

    if scale <= 0:
        return _hold("SCALE_NOT_POSITIVE")

    if abs(scale.adjusted()) > 12 or abs(value.adjusted()) > 12:
        return _hold("NUMERIC_RANGE_UNSUPPORTED")

    with localcontext() as context:
        context.prec = 28
        converted = value * scale

    if not converted.is_finite():
        return _hold("CONVERSION_NONFINITE")

    # A hash identifies declared bytes, not their authority.
    canonical_mapping = json.dumps(
        mapping,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    mapping_hash = hashlib.sha256(
        canonical_mapping.encode("utf-8")
    ).hexdigest()

    return {
        "status": "CANDIDATE_ONLY",
        "reason": "DIMENSIONAL_BINDING_STRUCTURAL_ONLY",
        "structurally_valid": True,
        "trust_verified": False,
        "measure_valid": False,
        "kernel_ready": False,
        "execution_authorized": False,
        "decision_authority": "KX108_ONLY",
        "readonly": True,
        "canonical_measure": {
            "domain": observation["domain"],
            "metric": observation["metric"],
            "dimension": observation["dimension"],
            "source_value": str(value),
            "source_unit": observation["unit"],
            "canonical_value": str(converted),
            "canonical_unit": mapping["canonical_unit"],
            "evidence_refs": [observation["evidence_ref"]],
            "mapping_ref": mapping["mapping_ref"],
            "mapping_sha256": mapping_hash,
            "mapping_authenticity": "UNVERIFIED",
            "unknowns": ["MAPPING_AUTHORITY_UNVERIFIED"],
        },
    }
