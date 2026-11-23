"""OS4 registry-to-dimensional binding. Read-only, never sovereign."""

from __future__ import annotations

from typing import Any

from obsidia_os4_mapping_registry_v1 import (
    inspect_os4_mapping_registry,
)
from obsidia_os4_dimension_binding_v1 import (
    bind_dimension_readonly,
)


def _hold(reason: str) -> dict[str, Any]:
    return {
        "status": "HOLD",
        "reason": reason,
        "readonly": True,
        "trust_verified": False,
        "measure_valid": False,
        "kernel_ready": False,
        "execution_authorized": False,
        "decision_authority": "KX108_ONLY",
    }


def bind_os4_registry_observation(
    observation: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    """Select exactly one declared mapping; preserve untrusted status."""

    inspection = inspect_os4_mapping_registry(registry)

    if inspection["status"] != "STRUCTURE_VALID_UNTRUSTED":
        return _hold("REGISTRY_INVALID:" + inspection["reason"])

    if type(observation) is not dict:
        return _hold("OBSERVATION_INVALID")

    identity_fields = (
        "domain",
        "metric",
        "dimension",
        "unit",
    )

    if any(
        type(observation.get(field)) is not str
        or not observation[field].strip()
        for field in identity_fields
    ):
        return _hold("OBSERVATION_IDENTITY_INVALID")

    matches = [
        mapping
        for mapping in registry["mappings"]
        if (
            mapping["domain"] == observation["domain"]
            and mapping["metric"] == observation["metric"]
            and mapping["dimension"] == observation["dimension"]
            and mapping["source_unit"] == observation["unit"]
        )
    ]

    if len(matches) == 0:
        return _hold("MAPPING_NOT_FOUND")

    if len(matches) != 1:
        return _hold("MAPPING_AMBIGUOUS")

    selected = matches[0]

    if selected["revocation_ref"] is not None:
        return _hold("MAPPING_REVOCATION_UNVERIFIED")

    conversion_mapping = {
        key: selected[key]
        for key in (
            "domain",
            "metric",
            "dimension",
            "source_unit",
            "canonical_unit",
            "scale",
            "mapping_ref",
        )
    }

    conversion = bind_dimension_readonly(
        observation,
        conversion_mapping,
    )

    if conversion["status"] != "CANDIDATE_ONLY":
        return _hold("CONVERSION_INVALID:" + conversion["reason"])

    if (
        conversion["trust_verified"] is not False
        or conversion["measure_valid"] is not False
        or conversion["kernel_ready"] is not False
        or conversion["execution_authorized"] is not False
    ):
        return _hold("CONVERSION_AUTHORITY_BOUNDARY_INVALID")

    return {
        "status": "CANDIDATE_ONLY",
        "reason": "OS4_REGISTRY_BINDING_UNTRUSTED",
        "registry_sha256": inspection["registry_sha256"],
        "mapping_version": selected["version"],
        "canonical_measure": conversion["canonical_measure"],
        "readonly": True,
        "trust_verified": False,
        "measure_valid": False,
        "kernel_ready": False,
        "execution_authorized": False,
        "decision_authority": "KX108_ONLY",
    }
