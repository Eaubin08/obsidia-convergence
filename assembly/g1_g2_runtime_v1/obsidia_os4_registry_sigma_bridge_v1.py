"""OS4 registry-to-Sigma bridge, read-only and fail-closed.

A structurally valid conversion remains untrusted.
No registry declaration can authorize execution or qualify a measurement.
"""

from __future__ import annotations

from typing import Any

from obsidia_os4_registry_binding_v1 import (
    bind_os4_registry_observation,
)
import obsidia_os4_registry_binding_v1 as _registry_binding_reference
from obsidia_os4_sigma_adapter_v1 import (
    evaluate_domain_observation_readonly,
)


def _hold(reason: str) -> dict[str, Any]:
    return {
        "status": "HOLD",
        "reason": reason,
        "kx108_gate": "HOLD",
        "trust_verified": False,
        "measure_valid": False,
        "execution_authorized": False,
        "action_ticket_issued": False,
        "decision_authority": "KX108_ONLY",
        "readonly": True,
    }


def evaluate_os4_registry_sigma_readonly(
    observation: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    """Bind one mapping, then invoke the existing Sigma/KX108 boundary."""

    try:
        binding = bind_os4_registry_observation(
            observation,
            registry,
        )
    except Exception:
        return _hold("OS4_REGISTRY_BINDING_FAILED")

    if (
        type(binding) is not dict
        or binding.get("status") != "CANDIDATE_ONLY"
        or binding.get("trust_verified") is not False
        or binding.get("measure_valid") is not False
        or binding.get("kernel_ready") is not False
        or binding.get("execution_authorized") is not False
        or binding.get("decision_authority") != "KX108_ONLY"
    ):
        return _hold("OS4_REGISTRY_BINDING_NOT_QUALIFIED")

    # Recompute from the supplied registry and observation through
    # the registry module. This checks local consistency, not issuer trust.
    try:
        reference_binding = (
            _registry_binding_reference.bind_os4_registry_observation(
                observation,
                registry,
            )
        )
    except Exception:
        return _hold("OS4_REGISTRY_REFERENCE_RECOMPUTE_FAILED")

    if (
        type(reference_binding) is not dict
        or reference_binding.get("status") != "CANDIDATE_ONLY"
        or binding != reference_binding
    ):
        return _hold("OS4_REGISTRY_BINDING_RECOMPUTE_MISMATCH")

    # Sigma V1 accepts the original observation without "dimension".
    # This is a structural projection, not a qualified canonical measure.
    legacy = {
        key: observation[key]
        for key in (
            "domain",
            "metric",
            "value",
            "unit",
            "evidence_ref",
        )
    }

    try:
        sigma = evaluate_domain_observation_readonly(legacy)
    except Exception:
        return _hold("OS4_SIGMA_EVALUATION_FAILED")

    if (
        type(sigma) is not dict
        or sigma.get("kx108_gate") != "HOLD"
        or sigma.get("execution_authorized") is not False
        or sigma.get("decision_authority") != "KX108_ONLY"
        or sigma.get("readonly") is not True
    ):
        return _hold("OS4_SIGMA_AUTHORITY_BOUNDARY_INVALID")

    # Reject inconsistent or forged secondary authority claims.
    if sigma.get("status") != "CANDIDATE_ONLY":
        return _hold("OS4_SIGMA_STATUS_INVALID")

    for field in (
        "action_ticket_issued",
        "release_authorized",
        "target_mutated",
        "measure_valid",
        "trust_verified",
        "kernel_ready",
    ):
        if field in sigma and sigma[field] is not False:
            return _hold("OS4_SIGMA_SECONDARY_AUTHORITY_INVALID:" + field)

    # Expose only the non-sovereign diagnostic subset.
    # Never forward arbitrary Sigma fields to downstream consumers.
    safe_sigma = {
        "status": "CANDIDATE_ONLY",
        "reason": str(sigma.get("reason", "UNKNOWN")),
        "kx108_gate": "HOLD",
        "decision_authority": "KX108_ONLY",
        "execution_authorized": False,
        "action_ticket_issued": False,
        "release_authorized": False,
        "target_mutated": False,
        "measure_valid": False,
        "trust_verified": False,
        "kernel_ready": False,
        "readonly": True,
    }

    # Canonical data are untrusted and must have an exact schema.
    canonical = binding.get("canonical_measure")

    canonical_fields = {
        "domain",
        "metric",
        "dimension",
        "source_value",
        "source_unit",
        "canonical_value",
        "canonical_unit",
        "evidence_refs",
        "mapping_ref",
        "mapping_sha256",
        "mapping_authenticity",
        "unknowns",
    }

    if type(canonical) is not dict or set(canonical) != canonical_fields:
        return _hold("OS4_CANONICAL_MEASURE_SCHEMA_INVALID")

    if (
        canonical.get("mapping_authenticity") != "UNVERIFIED"
        or type(canonical.get("unknowns")) is not list
        or "MAPPING_AUTHORITY_UNVERIFIED" not in canonical["unknowns"]
        or type(canonical.get("evidence_refs")) is not list
    ):
        return _hold("OS4_CANONICAL_MEASURE_TRUST_INVALID")

    safe_canonical = {
        key: (
            list(canonical[key])
            if key in ("evidence_refs", "unknowns")
            else canonical[key]
        )
        for key in canonical_fields
    }

    safe_binding = {
        "status": "CANDIDATE_ONLY",
        "reason": "OS4_REGISTRY_BINDING_UNTRUSTED",
        "registry_sha256": binding.get("registry_sha256"),
        "mapping_version": binding.get("mapping_version"),
        "canonical_measure": safe_canonical,
        "readonly": True,
        "trust_verified": False,
        "measure_valid": False,
        "kernel_ready": False,
        "execution_authorized": False,
        "decision_authority": "KX108_ONLY",
    }

    return {
        "status": "CANDIDATE_ONLY",
        "reason": "OS4_REGISTRY_SIGMA_UNTRUSTED",
        "registry_binding": safe_binding,
        "sigma_evaluation": safe_sigma,
        "kx108_gate": "HOLD",
        "trust_verified": False,
        "measure_valid": False,
        "execution_authorized": False,
        "action_ticket_issued": False,
        "decision_authority": "KX108_ONLY",
        "readonly": True,
    }
