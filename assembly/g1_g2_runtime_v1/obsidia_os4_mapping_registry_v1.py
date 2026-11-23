"""OS4 mapping registry V1 — strict structural inspection, never an authority."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

_SCHEMA = "OBSIDIA_OS4_MAPPING_REGISTRY_V1"
_ROOT_FIELDS = {
    "schema", "registry_version", "decision_authority",
    "mappings",
}
_MAPPING_FIELDS = {
    "domain", "metric", "dimension",
    "source_unit", "canonical_unit", "scale",
    "mapping_ref",
    "version", "issuer_ref", "qualification_ref",
    "revocation_ref",
}


def _hold(reason: str) -> dict[str, Any]:
    return {
        "status": "HOLD",
        "reason": reason,
        "registry_authenticated": False,
        "semantic_qualification_verified": False,
        "measure_valid": False,
        "execution_authorized": False,
        "decision_authority": "KX108_ONLY",
        "readonly": True,
    }


def inspect_os4_mapping_registry(registry: Any) -> dict[str, Any]:
    if type(registry) is not dict or set(registry) != _ROOT_FIELDS:
        return _hold("REGISTRY_SCHEMA_FIELDS_INVALID")

    if registry["schema"] != _SCHEMA:
        return _hold("REGISTRY_SCHEMA_INVALID")

    if registry["decision_authority"] != "KX108_ONLY":
        return _hold("REGISTRY_AUTHORITY_INVALID")

    if (
        type(registry["registry_version"]) is not str
        or not registry["registry_version"].strip()
    ):
        return _hold("REGISTRY_VERSION_INVALID")

    mappings = registry["mappings"]

    if type(mappings) is not list or len(mappings) > 256:
        return _hold("REGISTRY_SIZE_INVALID")

    identities = set()

    for index, mapping in enumerate(mappings):
        if type(mapping) is not dict or set(mapping) != _MAPPING_FIELDS:
            return _hold(f"MAPPING_FIELDS_INVALID:{index}")

        for name in (
            "domain", "metric", "dimension",
            "source_unit", "canonical_unit",
            "scale", "mapping_ref", "version",
        ):
            value = mapping[name]

            if type(value) is not str or not value.strip():
                return _hold(f"MAPPING_FIELD_INVALID:{index}:{name}")

        for name in ("issuer_ref", "qualification_ref", "revocation_ref"):
            value = mapping[name]

            if value is not None and (
                type(value) is not str or not value.strip()
            ):
                return _hold(f"MAPPING_REFERENCE_INVALID:{index}:{name}")

        if mapping["revocation_ref"] is not None:
            return _hold("MAPPING_REVOCATION_UNVERIFIED")

        try:
            scale = Decimal(mapping["scale"])
        except InvalidOperation:
            return _hold("MAPPING_SCALE_INVALID")

        if not scale.is_finite():
            return _hold("MAPPING_SCALE_NONFINITE")

        if scale <= 0:
            return _hold("MAPPING_SCALE_NOT_POSITIVE")

        if abs(scale.adjusted()) > 12:
            return _hold("MAPPING_SCALE_RANGE_UNSUPPORTED")

        # Une seule correspondance possible pour cette entr?e.
        # Une version concurrente exige une r?solution explicite,
        # jamais une s?lection implicite par l'ordre de la liste.
        identity = (
            mapping["domain"],
            mapping["metric"],
            mapping["dimension"],
            mapping["source_unit"],
        )

        if identity in identities:
            return _hold("MAPPING_AMBIGUOUS_OR_DUPLICATE")

        identities.add(identity)

    canonical = json.dumps(
        registry,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    return {
        "status": "STRUCTURE_VALID_UNTRUSTED",
        "reason": "OS4_REGISTRY_DECLARATIVE_ONLY",
        "registry_sha256": hashlib.sha256(canonical).hexdigest(),
        "mapping_count": len(mappings),
        "registry_authenticated": False,
        "semantic_qualification_verified": False,
        "measure_valid": False,
        "execution_authorized": False,
        "decision_authority": "KX108_ONLY",
        "readonly": True,
    }


def inspect_os4_mapping_registry_file(path: Path) -> dict[str, Any]:
    """Read a caller-selected file; never create or modify the registry."""
    if not isinstance(path, Path):
        return _hold("REGISTRY_PATH_INVALID")

    try:
        if not path.is_file():
            return _hold("REGISTRY_FILE_MISSING")

        if path.stat().st_size > 262144:
            return _hold("REGISTRY_FILE_TOO_LARGE")

        raw = path.read_bytes()

        if len(raw) > 262144:
            return _hold("REGISTRY_FILE_TOO_LARGE")

        def unique_fields(pairs):
            result = {}

            for key, value in pairs:
                if key in result:
                    raise ValueError("DUPLICATE_JSON_FIELD")

                result[key] = value

            return result

        registry = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_fields,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError("NONFINITE_JSON_VALUE")
            ),
        )

    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return _hold("REGISTRY_FILE_INVALID")

    return inspect_os4_mapping_registry(registry)
