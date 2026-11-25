"""P1-C371: authenticated reload of signed sovereign producers.

Static contract regression only.
No kernel invocation, signing key, production store or real ACT.
"""

import ast
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]

MODULE = ROOT / "scripts" / "obsidia_kx108_decision_store.py"

PRODUCERS = (
    "run_and_persist_kx108_decision",
    "run_and_persist_kx108_pre_execution_decision",
)


def _calls(function):
    result = []

    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue

        if isinstance(node.func, ast.Name):
            result.append((node.lineno, node.func.id, node))

    return result


@pytest.mark.parametrize("producer", PRODUCERS)
def test_signed_producer_reload_requires_authenticity(producer):
    tree = ast.parse(MODULE.read_text(encoding="utf-8-sig"))

    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == producer
    ]

    assert len(matches) == 1

    function = matches[0]
    calls = _calls(function)

    signing = [
        line
        for line, name, _ in calls
        if name == "_authenticate_decision_record"
    ]

    storage = [
        line
        for line, name, _ in calls
        if name == "store_kx108_decision_record"
    ]

    authenticated = [
        node
        for _, name, node in calls
        if name == "verify_kx108_decision_record_authenticity"
    ]

    structural = [
        node
        for _, name, node in calls
        if name == "verify_kx108_decision_record"
    ]

    assert len(signing) == 1
    assert len(storage) == 1

    # Signature obligatoire avant publication.
    assert signing[0] < storage[0]

    # Le rechargement doit être authentifié, pas seulement hashé.
    assert len(authenticated) == 1
    assert structural == []

    verify = authenticated[0]

    assert len(verify.args) == 1
    assert isinstance(verify.args[0], ast.Name)
    assert verify.args[0].id == "reloaded"

    # L'authenticité doit être contrôlée après la publication.
    assert verify.lineno > storage[0]


def test_non_sovereign_producers_not_promoted_by_c368():
    tree = ast.parse(MODULE.read_text(encoding="utf-8-sig"))

    excluded = (
        "persist_kx108_agent_pre_execution_decision",
        "persist_kx108_world_action_pre_execution_decision",
    )

    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue

        if node.name not in excluded:
            continue

        names = [name for _, name, _ in _calls(node)]

        assert "_authenticate_decision_record" not in names
        assert "verify_kx108_decision_record_authenticity" not in names