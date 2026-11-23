"""OS4 V1 — Non-sovereign structural observation to Sigma boundary."""

from __future__ import annotations

from typing import Any

from obsidia_domain_translator_v0 import translate_domain_observation
from sigma.contracts import AgentVote, DomainAggregate
from sigma.guard import GuardX108


def evaluate_domain_observation_readonly(
    observation: dict[str, Any],
) -> dict[str, Any]:
    translation = translate_domain_observation(observation)

    if translation["status"] != "CANDIDATE_ONLY":
        return {
            "status": "HOLD",
            "reason": translation["reason"],
            "translation": translation,
            "kx108_gate": "HOLD",
            "decision_authority": "KX108_ONLY",
            "execution_authorized": False,
            "readonly": True,
        }

    canonical = translation["canonical_observation"]

    vote = AgentVote(
        agent_id="OS4_STRUCTURAL_TRANSLATOR",
        vote="HOLD",
        proposed_verdict="HOLD",
        confidence=0.0,
        domain=canonical["domain"],
        rule_id="OS4_UNVERIFIED_DOMAIN_RULE",
        observed_value=canonical["observed_value"],
        evidence_refs=list(canonical["evidence_refs"]),
        unknowns=list(canonical["unknowns"]),
        measure_valid=False,
    )

    aggregate = DomainAggregate(
        domain=canonical["domain"],
        market_verdict="HOLD",
        confidence=0.0,
        agent_votes=[vote],
        evidence_refs=list(canonical["evidence_refs"]),
        unknowns=list(canonical["unknowns"]),
    )

    decision = GuardX108().decide(aggregate)

    raw_gate = getattr(decision, "x108_gate", None)
    gate = str(getattr(raw_gate, "value", raw_gate))
    reason = str(getattr(decision, "reason_code", "UNKNOWN"))

    # V1 never releases a decision, even if a future guard changes.
    if gate != "HOLD":
        return {
            "status": "HOLD",
            "reason": "OS4_UNEXPECTED_NON_HOLD_GATE",
            "translation": translation,
            "kx108_gate": "HOLD",
            "decision_authority": "KX108_ONLY",
            "execution_authorized": False,
            "readonly": True,
        }

    return {
        "status": "CANDIDATE_ONLY",
        "reason": reason,
        "translation": translation,
        "kx108_gate": "HOLD",
        "decision_authority": "KX108_ONLY",
        "execution_authorized": False,
        "readonly": True,
    }
