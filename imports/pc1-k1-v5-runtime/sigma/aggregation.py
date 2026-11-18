from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Iterable

from .contracts import AgentVote, Domain, DomainAggregate, Layer, Severity


def _hash_ref(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _common(votes: list[AgentVote]):
    contradictions = []
    unknowns = []
    risk_flags = []
    evidence_refs = []
    for v in votes:
        contradictions.extend(v.contradictions or [])
        unknowns.extend(v.unknowns or [])
        risk_flags.extend(v.risk_flags or [])
        evidence_refs.append(_hash_ref(f"{v.agent_id}:{v.claim}:{v.proposed_verdict}"))
    # Déduplication déterministe avec préservation de l'ordre d'apparition
    contradictions = list(dict.fromkeys(contradictions))
    unknowns = list(dict.fromkeys(unknowns))
    risk_flags = list(dict.fromkeys(risk_flags))
    evidence_refs = list(dict.fromkeys(evidence_refs))
    return contradictions, unknowns, risk_flags, evidence_refs


def _calibrate_confidence(counts: dict[str, int], conf_sums: dict[str, float], winning_v: str, total_votes: int) -> float:
    """Calibre la confiance agrégée pour éviter toute saturation artificielle (Cas A).
    
    La confiance agrégée dérive de la moyenne des confiances des agents concordants,
    modulée par le ratio de consensus. Elle ne peut jamais dépasser la moyenne des agents
    concordants et ne sature jamais artificiellement à 0.98 pour des agents faibles.
    """
    if total_votes <= 0:
        return 0.50
    win_count = counts.get(winning_v, 0)
    if win_count <= 0:
        return 0.50
    mean_conf = conf_sums[winning_v] / win_count
    consensus_ratio = win_count / total_votes
    calibrated = mean_conf * consensus_ratio
    return round(max(0.0, min(0.98, calibrated)), 2)


def aggregate_trading(votes: Iterable[AgentVote]) -> DomainAggregate:
    votes = list(votes)
    if not votes:
        return DomainAggregate(Domain.TRADING, "REVIEW", 0.0, [], ["NO_VOTES"], [], [])

    scores = defaultdict(float)
    counts = defaultdict(int)
    conf_sums = defaultdict(float)

    # Détection et dé-corrélation des agents partageant la même source de données (Cas B)
    seen_sources = defaultdict(list)
    for v in votes:
        src = getattr(v, "measure_provenance", None) or f"{v.agent_id}:{getattr(v, 'claim', '')}"
        seen_sources[src].append(v)

    for src, vlist in seen_sources.items():
        effective_w = 1.0 / len(vlist)
        for v in vlist:
            c = max(0.0, min(1.0, float(getattr(v, "confidence", 0.0))))
            v_name = str(getattr(v, "proposed_verdict", "HOLD")).upper()
            scores[v_name] += c * effective_w
            counts[v_name] += 1
            conf_sums[v_name] += c

    buy = scores.get("BUY", 0.0)
    sell = scores.get("SELL", 0.0)
    hold = scores.get("HOLD", 0.0)

    if buy > max(sell, hold):
        market_verdict = "EXECUTE_LONG"
        winning_v = "BUY"
    elif sell > max(buy, hold):
        market_verdict = "EXECUTE_SHORT"
        winning_v = "SELL"
    else:
        market_verdict = "REVIEW"
        winning_v = "HOLD"

    confidence = _calibrate_confidence(counts, conf_sums, winning_v, len(votes))
    contradictions, unknowns, risk_flags, evidence_refs = _common(votes)
    extra_metrics = {"buy_score": buy, "sell_score": sell, "hold_score": hold, "proof_ready": True, "deterministic": True}
    return DomainAggregate(Domain.TRADING, market_verdict, confidence, contradictions, unknowns, risk_flags, evidence_refs, agent_votes=votes, extra_metrics=extra_metrics)


def aggregate_bank(votes: Iterable[AgentVote]) -> DomainAggregate:
    votes = list(votes)
    if not votes:
        return DomainAggregate(Domain.BANK, "ANALYZE", 0.0, [], ["NO_VOTES"], [], [])

    scores = defaultdict(float)
    counts = defaultdict(int)
    conf_sums = defaultdict(float)

    seen_sources = defaultdict(list)
    for v in votes:
        src = getattr(v, "measure_provenance", None) or f"{v.agent_id}:{getattr(v, 'claim', '')}"
        seen_sources[src].append(v)

    for src, vlist in seen_sources.items():
        effective_w = 1.0 / len(vlist)
        for v in vlist:
            c = max(0.0, min(1.0, float(getattr(v, "confidence", 0.0))))
            v_name = str(getattr(v, "proposed_verdict", "HOLD")).upper()
            scores[v_name] += c * effective_w
            counts[v_name] += 1
            conf_sums[v_name] += c

    auth = scores.get("AUTHORIZE", 0.0)
    analyze = scores.get("ANALYZE", 0.0)
    block = scores.get("BLOCK", 0.0)

    if block > max(auth, analyze):
        market_verdict = "BLOCK"
        winning_v = "BLOCK"
    elif auth > analyze:
        market_verdict = "AUTHORIZE"
        winning_v = "AUTHORIZE"
    else:
        market_verdict = "ANALYZE"
        winning_v = "ANALYZE"

    confidence = _calibrate_confidence(counts, conf_sums, winning_v, len(votes))
    contradictions, unknowns, risk_flags, evidence_refs = _common(votes)
    extra_metrics = {"authorize_score": auth, "analyze_score": analyze, "block_score": block, "proof_ready": True, "deterministic": True}
    return DomainAggregate(Domain.BANK, market_verdict, confidence, contradictions, unknowns, risk_flags, evidence_refs, agent_votes=votes, extra_metrics=extra_metrics)


def aggregate_ecom(votes: Iterable[AgentVote]) -> DomainAggregate:
    votes = list(votes)
    if not votes:
        return DomainAggregate(Domain.ECOM, "WAIT", 0.0, [], ["NO_VOTES"], [], [])

    scores = defaultdict(float)
    counts = defaultdict(int)
    conf_sums = defaultdict(float)

    seen_sources = defaultdict(list)
    for v in votes:
        src = getattr(v, "measure_provenance", None) or f"{v.agent_id}:{getattr(v, 'claim', '')}"
        seen_sources[src].append(v)

    for src, vlist in seen_sources.items():
        effective_w = 1.0 / len(vlist)
        for v in vlist:
            c = max(0.0, min(1.0, float(getattr(v, "confidence", 0.0))))
            v_name = str(getattr(v, "proposed_verdict", "HOLD")).upper()
            scores[v_name] += c * effective_w
            counts[v_name] += 1
            conf_sums[v_name] += c

    pay = scores.get("PAY", 0.0)
    wait = scores.get("WAIT", 0.0)
    refuse = scores.get("REFUSE", 0.0)

    if refuse > max(pay, wait):
        market_verdict = "REFUSE"
        winning_v = "REFUSE"
    elif pay > wait:
        market_verdict = "PAY"
        winning_v = "PAY"
    else:
        market_verdict = "WAIT"
        winning_v = "WAIT"

    confidence = _calibrate_confidence(counts, conf_sums, winning_v, len(votes))
    contradictions, unknowns, risk_flags, evidence_refs = _common(votes)
    extra_metrics = {"pay_score": pay, "wait_score": wait, "refuse_score": refuse, "proof_ready": True, "deterministic": True}
    return DomainAggregate(Domain.ECOM, market_verdict, confidence, contradictions, unknowns, risk_flags, evidence_refs, agent_votes=votes, extra_metrics=extra_metrics)


def aggregate_gps_defense_aviation(votes: Iterable[AgentVote]) -> DomainAggregate:
    votes = list(votes)
    if not votes:
        return DomainAggregate(Domain.GPS_DEFENSE_AVIATION, "ABORT_TRAJECTORY", 0.0, [], ["NO_VOTES"], [], [])

    scores = defaultdict(float)
    counts = defaultdict(int)
    conf_sums = defaultdict(float)

    seen_sources = defaultdict(list)
    for v in votes:
        src = getattr(v, "measure_provenance", None) or f"{v.agent_id}:{getattr(v, 'claim', '')}"
        seen_sources[src].append(v)

    for src, vlist in seen_sources.items():
        effective_w = 1.0 / len(vlist)
        for v in vlist:
            c = max(0.0, min(1.0, float(getattr(v, "confidence", 0.0))))
            v_name = str(getattr(v, "proposed_verdict", "RECALC_TRAJECTORY")).upper()
            scores[v_name] += c * effective_w
            counts[v_name] += 1
            conf_sums[v_name] += c

    valid = scores.get("TRAJECTORY_VALID", 0.0)
    recalc = scores.get("RECALC_TRAJECTORY", 0.0)
    degraded = scores.get("DEGRADED_NAVIGATION", 0.0)
    abort = scores.get("ABORT_TRAJECTORY", 0.0)

    contradictions, unknowns, risk_flags, evidence_refs = _common(votes)

    truth_penalty = 0.0
    if any(u in unknowns for u in ["GPS_MISSING", "INERTIAL_MISSING", "RADIO_MISSING"]):
        truth_penalty += 0.35
    if "TIME_SKEW_ACTIVE" in unknowns or "TEMPORAL_ALIGNMENT_UNCERTAIN" in unknowns:
        truth_penalty += 0.22
    if "BROWNOUT_ACTIVE" in unknowns or "POWER_STATE_UNCERTAIN" in unknowns:
        truth_penalty += 0.28
    if "SOURCE_CONFLICT" in contradictions:
        truth_penalty += 0.45
    if "ATTESTATION_NOT_READY" in unknowns:
        truth_penalty += 0.10

    if "SOURCE_CONFLICT" in contradictions or abort > max(valid, recalc, degraded):
        market_verdict = "ABORT_TRAJECTORY"
        winning_v = "ABORT_TRAJECTORY"
    elif "BROWNOUT" in risk_flags or "BROWNOUT_ACTIVE" in unknowns or "POWER_STATE_UNCERTAIN" in unknowns:
        market_verdict = "DEGRADED_NAVIGATION"
        winning_v = "DEGRADED_NAVIGATION"
    elif (
        "TIME_SKEW" in risk_flags
        or "TIME_SKEW_ACTIVE" in unknowns
        or "TEMPORAL_ALIGNMENT_UNCERTAIN" in unknowns
        or any(u in unknowns for u in ["GPS_MISSING", "INERTIAL_MISSING", "RADIO_MISSING"])
        or recalc > max(valid, degraded)
    ):
        market_verdict = "RECALC_TRAJECTORY"
        winning_v = "RECALC_TRAJECTORY"
    else:
        market_verdict = "TRAJECTORY_VALID"
        winning_v = "TRAJECTORY_VALID"

    confidence = _calibrate_confidence(counts, conf_sums, winning_v, len(votes))
    sigma_score = confidence
    truth_score = max(0.0, min(1.0, confidence - truth_penalty))
    mismatch_gap = abs(sigma_score - truth_score)

    extra_metrics = {
        "trajectory_valid_score": valid,
        "recalc_score": recalc,
        "degraded_score": degraded,
        "abort_score": abort,
        "truth_score": truth_score,
        "sigma_score": sigma_score,
        "mismatch_gap": mismatch_gap,
        "proof_ready": True,
        "deterministic": True,
    }

    return DomainAggregate(
        Domain.GPS_DEFENSE_AVIATION,
        market_verdict,
        confidence,
        contradictions,
        unknowns,
        risk_flags,
        evidence_refs,
        agent_votes=votes,
        extra_metrics=extra_metrics,
    )


def aggregate_tooling_build(votes: Iterable[AgentVote]) -> DomainAggregate:
    """Agrégation formelle pour le domaine tooling_build (aggregate4 : 4 agents requis).

    Confiance non biaisée : moyenne arithmétique des confiances (sans surpondération arbitraire
    créant une fausse autorité de couche). L'autorité finale demeure KX108_ONLY.
    """
    votes = list(votes)
    if not votes:
        return DomainAggregate(Domain.TOOLING_BUILD, "BUILD_BLOCK", 0.0, [], ["NO_VOTES"], [], [])
    contradictions, unknowns, risk_flags, evidence_refs = _common(votes)

    c_vals = [max(0.0, min(1.0, float(getattr(v, "confidence", 0.5)))) for v in votes]
    confidence = round(min(0.98, sum(c_vals) / len(c_vals) if c_vals else 0.5), 2)

    if contradictions:
        market_verdict = "BUILD_BLOCK"
    elif unknowns:
        market_verdict = "BUILD_HOLD"
    else:
        market_verdict = "READY_FOR_COMMIT_REVIEW"

    extra_metrics = {
        "vote_count": len(votes),
        "contradiction_count": len(contradictions),
        "unknown_count": len(unknowns),
        "risk_flag_count": len(risk_flags),
        "proof_ready": True,
        "deterministic": True,
        "decision_authority": "KX108_ONLY",
        "emits_act": False,
    }

    return DomainAggregate(
        Domain.TOOLING_BUILD,
        market_verdict,
        confidence,
        contradictions,
        unknowns,
        risk_flags,
        evidence_refs,
        agent_votes=votes,
        extra_metrics=extra_metrics,
    )
