from __future__ import annotations

import math
from ..base import BaseAgent
from ..contracts import AgentVote, BankState, Domain, Layer, Severity


def _is_same_val(a, b):
    if a is b:
        return True
    if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
        return True
    return a == b


def qualify_bank_measure(state: BankState, field_name: str) -> tuple[bool, float | None, str | None]:
    """
    Qualification champ par champ d'une mesure bancaire (Contrat strict Obsidia P0).
    Retourne: (is_qualified: bool, value: float | None, reason_code: str | None)

    Règles strictes :
    1. Champ non explicite dans _explicit_fields -> UNMEASURED
    2. Modification post-initialisation détectée -> TAMPERED_POST_INIT
    3. Valeur est None -> MISSING
    4. Valeur est SmartAttribute ou liste -> UNMEASURED
    5. Valeur est booléen -> INVALID_TYPE
    6. Valeur non numérique ou non finie (NaN, Inf) -> INVALID_NUMERIC
    """
    explicit = getattr(state, "_explicit_fields", None)
    if explicit is not None and field_name not in explicit:
        return False, None, "UNMEASURED"

    val = getattr(state, field_name, None)
    if val is None:
        return False, None, "MISSING"

    initial_map = getattr(state, "_initial_telemetry", None)
    if initial_map is not None and field_name in initial_map:
        if not _is_same_val(initial_map[field_name], val):
            return False, None, "TAMPERED_POST_INIT"

    if isinstance(val, list) or type(val).__name__ == "SmartAttribute":
        return False, None, "UNMEASURED"

    if isinstance(val, bool):
        return False, None, "INVALID_TYPE"

    try:
        f_val = float(val)
        if not math.isfinite(f_val):
            return False, None, "INVALID_NUMERIC"
        return True, f_val, None
    except (ValueError, TypeError):
        return False, None, "INVALID_NUMERIC"


class TransactionContextAgent(BaseAgent):
    agent_id = "TransactionContextAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        unknown_keys = sorted(getattr(state, "_unknown_fields", frozenset()))
        if unknown_keys:
            unknowns = [f"UNDECLARED_FIELD_{k}" for k in unknown_keys]
            if not getattr(state, "channel", None):
                unknowns.append("UNKNOWN_CHANNEL")
            return AgentVote(
                self.agent_id, Domain.BANK, Layer.OBSERVATION,
                f"type={getattr(state, 'transaction_type', '')}, channel={getattr(state, 'channel', '')}, undeclared_fields={','.join(unknown_keys)}",
                0.0, Severity.S3,
                proposed_verdict="HOLD", unknowns=unknowns,
                rule_id="RULE_BANK_CONTEXT_ADVISORY", rule_version="1.0",
                measure_provenance="bank.core.context", measure_age_s=0.0, measure_valid=False,
                observed_value=unknown_keys, predicate_violated=True
            )
        unknowns = ["UNKNOWN_CHANNEL"] if not state.channel else []
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.OBSERVATION,
            f"type={state.transaction_type}, channel={state.channel}", 0.8, Severity.S1,
            proposed_verdict="ANALYZE", unknowns=unknowns,
            rule_id="RULE_BANK_CONTEXT_ADVISORY", rule_version="1.0",
            measure_provenance="bank.core.context", measure_age_s=0.0, measure_valid=True,
            observed_value=state.channel, predicate_violated=False
        )


class CounterpartyAgent(BaseAgent):
    agent_id = "CounterpartyAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        known_valid = state.counterparty_known and state.counterparty_age_days > 30
        verdict = "AUTHORIZE" if known_valid else "ANALYZE"
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.OBSERVATION,
            f"counterparty_known={state.counterparty_known}, age_days={state.counterparty_age_days}",
            0.75 if verdict=="AUTHORIZE" else 0.55, Severity.S1,
            proposed_verdict=verdict,
            rule_id="RULE_BANK_COUNTERPARTY", rule_version="1.0",
            measure_provenance="bank.kyc.registry", measure_age_s=0.0, measure_valid=True,
            observed_value=known_valid, predicate_violated=(not known_valid)
        )


class LiquidityExposureAgent(BaseAgent):
    agent_id = "LiquidityExposureAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        pressure = 1.0 if state.account_balance <= 0 else state.amount / max(state.account_balance, 1e-9)
        verdict = "BLOCK" if pressure > 0.9 else "ANALYZE" if pressure > 0.5 else "AUTHORIZE"
        sev = Severity.S3 if verdict=="BLOCK" else Severity.S2 if verdict=="ANALYZE" else Severity.S1
        conf = min(1.0, pressure) if verdict in ("BLOCK", "ANALYZE") else min(1.0, max(0.0, 1.0 - pressure))
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.OBSERVATION,
            f"liquidity_pressure={pressure:.2f}", conf, sev,
            proposed_verdict=verdict, risk_flags=["CASH_PRESSURE"] if pressure > 0.5 else [],
            rule_id="RULE_BANK_LIQUIDITY_EXPOSURE", rule_version="1.0",
            measure_provenance="bank.ledger.balance", measure_age_s=0.0, measure_valid=True,
            observed_value=pressure, predicate_violated=(pressure > 0.90)
        )


def _is_uninitialized_or_none(state: BankState, field_name: str) -> bool:
    is_qual, _, _ = qualify_bank_measure(state, field_name)
    return not is_qual


class BehaviorShiftAgent(BaseAgent):
    agent_id = "BehaviorShiftAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        is_qual, score, reason = qualify_bank_measure(state, "behavior_shift_score")
        if not is_qual:
            unknown = f"{reason}_BEHAVIOR_SHIFT" if reason != "MISSING" else "UNMEASURED_BEHAVIOR_SHIFT"
            return AgentVote(
                self.agent_id, Domain.BANK, Layer.OBSERVATION,
                f"unqualified behavior shift measure ({reason})", 0.0, Severity.S1,
                proposed_verdict="HOLD", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        verdict = "ANALYZE" if score > 0.5 else "AUTHORIZE"
        conf = score if verdict == "ANALYZE" else min(1.0, max(0.0, 1.0 - score))
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.OBSERVATION,
            f"behavior_shift={score:.2f}", conf,
            Severity.S2 if verdict=="ANALYZE" else Severity.S1, proposed_verdict=verdict,
            rule_id="RULE_BANK_BEHAVIOR_SHIFT", rule_version="1.0",
            measure_provenance="bank.ml.behavior", measure_age_s=0.0, measure_valid=True,
            observed_value=score, predicate_violated=(score > 0.50)
        )


class FraudPatternAgent(BaseAgent):
    agent_id = "FraudPatternAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        is_qual, score, reason = qualify_bank_measure(state, "fraud_score")
        if not is_qual:
            unknown = f"{reason}_FRAUD_SCORE" if reason != "MISSING" else "UNMEASURED_FRAUD_SCORE"
            return AgentVote(
                self.agent_id, Domain.BANK, Layer.INTERPRETATION,
                f"unqualified fraud score measure ({reason})", 0.0, Severity.S1,
                proposed_verdict="HOLD", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        verdict = "BLOCK" if score > 0.75 else "ANALYZE" if score > 0.45 else "AUTHORIZE"
        sev = Severity.S4 if verdict=="BLOCK" else Severity.S2 if verdict=="ANALYZE" else Severity.S1
        conf = score if verdict in ("BLOCK", "ANALYZE") else min(1.0, max(0.0, 1.0 - score))
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.INTERPRETATION,
            f"fraud_score={score:.2f}", conf, sev,
            proposed_verdict=verdict, risk_flags=["FRAUD_PATTERN"] if verdict!="AUTHORIZE" else [],
            rule_id="RULE_BANK_FRAUD_PATTERN", rule_version="1.0",
            measure_provenance="bank.fraud.detector", measure_age_s=0.0, measure_valid=True,
            observed_value=score, predicate_violated=(score > 0.75)
        )


class LimitPolicyAgent(BaseAgent):
    agent_id = "LimitPolicyAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        ratio = state.amount / max(state.policy_limit, 1e-9)
        verdict = "BLOCK" if ratio > 1.0 else "ANALYZE" if ratio > 0.8 else "AUTHORIZE"
        sev = Severity.S3 if verdict=="BLOCK" else Severity.S2 if verdict=="ANALYZE" else Severity.S1
        conf = min(1.0, ratio) if verdict in ("BLOCK", "ANALYZE") else min(1.0, max(0.0, 1.0 - ratio))
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.INTERPRETATION,
            f"limit_ratio={ratio:.2f}", conf, sev,
            proposed_verdict=verdict, risk_flags=["LIMIT_PRESSURE"] if ratio > 0.8 else [],
            rule_id="RULE_BANK_LIMIT_POLICY", rule_version="1.0",
            measure_provenance="bank.policy.engine", measure_age_s=0.0, measure_valid=True,
            observed_value=ratio, predicate_violated=(ratio > 1.0)
        )


class AffordabilityAgent(BaseAgent):
    agent_id = "AffordabilityAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        is_qual, score, reason = qualify_bank_measure(state, "affordability_score")
        if not is_qual:
            unknown = f"{reason}_AFFORDABILITY" if reason != "MISSING" else "UNMEASURED_AFFORDABILITY"
            return AgentVote(
                self.agent_id, Domain.BANK, Layer.INTERPRETATION,
                f"unqualified affordability measure ({reason})", 0.0, Severity.S3,
                proposed_verdict="HOLD", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        verdict = "AUTHORIZE" if score > 0.7 else "ANALYZE" if score > 0.4 else "BLOCK"
        sev = Severity.S3 if verdict=="BLOCK" else Severity.S2 if verdict=="ANALYZE" else Severity.S1
        conf = score if verdict == "AUTHORIZE" else min(1.0, max(0.0, 1.0 - score))
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.INTERPRETATION,
            f"affordability={score:.2f}", conf, sev,
            proposed_verdict=verdict,
            rule_id="RULE_BANK_AFFORDABILITY", rule_version="1.0",
            measure_provenance="bank.credit.scoring", measure_age_s=0.0, measure_valid=True,
            observed_value=score, predicate_violated=(score <= 0.40)
        )


class TemporalUrgencyAgent(BaseAgent):
    agent_id = "TemporalUrgencyAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        is_qual, score, reason = qualify_bank_measure(state, "urgency_score")
        if not is_qual:
            unknown = f"{reason}_URGENCY_SCORE" if reason != "MISSING" else "UNMEASURED_URGENCY_SCORE"
            return AgentVote(
                self.agent_id, Domain.BANK, Layer.INTERPRETATION,
                f"unqualified urgency score measure ({reason})", 0.0, Severity.S1,
                proposed_verdict="HOLD", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        verdict = "ANALYZE" if score > 0.75 else "AUTHORIZE"
        conf = score if verdict == "ANALYZE" else min(1.0, max(0.0, 1.0 - score))
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.INTERPRETATION,
            f"urgency={score:.2f}", conf,
            Severity.S2 if verdict=="ANALYZE" else Severity.S1, proposed_verdict=verdict,
            contradictions=["URGENT_BEHAVIOR"] if verdict=="ANALYZE" else [],
            rule_id="RULE_BANK_TEMPORAL_URGENCY", rule_version="1.0",
            measure_provenance="bank.session.urgency", measure_age_s=0.0, measure_valid=True,
            observed_value=score, predicate_violated=(score > 0.75)
        )


class IdentityMismatchAgent(BaseAgent):
    agent_id = "IdentityMismatchAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        q_id, s_id, r_id = qualify_bank_measure(state, "identity_mismatch_score")
        q_dev, s_dev, r_dev = qualify_bank_measure(state, "device_trust_score")
        if not q_id and not q_dev:
            return AgentVote(
                self.agent_id, Domain.BANK, Layer.CONTRADICTION,
                "unmeasured identity telemetry", 0.0, Severity.S1,
                proposed_verdict="HOLD", unknowns=["UNMEASURED_IDENTITY"],
                measure_valid=False,
                observed_value=None,
            )
        if not q_id or not q_dev:
            missing_tag = "UNMEASURED_IDENTITY_MISMATCH" if not q_id else "UNMEASURED_DEVICE_TRUST"
            return AgentVote(
                self.agent_id, Domain.BANK, Layer.CONTRADICTION,
                f"incomplete identity telemetry ({missing_tag})", 0.0, Severity.S2,
                proposed_verdict="HOLD", unknowns=[missing_tag],
                measure_valid=False,
                observed_value=None,
            )
        combined = max(s_id, 1.0 - s_dev)
        verdict = "BLOCK" if combined > 0.75 else "ANALYZE" if combined > 0.4 else "AUTHORIZE"
        sev = Severity.S4 if verdict=="BLOCK" else Severity.S2 if verdict=="ANALYZE" else Severity.S1
        conf = min(1.0, combined) if verdict in ("BLOCK", "ANALYZE") else min(1.0, max(0.0, 1.0 - combined))
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.CONTRADICTION,
            f"identity_mismatch={combined:.2f}", conf, sev,
            proposed_verdict=verdict,
            contradictions=["IDENTITY_CONTEXT_MISMATCH"] if combined > 0.4 else [],
            rule_id="RULE_BANK_IDENTITY_MISMATCH", rule_version="1.0",
            measure_provenance="bank.device.identity", measure_age_s=0.0, measure_valid=True,
            observed_value=combined, predicate_violated=(combined > 0.75)
        )


class NarrativeConflictAgent(BaseAgent):
    agent_id = "NarrativeConflictAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        is_qual, score, reason = qualify_bank_measure(state, "narrative_conflict_score")
        if not is_qual:
            unknown = f"{reason}_NARRATIVE_CONFLICT" if reason != "MISSING" else "UNMEASURED_NARRATIVE_CONFLICT"
            return AgentVote(
                self.agent_id, Domain.BANK, Layer.CONTRADICTION,
                f"unmeasured narrative conflict ({reason})", 0.0, Severity.S1,
                proposed_verdict="HOLD", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        verdict = "ANALYZE" if score > 0.45 else "AUTHORIZE"
        conf = score if verdict == "ANALYZE" else min(1.0, max(0.0, 1.0 - score))
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.CONTRADICTION,
            f"narrative_conflict={score:.2f}", conf,
            Severity.S2 if verdict=="ANALYZE" else Severity.S1, proposed_verdict=verdict,
            contradictions=["NARRATIVE_CONFLICT"] if verdict=="ANALYZE" else [],
            rule_id="RULE_BANK_NARRATIVE_CONFLICT", rule_version="1.0",
            measure_provenance="bank.nlp.intent", measure_age_s=0.0, measure_valid=True,
            observed_value=score, predicate_violated=(score > 0.45)
        )


class RecoveryPathAgent(BaseAgent):
    agent_id = "RecoveryPathAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        claim = "manual confirmation / delayed verification path available"
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.PROOF,
            claim, 0.85, Severity.S1, proposed_verdict="ANALYZE",
            rule_id="RULE_BANK_RECOVERY_PATH", rule_version="1.0",
            measure_provenance="bank.ops.recovery", measure_age_s=0.0, measure_valid=True,
            observed_value=claim, predicate_violated=False
        )


class BankProofAgent(BaseAgent):
    agent_id = "BankProofAgent"
    def evaluate(self, state: BankState) -> AgentVote:
        unknowns = []
        if state.elapsed_s < state.min_required_elapsed_s:
            unknowns.append("TEMPORAL_LOCK_NOT_MATURE")
        if state.recent_failed_attempts > 0:
            unknowns.append("RECENT_FAILED_ATTEMPTS")
        verdict = "ANALYZE" if unknowns else "AUTHORIZE"
        obs = {"elapsed_s": state.elapsed_s, "failed": state.recent_failed_attempts}
        return AgentVote(
            self.agent_id, Domain.BANK, Layer.PROOF,
            "bank proof readiness", 0.9 if not unknowns else 0.45,
            Severity.S2 if unknowns else Severity.S0, proposed_verdict=verdict, unknowns=unknowns,
            rule_id="RULE_BANK_PROOF", rule_version="1.0",
            measure_provenance="bank.audit.proofkit", measure_age_s=0.0, measure_valid=True,
            observed_value=obs, predicate_violated=bool(unknowns)
        )


def build_bank_agents() -> list[BaseAgent]:
    return [
        TransactionContextAgent(),
        CounterpartyAgent(),
        LiquidityExposureAgent(),
        BehaviorShiftAgent(),
        FraudPatternAgent(),
        LimitPolicyAgent(),
        AffordabilityAgent(),
        TemporalUrgencyAgent(),
        IdentityMismatchAgent(),
        NarrativeConflictAgent(),
        RecoveryPathAgent(),
        BankProofAgent(),
    ]
