from __future__ import annotations

from typing import Any
from ..base import BaseAgent
from ..contracts import AgentVote, Domain, EcomState, Layer, Severity
from periphery.ecom_attestation import get_or_verify_state_attestation


def _is_qualified_num(val: Any) -> bool:
    """A numeric measure is qualified if present, not a SmartAttribute list, and int/float."""
    if val is None or isinstance(val, list):
        return False
    return isinstance(val, (int, float)) and not isinstance(val, bool)


def _is_qualified_bool(val: Any) -> bool:
    """A boolean measure is qualified if strictly a boolean and not a SmartAttribute list."""
    if val is None or isinstance(val, list):
        return False
    return isinstance(val, bool)


def _unverified_vote(
    agent_id: str,
    layer: Layer,
    metric_name: str,
    att_status: str,
    age_s: float | None,
    observed_val: Any = None,
) -> AgentVote:
    """Helper for present but unverified / stale / invalid upstream attestation status."""
    unknown_code = "PRESENT_UNVERIFIED_SOURCE" if att_status == "PRESENT_UNVERIFIED" else f"{att_status}_MEASURE"
    return AgentVote(
        agent_id=agent_id,
        domain=Domain.ECOM,
        layer=layer,
        claim=f"{metric_name}=UNVERIFIED ({att_status})",
        confidence=0.4,
        severity_hint=Severity.S1,
        proposed_verdict="WAIT",
        unknowns=[unknown_code],
        measure_provenance=f"ecom.unverified.{metric_name}",
        measure_valid=False,
        measure_age_s=age_s,
        observed_value=observed_val,
    )


class TrafficQualityAgent(BaseAgent):
    agent_id = "TrafficQualityAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "traffic_quality", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.OBSERVATION,
                "traffic_quality=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_TRAFFIC_QUALITY"],
                measure_provenance="ecom.traffic", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.OBSERVATION, "traffic", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "PAY" if f_val > 0.7 else "WAIT" if f_val > 0.4 else "REFUSE"
        sev = Severity.S2 if verdict == "REFUSE" else Severity.S1
        conf = f_val if verdict == "PAY" else (0.5 if verdict == "WAIT" else max(0.0, 1.0 - f_val))
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.OBSERVATION,
            f"traffic_quality={f_val:.2f}", conf, sev,
            proposed_verdict=verdict,
            measure_provenance=f"ecom.{source_id}.traffic", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class BasketIntentAgent(BaseAgent):
    agent_id = "BasketIntentAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "basket_intent_score", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.OBSERVATION,
                "basket_intent=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_BASKET_INTENT"],
                measure_provenance="ecom.basket", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.OBSERVATION, "basket", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "PAY" if f_val > 0.7 else "WAIT" if f_val > 0.4 else "REFUSE"
        conf = f_val if verdict == "PAY" else (0.5 if verdict == "WAIT" else max(0.0, 1.0 - f_val))
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.OBSERVATION,
            f"basket_intent={f_val:.2f}", conf, Severity.S1,
            proposed_verdict=verdict,
            measure_provenance=f"ecom.{source_id}.basket", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class OfferHealthAgent(BaseAgent):
    agent_id = "OfferHealthAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        stock = getattr(state, "stock_ok", None)
        margin = getattr(state, "margin_rate", None)
        q_stock = _is_qualified_bool(stock)
        q_margin = _is_qualified_num(margin)
        if not q_stock or not q_margin:
            unknowns = []
            if not q_stock:
                unknowns.append("UNMEASURED_STOCK")
            if not q_margin:
                unknowns.append("UNMEASURED_MARGIN")
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.OBSERVATION,
                f"stock_ok={'QUAL' if q_stock else 'UNMEASURED'}, margin={'QUAL' if q_margin else 'UNMEASURED'}",
                0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=unknowns,
                measure_provenance="ecom.inventory", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        b_stock = bool(stock)
        f_margin = float(margin)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(
                self.agent_id, Layer.OBSERVATION, "inventory", att_status, age_s,
                {"stock_ok": b_stock, "margin_rate": f_margin},
            )

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "REFUSE" if not b_stock or f_margin < 0 else "WAIT" if f_margin < 0.1 else "PAY"
        sev = Severity.S3 if verdict == "REFUSE" else Severity.S2 if verdict == "WAIT" else Severity.S1
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.OBSERVATION,
            f"stock_ok={b_stock}, margin={f_margin:.2f}", 0.8, sev,
            proposed_verdict=verdict,
            measure_provenance=f"ecom.{source_id}.inventory", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0,
            observed_value={"stock_ok": b_stock, "margin_rate": f_margin},
        )


class CustomerTrustAgent(BaseAgent):
    agent_id = "CustomerTrustAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "customer_trust", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.OBSERVATION,
                "customer_trust=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_CUSTOMER_TRUST"],
                measure_provenance="ecom.trust", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.OBSERVATION, "trust", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "PAY" if f_val > 0.7 else "WAIT" if f_val > 0.4 else "REFUSE"
        conf = f_val if verdict == "PAY" else (0.5 if verdict == "WAIT" else max(0.0, 1.0 - f_val))
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.OBSERVATION,
            f"customer_trust={f_val:.2f}", conf, Severity.S1,
            proposed_verdict=verdict,
            measure_provenance=f"ecom.{source_id}.trust", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class ConversionReadinessAgent(BaseAgent):
    agent_id = "ConversionReadinessAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "conversion_readiness", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.INTERPRETATION,
                "conversion_readiness=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_CONVERSION_READINESS"],
                measure_provenance="ecom.conversion", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.INTERPRETATION, "conversion", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "PAY" if f_val > 0.75 else "WAIT" if f_val > 0.45 else "REFUSE"
        conf = f_val if verdict == "PAY" else (0.5 if verdict == "WAIT" else max(0.0, 1.0 - f_val))
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.INTERPRETATION,
            f"conversion_readiness={f_val:.2f}", conf, Severity.S1,
            proposed_verdict=verdict,
            measure_provenance=f"ecom.{source_id}.conversion", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class MarginProtectionAgent(BaseAgent):
    agent_id = "MarginProtectionAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "margin_rate", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.INTERPRETATION,
                "margin_rate=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_MARGIN"],
                measure_provenance="ecom.margin", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.INTERPRETATION, "margin", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "REFUSE" if f_val < 0.05 else "WAIT" if f_val < 0.15 else "PAY"
        sev = Severity.S3 if verdict == "REFUSE" else Severity.S2 if verdict == "WAIT" else Severity.S1
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.INTERPRETATION,
            f"margin_rate={f_val:.2f}", min(1.0, max(0.0, 1.0 - f_val)), sev,
            proposed_verdict=verdict,
            risk_flags=["LOW_MARGIN"] if verdict != "PAY" else [],
            measure_provenance=f"ecom.{source_id}.margin", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class ROASRealityAgent(BaseAgent):
    agent_id = "ROASRealityAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "roas", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.INTERPRETATION,
                "roas=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_ROAS"],
                measure_provenance="ecom.roas", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.INTERPRETATION, "roas", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "PAY" if f_val > 2.0 else "WAIT" if f_val > 1.0 else "REFUSE"
        sev = Severity.S2 if verdict == "REFUSE" else Severity.S1
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.INTERPRETATION,
            f"roas={f_val:.2f}", min(1.0, f_val / 4.0), sev,
            proposed_verdict=verdict,
            risk_flags=["LOW_ROAS"] if verdict == "REFUSE" else [],
            measure_provenance=f"ecom.{source_id}.roas", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class FulfillmentRiskAgent(BaseAgent):
    agent_id = "FulfillmentRiskAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "fulfillment_risk", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.INTERPRETATION,
                "fulfillment_risk=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_FULFILLMENT_RISK"],
                measure_provenance="ecom.fulfillment", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.INTERPRETATION, "fulfillment", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "REFUSE" if f_val > 0.75 else "WAIT" if f_val > 0.45 else "PAY"
        sev = Severity.S3 if verdict == "REFUSE" else Severity.S2 if verdict == "WAIT" else Severity.S1
        conf = f_val if verdict == "REFUSE" else (0.5 if verdict == "WAIT" else max(0.0, 1.0 - f_val))
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.INTERPRETATION,
            f"fulfillment_risk={f_val:.2f}", conf, sev,
            proposed_verdict=verdict,
            measure_provenance=f"ecom.{source_id}.fulfillment", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class IntentConflictAgent(BaseAgent):
    agent_id = "IntentConflictAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "intent_conflict_score", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.CONTRADICTION,
                "intent_conflict=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_INTENT_CONFLICT"],
                measure_provenance="ecom.intent", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.CONTRADICTION, "intent", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "WAIT" if f_val > 0.4 else "PAY"
        sev = Severity.S2 if verdict == "WAIT" else Severity.S1
        conf = f_val if verdict == "WAIT" else max(0.0, 1.0 - f_val)
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.CONTRADICTION,
            f"intent_conflict={f_val:.2f}", conf, sev,
            proposed_verdict=verdict,
            contradictions=["INTENT_CONFLICT"] if verdict == "WAIT" else [],
            measure_provenance=f"ecom.{source_id}.intent", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class CheckoutFrictionAgent(BaseAgent):
    agent_id = "CheckoutFrictionAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "checkout_friction_score", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.CONTRADICTION,
                "checkout_friction=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_CHECKOUT_FRICTION"],
                measure_provenance="ecom.checkout", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.CONTRADICTION, "checkout", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "WAIT" if f_val > 0.45 else "PAY"
        sev = Severity.S2 if verdict == "WAIT" else Severity.S1
        conf = f_val if verdict == "WAIT" else max(0.0, 1.0 - f_val)
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.CONTRADICTION,
            f"checkout_friction={f_val:.2f}", conf, sev,
            proposed_verdict=verdict,
            contradictions=["CHECKOUT_FRICTION"] if verdict == "WAIT" else [],
            measure_provenance=f"ecom.{source_id}.checkout", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class MerchantPolicyAgent(BaseAgent):
    agent_id = "MerchantPolicyAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        val = getattr(state, "merchant_policy_score", None)
        if not _is_qualified_num(val):
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.CONTRADICTION,
                "merchant_policy=UNMEASURED", 0.4, Severity.S1,
                proposed_verdict="WAIT", unknowns=["UNMEASURED_MERCHANT_POLICY"],
                risk_flags=[],
                measure_provenance="ecom.merchant_policy", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_val = float(val)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(self.agent_id, Layer.CONTRADICTION, "merchant_policy", att_status, age_s, f_val)

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        verdict = "REFUSE" if f_val < 0.2 else "WAIT" if f_val < 0.5 else "PAY"
        sev = Severity.S3 if verdict == "REFUSE" else Severity.S2 if verdict == "WAIT" else Severity.S1
        claim_str = f"merchant_policy={f_val:.2f}" + (" (CRITICAL_VIOLATION)" if f_val < 0.2 else "")
        conf = max(0.0, 1.0 - f_val) if verdict == "REFUSE" else (0.5 if verdict == "WAIT" else f_val)
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.CONTRADICTION,
            claim_str, conf, sev,
            proposed_verdict=verdict,
            risk_flags=["MERCHANT_POLICY_CONSTRAINT"] if verdict == "REFUSE" else [],
            measure_provenance=f"ecom.{source_id}.merchant_policy", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0, observed_value=f_val,
        )


class EcomProofAgent(BaseAgent):
    agent_id = "EcomProofAgent"

    def evaluate(self, state: EcomState) -> AgentVote:
        comp = getattr(state, "x108_compliance_rate", None)
        order = getattr(state, "order_value", None)
        q_comp = _is_qualified_num(comp)
        q_order = _is_qualified_num(order)
        if not q_comp or not q_order:
            unknowns = []
            if not q_comp:
                unknowns.append("LOW_X108_COMPLIANCE")
            if not q_order:
                unknowns.append("NO_ORDER_VALUE")
            return AgentVote(
                self.agent_id, Domain.ECOM, Layer.PROOF,
                "ecom proof readiness (unmeasured)", 0.45, Severity.S2,
                proposed_verdict="WAIT", unknowns=unknowns,
                measure_provenance="ecom.proof", measure_valid=False,
                measure_age_s=None, observed_value=None,
            )

        f_comp = float(comp)
        f_order = float(order)
        att_status, _, age_s = get_or_verify_state_attestation(state)
        if att_status != "VERIFIED":
            return _unverified_vote(
                self.agent_id, Layer.PROOF, "proof", att_status, age_s,
                {"compliance": f_comp, "order_value": f_order},
            )

        source_id = getattr(getattr(state, "attestation", None), "source_id", "pos_gateway_alpha")
        unknowns = []
        if f_comp < 0.8:
            unknowns.append("LOW_X108_COMPLIANCE")
        if f_order <= 0:
            unknowns.append("NO_ORDER_VALUE")
        verdict = "WAIT" if unknowns else "PAY"
        return AgentVote(
            self.agent_id, Domain.ECOM, Layer.PROOF,
            "ecom proof readiness", 0.9 if not unknowns else 0.45,
            Severity.S0 if not unknowns else Severity.S2,
            proposed_verdict=verdict, unknowns=unknowns,
            measure_provenance=f"ecom.{source_id}.proof", measure_valid=True,
            measure_age_s=age_s if age_s is not None else 0.0,
            observed_value={"compliance": f_comp, "order_value": f_order},
        )


def build_ecom_agents() -> list[BaseAgent]:
    return [
        TrafficQualityAgent(),
        BasketIntentAgent(),
        OfferHealthAgent(),
        CustomerTrustAgent(),
        ConversionReadinessAgent(),
        MarginProtectionAgent(),
        ROASRealityAgent(),
        FulfillmentRiskAgent(),
        IntentConflictAgent(),
        CheckoutFrictionAgent(),
        MerchantPolicyAgent(),
        EcomProofAgent(),
    ]
