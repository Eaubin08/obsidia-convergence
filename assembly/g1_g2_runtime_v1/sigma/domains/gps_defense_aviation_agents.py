from __future__ import annotations

import math
from ..base import BaseAgent
from ..contracts import AgentVote, Domain, Layer, Severity, GpsDefenseAviationState


def _is_same_val(a, b):
    if a is b:
        return True
    if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
        return True
    return a == b


def qualify_gps_measure(state: GpsDefenseAviationState, field_name: str) -> tuple[bool, float | None, str | None]:
    """
    Qualification champ par champ d'une mesure GPS / Aviation (Contrat strict Obsidia P0).
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


def _is_uninitialized_or_none(state: GpsDefenseAviationState, field_name: str) -> bool:
    is_qual, _, _ = qualify_gps_measure(state, field_name)
    return not is_qual


class SourceAvailabilityAgent(BaseAgent):
    agent_id = "SourceAvailabilityAgent"
    def evaluate(self, state: GpsDefenseAviationState) -> AgentVote:
        missing = []
        if not state.gps_available:
            missing.append("GPS_MISSING")
        if not state.inertial_available:
            missing.append("INERTIAL_MISSING")
        if not state.radio_available:
            missing.append("RADIO_MISSING")
        is_missing = bool(missing)
        obs = {"gps": state.gps_available, "inertial": state.inertial_available, "radio": state.radio_available}
        return AgentVote(
            agent_id=self.agent_id,
            domain=Domain.GPS_DEFENSE_AVIATION,
            layer=Layer.OBSERVATION,
            claim="source availability",
            confidence=0.95 if not is_missing else 0.35,
            severity_hint=Severity.S0 if not is_missing else Severity.S3,
            unknowns=missing,
            proposed_verdict="RECALC_TRAJECTORY" if is_missing else "TRAJECTORY_VALID",
            rule_id="RULE_GPS_SOURCE_AVAILABILITY",
            rule_version="1.0",
            measure_provenance="gnss.sensors.availability",
            measure_age_s=0.0,
            measure_valid=True,
            observed_value=obs,
            predicate_violated=is_missing,
        )


class TrajectoryIntegrityAgent(BaseAgent):
    agent_id = "TrajectoryIntegrityAgent"
    def evaluate(self, state: GpsDefenseAviationState) -> AgentVote:
        is_qual, drift, reason = qualify_gps_measure(state, "trajectory_drift_score")
        if not is_qual:
            unknown = f"{reason}_TRAJECTORY_DRIFT" if reason != "MISSING" else "UNMEASURED_TRAJECTORY_DRIFT"
            return AgentVote(
                self.agent_id, Domain.GPS_DEFENSE_AVIATION, Layer.PROOF,
                f"unmeasured trajectory drift ({reason})", 0.0, Severity.S2,
                proposed_verdict="RECALC_TRAJECTORY", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        risk = ["TRAJECTORY_DRIFT"] if drift >= 0.6 else []
        verdict = "ABORT_TRAJECTORY" if drift >= 0.85 else "DEGRADED_NAVIGATION" if drift >= 0.6 else "TRAJECTORY_VALID"
        conf = min(1.0, drift) if verdict in ("ABORT_TRAJECTORY", "DEGRADED_NAVIGATION") else min(1.0, max(0.0, 1.0 - drift))
        return AgentVote(
            self.agent_id,
            Domain.GPS_DEFENSE_AVIATION,
            Layer.PROOF,
            "trajectory integrity",
            conf,
            Severity.S4 if drift >= 0.85 else Severity.S2 if drift >= 0.6 else Severity.S0,
            risk_flags=risk,
            proposed_verdict=verdict,
            rule_id="INV_GPS_DRIFT_MAX",
            rule_version="1.0",
            measure_provenance="gnss.avionics.inertial",
            measure_age_s=0.0,
            measure_valid=True,
            observed_value=drift,
            predicate_violated=(drift >= 0.85),
        )


class SourceConflictAgent(BaseAgent):
    agent_id = "SourceConflictAgent"
    def evaluate(self, state: GpsDefenseAviationState) -> AgentVote:
        is_qual, conflict, reason = qualify_gps_measure(state, "source_conflict_score")
        if not is_qual:
            unknown = f"{reason}_SOURCE_CONFLICT" if reason != "MISSING" else "UNMEASURED_SOURCE_CONFLICT"
            return AgentVote(
                self.agent_id, Domain.GPS_DEFENSE_AVIATION, Layer.CONTRADICTION,
                f"unmeasured source conflict ({reason})", 0.0, Severity.S2,
                proposed_verdict="RECALC_TRAJECTORY", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        contradictions = ["SOURCE_CONFLICT"] if conflict >= 0.5 else []
        verdict = "ABORT_TRAJECTORY" if conflict >= 0.8 else "RECALC_TRAJECTORY" if conflict >= 0.5 else "TRAJECTORY_VALID"
        conf = min(1.0, conflict) if verdict in ("ABORT_TRAJECTORY", "RECALC_TRAJECTORY") else min(1.0, max(0.0, 1.0 - conflict))
        return AgentVote(
            self.agent_id,
            Domain.GPS_DEFENSE_AVIATION,
            Layer.CONTRADICTION,
            "source conflict",
            conf,
            Severity.S4 if conflict >= 0.8 else Severity.S2 if conflict >= 0.5 else Severity.S0,
            contradictions=contradictions,
            proposed_verdict=verdict,
            rule_id="RULE_GPS_SENSOR_FUSION",
            rule_version="1.0",
            measure_provenance="gnss.sensors.fusion",
            measure_age_s=0.0,
            measure_valid=True,
            observed_value=conflict,
            predicate_violated=(conflict >= 0.80),
        )


class TimeSkewAgent(BaseAgent):
    agent_id = "TimeSkewAgent"
    def evaluate(self, state: GpsDefenseAviationState) -> AgentVote:
        is_qual, skew, reason = qualify_gps_measure(state, "time_skew_score")
        if not is_qual:
            unknown = f"{reason}_TIME_SKEW" if reason != "MISSING" else "UNMEASURED_TIME_SKEW"
            return AgentVote(
                self.agent_id, Domain.GPS_DEFENSE_AVIATION, Layer.PROOF,
                f"unmeasured time skew ({reason})", 0.0, Severity.S2,
                proposed_verdict="RECALC_TRAJECTORY", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        risk = ["TIME_SKEW"] if skew >= 0.5 else []
        severe_unknowns = ["TIME_SKEW_ACTIVE", "TEMPORAL_ALIGNMENT_UNCERTAIN"] if skew >= 0.8 else []
        verdict = "ABORT_TRAJECTORY" if skew >= 0.9 else "RECALC_TRAJECTORY" if skew >= 0.5 else "TRAJECTORY_VALID"
        conf = min(1.0, skew) if verdict in ("ABORT_TRAJECTORY", "RECALC_TRAJECTORY") else min(1.0, max(0.0, 1.0 - skew))
        return AgentVote(
            self.agent_id,
            Domain.GPS_DEFENSE_AVIATION,
            Layer.PROOF,
            "time skew",
            conf,
            Severity.S4 if skew >= 0.9 else Severity.S3 if skew >= 0.8 else Severity.S2 if skew >= 0.5 else Severity.S0,
            risk_flags=risk,
            unknowns=severe_unknowns,
            proposed_verdict=verdict,
            rule_id="RULE_GPS_TEMPORAL_ALIGNMENT",
            rule_version="1.0",
            measure_provenance="gnss.timing.atomic_clock",
            measure_age_s=0.0,
            measure_valid=True,
            observed_value=skew,
            predicate_violated=(skew >= 0.90),
        )


class BrownoutAgent(BaseAgent):
    agent_id = "BrownoutAgent"
    def evaluate(self, state: GpsDefenseAviationState) -> AgentVote:
        is_qual, b, reason = qualify_gps_measure(state, "brownout_score")
        if not is_qual:
            unknown = f"{reason}_BROWNOUT" if reason != "MISSING" else "UNMEASURED_BROWNOUT"
            return AgentVote(
                self.agent_id, Domain.GPS_DEFENSE_AVIATION, Layer.PROOF,
                f"unmeasured brownout score ({reason})", 0.0, Severity.S2,
                proposed_verdict="RECALC_TRAJECTORY", unknowns=[unknown],
                measure_valid=False,
                observed_value=None,
            )
        risk = ["BROWNOUT"] if b >= 0.5 else []
        severe_unknowns = ["BROWNOUT_ACTIVE", "POWER_STATE_UNCERTAIN"] if b >= 0.8 else []
        verdict = "ABORT_TRAJECTORY" if b >= 0.9 else "DEGRADED_NAVIGATION" if b >= 0.5 else "TRAJECTORY_VALID"
        conf = min(1.0, b) if verdict in ("ABORT_TRAJECTORY", "DEGRADED_NAVIGATION") else min(1.0, max(0.0, 1.0 - b))
        return AgentVote(
            self.agent_id,
            Domain.GPS_DEFENSE_AVIATION,
            Layer.OBSERVATION,
            "brownout risk",
            conf,
            Severity.S4 if b >= 0.9 else Severity.S3 if b >= 0.8 else Severity.S2 if b >= 0.5 else Severity.S0,
            risk_flags=risk,
            unknowns=severe_unknowns,
            proposed_verdict=verdict,
            rule_id="RULE_GPS_BROWNOUT_DEFENSE",
            rule_version="1.0",
            measure_provenance="gnss.power.battery",
            measure_age_s=0.0,
            measure_valid=True,
            observed_value=b,
            predicate_violated=(b >= 0.90),
        )


class AttestationReadinessAgent(BaseAgent):
    agent_id = "GpsAttestationReadinessAgent"
    def evaluate(self, state: GpsDefenseAviationState) -> AgentVote:
        ready = state.attestation_ready and state.rollback_possible
        return AgentVote(
            self.agent_id,
            Domain.GPS_DEFENSE_AVIATION,
            Layer.PROOF,
            "attestation readiness",
            0.9 if ready else 0.4,
            Severity.S0 if ready else Severity.S2,
            unknowns=[] if ready else ["ATTESTATION_NOT_READY"],
            proposed_verdict="TRAJECTORY_VALID" if ready else "RECALC_TRAJECTORY",
            rule_id="RULE_GPS_HARDWARE_ATTESTATION",
            rule_version="1.0",
            measure_provenance="gnss.hardware.hsm",
            measure_age_s=0.0,
            measure_valid=True,
            observed_value=ready,
            predicate_violated=(not ready),
        )


def build_gps_defense_aviation_agents():
    return [
        SourceAvailabilityAgent(),
        TrajectoryIntegrityAgent(),
        SourceConflictAgent(),
        TimeSkewAgent(),
        BrownoutAgent(),
        AttestationReadinessAgent(),
    ]
