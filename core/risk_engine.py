"""
Zero-Trust Risk Scoring Engine.
Synthesizes unsupervised ML anomaly intensity with zero-trust contextual telemetry
into a continuous Risk Score (0 to 100) and decides actionable security postures.
"""
from typing import Dict, Any
import numpy as np
from config import RISK_THRESHOLD_ALLOW, RISK_THRESHOLD_CHALLENGE


class RiskEngine:
    """Evaluates telemetry records and outputs risk scores, tier classifications, and threat narratives."""

    def __init__(self, allow_threshold: float = RISK_THRESHOLD_ALLOW,
                 challenge_threshold: float = RISK_THRESHOLD_CHALLENGE):
        self.allow_threshold = allow_threshold
        self.challenge_threshold = challenge_threshold

    def calculate_risk(self, telemetry: Dict[str, Any], anomaly_intensity: float) -> Dict[str, Any]:
        """
        Combines ML anomaly intensity with domain-specific heuristic indicators:
        - ML baseline component: 55% weight
        - Contextual rule penalties: 45% weight (Impossible travel, bulk exfiltration, off-hours access, auth failures)
        """
        # Base ML contribution (0 to 55 points)
        ml_score = anomaly_intensity * 55.0

        # Contextual heuristic points (0 to 45 points max)
        heuristics_points = 0.0
        active_triggers = []

        # 1. Impossible Travel violation (physically impossible speed between IP locations)
        geo_vel = float(telemetry.get("geo_velocity_kmh", 0.0))
        if geo_vel > 850.0:  # Faster than commercial jet flight
            heuristics_points += 30.0
            active_triggers.append(f"Impossible Travel Violation: {geo_vel:,.0f} km/h between IP hops")
        elif geo_vel > 300.0:
            heuristics_points += 15.0
            active_triggers.append(f"High-Speed Geolocation Hop: {geo_vel:,.0f} km/h")

        # 2. Massive Data Download Spike (Exfiltration indicator)
        download_mb = float(telemetry.get("data_download_mb", 0.0))
        if download_mb > 2000.0:
            heuristics_points += 25.0
            active_triggers.append(f"Critical Data Egress Spike: {download_mb:,.1f} MB downloaded")
        elif download_mb > 500.0:
            heuristics_points += 12.0
            active_triggers.append(f"Elevated Data Export: {download_mb:,.1f} MB downloaded")

        # 3. Off-Hours Sensitive Registry Access
        hour = float(telemetry.get("hour_of_day", 12.0))
        sensitive_ratio = float(telemetry.get("sensitive_endpoint_ratio", 0.0))
        if (hour < 5.0 or hour > 22.0) and sensitive_ratio > 0.6:
            heuristics_points += 20.0
            active_triggers.append(f"Unusual Off-Hours ({hour:.1f}h) bulk access to sensitive registry ({sensitive_ratio*100:.0f}%)")

        # 4. Authentication Failure Probes (401/403 fuzzing)
        failed_auth = int(telemetry.get("failed_auth_attempts", 0))
        if failed_auth >= 4:
            heuristics_points += 18.0
            active_triggers.append(f"Multiple Authentication Failures ({failed_auth} unauthorized attempts)")
        elif failed_auth >= 2:
            heuristics_points += 8.0
            active_triggers.append(f"Authentication Errors ({failed_auth} unauthorized attempts)")

        # 5. High Request Entropy (Endpoint scanning/fuzzing)
        entropy = float(telemetry.get("request_entropy", 0.0))
        if entropy > 0.85:
            heuristics_points += 10.0
            active_triggers.append("Anomalous API Endpoint Exploration (High Entropy)")

        # Cap heuristics and sum total risk
        heuristics_score = min(heuristics_points, 45.0)
        total_risk = min(max(ml_score + heuristics_score, 0.0), 100.0)

        # Policy decision
        if total_risk < self.allow_threshold:
            action = "ALLOW"
            risk_tier = "LOW"
            action_description = "Continuous Trust Maintained: Session verified normal."
            status_color = "#10B981"  # Emerald Green
        elif total_risk < self.challenge_threshold:
            action = "CHALLENGE"
            risk_tier = "MEDIUM"
            action_description = "Step-Up Required: Mandatory Multi-Factor (TOTP/Biometric) Challenge & API Throttling."
            status_color = "#F59E0B"  # Amber
        else:
            action = "REVOKE"
            risk_tier = "HIGH / CRITICAL"
            action_description = "Zero-Trust Enforcement: Immediate Session Revocation, IP Quarantine & Admin Lockout."
            status_color = "#EF4444"  # Red

        return {
            "risk_score": round(total_risk, 1),
            "risk_tier": risk_tier,
            "action": action,
            "action_description": action_description,
            "status_color": status_color,
            "ml_contribution": round(ml_score, 1),
            "heuristic_contribution": round(heuristics_score, 1),
            "active_triggers": active_triggers
        }
