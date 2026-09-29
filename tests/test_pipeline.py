"""
Unit and Integration Tests for AegisTrust Zero-Trust Pipeline.
"""
import pytest
import numpy as np
import pandas as pd
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.data_generator import TelemetryGenerator, haversine_distance
from core.feature_pipeline import FeaturePipeline
from core.anomaly_detector import BehavioralAnomalyDetector
from core.risk_engine import RiskEngine
from core.policy_enforcer import PolicyEnforcer
from simulation.attack_scenarios import PRESET_SCENARIOS


def test_haversine_distance():
    # DC to NYC is ~330 km
    dc_lat, dc_lon = 38.8951, -77.0364
    nyc_lat, nyc_lon = 40.7128, -74.0060
    dist = haversine_distance(dc_lat, dc_lon, nyc_lat, nyc_lon)
    assert 300 < dist < 360


def test_telemetry_generator():
    generator = TelemetryGenerator(seed=123)
    df = generator.generate_baseline(n_samples=50)
    assert len(df) == 50
    assert "hour_of_day" in df.columns
    assert "data_download_mb" in df.columns

    attack = generator.generate_attack("mass_exfiltration")
    assert attack["is_attack"] == 1
    assert attack["data_download_mb"] > 1000.0


def test_pipeline_and_detector():
    pipeline = FeaturePipeline()
    pipeline.load()
    assert pipeline.is_fitted

    detector = BehavioralAnomalyDetector()
    detector.load()
    assert detector.is_trained

    # Normal sample
    normal_record = {
        "hour_of_day": 13.0,
        "api_calls_per_min": 20.0,
        "data_download_mb": 10.0,
        "geo_velocity_kmh": 0.0,
        "sensitive_endpoint_ratio": 0.05,
        "failed_auth_attempts": 0,
        "session_duration_min": 60.0,
        "request_entropy": 0.45
    }
    x_norm = pipeline.transform(normal_record)
    _, norm_intensity = detector.predict_anomaly(x_norm)

    # Attack sample
    attack_record = PRESET_SCENARIOS["mass_exfiltration"]["telemetry"]
    x_atk = pipeline.transform(attack_record)
    _, atk_intensity = detector.predict_anomaly(x_atk)

    assert atk_intensity[0] > norm_intensity[0]


def test_risk_engine_policies():
    risk_engine = RiskEngine()

    # Normal profile
    norm_res = risk_engine.calculate_risk({"hour_of_day": 12.0, "data_download_mb": 15.0}, anomaly_intensity=0.1)
    assert norm_res["action"] == "ALLOW"
    assert norm_res["risk_score"] < 35.0

    # Critical breach (Mass download + Impossible travel)
    crit_telemetry = {
        "geo_velocity_kmh": 25000.0,
        "data_download_mb": 4500.0,
        "hour_of_day": 3.0,
        "sensitive_endpoint_ratio": 0.9,
        "failed_auth_attempts": 3
    }
    crit_res = risk_engine.calculate_risk(crit_telemetry, anomaly_intensity=0.95)
    assert crit_res["action"] == "REVOKE"
    assert crit_res["risk_score"] >= 65.0
    assert len(crit_res["active_triggers"]) >= 3


def test_policy_enforcer_and_step_up():
    enforcer = PolicyEnforcer()

    # Test challenge workflow
    sess_telemetry = {
        "session_id": "sess_test_challenge",
        "user_id": "admin_clara",
        "asn": "AS701",
        "city": "Washington, D.C."
    }
    risk_res = {
        "risk_score": 52.0,
        "risk_tier": "MEDIUM",
        "action": "CHALLENGE",
        "active_triggers": ["Suspicious endpoint exploration"]
    }
    record = enforcer.register_or_update_session(sess_telemetry, risk_res)
    assert record["state"] == "CHALLENGED"

    # Admin answers step-up OTP challenge
    otp_fail = enforcer.submit_step_up_mfa("sess_test_challenge", "wrong")
    assert not otp_fail["success"]

    otp_success = enforcer.submit_step_up_mfa("sess_test_challenge", "123456")
    assert otp_success["success"]
    assert enforcer.active_sessions["sess_test_challenge"]["state"] == "ACTIVE"


if __name__ == "__main__":
    test_haversine_distance()
    test_telemetry_generator()
    test_pipeline_and_detector()
    test_risk_engine_policies()
    test_policy_enforcer_and_step_up()
    print("All unit tests passed successfully!")
