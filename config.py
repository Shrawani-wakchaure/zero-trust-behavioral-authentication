"""
Configuration parameters for AegisTrust Zero-Trust Behavioral Authentication.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Risk Thresholds (0 - 100)
RISK_THRESHOLD_ALLOW = 35        # Below 35: Normal activity
RISK_THRESHOLD_CHALLENGE = 65    # 35 to 65: Step-up authentication required (MFA prompt, throttling)
# Above 65: Revoke session, lock account, quarantine IP

# Telemetry features analyzed by ML model
CORE_FEATURES = [
    "hour_of_day",
    "api_calls_per_min",
    "data_download_mb",
    "geo_velocity_kmh",
    "sensitive_endpoint_ratio",
    "failed_auth_attempts",
    "session_duration_min",
    "request_entropy"
]

# Sensitive endpoints in Public Sector / Healthcare Infrastructure
SENSITIVE_ENDPOINTS = [
    "/api/v1/registry/export-bulk",
    "/api/v1/citizens/ssn-lookup",
    "/api/v1/patient-records/pii-dump",
    "/api/v1/welfare-grants/disburse-all",
    "/api/v1/admin/privilege-escalation",
    "/api/v1/audit-logs/delete"
]

BENIGN_ENDPOINTS = [
    "/api/v1/dashboard/metrics",
    "/api/v1/system/health",
    "/api/v1/registry/citizen-status",
    "/api/v1/reports/monthly-summary",
    "/api/v1/admin/user-list",
    "/api/v1/config/view"
]

# Known Admin Office Coordinates (e.g. Washington DC Agency HQ)
BASE_OFFICE_COORDS = {"lat": 38.8951, "lon": -77.0364, "city": "Washington, D.C., USA"}

# Model Hyperparameters
ISOLATION_FOREST_PARAMS = {
    "n_estimators": 150,
    "contamination": 0.04,
    "random_state": 42,
    "max_samples": "auto"
}

SVM_PARAMS = {
    "kernel": "rbf",
    "gamma": "scale",
    "nu": 0.04
}
