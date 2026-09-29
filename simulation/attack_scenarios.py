"""
Pre-configured Attack Scenarios and Workload Profiles for Zero-Trust Validation.
"""
from typing import Dict, Any, List
from core.data_generator import TelemetryGenerator

generator = TelemetryGenerator()

PRESET_SCENARIOS = {
    "normal_admin": {
        "title": "1. Normal Administrative Routine",
        "description": "DBA Clara performs routine morning database index checks and health queries from the official Washington D.C. network.",
        "icon": "🟢",
        "telemetry": generator.generate_attack("normal")
    },
    "mass_exfiltration": {
        "title": "2. Compromised Credentials: Mass PII Exfiltration",
        "description": "Stolen credentials used at 3:15 AM to trigger a 4.8 GB bulk download of citizen healthcare registries from an offshore IP.",
        "icon": "🚨",
        "telemetry": generator.generate_attack("mass_exfiltration")
    },
    "impossible_travel": {
        "title": "3. Session Cookie Hijack: Impossible Travel Anomaly",
        "description": "Session cookie stolen via Infostealer malware. The active session makes an API call from St. Petersburg just 5 minutes after Washington D.C.",
        "icon": "⚡",
        "telemetry": generator.generate_attack("impossible_travel")
    },
    "slow_and_low": {
        "title": "4. Advanced Persistent Threat (APT): Low & Slow Harvester",
        "description": "Adversary mimics low-frequency queries (18 req/min) off-hours via TOR to bypass classic volumetric firewalls while harvesting PII.",
        "icon": "🕵️",
        "telemetry": generator.generate_attack("slow_and_low_apt")
    },
    "privilege_recon": {
        "title": "5. Internal Reconnaissance & Privilege Escalation",
        "description": "Compromised admin token fuzzes non-standard sensitive endpoints late at night, racking up multiple 403 Forbidden responses.",
        "icon": "🔍",
        "telemetry": generator.generate_attack("privilege_escalation_recon")
    }
}


def get_scenario_names() -> List[str]:
    return list(PRESET_SCENARIOS.keys())


def get_scenario(key: str) -> Dict[str, Any]:
    return PRESET_SCENARIOS.get(key, PRESET_SCENARIOS["normal_admin"])
