"""
Synthetic Telemetry Generator for Public Cloud Infrastructure Administrative Sessions.
Simulates baseline behavioral telemetry and realistic attack vectors targeting government/healthcare clouds.
"""
import math
import random
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from config import BASE_OFFICE_COORDS, CORE_FEATURES, SENSITIVE_ENDPOINTS, BENIGN_ENDPOINTS


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate Great Circle distance between two points in km."""
    r = 6371.0  # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (math.sin(delta_phi / 2) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c


class TelemetryGenerator:
    """Generates realistic normal baseline and anomalous telemetry."""

    def __init__(self, seed: int = 42):
        np.random.seed(seed)
        random.seed(seed)
        self.admins = [
            {"user_id": "admin_clara_s", "role": "Senior Health Registry DBA", "base_city": "Washington, D.C."},
            {"user_id": "admin_marcus_k", "role": "Public Welfare Cloud Architect", "base_city": "Reston, VA"},
            {"user_id": "admin_elena_r", "role": "National Identity Ops Lead", "base_city": "Bethesda, MD"},
            {"user_id": "admin_dave_m", "role": "Healthcare Records Auditor", "base_city": "Arlington, VA"},
        ]
        self.locations = [
            {"city": "Washington, D.C.", "lat": 38.8951, "lon": -77.0364, "asn": "AS701-Verizon-Gov"},
            {"city": "Reston, VA", "lat": 38.9586, "lon": -77.3570, "asn": "AS701-Verizon-Gov"},
            {"city": "Bethesda, MD", "lat": 38.9847, "lon": -77.0947, "asn": "AS22773-Cox-Enterprise"},
            {"city": "Arlington, VA", "lat": 38.8799, "lon": -77.1068, "asn": "AS701-Verizon-Gov"}
        ]
        self.foreign_locations = [
            {"city": "Bucharest, Romania", "lat": 44.4268, "lon": 26.1025, "asn": "AS9009-M247-Hosting"},
            {"city": "St. Petersburg, Russia", "lat": 59.9311, "lon": 30.3609, "asn": "AS12389-Rostelecom"},
            {"city": "Lagos, Nigeria", "lat": 6.5244, "lon": 3.3792, "asn": "AS37108-Cobranet"},
            {"city": "Hong Kong", "lat": 22.3193, "lon": 114.1694, "asn": "AS45102-Alibaba-Cloud"}
        ]

    def generate_baseline(self, n_samples: int = 2500) -> pd.DataFrame:
        """
        Generates normal operational telemetry reflecting government cloud administrators.
        Admins work typical business hours (08:30 - 18:00), low data exports, low travel velocity,
        routine health endpoints, and zero or minimal failed authentications.
        """
        records = []
        base_time = datetime.now() - timedelta(days=60)

        for i in range(n_samples):
            admin = random.choice(self.admins)
            loc = random.choice(self.locations)

            # Hour: 80% between 8.5 and 18.0, 15% between 18.0 and 21.0, 5% on-call
            rand_bracket = random.random()
            if rand_bracket < 0.80:
                hour = np.clip(np.random.normal(13.0, 2.5), 8.5, 18.0)
            elif rand_bracket < 0.95:
                hour = np.clip(np.random.normal(19.5, 1.0), 18.0, 21.5)
            else:
                hour = np.random.uniform(0.0, 24.0)

            # API calls per minute: routine administrative work (5 - 40 calls/min)
            api_calls = float(np.clip(np.random.normal(22.0, 7.5), 3.0, 55.0))

            # Data download: small operational query logs & configs (1 to 45 MB)
            data_download_mb = float(np.clip(np.random.exponential(scale=12.0), 0.5, 65.0))

            # Geo velocity: stationary or commuting within metro area (0 to 45 km/h)
            geo_velocity_kmh = float(np.clip(np.random.exponential(scale=4.0), 0.0, 50.0))

            # Sensitive endpoint ratio: low in normal work (0.0 to 0.15)
            sensitive_ratio = float(np.clip(np.random.beta(a=1.2, b=15.0), 0.0, 0.18))

            # Failed auth attempts in session: 0 most of time, occasionally 1
            failed_auth = 1 if random.random() < 0.04 else 0

            # Session duration (minutes)
            session_duration = float(np.clip(np.random.normal(90.0, 35.0), 5.0, 360.0))

            # Request entropy: normal spread across endpoints (0.35 - 0.65)
            request_entropy = float(np.clip(np.random.normal(0.48, 0.08), 0.25, 0.72))

            timestamp = base_time + timedelta(
                days=int(i / (n_samples / 60)),
                hours=float(hour)
            )

            records.append({
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "session_id": f"sess_base_{i:05d}",
                "user_id": admin["user_id"],
                "role": admin["role"],
                "city": loc["city"],
                "lat": loc["lat"],
                "lon": loc["lon"],
                "asn": loc["asn"],
                "hour_of_day": round(hour, 2),
                "api_calls_per_min": round(api_calls, 2),
                "data_download_mb": round(data_download_mb, 2),
                "geo_velocity_kmh": round(geo_velocity_kmh, 2),
                "sensitive_endpoint_ratio": round(sensitive_ratio, 3),
                "failed_auth_attempts": failed_auth,
                "session_duration_min": round(session_duration, 1),
                "request_entropy": round(request_entropy, 3),
                "is_attack": 0,
                "attack_type": "Normal Administration"
            })

        return pd.DataFrame(records)

    def generate_attack(self, attack_type: str = "mass_exfiltration", user_id: str = "admin_clara_s") -> dict:
        """
        Generates a specific high-fidelity attack telemetry snapshot.
        """
        now = datetime.now()
        role = "Senior Health Registry DBA"

        if attack_type == "mass_exfiltration":
            # Attacker compromised credentials; exfiltrating patient PII at 3:15 AM
            foreign = self.foreign_locations[0]
            dist = haversine_distance(BASE_OFFICE_COORDS["lat"], BASE_OFFICE_COORDS["lon"],
                                      foreign["lat"], foreign["lon"])
            # IP jump in 10 minutes: ~45,000 km/h
            return {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "session_id": f"sess_attack_{random.randint(1000, 9999)}",
                "user_id": user_id,
                "role": role,
                "city": foreign["city"],
                "lat": foreign["lat"],
                "lon": foreign["lon"],
                "asn": foreign["asn"],
                "hour_of_day": 3.25,  # 3:15 AM
                "api_calls_per_min": 240.0,  # Fast scraper
                "data_download_mb": 4850.0,  # Bulk dump of citizen records
                "geo_velocity_kmh": round(dist / (10 / 60), 1),  # > 40,000 km/h
                "sensitive_endpoint_ratio": 0.94,  # Targeting /api/v1/registry/export-bulk
                "failed_auth_attempts": 3,
                "session_duration_min": 14.5,
                "request_entropy": 0.91,
                "is_attack": 1,
                "attack_type": "Credential Compromise: Mass Welfare DB Exfiltration"
            }

        elif attack_type == "impossible_travel":
            # Session hijacked mid-flight from foreign proxy
            foreign = self.foreign_locations[1]
            dist = haversine_distance(BASE_OFFICE_COORDS["lat"], BASE_OFFICE_COORDS["lon"],
                                      foreign["lat"], foreign["lon"])
            return {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "session_id": f"sess_attack_{random.randint(1000, 9999)}",
                "user_id": user_id,
                "role": role,
                "city": foreign["city"],
                "lat": foreign["lat"],
                "lon": foreign["lon"],
                "asn": foreign["asn"],
                "hour_of_day": 14.2,  # Normal afternoon hour, but impossible location hop
                "api_calls_per_min": 52.0,
                "data_download_mb": 85.0,
                "geo_velocity_kmh": round(dist / (5 / 60), 1),  # 80,000+ km/h
                "sensitive_endpoint_ratio": 0.45,
                "failed_auth_attempts": 1,
                "session_duration_min": 22.0,
                "request_entropy": 0.62,
                "is_attack": 1,
                "attack_type": "Session Token Hijack: Impossible Travel Anomaly"
            }

        elif attack_type == "slow_and_low_apt":
            # Stealthy data harvester operating at odd hours, throttling download volume
            return {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "session_id": f"sess_attack_{random.randint(1000, 9999)}",
                "user_id": user_id,
                "role": role,
                "city": "Unknown / TOR Exit Node",
                "lat": 52.5200,
                "lon": 13.4050,
                "asn": "AS208323-Tor-Relay",
                "hour_of_day": 2.1,  # 2:06 AM
                "api_calls_per_min": 18.0,  # Slow rate to evade traditional WAF
                "data_download_mb": 290.0,  # Moderate data volume
                "geo_velocity_kmh": 6800.0,
                "sensitive_endpoint_ratio": 0.88,  # Only queries sensitive citizen PII
                "failed_auth_attempts": 2,
                "session_duration_min": 185.0,
                "request_entropy": 0.82,
                "is_attack": 1,
                "attack_type": "Advanced Persistent Threat (APT): Low & Slow Off-Hours Harvester"
            }

        elif attack_type == "privilege_escalation_recon":
            # Insider or stolen dev token trying unlisted endpoints
            loc = self.locations[0]
            return {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "session_id": f"sess_attack_{random.randint(1000, 9999)}",
                "user_id": user_id,
                "role": role,
                "city": loc["city"],
                "lat": loc["lat"],
                "lon": loc["lon"],
                "asn": loc["asn"],
                "hour_of_day": 23.4,  # Late night
                "api_calls_per_min": 175.0,
                "data_download_mb": 42.0,
                "geo_velocity_kmh": 0.0,  # From office VPN
                "sensitive_endpoint_ratio": 0.78,
                "failed_auth_attempts": 6,  # Repeated 401/403 forbidden responses
                "session_duration_min": 8.0,
                "request_entropy": 0.96,  # Endpoint fuzzing
                "is_attack": 1,
                "attack_type": "Internal Recon: Privilege Escalation & Endpoint Fuzzing"
            }

        else:
            # Fallback normal
            loc = self.locations[0]
            return {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "session_id": f"sess_norm_{random.randint(1000, 9999)}",
                "user_id": user_id,
                "role": role,
                "city": loc["city"],
                "lat": loc["lat"],
                "lon": loc["lon"],
                "asn": loc["asn"],
                "hour_of_day": 11.5,
                "api_calls_per_min": 24.0,
                "data_download_mb": 18.0,
                "geo_velocity_kmh": 0.0,
                "sensitive_endpoint_ratio": 0.04,
                "failed_auth_attempts": 0,
                "session_duration_min": 75.0,
                "request_entropy": 0.44,
                "is_attack": 0,
                "attack_type": "Normal Administration"
            }
