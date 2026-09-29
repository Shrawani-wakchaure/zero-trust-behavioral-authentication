"""
AegisTrust Command-Line Interface (CLI).
Provides fast terminal testing of zero-trust behavioral evaluation, benchmark runs, and demo launcher.
"""
import argparse
import sys
import subprocess
from pathlib import Path
import json

from config import RISK_THRESHOLD_ALLOW, RISK_THRESHOLD_CHALLENGE
from core.feature_pipeline import FeaturePipeline
from core.anomaly_detector import BehavioralAnomalyDetector
from core.risk_engine import RiskEngine
from core.policy_enforcer import PolicyEnforcer
from simulation.attack_scenarios import PRESET_SCENARIOS, get_scenario


def run_scenario(scenario_key: str):
    """Evaluates a single scenario and outputs structured zero-trust decision."""
    scenario = get_scenario(scenario_key)
    telemetry = scenario["telemetry"]

    pipeline = FeaturePipeline()
    pipeline.load()
    detector = BehavioralAnomalyDetector()
    detector.load()
    risk_engine = RiskEngine()
    enforcer = PolicyEnforcer()

    # Preprocessing & Inference
    x = pipeline.transform(telemetry)
    _, intensity = detector.predict_anomaly(x)
    risk_result = risk_engine.calculate_risk(telemetry, intensity[0])
    session_record = enforcer.register_or_update_session(telemetry, risk_result)
    deviations = pipeline.explain_deviations(telemetry)

    print("\n" + "=" * 75)
    print(f"🛡️  AEGISTRUST ZERO-TRUST SESSION EVALUATION: {scenario['title']}")
    print("=" * 75)
    print(f"Session ID       : {session_record['session_id']}")
    print(f"Admin User       : {session_record['user_id']} ({session_record['role']})")
    print(f"Ingress Location : {session_record['city']} ({session_record['asn']})")
    print(f"Continuous Risk  : {session_record['risk_score']} / 100  [Tier: {session_record['risk_tier']}]")

    action = session_record['action_taken']
    if action == "ALLOW":
        badge = "🟢 [ALLOW - TRUST VERIFIED]"
    elif action == "CHALLENGE":
        badge = "🟡 [CHALLENGE - STEP-UP MFA REQUIRED]"
    else:
        badge = "🔴 [REVOKE - ZERO-TRUST QUARANTINE]"

    print(f"Policy Action    : {badge}")
    print(f"Enforcement      : {session_record['enforcement_message']}")

    if session_record["active_triggers"]:
        print("\nActive Threat Triggers:")
        for t in session_record["active_triggers"]:
            print(f"  * {t}")

    print("\nTop Behavioral Anomalies (vs Baseline Norm):")
    for dev in deviations[:3]:
        print(f"  - {dev['feature']:<25}: Observed={dev['value']:>8.1f} | Norm={dev['baseline_mean']:>8.1f} | Dev={dev['z_deviation']:>+5.1f}σ [{dev['severity']}]")

    print("=" * 75 + "\n")


def run_benchmark():
    """Runs all preset scenarios and prints an executive summary table."""
    pipeline = FeaturePipeline()
    pipeline.load()
    detector = BehavioralAnomalyDetector()
    detector.load()
    risk_engine = RiskEngine()

    print("\n" + "=" * 80)
    print("🛡️  AEGISTRUST BENCHMARK SUITE: ZERO-TRUST THREAT VECTOR EVALUATION")
    print("=" * 80)
    print(f"{'Threat Scenario':<35} | {'Risk':<6} | {'ML':<5} | {'Heur':<5} | {'Action':<10} | {'Status'}")
    print("-" * 80)

    for key, scenario in PRESET_SCENARIOS.items():
        t = scenario["telemetry"]
        x = pipeline.transform(t)
        _, intensity = detector.predict_anomaly(x)
        res = risk_engine.calculate_risk(t, intensity[0])

        status = "PASSED" if (key == "normal_admin" and res["action"] == "ALLOW") or (key != "normal_admin" and res["action"] in ["CHALLENGE", "REVOKE"]) else "FLAG"
        print(f"{scenario['title'][:35]:<35} | {res['risk_score']:>4.1f} | {res['ml_contribution']:>4.1f} | {res['heuristic_contribution']:>4.1f} | {res['action']:<10} | [{status}]")

    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="AegisTrust Zero-Trust Behavioral Authentication CLI")
    parser.add_argument("--scenario", choices=list(PRESET_SCENARIOS.keys()), help="Evaluate a specific attack scenario")
    parser.add_argument("--benchmark", action="store_true", help="Run benchmark across all threat vectors")
    parser.add_argument("--dashboard", action="store_true", help="Launch the interactive Streamlit Web Operations Center")

    args = parser.parse_args()

    if args.dashboard:
        app_path = Path(__file__).parent / "dashboard" / "app.py"
        subprocess.run(["streamlit", "run", str(app_path)])
    elif args.benchmark:
        run_benchmark()
    elif args.scenario:
        run_scenario(args.scenario)
    else:
        # Default run benchmark
        run_benchmark()
        print("Tip: Run 'python3 cli.py --scenario mass_exfiltration' or 'python3 cli.py --dashboard'")


if __name__ == "__main__":
    main()
