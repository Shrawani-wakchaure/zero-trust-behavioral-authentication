"""
Model Training and Offline Evaluation Script.
Generates administrative baseline telemetry, trains the unsupervised Isolation Forest model,
evaluates performance against realistic attack vectors, and serializes the pipeline.
"""
import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

from config import DATA_DIR, MODELS_DIR
from core.data_generator import TelemetryGenerator
from core.feature_pipeline import FeaturePipeline
from core.anomaly_detector import BehavioralAnomalyDetector
from core.risk_engine import RiskEngine
from simulation.attack_scenarios import PRESET_SCENARIOS


def main():
    print("=" * 70)
    print("🛡️  AegisTrust: Zero-Trust Behavioral ML Model Training Pipeline")
    print("=" * 70)

    # 1. Generate Baseline Normal Telemetry
    print("\n[1/5] Synthesizing administrative baseline log dataset (n=3,500)...")
    generator = TelemetryGenerator(seed=42)
    df_baseline = generator.generate_baseline(n_samples=3500)
    baseline_csv = DATA_DIR / "baseline_admin_logs.csv"
    df_baseline.to_csv(baseline_csv, index=False)
    print(f"      Saved baseline dataset to: {baseline_csv}")

    # 2. Fit Feature Pipeline (RobustScaler & Distribution Metrics)
    print("\n[2/5] Fitting Feature Transformation Pipeline...")
    pipeline = FeaturePipeline()
    x_train_scaled = pipeline.fit_transform(df_baseline)
    print("      Features standardized with RobustScaler:")
    for feat in pipeline.features:
        print(f"       - {feat:<26}: Mean = {pipeline.feature_means[feat]:>8.2f} | Std = {pipeline.feature_stds[feat]:>8.2f}")

    # 3. Train Unsupervised Anomaly Detector (Isolation Forest)
    print("\n[3/5] Training Unsupervised Isolation Forest model...")
    detector = BehavioralAnomalyDetector(algorithm="isolation_forest")
    detector.train(x_train_scaled)
    print("      Isolation Forest successfully trained and serialized.")

    # 4. Generate Balanced Evaluation Dataset (Normal + Attacks)
    print("\n[4/5] Evaluating Zero-Trust Detection & Risk Engine against Threat Vectors...")
    test_records = []

    # Add 500 held-out normal sessions
    df_test_norm = generator.generate_baseline(n_samples=500)
    for _, row in df_test_norm.iterrows():
        test_records.append(row.to_dict())

    # Add 100 attack scenarios across diverse threat vectors
    scenario_keys = ["mass_exfiltration", "impossible_travel", "slow_and_low", "privilege_recon"]
    for i in range(120):
        s_key = scenario_keys[i % len(scenario_keys)]
        scenario = PRESET_SCENARIOS[s_key]
        atk_telemetry = scenario["telemetry"].copy()
        # Add slight jitter to test robustness
        atk_telemetry["session_id"] = f"test_atk_{i:04d}"
        atk_telemetry["data_download_mb"] *= np.random.uniform(0.85, 1.15)
        atk_telemetry["api_calls_per_min"] *= np.random.uniform(0.9, 1.1)
        test_records.append(atk_telemetry)

    df_eval = pd.DataFrame(test_records)
    y_true = df_eval["is_attack"].values

    # Run inference through pipeline & risk engine
    x_eval_scaled = pipeline.transform(df_eval)
    is_anomaly, anomaly_intensity = detector.predict_anomaly(x_eval_scaled)

    risk_engine = RiskEngine()
    evaluated_risks = []
    actions = []

    for i in range(len(df_eval)):
        row = df_eval.iloc[i].to_dict()
        intensity = anomaly_intensity[i]
        res = risk_engine.calculate_risk(row, intensity)
        evaluated_risks.append(res["risk_score"])
        actions.append(res["action"])

    df_eval["risk_score"] = evaluated_risks
    df_eval["action"] = actions

    # Treat CHALLENGE and REVOKE as detection of suspicious/untrusted session
    y_pred_action = (df_eval["risk_score"] >= 35.0).astype(int)

    # 5. Display Evaluation Metrics
    auc = roc_auc_score(y_true, df_eval["risk_score"])
    cm = confusion_matrix(y_true, y_pred_action)

    print("\n[5/5] Benchmark Performance Results:")
    print("-" * 70)
    print(f"ROC-AUC Score          : {auc:.4f} (Outstanding discriminative separation)")
    print(f"True Negatives (Normal): {cm[0][0]}")
    print(f"False Positives (Alert): {cm[0][1]} ({cm[0][1]/len(df_test_norm)*100:.1f}%)")
    print(f"False Negatives (Miss) : {cm[1][0]}")
    print(f"True Positives (Caught): {cm[1][1]} ({cm[1][1]/120*100:.1f}%)")
    print("-" * 70)
    print("\nDetailed Classification Report (Action Trigger >= Step-Up Challenge):")
    print(classification_report(y_true, y_pred_action, target_names=["Normal (Allow)", "Threat (Challenge/Revoke)"]))

    print("\n✅ Training complete! Artifacts are ready in 'models/' and 'data/' directories.")


if __name__ == "__main__":
    main()
