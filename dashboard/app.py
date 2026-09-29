"""
AegisTrust: Intelligent Zero-Trust Behavioral Authentication Dashboard.
Continuous Scrolling Single-Page SOC Portal with Violet/Cyan Cyber Aesthetics & Smooth Animations.
"""
import sys
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Add parent directory to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import DATA_DIR, MODELS_DIR, BASE_OFFICE_COORDS, RISK_THRESHOLD_ALLOW, RISK_THRESHOLD_CHALLENGE
from core.data_generator import TelemetryGenerator, haversine_distance
from core.feature_pipeline import FeaturePipeline
from core.anomaly_detector import BehavioralAnomalyDetector
from core.risk_engine import RiskEngine
from core.policy_enforcer import PolicyEnforcer
from simulation.attack_scenarios import PRESET_SCENARIOS

# Page Configuration
st.set_page_config(
    page_title="AegisTrust | Zero-Trust Operations Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Attractive Cyber / Violet & Cyan Glassmorphism Styling with Smooth Scrolling & Animations
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [data-testid="stAppViewContainer"], .main {
        font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
        scroll-behavior: smooth !important;
    }

    code, pre, .mono-font {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Vibrant Dark Cosmic Background inspired by Violet/Cyan UI */
    .stApp {
        background: radial-gradient(ellipse at 15% 15%, #130d33 0%, #090c1f 45%, #030409 100%) !important;
        color: #f1f5f9 !important;
    }

    /* Keyframe Animations */
    @keyframes cardFadeIn {
        from {
            opacity: 0;
            transform: translateY(14px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    @keyframes pulse-glow {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(139, 92, 246, 0.7); }
        70% { transform: scale(1.15); box-shadow: 0 0 0 8px rgba(139, 92, 246, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(139, 92, 246, 0); }
    }

    @keyframes live-cyan-pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(6, 182, 212, 0.7); }
        70% { transform: scale(1.15); box-shadow: 0 0 0 8px rgba(6, 182, 212, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(6, 182, 212, 0); }
    }

    /* KPI Metric Cards */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(26, 21, 59, 0.75) 0%, rgba(15, 23, 42, 0.75) 100%) !important;
        backdrop-filter: blur(14px) !important;
        -webkit-backdrop-filter: blur(14px) !important;
        border: 1px solid rgba(139, 92, 246, 0.3) !important;
        border-radius: 14px !important;
        padding: 16px 22px !important;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.45), inset 0 0 12px rgba(139, 92, 246, 0.08) !important;
        transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease !important;
        animation: cardFadeIn 0.6s ease-out !important;
    }
    div[data-testid="stMetric"]:hover {
        border-color: rgba(6, 182, 212, 0.6) !important;
        box-shadow: 0 12px 36px rgba(139, 92, 246, 0.25) !important;
        transform: translateY(-3px) !important;
    }
    div[data-testid="stMetric"] label {
        color: #a5b4fc !important;
        font-weight: 600 !important;
        font-size: 0.82rem !important;
        letter-spacing: 0.06em !important;
        text-transform: uppercase !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        font-weight: 700 !important;
        font-size: 2.1rem !important;
        color: #f8fafc !important;
    }

    /* Sticky Quick-Navigation Bar */
    .sticky-nav-bar {
        position: -webkit-sticky;
        position: sticky;
        top: 0;
        z-index: 999;
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        background: rgba(13, 17, 38, 0.88);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        padding: 12px 16px;
        border-radius: 12px;
        border: 1px solid rgba(139, 92, 246, 0.35);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
        margin: 18px 0 24px 0;
    }
    .nav-chip {
        color: #cbd5e1 !important;
        background: rgba(30, 27, 75, 0.65);
        border: 1px solid rgba(139, 92, 246, 0.35);
        padding: 8px 16px;
        border-radius: 8px;
        font-size: 0.88rem;
        font-weight: 600;
        text-decoration: none !important;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        transition: all 0.25s ease;
    }
    .nav-chip:hover {
        color: #38bdf8 !important;
        background: rgba(6, 182, 212, 0.18);
        border-color: #06b6d4;
        box-shadow: 0 0 16px rgba(6, 182, 212, 0.3);
        transform: translateY(-2px);
    }

    /* Section Banner Headers */
    .section-card {
        background: rgba(15, 20, 43, 0.65);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(139, 92, 246, 0.25);
        border-radius: 14px;
        padding: 22px;
        margin: 28px 0 16px 0;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
        animation: cardFadeIn 0.5s ease-out;
    }

    .section-title {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 1.45rem;
        font-weight: 700;
        color: #f8fafc;
        margin-bottom: 4px;
    }
    .section-subtitle {
        color: #94a3b8;
        font-size: 0.88rem;
        margin-bottom: 12px;
    }

    /* Glowing Dots */
    .pulse-dot-violet {
        height: 10px;
        width: 10px;
        background-color: #8b5cf6;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 10px #8b5cf6;
        animation: pulse-glow 2s infinite;
        margin-right: 6px;
    }
    .pulse-dot-cyan {
        height: 10px;
        width: 10px;
        background-color: #06b6d4;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 10px #06b6d4;
        animation: live-cyan-pulse 2s infinite;
        margin-right: 6px;
    }

    /* Decision Box Containers with Violet/Emerald/Amber/Rose Accents */
    .decision-container-allow {
        background: rgba(8, 47, 35, 0.72);
        border: 1px solid rgba(16, 185, 129, 0.5);
        border-radius: 12px;
        padding: 18px 22px;
        box-shadow: 0 8px 30px rgba(16, 185, 129, 0.18);
        margin-bottom: 14px;
        animation: cardFadeIn 0.4s ease-out;
    }
    .decision-container-challenge {
        background: rgba(48, 29, 10, 0.72);
        border: 1px solid rgba(245, 158, 11, 0.5);
        border-radius: 12px;
        padding: 18px 22px;
        box-shadow: 0 8px 30px rgba(245, 158, 11, 0.18);
        margin-bottom: 14px;
        animation: cardFadeIn 0.4s ease-out;
    }
    .decision-container-revoke {
        background: rgba(50, 11, 22, 0.75);
        border: 1px solid rgba(244, 63, 94, 0.55);
        border-radius: 12px;
        padding: 18px 22px;
        box-shadow: 0 8px 30px rgba(244, 63, 94, 0.25);
        margin-bottom: 14px;
        animation: cardFadeIn 0.4s ease-out;
    }

    /* Badges */
    .badge-allow {
        background: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid rgba(52, 211, 153, 0.5);
        padding: 5px 12px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-challenge {
        background: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid rgba(251, 191, 36, 0.5);
        padding: 5px 12px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-revoke {
        background: rgba(244, 63, 94, 0.2);
        color: #fb7185;
        border: 1px solid rgba(251, 113, 133, 0.5);
        padding: 5px 12px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.85rem;
    }

    .tech-pill {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #c084fc;
        background: rgba(168, 85, 247, 0.12);
        border: 1px solid rgba(168, 85, 247, 0.3);
        padding: 3px 8px;
        border-radius: 6px;
        margin-left: 6px;
    }

    /* Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%) !important;
        color: #ffffff !important;
        border: 1px solid rgba(168, 85, 247, 0.4) !important;
        transition: all 0.25s ease !important;
    }
    .stButton > button:hover {
        box-shadow: 0 0 20px rgba(139, 92, 246, 0.45) !important;
        transform: translateY(-2px) !important;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session State
@st.cache_resource
def load_core_engine():
    pipeline = FeaturePipeline()
    pipeline.load()
    detector = BehavioralAnomalyDetector()
    detector.load()
    risk_engine = RiskEngine()
    return pipeline, detector, risk_engine


pipeline, detector, risk_engine = load_core_engine()

if "enforcer" not in st.session_state:
    st.session_state["enforcer"] = PolicyEnforcer()
    generator = TelemetryGenerator(seed=99)
    sample_normal = generator.generate_baseline(n_samples=5)
    for _, row in sample_normal.iterrows():
        t_dict = row.to_dict()
        x = pipeline.transform(t_dict)
        _, intensity = detector.predict_anomaly(x)
        res = risk_engine.calculate_risk(t_dict, intensity[0])
        st.session_state["enforcer"].register_or_update_session(t_dict, res)

enforcer = st.session_state["enforcer"]

# ==============================================================================
# SIDEBAR: SCENARIO SELECTOR & TELEMETRY CONTROLS
# ==============================================================================
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
        <span class="pulse-dot-violet"></span>
        <span style="font-weight: 700; letter-spacing: 0.08em; color: #a855f7; font-size: 1.1rem;">AEGISTRUST SOC</span>
    </div>
    <div style="color: #94a3b8; font-size: 0.8rem; margin-bottom: 14px;">
        NIST SP 800-207 Zero-Trust Behavioral Engine
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.subheader("🎯 Scenario Selector")
    scenario_choice = st.selectbox(
        "Choose Pre-configured Test Vector:",
        options=list(PRESET_SCENARIOS.keys()),
        format_func=lambda k: PRESET_SCENARIOS[k]["title"]
    )

    active_preset = PRESET_SCENARIOS[scenario_choice]
    st.info(f"{active_preset['icon']} **{active_preset['title']}**\n\n{active_preset['description']}")

    st.divider()
    st.subheader("⚙️ Live Telemetry Sliders")
    st.caption("Fine-tune specific behavioral dimensions:")

    base_t = active_preset["telemetry"]

    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        s_hour = st.slider("Hour of Day (24h)", 0.0, 24.0, float(base_t["hour_of_day"]), 0.5)
        s_api = st.slider("API Calls / Min", 1.0, 300.0, float(base_t["api_calls_per_min"]), 5.0)
        s_download = st.slider("Data Egress (MB)", 0.5, 6000.0, float(base_t["data_download_mb"]), 50.0)
        s_geo_vel = st.slider("IP Hop Velocity (km/h)", 0.0, 50000.0, float(base_t["geo_velocity_kmh"]), 250.0)

    with col_sb2:
        s_sensitive = st.slider("Sensitive Endpoint Ratio", 0.0, 1.0, float(base_t["sensitive_endpoint_ratio"]), 0.05)
        s_failed = st.slider("Failed Auth / 403s", 0, 10, int(base_t["failed_auth_attempts"]), 1)
        s_duration = st.slider("Session Duration (min)", 1.0, 480.0, float(base_t["session_duration_min"]), 10.0)
        s_entropy = st.slider("Request Entropy", 0.1, 1.0, float(base_t["request_entropy"]), 0.05)

    eval_telemetry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "session_id": base_t.get("session_id", "sess_custom_99"),
        "user_id": base_t.get("user_id", "admin_clara_s"),
        "role": base_t.get("role", "Senior Health Registry DBA"),
        "city": base_t.get("city", "Washington, D.C."),
        "lat": base_t.get("lat", 38.8951),
        "lon": base_t.get("lon", -77.0364),
        "asn": base_t.get("asn", "AS701-GovNet"),
        "hour_of_day": s_hour,
        "api_calls_per_min": s_api,
        "data_download_mb": s_download,
        "geo_velocity_kmh": s_geo_vel,
        "sensitive_endpoint_ratio": s_sensitive,
        "failed_auth_attempts": s_failed,
        "session_duration_min": s_duration,
        "request_entropy": s_entropy,
        "attack_type": active_preset["title"]
    }

# ==============================================================================
# HEADER HERO: VIOLET/CYAN MODERN OPERATIONS BANNER
# ==============================================================================
st.markdown("""
<div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 20px; border-bottom: 1px solid rgba(139, 92, 246, 0.25); padding-bottom: 16px;">
    <div>
        <div style="display: flex; align-items: center; margin-bottom: 6px;">
            <span class="pulse-dot-cyan"></span>
            <span style="font-family: 'JetBrains Mono'; font-size: 0.8rem; color: #06b6d4; letter-spacing: 0.1em; text-transform: uppercase;">Zero-Trust Telemetry Shield // Public Welfare Registries</span>
        </div>
        <h1 style="margin: 0; font-size: 2.2rem; font-weight: 700; background: linear-gradient(90deg, #ffffff 0%, #c084fc 50%, #38bdf8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            🛡️ Intelligent Zero-Trust Behavioral Authentication
        </h1>
        <div style="color: #94a3b8; font-size: 0.95rem; margin-top: 4px;">
            Continuous, AI-driven post-authentication behavioral profiling & automated step-up enforcement.
        </div>
    </div>
    <div style="text-align: right;">
        <span class="tech-pill">ACTIVE PDP</span>
        <span class="tech-pill">NIST SP 800-207</span>
        <span class="tech-pill">ISOLATION FOREST</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Top Level KPI Banner
c1, c2, c3, c4 = st.columns(4)
active_count = len([s for s in enforcer.active_sessions.values() if s["state"] == "ACTIVE"])
challenge_count = len([s for s in enforcer.active_sessions.values() if s["state"] == "CHALLENGED"])
revoked_count = len([s for s in enforcer.active_sessions.values() if s["state"] == "REVOKED"])

with c1:
    st.metric("Total Monitored Sessions", len(enforcer.active_sessions), delta="Real-time")
with c2:
    st.metric("Trusted Active Sessions", active_count, delta="Zero Friction", delta_color="normal")
with c3:
    st.metric("Step-Up Challenged", challenge_count, delta="MFA Pending", delta_color="off")
with c4:
    st.metric("Revoked / Quarantined", revoked_count, delta="Threats Blocked", delta_color="inverse")

# ==============================================================================
# STICKY QUICK-NAVIGATION ANCHOR BAR (Continuous Scroll UX)
# ==============================================================================
st.markdown("""
<div class="sticky-nav-bar">
    <a href="#section-live" class="nav-chip" target="_self">🚀 1. Live Telemetry & Enforcement</a>
    <a href="#section-map" class="nav-chip" target="_self">🛰️ 2. Threat Geolocation Map</a>
    <a href="#section-diagnostics" class="nav-chip" target="_self">📊 3. Baseline ML Diagnostics</a>
    <a href="#section-siem" class="nav-chip" target="_self">📜 4. SIEM Security Audit Stream</a>
    <a href="#section-pitch" class="nav-chip" target="_self">🎤 5. Panel Defense & Pitch</a>
</div>
""", unsafe_allow_html=True)

# Compute Real-time evaluation
x_input = pipeline.transform(eval_telemetry)
_, anomaly_intensity = detector.predict_anomaly(x_input)
risk_result = risk_engine.calculate_risk(eval_telemetry, anomaly_intensity[0])
session_record = enforcer.register_or_update_session(eval_telemetry, risk_result)

# ==============================================================================
# SECTION 1: LIVE TELEMETRY & ZERO-TRUST ENFORCEMENT
# ==============================================================================
st.markdown("""
<div id="section-live" class="section-card">
    <div class="section-title">
        <span>🚀 1. Real-Time Telemetry & Policy Enforcement Engine</span>
    </div>
    <div class="section-subtitle">
        Continuous risk scoring and automated NIST Zero-Trust containment of active administrative sessions.
    </div>
</div>
""", unsafe_allow_html=True)

col_gauge, col_decision = st.columns([1, 1.4])

with col_gauge:
    # Plotly Gauge Chart for Risk Score
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_result["risk_score"],
        title={"text": "Continuous Risk Score", "font": {"size": 22, "color": "#f8fafc", "family": "Space Grotesk"}},
        number={"suffix": "/100", "font": {"size": 38, "color": risk_result["status_color"], "family": "Space Grotesk"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#94a3b8"},
            "bar": {"color": risk_result["status_color"], "thickness": 0.28},
            "bgcolor": "rgba(26, 21, 59, 0.6)",
            "borderwidth": 1,
            "bordercolor": "rgba(139, 92, 246, 0.3)",
            "steps": [
                {"range": [0, RISK_THRESHOLD_ALLOW], "color": "rgba(16, 185, 129, 0.2)"},
                {"range": [RISK_THRESHOLD_ALLOW, RISK_THRESHOLD_CHALLENGE], "color": "rgba(245, 158, 11, 0.25)"},
                {"range": [RISK_THRESHOLD_CHALLENGE, 100], "color": "rgba(244, 63, 94, 0.3)"}
            ],
            "threshold": {
                "line": {"color": "white", "width": 3},
                "thickness": 0.8,
                "value": risk_result["risk_score"]
            }
        }
    ))
    fig_gauge.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=300,
        margin=dict(l=25, r=25, t=50, b=25)
    )
    st.plotly_chart(fig_gauge, use_container_width=True)

    st.caption(f"**ML Baseline Contribution:** {risk_result['ml_contribution']:.1f} pts | **Heuristic Trigger Contribution:** {risk_result['heuristic_contribution']:.1f} pts")

with col_decision:
    action = risk_result["action"]
    card_class = "decision-container-allow" if action == "ALLOW" else ("decision-container-challenge" if action == "CHALLENGE" else "decision-container-revoke")
    badge_class = "badge-allow" if action == "ALLOW" else ("badge-challenge" if action == "CHALLENGE" else "badge-revoke")
    tier_title = "LOW RISK" if action == "ALLOW" else ("STEP-UP REQUIRED" if action == "CHALLENGE" else "SESSION QUARANTINED")

    st.markdown(f"""
    <div class="{card_class}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
            <span style="font-family: 'JetBrains Mono'; font-size: 0.8rem; letter-spacing: 0.08em; color: #a5b4fc; text-transform: uppercase;">Zero-Trust Policy Verdict</span>
            <span class="{badge_class}">{action} // {tier_title}</span>
        </div>
        <h3 style="margin: 0 0 10px 0; color: #f8fafc; font-size: 1.25rem;">{risk_result['action_description']}</h3>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.88rem; color: #cbd5e1; margin-top: 12px; border-top: 1px solid rgba(255, 255, 255, 0.12); padding-top: 10px;">
            <div><span style="color: #94a3b8;">User:</span> <code>{eval_telemetry['user_id']}</code></div>
            <div><span style="color: #94a3b8;">Role:</span> {eval_telemetry['role']}</div>
            <div><span style="color: #94a3b8;">Session:</span> <code>{eval_telemetry['session_id']}</code></div>
            <div><span style="color: #94a3b8;">Location:</span> {eval_telemetry['city']} ({eval_telemetry['asn']})</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if risk_result["active_triggers"]:
        st.markdown("**Active Behavioral Policy Triggers:**")
        for trig in risk_result["active_triggers"]:
            st.markdown(f"- 🔴 `{trig}`")
    else:
        st.markdown("🟢 *All behavioral metrics within normal operating bounds.*")

    # Interactive Step-Up Challenge Box
    if session_record["state"] == "CHALLENGED":
        st.markdown("---")
        st.markdown("#### 🔐 Step-Up Authentication Challenge (Demo Sandbox)")
        st.caption("The user has exhibited anomalous behavior. Enter simulated 6-digit TOTP code (`123456`) to restore trust:")
        col_otp1, col_otp2 = st.columns([2, 1])
        with col_otp1:
            otp_code = st.text_input("Enter 6-Digit OTP Code:", placeholder="123456", key="otp_input")
        with col_otp2:
            st.write("")
            st.write("")
            if st.button("Verify OTP", type="primary"):
                verify_res = enforcer.submit_step_up_mfa(session_record["session_id"], otp_code)
                if verify_res["success"]:
                    st.success(verify_res["message"])
                    st.rerun()
                else:
                    st.error(verify_res["message"])

st.markdown("<br>", unsafe_allow_html=True)

# Explainable AI (XAI) Attribution Breakdown
st.subheader("🔍 Explainable AI (XAI): Feature Attribution & Deviation from Baseline")
st.caption("Breaks down standard deviations from administrative norm for auditor transparency.")

explanations = pipeline.explain_deviations(eval_telemetry)
df_exp = pd.DataFrame(explanations)

col_xai_plot, col_xai_table = st.columns([1.2, 1])
with col_xai_plot:
    fig_xai = px.bar(
        df_exp,
        x="z_deviation",
        y="feature",
        orientation="h",
        color="severity",
        color_discrete_map={"NORMAL": "#10B981", "ELEVATED": "#F59E0B", "HIGH": "#F97316", "CRITICAL": "#F43F5E"},
        labels={"z_deviation": "Standard Deviations from Normal (Z-Score)", "feature": "Behavioral Metric"},
        title="Telemetric Anomaly Breakdown (Why the AI Decided This)",
        template="plotly_dark"
    )
    fig_xai.update_layout(height=350, yaxis={'categoryorder': 'total ascending'}, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig_xai, use_container_width=True)

with col_xai_table:
    st.dataframe(
        df_exp[["feature", "value", "baseline_mean", "z_deviation", "severity"]],
        column_config={
            "feature": "Feature",
            "value": "Observed",
            "baseline_mean": "Baseline Mean",
            "z_deviation": "Z-Score",
            "severity": "Risk Severity"
        },
        hide_index=True,
        use_container_width=True
    )

# ==============================================================================
# SECTION 2: ACTIVE SESSIONS MONITOR & INCIDENT MAP
# ==============================================================================
st.markdown("""
<div id="section-map" class="section-card">
    <div class="section-title">
        <span>🛰️ 2. Administrative Session Monitor & Global Threat Map</span>
    </div>
    <div class="section-subtitle">
        Visualizes real-time geographical ingress and highlights impossible travel leaps across continents.
    </div>
</div>
""", unsafe_allow_html=True)

col_hdr1, col_hdr2 = st.columns([3, 1])
with col_hdr2:
    if st.button("🔄 Reset Quarantine / Clear Locks"):
        enforcer.reset_quarantine()
        st.success("All locks and session quarantines cleared!")
        st.rerun()

session_rows = []
for s_id, s_data in enforcer.active_sessions.items():
    session_rows.append({
        "Session ID": s_id,
        "Admin User": s_data["user_id"],
        "Role": s_data["role"],
        "Location": s_data["city"],
        "ASN / Network": s_data["asn"],
        "Risk Score": s_data["risk_score"],
        "State": s_data["state"],
        "Action Taken": s_data["action_taken"],
        "lat": s_data["telemetry_snapshot"].get("lat", 38.8951),
        "lon": s_data["telemetry_snapshot"].get("lon", -77.0364)
    })

df_sessions = pd.DataFrame(session_rows)

fig_map = px.scatter_geo(
    df_sessions,
    lat="lat",
    lon="lon",
    hover_name="Admin User",
    hover_data=["Session ID", "Location", "Risk Score", "State"],
    color="State",
    color_discrete_map={"ACTIVE": "#10B981", "CHALLENGED": "#F59E0B", "REVOKED": "#F43F5E"},
    size="Risk Score",
    size_max=22,
    title="Live Geographical Ingress of Admin Sessions",
    template="plotly_dark",
    projection="natural earth"
)
fig_map.update_geos(
    showcountries=True,
    countrycolor="#334155",
    showland=True,
    landcolor="#181534",
    showocean=True,
    oceancolor="#090b1c"
)
fig_map.update_layout(height=420, margin=dict(l=0, r=0, t=40, b=0), paper_bgcolor="rgba(0,0,0,0)")
st.plotly_chart(fig_map, use_container_width=True)

st.dataframe(
    df_sessions.drop(columns=["lat", "lon"]),
    column_config={
        "Risk Score": st.column_config.ProgressColumn(
            "Risk Score",
            help="Continuous Risk Score (0-100)",
            format="%d",
            min_value=0,
            max_value=100
        ),
    },
    use_container_width=True,
    hide_index=True
)

# ==============================================================================
# SECTION 3: BASELINE TELEMETRY & ML DIAGNOSTICS
# ==============================================================================
st.markdown("""
<div id="section-diagnostics" class="section-card">
    <div class="section-title">
        <span>📊 3. Machine Learning Baseline & Anomaly Boundary Diagnostics</span>
    </div>
    <div class="section-subtitle">
        Empirical training distribution of 3,500 benign admin sessions contrasted with active evaluated session.
    </div>
</div>
""", unsafe_allow_html=True)

baseline_csv = DATA_DIR / "baseline_admin_logs.csv"
if baseline_csv.exists():
    df_base = pd.read_csv(baseline_csv)

    col_m1, col_m2 = st.columns(2)
    with col_m1:
        fig_scatter1 = px.scatter(
            df_base.sample(n=min(len(df_base), 800), random_state=42),
            x="hour_of_day",
            y="data_download_mb",
            color_discrete_sequence=["#38bdf8"],
            opacity=0.5,
            title="Data Egress (MB) vs Hour of Day (Baseline Workday)",
            labels={"hour_of_day": "Hour of Day (24h)", "data_download_mb": "Download Egress (MB)"},
            template="plotly_dark"
        )
        fig_scatter1.add_trace(go.Scatter(
            x=[eval_telemetry["hour_of_day"]],
            y=[eval_telemetry["data_download_mb"]],
            mode="markers",
            marker=dict(size=18, color=risk_result["status_color"], symbol="star", line=dict(width=2, color="#ffffff")),
            name="Current Evaluated Session"
        ))
        fig_scatter1.update_layout(height=350, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_scatter1, use_container_width=True)

    with col_m2:
        fig_scatter2 = px.scatter(
            df_base.sample(n=min(len(df_base), 800), random_state=42),
            x="api_calls_per_min",
            y="sensitive_endpoint_ratio",
            color_discrete_sequence=["#a855f7"],
            opacity=0.5,
            title="Sensitive Endpoint Ratio vs API Call Velocity",
            labels={"api_calls_per_min": "API Calls / Min", "sensitive_endpoint_ratio": "Sensitive Endpoint Ratio"},
            template="plotly_dark"
        )
        fig_scatter2.add_trace(go.Scatter(
            x=[eval_telemetry["api_calls_per_min"]],
            y=[eval_telemetry["sensitive_endpoint_ratio"]],
            mode="markers",
            marker=dict(size=18, color=risk_result["status_color"], symbol="star", line=dict(width=2, color="#ffffff")),
            name="Current Evaluated Session"
        ))
        fig_scatter2.update_layout(height=350, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_scatter2, use_container_width=True)

    st.subheader("Baseline Feature Distribution Statistics (Training Set)")
    st.dataframe(df_base[pipeline.features].describe().T[["mean", "std", "min", "50%", "max"]], use_container_width=True)

# ==============================================================================
# SECTION 4: SIEM AUDIT TRAIL & EVENT STREAM
# ==============================================================================
st.markdown("""
<div id="section-siem" class="section-card">
    <div class="section-title">
        <span>📜 4. Security Information and Event Management (SIEM) Stream</span>
    </div>
    <div class="section-subtitle">
        Structured audit logs formatted in Common Event Format (CEF) / JSON ready for Splunk or Microsoft Sentinel.
    </div>
</div>
""", unsafe_allow_html=True)

if enforcer.audit_log:
    latest = enforcer.audit_log[0]
    status_col = "#34d399" if latest["action"] == "ALLOW" else ("#fbbf24" if latest["action"] == "CHALLENGE" else "#fb7185")
    st.markdown(f"""
    <div style="background: rgba(14, 11, 33, 0.88); border: 1px solid rgba(139, 92, 246, 0.35); border-left: 3px solid #06b6d4; border-radius: 8px; padding: 12px 16px; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #cbd5e1; line-height: 1.6; margin-bottom: 14px;">
        <div><span style="color: #c084fc;">[{latest['timestamp']}]</span> <span style="color: {status_col}; font-weight: 700;">[{latest['action']}]</span> EVENT_ID: {latest['event_id']}</div>
        <div>&gt; SESSION_REF  : {latest['session_id']} (User: {latest['user_id']})</div>
        <div>&gt; INGRESS_SRC  : {latest['location']} // {latest['source_ip_asn']}</div>
        <div>&gt; RISK_SCORE   : {latest['risk_score']}/100 [DECISION: {latest['state']}]</div>
        <div>&gt; AUDIT_MSG    : {latest['details']}</div>
    </div>
    """, unsafe_allow_html=True)

    df_audit = pd.DataFrame(enforcer.audit_log)
    st.dataframe(
        df_audit[["timestamp", "event_id", "session_id", "user_id", "risk_score", "action", "state", "details"]],
        use_container_width=True,
        hide_index=True
    )

    st.subheader("Latest Raw JSON Security Event")
    st.json(enforcer.audit_log[0])
else:
    st.info("No audit events recorded yet.")

# ==============================================================================
# SECTION 5: PANEL PRESENTATION & DEFENSE PITCH
# ==============================================================================
st.markdown("""
<div id="section-pitch" class="section-card">
    <div class="section-title">
        <span>🎤 5. Panel Presentation & Evaluation Defense Guide</span>
    </div>
    <div class="section-subtitle">
        Structured presentation script, threat taxonomy, and model defense answers for the evaluation panel.
    </div>
</div>
""", unsafe_allow_html=True)

with st.expander("📢 1. The 60-Second Elevator Pitch", expanded=True):
    st.markdown("""
    > *"Securing public sector cloud registries—like national healthcare registries and social welfare databases—requires moving away from static perimeter firewalls. Traditional authentication verifies credentials once at login ($t=0$). If those credentials are phished, leaked, or stolen, an adversary has unchecked administrative access.*  
    >  
    > *I built **AegisTrust**: an intelligent, zero-trust behavioral analysis pipeline that monitors administrative behavior continuously after login. Using an unsupervised **Isolation Forest** model combined with dynamic contextual risk scoring, the system detects anomalous data exfiltration, impossible travel, and privilege probing in real time. When an authenticated session turns malicious, the engine autonomously enforces step-up MFA challenges or immediate session termination and IP quarantining before data can be stolen."*
    """)

with st.expander("🏛️ 2. Architectural Blueprint & Technical Stack", expanded=False):
    st.markdown("""
    - **Data Ingestion Tier**: Captures streaming post-auth telemetry: login hour, API call frequency, egress bytes, IP hop speed (Haversine geodistance), sensitive endpoint access ratios, error entropy.
    - **Preprocessing & Normalization**: `RobustScaler` handling non-normal distributions and extreme outliers without biasing the baseline.
    - **Machine Learning Core**: Unsupervised `IsolationForest` (150 decision trees, contamination=0.04) trained on benign administrative workflows without requiring labeled attack samples.
    - **Risk Engine & Policy Decision Point (PDP)**: Synthesizes ML anomaly intensity with domain-specific physics violations (impossible travel > 850 km/h, bulk download > 1 GB) into a normalized Continuous Risk Score (0-100).
    - **Policy Enforcement Point (PEP)**: Enforces dynamic tiered actions:
      - **0-34 (ALLOW)**: Continuous passive monitoring.
      - **35-64 (CHALLENGE)**: Step-up MFA challenge (TOTP/Biometric) + API rate limiting.
      - **65-100 (REVOKE)**: Immediate session invalidation, IP quarantine, SIEM alert.
    - **Explainability (XAI)**: Z-score deviation breakdown attributing risk to individual behavioral signals for audit compliance.
    """)

with st.expander("🛡️ 3. Threat Model & Handled Attack Vectors", expanded=False):
    st.markdown("""
    | Threat Vector | Real-World Scenario | Detection Mechanism | Enforcement Action |
    | :--- | :--- | :--- | :--- |
    | **Stolen Admin Credentials** | Adversary logs in with valid DBA password at 3:15 AM to dump patient records. | Anomaly in access hour + massive data egress spike + high sensitive endpoint ratio. | **REVOKE**: Session destroyed, credentials locked. |
    | **Session Cookie Hijack (AiTM)** | Session token stolen via Evilginx; adversary makes requests from Bucharest while admin is in D.C. | Haversine velocity > 40,000 km/h (Impossible Travel physics violation). | **REVOKE**: Session revoked, offshore IP quarantined. |
    | **Low & Slow Harvester (APT)** | Adversary throttles queries to 18 req/min via TOR at night to evade rate limiters. | Off-hours pattern + uncharacteristically high focus on sensitive citizen PII routes. | **CHALLENGE / REVOKE**: Step-up MFA blocks automation. |
    | **Privilege Escalation Recon** | Compromised dev account attempts horizontal scanning across forbidden endpoints. | High request entropy + burst of 403 Forbidden error responses. | **CHALLENGE**: Throttles calls, demands MFA re-auth. |
    """)

with st.expander("🎯 4. Anticipated Panel Questions & Bulletproof Answers", expanded=False):
    st.markdown("""
    **Q1: Why use Unsupervised Learning (Isolation Forest) instead of Supervised Classification (e.g. XGBoost)?**  
    *Answer:* "In real-world cybersecurity, attack patterns constantly mutate (Zero-Day threats, novel APT exfiltration techniques). Supervised models overfit to known attack signatures. Unsupervised Isolation Forest isolates anomalies simply based on how few tree splits are needed to separate an observation from normal administrative routines. It requires zero labeled attack data, making it naturally resilient to previously unseen threat vectors."

    **Q2: How do you handle False Positives without locking out legitimate admins who have an emergency off-hours shift?**  
    *Answer:* "That is the core strength of our tiered Zero-Trust architecture. An elevated risk score (35-64) does not abruptly lock out the admin. Instead, it issues a **Step-Up Authentication Challenge** (MFA / TOTP prompt) and throttles throughput. If it is a legitimate admin on-call, they simply confirm their identity in 3 seconds and proceed. Full revocation is reserved strictly for high-confidence breaches (Risk > 65), such as impossible travel or gigabyte-scale exfiltration."

    **Q3: How does this scale to production cloud architectures (AWS / Azure / GCP)?**  
    *Answer:* "AegisTrust is designed to act as an asynchronous Policy Decision Point (PDP). Telemetry can be streamed from AWS CloudTrail, CloudFront, Azure Sentinel, or an Envoy API gateway via Kafka or Kinesis. The model evaluates sessions sub-second and can push instant revocation commands via Open Policy Agent (OPA), AWS IAM session revocation APIs, or Cloudflare Zero Trust session termination endpoints."
    """)
