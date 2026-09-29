"""
AegisTrust: Intelligent Zero-Trust Behavioral Authentication Dashboard.
Futuristic Cyber-Operations Center inspired by Cosmic Glassmorphism & Blueprint UI Design.
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta
import random
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
    page_title="AegisTrust | Zero-Trust Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Futuristic Cyber / Cosmic Blueprint Styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .mono-font {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Background and Glassmorphism */
    .stApp {
        background: radial-gradient(circle at 15% 15%, #0d172e 0%, #060913 60%, #020409 100%);
        color: #e2e8f0;
    }

    /* Blueprint Cyber Border Containers */
    .cyber-card {
        background: rgba(13, 22, 44, 0.72);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid rgba(0, 242, 254, 0.22);
        border-radius: 14px;
        padding: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.55), inset 0 0 12px rgba(0, 242, 254, 0.05);
        margin-bottom: 16px;
        transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
    }
    .cyber-card:hover {
        border-color: rgba(0, 242, 254, 0.5);
        box-shadow: 0 10px 40px 0 rgba(0, 242, 254, 0.15);
    }

    .cyber-card-danger {
        background: rgba(36, 12, 21, 0.75);
        border: 1px solid rgba(239, 68, 68, 0.45);
        border-radius: 14px;
        padding: 20px;
        box-shadow: 0 8px 32px 0 rgba(239, 68, 68, 0.2);
        margin-bottom: 16px;
    }

    .cyber-card-warning {
        background: rgba(38, 25, 11, 0.75);
        border: 1px solid rgba(245, 158, 11, 0.45);
        border-radius: 14px;
        padding: 20px;
        box-shadow: 0 8px 32px 0 rgba(245, 158, 11, 0.2);
        margin-bottom: 16px;
    }

    .cyber-card-success {
        background: rgba(11, 35, 27, 0.75);
        border: 1px solid rgba(16, 185, 129, 0.45);
        border-radius: 14px;
        padding: 20px;
        box-shadow: 0 8px 32px 0 rgba(16, 185, 129, 0.2);
        margin-bottom: 16px;
    }

    /* Glowing Status Badges */
    .glow-badge-emerald {
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid rgba(52, 211, 153, 0.4);
        padding: 6px 14px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 0 14px rgba(16, 185, 129, 0.3);
    }
    .glow-badge-amber {
        background: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid rgba(251, 191, 36, 0.4);
        padding: 6px 14px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 0 14px rgba(245, 158, 11, 0.3);
    }
    .glow-badge-crimson {
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid rgba(248, 113, 113, 0.4);
        padding: 6px 14px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 0 16px rgba(239, 68, 68, 0.4);
    }

    /* Live Telemetry Pulse Indicator */
    .live-dot {
        height: 10px;
        width: 10px;
        background-color: #00f2fe;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 10px #00f2fe;
        animation: pulse-ring 1.8s infinite;
    }
    @keyframes pulse-ring {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 242, 254, 0.7); }
        70% { transform: scale(1.15); box-shadow: 0 0 0 9px rgba(0, 242, 254, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 242, 254, 0); }
    }

    /* Futuristic Monospace Tags */
    .blueprint-tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #38bdf8;
        background: rgba(56, 189, 248, 0.1);
        border: 1px solid rgba(56, 189, 248, 0.25);
        padding: 3px 8px;
        border-radius: 4px;
        margin-right: 6px;
    }

    /* Terminal Console Window */
    .cyber-terminal {
        background: #020612;
        border: 1px solid #1e293b;
        border-left: 3px solid #00f2fe;
        border-radius: 8px;
        padding: 14px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        color: #94a3b8;
        line-height: 1.6;
        box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.7);
    }

    /* Enhanced Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 12px;
        background-color: rgba(15, 23, 42, 0.5);
        padding: 8px;
        border-radius: 12px;
        border: 1px solid rgba(51, 65, 85, 0.5);
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 10px 22px;
        color: #94a3b8;
        font-weight: 500;
        transition: all 0.2s ease;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(0, 242, 254, 0.15) 0%, rgba(99, 102, 241, 0.15) 100%) !important;
        color: #00f2fe !important;
        border: 1px solid rgba(0, 242, 254, 0.4) !important;
        box-shadow: 0 4px 16px rgba(0, 242, 254, 0.15);
    }
</style>
""", unsafe_allow_html=True)


# Initialize Core ML & Policy Engine
@st.cache_resource
def load_core_engine():
    pipeline = FeaturePipeline()
    pipeline.load()
    detector = BehavioralAnomalyDetector()
    detector.load()
    risk_engine = RiskEngine()
    return pipeline, detector, risk_engine


pipeline, detector, risk_engine = load_core_engine()

# Initialize Persistent Session State
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

if "selected_scenario_key" not in st.session_state:
    st.session_state["selected_scenario_key"] = "normal_admin"

# ==============================================================================
# SIDEBAR: ADVANCED TELEMETRY CONTROL
# ==============================================================================
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <span class="live-dot"></span>
        <span style="font-weight: 700; letter-spacing: 0.1em; color: #00f2fe; font-size: 1.1rem;">AEGISTRUST SOC</span>
    </div>
    <div style="color: #64748b; font-size: 0.8rem; margin-bottom: 14px;">
        NIST SP 800-207 Zero-Trust Behavioral Guard
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<span class='blueprint-tag'>CORE_ALGO</span> Isolation Forest (n=150)<br><span class='blueprint-tag'>PDP_MODE</span> Sub-15ms Active Telemetry", unsafe_allow_html=True)
    st.divider()

    st.subheader("🎯 Threat Vector Presets")
    scenario_keys = list(PRESET_SCENARIOS.keys())

    # Dropdown synchronized with state
    current_key = st.selectbox(
        "Choose Target Workload:",
        options=scenario_keys,
        index=scenario_keys.index(st.session_state["selected_scenario_key"]),
        format_func=lambda k: PRESET_SCENARIOS[k]["title"]
    )
    if current_key != st.session_state["selected_scenario_key"]:
        st.session_state["selected_scenario_key"] = current_key
        st.rerun()

    active_preset = PRESET_SCENARIOS[st.session_state["selected_scenario_key"]]
    base_t = active_preset["telemetry"]

    st.info(f"{active_preset['icon']} **{active_preset['title']}**\n\n{active_preset['description']}")

    st.divider()
    st.subheader("⚡ Live Behavioral Probes")
    st.caption("Fine-tune specific telemetry dimensions in real-time:")

    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        s_hour = st.slider("Hour of Day", 0.0, 24.0, float(base_t["hour_of_day"]), 0.5)
        s_api = st.slider("API Calls/min", 1.0, 300.0, float(base_t["api_calls_per_min"]), 5.0)
        s_download = st.slider("Egress (MB)", 0.5, 6000.0, float(base_t["data_download_mb"]), 50.0)
        s_geo_vel = st.slider("IP Hop (km/h)", 0.0, 60000.0, float(base_t["geo_velocity_kmh"]), 250.0)

    with col_sb2:
        s_sensitive = st.slider("Sensitive Ratio", 0.0, 1.0, float(base_t["sensitive_endpoint_ratio"]), 0.05)
        s_failed = st.slider("403 Forbidden", 0, 10, int(base_t["failed_auth_attempts"]), 1)
        s_duration = st.slider("Duration (min)", 1.0, 480.0, float(base_t["session_duration_min"]), 10.0)
        s_entropy = st.slider("Entropy", 0.1, 1.0, float(base_t["request_entropy"]), 0.05)

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
# HEADER HERO: FUTURISTIC BLUEPRINT & KPI STRIP
# ==============================================================================
st.markdown("""
<div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 20px; border-bottom: 1px solid rgba(0, 242, 254, 0.2); padding-bottom: 18px;">
    <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
            <span class="live-dot"></span>
            <span style="font-family: 'JetBrains Mono'; font-size: 0.85rem; color: #00f2fe; letter-spacing: 0.12em;">ZERO-TRUST TELEMETRY SHIELD // PUBLIC CLOUD REGISTRIES</span>
        </div>
        <h1 style="margin: 0; font-size: 2.2rem; font-weight: 700; background: linear-gradient(90deg, #ffffff 0%, #38bdf8 60%, #00f2fe 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            Intelligent Zero-Trust Behavioral Authentication
        </h1>
        <div style="color: #94a3b8; font-size: 0.95rem; margin-top: 4px;">
            Continuous, AI-driven post-authentication behavioral profiling & automated step-up enforcement.
        </div>
    </div>
    <div style="text-align: right;">
        <span class="blueprint-tag">SYSTEM ONLINE</span>
        <span class="blueprint-tag">LATENCY: 12ms</span>
        <span class="blueprint-tag">POLICY: NIST SP 800-207</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Top KPI Metric Cards (Inspired by Pin 3 Modern SOC Dashboard)
kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
active_count = len([s for s in enforcer.active_sessions.values() if s["state"] == "ACTIVE"])
challenge_count = len([s for s in enforcer.active_sessions.values() if s["state"] == "CHALLENGED"])
revoked_count = len([s for s in enforcer.active_sessions.values() if s["state"] == "REVOKED"])

with kpi_col1:
    st.markdown("""
    <div class="cyber-card">
        <div style="color: #64748b; font-size: 0.8rem; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">Monitored Sessions</div>
        <div style="font-size: 2.1rem; font-weight: 700; color: #f8fafc; margin: 4px 0;">{}</div>
        <div style="color: #38bdf8; font-size: 0.82rem;">⚡ Real-time Telemetry Stream</div>
    </div>
    """.format(len(enforcer.active_sessions)), unsafe_allow_html=True)

with kpi_col2:
    st.markdown("""
    <div class="cyber-card">
        <div style="color: #64748b; font-size: 0.8rem; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">Trusted In-Bound</div>
        <div style="font-size: 2.1rem; font-weight: 700; color: #34d399; margin: 4px 0;">{}</div>
        <div style="color: #10b981; font-size: 0.82rem;">🟢 Zero-Friction Allow</div>
    </div>
    """.format(active_count), unsafe_allow_html=True)

with kpi_col3:
    st.markdown("""
    <div class="cyber-card">
        <div style="color: #64748b; font-size: 0.8rem; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">Step-Up Challenged</div>
        <div style="font-size: 2.1rem; font-weight: 700; color: #fbbf24; margin: 4px 0;">{}</div>
        <div style="color: #f59e0b; font-size: 0.82rem;">🟡 Mandatory TOTP / Biometric</div>
    </div>
    """.format(challenge_count), unsafe_allow_html=True)

with kpi_col4:
    st.markdown("""
    <div class="cyber-card">
        <div style="color: #64748b; font-size: 0.8rem; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">Quarantined Breaches</div>
        <div style="font-size: 2.1rem; font-weight: 700; color: #f87171; margin: 4px 0;">{}</div>
        <div style="color: #ef4444; font-size: 0.82rem;">🔴 Instant Revoke & Lock</div>
    </div>
    """.format(revoked_count), unsafe_allow_html=True)

# Main Navigation Tabs
tab_live, tab_radar, tab_sessions, tab_model, tab_siem, tab_pitch = st.tabs([
    "🚀 Live Simulation & Enforcement",
    "🕸️ Behavioral Radar Profiler",
    "🛰️ Active Threat Geo-Map",
    "📊 Baseline Diagnostics",
    "📜 SIEM Event Stream",
    "🎤 Panel Presentation & Pitch"
])

# ==============================================================================
# TAB 1: LIVE SIMULATION & DYNAMIC ZERO-TRUST ENFORCEMENT
# ==============================================================================
with tab_live:
    # Interactive Visual Quick-Selector Cards across top of Tab 1
    st.markdown("##### ⚡ Quick Threat Scenario Launcher")
    q_col1, q_col2, q_col3, q_col4, q_col5 = st.columns(5)

    with q_col1:
        if st.button("🟢 1. Routine Workday", use_container_width=True, help="Normal DBA performing routine morning maintenance"):
            st.session_state["selected_scenario_key"] = "normal_admin"
            st.rerun()

    with q_col2:
        if st.button("🚨 2. Mass Exfiltration", use_container_width=True, help="Stolen creds used at 3:15 AM to dump 4.8 GB citizen records"):
            st.session_state["selected_scenario_key"] = "mass_exfiltration"
            st.rerun()

    with q_col3:
        if st.button("⚡ 3. Cookie Hijack", use_container_width=True, help="Session cookie stolen; impossible travel from Romania"):
            st.session_state["selected_scenario_key"] = "impossible_travel"
            st.rerun()

    with q_col4:
        if st.button("🕵️ 4. Low & Slow APT", use_container_width=True, help="Stealth queries via TOR at night harvesting PII"):
            st.session_state["selected_scenario_key"] = "slow_and_low"
            st.rerun()

    with q_col5:
        if st.button("🔍 5. Internal Recon", use_container_width=True, help="Probing restricted admin endpoints with 403 spikes"):
            st.session_state["selected_scenario_key"] = "privilege_recon"
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Perform Live Evaluation
    x_input = pipeline.transform(eval_telemetry)
    _, anomaly_intensity = detector.predict_anomaly(x_input)
    risk_result = risk_engine.calculate_risk(eval_telemetry, anomaly_intensity[0])
    session_record = enforcer.register_or_update_session(eval_telemetry, risk_result)

    # Two Column Layout: Futuristic Gauge + Decision Banner
    col_gauge, col_decision = st.columns([1.1, 1.4])

    with col_gauge:
        # Radial Gauge Meter with Cosmic Neon Arc Styling
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_result["risk_score"],
            title={"text": "CONTINUOUS RISK METER", "font": {"size": 18, "color": "#94a3b8", "family": "JetBrains Mono"}},
            number={"suffix": "/100", "font": {"size": 42, "color": risk_result["status_color"], "family": "Space Grotesk"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#64748b", "tickfont": {"size": 12}},
                "bar": {"color": risk_result["status_color"], "thickness": 0.26},
                "bgcolor": "rgba(15, 23, 42, 0.6)",
                "borderwidth": 1,
                "bordercolor": "rgba(51, 65, 85, 0.6)",
                "steps": [
                    {"range": [0, RISK_THRESHOLD_ALLOW], "color": "rgba(16, 185, 129, 0.15)"},
                    {"range": [RISK_THRESHOLD_ALLOW, RISK_THRESHOLD_CHALLENGE], "color": "rgba(245, 158, 11, 0.2)"},
                    {"range": [RISK_THRESHOLD_CHALLENGE, 100], "color": "rgba(239, 68, 68, 0.25)"}
                ],
                "threshold": {
                    "line": {"color": "#ffffff", "width": 3},
                    "thickness": 0.85,
                    "value": risk_result["risk_score"]
                }
            }
        ))
        fig_gauge.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=300,
            margin=dict(l=20, r=20, t=50, b=20)
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

        st.markdown(f"""
        <div style="display: flex; justify-content: space-around; background: rgba(15, 23, 42, 0.6); padding: 10px; border-radius: 8px; border: 1px solid rgba(51, 65, 85, 0.4); font-size: 0.85rem;">
            <div><span style="color: #64748b;">ML Baseline Score:</span> <strong style="color: #38bdf8;">{risk_result['ml_contribution']:.1f} pts</strong></div>
            <div><span style="color: #64748b;">Contextual Penalty:</span> <strong style="color: #f59e0b;">{risk_result['heuristic_contribution']:.1f} pts</strong></div>
        </div>
        """, unsafe_allow_html=True)

    with col_decision:
        action = risk_result["action"]
        card_class = "cyber-card-success" if action == "ALLOW" else ("cyber-card-warning" if action == "CHALLENGE" else "cyber-card-danger")

        st.markdown(f"""
        <div class="{card_class}">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <span style="font-family: 'JetBrains Mono'; font-size: 0.85rem; letter-spacing: 0.1em; color: #94a3b8;">ZERO-TRUST PDP ENFORCEMENT VERDICT</span>
                <span class="{('glow-badge-emerald' if action == 'ALLOW' else ('glow-badge-amber' if action == 'CHALLENGE' else 'glow-badge-crimson'))}">
                    {action} // TIER: {risk_result['risk_tier']}
                </span>
            </div>
            <h3 style="margin: 0 0 8px 0; color: #f8fafc; font-size: 1.35rem;">{risk_result['action_description']}</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.88rem; color: #cbd5e1; margin-top: 14px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 10px;">
                <div><strong>Admin Identity:</strong> <code>{eval_telemetry['user_id']}</code></div>
                <div><strong>Role:</strong> {eval_telemetry['role']}</div>
                <div><strong>Session ID:</strong> <code>{eval_telemetry['session_id']}</code></div>
                <div><strong>Ingress Point:</strong> {eval_telemetry['city']} ({eval_telemetry['asn']})</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if risk_result["active_triggers"]:
            st.markdown("**🚨 Active Anomaly Triggers:**")
            for trig in risk_result["active_triggers"]:
                st.markdown(f"- 🔴 `{trig}`")
        else:
            st.markdown("🟢 *All behavioral telemetry dimensions comply with normal administrative baselines.*")

        # Interactive Step-Up Challenge (If Challenged)
        if session_record["state"] == "CHALLENGED":
            st.markdown("""
            <div class="cyber-card" style="border-color: #f59e0b; background: rgba(38, 25, 11, 0.8);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h4 style="margin: 0; color: #fbbf24;">🔐 Step-Up MFA Challenge Required</h4>
                    <span class="glow-badge-amber">VERIFICATION PENDING</span>
                </div>
                <p style="font-size: 0.85rem; color: #cbd5e1; margin: 8px 0 14px 0;">
                    Anomalous behavior detected. Sensitive database queries have been throttled. Complete step-up authentication to restore full session trust:
                </p>
            </div>
            """, unsafe_allow_html=True)

            col_otp1, col_otp2 = st.columns([1.5, 1])
            with col_otp1:
                otp_code = st.text_input("Enter 6-Digit TOTP Token:", placeholder="123456", key="otp_input")
            with col_otp2:
                st.write("")
                st.write("")
                if st.button("🔑 Verify & Clear Challenge", type="primary", use_container_width=True):
                    verify_res = enforcer.submit_step_up_mfa(session_record["session_id"], otp_code)
                    if verify_res["success"]:
                        st.success(verify_res["message"])
                        st.rerun()
                    else:
                        st.error(verify_res["message"])

    st.divider()

    # Dynamic 15-Minute Risk Evolution Graph
    st.subheader("📈 Real-Time Dynamic Risk Horizon (Last 15 Minutes)")
    st.caption("Illustrates the continuous drift of the session's risk score from initial login to present.")

    # Generate synthetic time-series showing risk evolution
    time_pts = [datetime.now() - timedelta(minutes=15 - i) for i in range(16)]
    current_risk = risk_result["risk_score"]

    if current_risk > 65:
        # Rapid rise
        risks_over_time = [random.uniform(5.0, 18.0) for _ in range(8)]
        risks_over_time += [random.uniform(25.0, 50.0) for _ in range(4)]
        risks_over_time += [current_risk * 0.85, current_risk * 0.95, current_risk, current_risk]
    elif current_risk > 35:
        # Moderate rise
        risks_over_time = [random.uniform(5.0, 15.0) for _ in range(10)]
        risks_over_time += [random.uniform(20.0, 38.0) for _ in range(3)]
        risks_over_time += [current_risk * 0.9, current_risk * 0.95, current_risk]
    else:
        # Stationary low
        risks_over_time = [random.uniform(2.0, max(current_risk + 4, 12.0)) for _ in range(15)] + [current_risk]

    df_trend = pd.DataFrame({
        "Timestamp": [t.strftime("%H:%M:%S") for t in time_pts],
        "Risk Score": risks_over_time
    })

    fig_trend = px.area(
        df_trend,
        x="Timestamp",
        y="Risk Score",
        template="plotly_dark",
        labels={"Risk Score": "Continuous Risk Score (0-100)", "Timestamp": "Timeline"}
    )
    fig_trend.update_traces(
        line_color=risk_result["status_color"],
        fillcolor=f"rgba({16 if action=='ALLOW' else (245 if action=='CHALLENGE' else 239)}, {185 if action=='ALLOW' else (158 if action=='CHALLENGE' else 68)}, {129 if action=='ALLOW' else (11 if action=='CHALLENGE' else 68)}, 0.25)"
    )
    # Add horizontal threshold lines
    fig_trend.add_hline(y=RISK_THRESHOLD_CHALLENGE, line_dash="dash", line_color="#ef4444", annotation_text="Revoke Threshold (65)", annotation_position="top right")
    fig_trend.add_hline(y=RISK_THRESHOLD_ALLOW, line_dash="dash", line_color="#f59e0b", annotation_text="Challenge Threshold (35)", annotation_position="top right")
    fig_trend.update_layout(
        height=260,
        margin=dict(l=20, r=20, t=20, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )
    st.plotly_chart(fig_trend, use_container_width=True)

# ==============================================================================
# TAB 2: BEHAVIORAL RADAR PROFILER (SPIDER CHART)
# ==============================================================================
with tab_radar:
    st.subheader("🕸️ Multi-Dimensional Behavioral Radar Profiler")
    st.markdown("""
    This radar chart compares the **Normal Administrative Operating Baseline** against the **Current Live Session** across 6 key telemetry dimensions.
    Anomalous spikes expand the polygon dramatically outside the safe envelope.
    """)

    # Compute normalized indices for radar chart (0.0 to 1.0)
    radar_categories = [
        "Temporal Deviation",
        "API Request Velocity",
        "Data Egress Volume",
        "IP Hop Speed (Geo)",
        "Resource Sensitivity",
        "Request Entropy / 403s"
    ]

    # Baseline envelope (typical normal values normalized)
    baseline_radar = [0.15, 0.25, 0.12, 0.05, 0.10, 0.20]

    # Evaluated session normalized values
    norm_hour_dev = min(abs(eval_telemetry["hour_of_day"] - 13.5) / 10.0, 1.0)
    norm_api_vel = min(eval_telemetry["api_calls_per_min"] / 200.0, 1.0)
    norm_egress = min(eval_telemetry["data_download_mb"] / 3000.0, 1.0)
    norm_geo_speed = min(eval_telemetry["geo_velocity_kmh"] / 10000.0, 1.0)
    norm_sensitivity = float(eval_telemetry["sensitive_endpoint_ratio"])
    norm_entropy = min((eval_telemetry["request_entropy"] + (eval_telemetry["failed_auth_attempts"] * 0.15)), 1.0)

    current_radar = [
        round(norm_hour_dev, 2),
        round(norm_api_vel, 2),
        round(norm_egress, 2),
        round(norm_geo_speed, 2),
        round(norm_sensitivity, 2),
        round(norm_entropy, 2)
    ]

    col_radar_plot, col_radar_xai = st.columns([1.2, 1])

    with col_radar_plot:
        fig_radar = go.Figure()

        # Baseline Safe Boundary Trace
        fig_radar.add_trace(go.Scatterpolar(
            r=baseline_radar + [baseline_radar[0]],
            theta=radar_categories + [radar_categories[0]],
            fill="toself",
            name="Baseline Admin Norm",
            line=dict(color="#00f2fe", width=2),
            fillcolor="rgba(0, 242, 254, 0.15)"
        ))

        # Active Session Trace
        fig_radar.add_trace(go.Scatterpolar(
            r=current_radar + [current_radar[0]],
            theta=radar_categories + [radar_categories[0]],
            fill="toself",
            name="Active Session Profile",
            line=dict(color=risk_result["status_color"], width=3),
            fillcolor=f"rgba({239 if action=='REVOKE' else (245 if action=='CHALLENGE' else 16)}, {68 if action=='REVOKE' else (158 if action=='CHALLENGE' else 185)}, {68 if action=='REVOKE' else (11 if action=='CHALLENGE' else 129)}, 0.35)"
        ))

        fig_radar.update_layout(
            polar=dict(
                radialaxis=dict(visible=True, range=[0, 1.0], tickfont=dict(size=10, color="#64748b"), gridcolor="rgba(51, 65, 85, 0.4)"),
                angularaxis=dict(tickfont=dict(size=12, color="#cbd5e1", family="Space Grotesk"), gridcolor="rgba(51, 65, 85, 0.4)")
            ),
            showlegend=True,
            legend=dict(font=dict(color="#f8fafc"), orientation="h", yanchor="bottom", y=1.05, xanchor="center", x=0.5),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=400,
            margin=dict(l=40, r=40, t=50, b=30)
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    with col_radar_xai:
        st.markdown("#### 🔍 Explainable AI (XAI) Attribution")
        st.caption("Standard deviations ($\sigma$) from benign DBA baseline:")

        explanations = pipeline.explain_deviations(eval_telemetry)
        for exp in explanations[:4]:
            sev = exp["severity"]
            badge_class = "glow-badge-crimson" if sev == "CRITICAL" else ("glow-badge-amber" if sev in ["HIGH", "ELEVATED"] else "glow-badge-emerald")
            st.markdown(f"""
            <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(15, 23, 42, 0.6); padding: 8px 12px; border-radius: 8px; margin-bottom: 6px; border: 1px solid rgba(51, 65, 85, 0.4);">
                <div>
                    <code style="color: #38bdf8;">{exp['feature']}</code><br>
                    <small style="color: #94a3b8;">Observed: <strong>{exp['value']}</strong> | Norm: {exp['baseline_mean']}</small>
                </div>
                <div style="text-align: right;">
                    <span class="{badge_class}">{exp['z_deviation']:>+5.1f}σ</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

# ==============================================================================
# TAB 3: ACTIVE THREAT GEO-MAP WITH TRAJECTORIES
# ==============================================================================
with tab_sessions:
    st.subheader("🛰️ Active Ingress Geolocation & Impossible Travel Trajectory")
    st.caption("Monitors active administrative ingress points. When an impossible travel anomaly occurs, flight arcs demonstrate velocity violations.")

    col_btn1, col_btn2 = st.columns([3, 1])
    with col_btn2:
        if st.button("🔄 Clear All Quarantines", use_container_width=True):
            enforcer.reset_quarantine()
            st.success("All locks cleared!")
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
        color_discrete_map={"ACTIVE": "#10B981", "CHALLENGED": "#F59E0B", "REVOKED": "#EF4444"},
        size="Risk Score",
        size_max=24,
        template="plotly_dark",
        projection="natural earth"
    )

    # Draw Impossible Travel Arc between D.C. HQ and active session if distant
    curr_lat = float(eval_telemetry.get("lat", 38.8951))
    curr_lon = float(eval_telemetry.get("lon", -77.0364))
    if curr_lat != BASE_OFFICE_COORDS["lat"]:
        fig_map.add_trace(go.Scattergeo(
            lat=[BASE_OFFICE_COORDS["lat"], curr_lat],
            lon=[BASE_OFFICE_COORDS["lon"], curr_lon],
            mode="lines+markers",
            line=dict(width=2, color="#ef4444", dash="dash"),
            marker=dict(size=[8, 12], color=["#00f2fe", "#ef4444"]),
            name=f"Impossible Flight ({eval_telemetry['geo_velocity_kmh']:,.0f} km/h)"
        ))

    fig_map.update_geos(
        showcountries=True,
        countrycolor="#334155",
        showland=True,
        landcolor="#0f172a",
        showocean=True,
        oceancolor="#020617"
    )
    fig_map.update_layout(height=420, margin=dict(l=0, r=0, t=30, b=0), paper_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig_map, use_container_width=True)

    st.dataframe(
        df_sessions.drop(columns=["lat", "lon"]),
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score",
                format="%d",
                min_value=0,
                max_value=100
            ),
        },
        use_container_width=True,
        hide_index=True
    )

# ==============================================================================
# TAB 4: BASELINE DIAGNOSTICS & ANOMALY BOUNDARIES
# ==============================================================================
with tab_model:
    st.subheader("📊 Empirical Baseline Diagnostics & Decision Boundaries")
    baseline_csv = DATA_DIR / "baseline_admin_logs.csv"
    if baseline_csv.exists():
        df_base = pd.read_csv(baseline_csv)
        col_m1, col_m2 = st.columns(2)

        with col_m1:
            fig_diag1 = px.scatter(
                df_base.sample(n=min(len(df_base), 800), random_state=42),
                x="hour_of_day",
                y="data_download_mb",
                color_discrete_sequence=["#38bdf8"],
                opacity=0.45,
                title="Data Egress (MB) vs Access Hour (Baseline Cloud Workday)",
                template="plotly_dark"
            )
            fig_diag1.add_trace(go.Scatter(
                x=[eval_telemetry["hour_of_day"]],
                y=[eval_telemetry["data_download_mb"]],
                mode="markers",
                marker=dict(size=18, color=risk_result["status_color"], symbol="star", line=dict(width=2, color="#ffffff")),
                name="Evaluated Session"
            ))
            fig_diag1.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_diag1, use_container_width=True)

        with col_m2:
            fig_diag2 = px.scatter(
                df_base.sample(n=min(len(df_base), 800), random_state=42),
                x="api_calls_per_min",
                y="sensitive_endpoint_ratio",
                color_discrete_sequence=["#a855f7"],
                opacity=0.45,
                title="Sensitive Route Ratio vs Query Velocity (API Calls/min)",
                template="plotly_dark"
            )
            fig_diag2.add_trace(go.Scatter(
                x=[eval_telemetry["api_calls_per_min"]],
                y=[eval_telemetry["sensitive_endpoint_ratio"]],
                mode="markers",
                marker=dict(size=18, color=risk_result["status_color"], symbol="star", line=dict(width=2, color="#ffffff")),
                name="Evaluated Session"
            ))
            fig_diag2.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_diag2, use_container_width=True)

# ==============================================================================
# TAB 5: SIEM AUDIT TRAIL & TERMINAL STREAM
# ==============================================================================
with tab_siem:
    st.subheader("📜 SIEM Live Security Stream (CEF / Syslog JSON)")
    st.caption("Structured security events emitted to SOC SIEM (Splunk, Elastic, Microsoft Sentinel).")

    if enforcer.audit_log:
        latest = enforcer.audit_log[0]
        st.markdown(f"""
        <div class="cyber-terminal">
            <div><span style="color: #38bdf8;">[{latest['timestamp']}]</span> <span style="color: {('#34d399' if latest['action']=='ALLOW' else ('#fbbf24' if latest['action']=='CHALLENGE' else '#f87171'))}; font-weight: 700;">[{latest['action']}]</span> EVENT_ID: {latest['event_id']}</div>
            <div>&gt; SESSION_REF  : {latest['session_id']} (User: {latest['user_id']})</div>
            <div>&gt; INGRESS_SRC  : {latest['location']} // {latest['source_ip_asn']}</div>
            <div>&gt; RISK_SCORE   : {latest['risk_score']}/100 [DECISION: {latest['state']}]</div>
            <div>&gt; AUDIT_MSG    : {latest['details']}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        df_audit = pd.DataFrame(enforcer.audit_log)
        st.dataframe(
            df_audit[["timestamp", "event_id", "session_id", "user_id", "risk_score", "action", "state", "details"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No audit events recorded.")

# ==============================================================================
# TAB 6: PANEL PRESENTATION & DEFENSE GUIDE
# ==============================================================================
with tab_pitch:
    st.subheader("🎓 Panel Presentation & Defense Pitch")

    st.markdown("""
    <div class="cyber-card">
        <h4 style="color: #00f2fe; margin-top: 0;">📢 The 60-Second Elevator Pitch</h4>
        <blockquote style="border-left: 3px solid #00f2fe; padding-left: 14px; color: #e2e8f0; font-size: 1.05rem; font-style: italic;">
            "Securing public sector cloud registries—like national healthcare registries and social welfare databases—requires moving away from static perimeter firewalls. Traditional authentication verifies credentials once at login (t=0). If those credentials are phished, leaked, or stolen, an adversary has unchecked administrative access.<br><br>
            I built <strong>AegisTrust</strong>: an automated, zero-trust behavioral analysis pipeline that monitors administrative behavior continuously after login. Using an unsupervised <strong>Isolation Forest</strong> model combined with dynamic contextual risk scoring, the system detects anomalous data exfiltration, impossible travel, and privilege probing in real time. When an authenticated session turns malicious, the engine autonomously enforces step-up MFA challenges or immediate session termination and IP quarantining before data can be stolen."
        </blockquote>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("🛡️ 1. Threat Matrix & Detection Mechanics", expanded=True):
        st.markdown("""
        | Threat Vector | Real-World Attack Scenario | Telemetry Flags | Policy Response |
        | :--- | :--- | :--- | :--- |
        | **Stolen DBA Credentials** | Adversary logs in at 3:15 AM to dump 4.8 GB of patient health records. | Extreme Egress Spike + Off-Hours + High Sensitive Ratio. | **REVOKE**: Session destroyed, IP quarantined. |
        | **Session Cookie Theft** | Infostealer malware steals session token; foreign IP issues queries 5 min later. | Impossible Travel (>40,000 km/h Haversine hop). | **REVOKE**: Session killed, token revoked. |
        | **Low & Slow Harvester** | Adversary throttles queries to 18 req/min via TOR at night to evade rate limiters. | Off-hours timing + 88% focus on citizen PII endpoints. | **CHALLENGE / REVOKE**: Step-up MFA blocks bot. |
        | **Privilege Reconnaissance** | Compromised account tests unauthorized endpoints, triggering 403 Forbidden spikes. | Error Burst (6 failures) + High URI entropy. | **CHALLENGE**: Throttled, MFA re-auth required. |
        """)

    with st.expander("🎯 2. High-Impact Panel Q&A Preparation", expanded=False):
        st.markdown("""
        **Q1: Why use Unsupervised Learning (Isolation Forest) instead of Supervised Classification (e.g. XGBoost)?**  
        *Answer:* "In real-world cybersecurity, attack patterns constantly mutate (Zero-Day threats, novel APT exfiltration techniques). Supervised models overfit to known attack signatures. Unsupervised Isolation Forest isolates anomalies simply based on how few tree splits are needed to separate an observation from normal administrative routines. It requires zero labeled attack data, making it naturally resilient to previously unseen threat vectors."

        **Q2: How do you handle False Positives without locking out legitimate admins who have an emergency off-hours shift?**  
        *Answer:* "That is the core strength of our tiered Zero-Trust architecture. An elevated risk score (35-64) does not abruptly lock out the admin. Instead, it issues a **Step-Up Authentication Challenge** (MFA / TOTP prompt) and throttles throughput. If it is a legitimate admin on-call, they simply confirm their identity in 3 seconds and proceed. Full revocation is reserved strictly for high-confidence breaches (Risk > 65), such as impossible travel or gigabyte-scale exfiltration."

        **Q3: How does this scale to production cloud architectures (AWS / Azure / GCP)?**  
        *Answer:* "AegisTrust functions as an asynchronous Policy Decision Point (PDP) under NIST SP 800-207. Telemetry can be streamed from AWS CloudTrail, CloudFront, Azure Sentinel, or an Envoy API gateway via Kafka or Kinesis. The model evaluates sessions sub-second and can push instant revocation commands via Open Policy Agent (OPA), AWS IAM session revocation APIs, or Cloudflare Zero Trust session termination endpoints."
        """)
