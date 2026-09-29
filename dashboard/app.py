"""
AegisTrust: Intelligent Zero-Trust Behavioral Authentication Dashboard.
Interactive Demonstration & Security Operations Center for Public Cloud Infrastructures.
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
    page_title="AegisTrust | Zero-Trust Behavioral Authentication",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Modern Dark Glassmorphic Dashboard Design)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .mono-font {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Cosmic Dark Background */
    .stApp {
        background: radial-gradient(circle at 12% 12%, #0d1830 0%, #070b16 55%, #03050a 100%);
        color: #e2e8f0;
    }

    /* Polished Metric & KPI Card */
    div[data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.72) !important;
        backdrop-filter: blur(14px) !important;
        -webkit-backdrop-filter: blur(14px) !important;
        border: 1px solid rgba(56, 189, 248, 0.2) !important;
        border-radius: 12px !important;
        padding: 16px 20px !important;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.45), inset 0 0 10px rgba(56, 189, 248, 0.04) !important;
        transition: transform 0.2s ease, border-color 0.2s ease !important;
    }
    div[data-testid="stMetric"]:hover {
        border-color: rgba(56, 189, 248, 0.5) !important;
        transform: translateY(-2px) !important;
    }
    div[data-testid="stMetric"] label {
        color: #94a3b8 !important;
        font-weight: 500 !important;
        font-size: 0.82rem !important;
        letter-spacing: 0.06em !important;
        text-transform: uppercase !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        font-weight: 700 !important;
        font-size: 2.1rem !important;
        color: #f8fafc !important;
    }

    /* Modern Styled Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: rgba(15, 23, 42, 0.55);
        padding: 6px 10px;
        border-radius: 12px;
        border: 1px solid rgba(51, 65, 85, 0.45);
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 18px;
        border-radius: 8px;
        color: #94a3b8;
        font-weight: 500;
        font-size: 0.9rem;
        transition: all 0.2s ease;
        border: none;
    }
    .stTabs [data-baseweb="tab"]:hover {
        color: #38bdf8;
        background: rgba(56, 189, 248, 0.08);
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(56, 189, 248, 0.18) 0%, rgba(99, 102, 241, 0.18) 100%) !important;
        color: #38bdf8 !important;
        border: 1px solid rgba(56, 189, 248, 0.4) !important;
        box-shadow: 0 4px 14px rgba(56, 189, 248, 0.15);
    }

    /* Glowing Pulse Live Dot */
    .pulse-dot {
        height: 9px;
        width: 9px;
        background-color: #00f2fe;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 10px #00f2fe;
        animation: pulse-glow 2s infinite;
        margin-right: 6px;
    }
    @keyframes pulse-glow {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 242, 254, 0.7); }
        70% { transform: scale(1.15); box-shadow: 0 0 0 7px rgba(0, 242, 254, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 242, 254, 0); }
    }

    /* Monospace Tech Tag */
    .tech-pill {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #38bdf8;
        background: rgba(56, 189, 248, 0.1);
        border: 1px solid rgba(56, 189, 248, 0.25);
        padding: 3px 8px;
        border-radius: 4px;
        margin-left: 6px;
    }

    /* Decision Box Styling */
    .decision-container-allow {
        background: rgba(11, 35, 27, 0.7);
        border: 1px solid rgba(16, 185, 129, 0.45);
        border-radius: 12px;
        padding: 18px 22px;
        box-shadow: 0 8px 30px rgba(16, 185, 129, 0.15);
        margin-bottom: 14px;
    }
    .decision-container-challenge {
        background: rgba(42, 28, 12, 0.7);
        border: 1px solid rgba(245, 158, 11, 0.45);
        border-radius: 12px;
        padding: 18px 22px;
        box-shadow: 0 8px 30px rgba(245, 158, 11, 0.15);
        margin-bottom: 14px;
    }
    .decision-container-revoke {
        background: rgba(42, 14, 22, 0.7);
        border: 1px solid rgba(239, 68, 68, 0.45);
        border-radius: 12px;
        padding: 18px 22px;
        box-shadow: 0 8px 30px rgba(239, 68, 68, 0.2);
        margin-bottom: 14px;
    }

    /* Status Badges */
    .badge-allow {
        background: rgba(16, 185, 129, 0.18);
        color: #34d399;
        border: 1px solid rgba(52, 211, 153, 0.4);
        padding: 5px 12px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-challenge {
        background: rgba(245, 158, 11, 0.18);
        color: #fbbf24;
        border: 1px solid rgba(251, 191, 36, 0.4);
        padding: 5px 12px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-revoke {
        background: rgba(239, 68, 68, 0.18);
        color: #f87171;
        border: 1px solid rgba(248, 113, 113, 0.4);
        padding: 5px 12px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 0.85rem;
    }

    /* Streamlit Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease;
        border: 1px solid rgba(56, 189, 248, 0.3);
    }
    .stButton > button:hover {
        box-shadow: 0 0 16px rgba(56, 189, 248, 0.25);
        border-color: #38bdf8;
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
    # Populate initial realistic active sessions
    generator = TelemetryGenerator(seed=99)
    sample_normal = generator.generate_baseline(n_samples=5)
    for _, row in sample_normal.iterrows():
        t_dict = row.to_dict()
        x = pipeline.transform(t_dict)
        _, intensity = detector.predict_anomaly(x)
        res = risk_engine.calculate_risk(t_dict, intensity[0])
        st.session_state["enforcer"].register_or_update_session(t_dict, res)

enforcer = st.session_state["enforcer"]

# Sidebar Configuration & Telemetry Inputs
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
        <span class="pulse-dot"></span>
        <span style="font-weight: 700; letter-spacing: 0.08em; color: #00f2fe; font-size: 1.05rem;">AEGISTRUST SOC</span>
    </div>
    <div style="color: #64748b; font-size: 0.8rem; margin-bottom: 14px;">
        Continuous Zero-Trust Post-Auth Defense
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
    st.caption("Modify behavioral signals in real time:")

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

# Main Application Layout: Polished Hero Header
st.markdown("""
<div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 18px; border-bottom: 1px solid rgba(56, 189, 248, 0.18); padding-bottom: 16px;">
    <div>
        <div style="display: flex; align-items: center; margin-bottom: 6px;">
            <span class="pulse-dot"></span>
            <span style="font-family: 'JetBrains Mono'; font-size: 0.8rem; color: #00f2fe; letter-spacing: 0.1em; text-transform: uppercase;">Zero-Trust Telemetry Engine // Public Cloud Infrastructures</span>
        </div>
        <h1 style="margin: 0; font-size: 2.1rem; font-weight: 700; color: #ffffff; letter-spacing: -0.01em;">
            🛡️ Intelligent Zero-Trust Behavioral Authentication
        </h1>
        <div style="color: #94a3b8; font-size: 0.95rem; margin-top: 4px;">
            Continuous, AI-powered post-authentication telemetry monitoring & automated risk containment.
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

st.markdown("<br>", unsafe_allow_html=True)

# Tabs
tab_live, tab_sessions, tab_model, tab_siem, tab_pitch = st.tabs([
    "🚀 Live Simulation & Enforcement",
    "🛰️ Active Sessions & Incident Map",
    "📊 Baseline Telemetry & ML Diagnostics",
    "📜 SIEM Audit Trail & Event Stream",
    "🎤 Panel Presentation & Defense Pitch"
])

# ==============================================================================
# TAB 1: LIVE ATTACK SIMULATOR & POLICY ENFORCEMENT
# ==============================================================================
with tab_live:
    st.subheader("Real-Time Behavioral Telemetry Evaluation")

    # Evaluate the telemetry
    x_input = pipeline.transform(eval_telemetry)
    _, anomaly_intensity = detector.predict_anomaly(x_input)
    risk_result = risk_engine.calculate_risk(eval_telemetry, anomaly_intensity[0])

    # Register/Update session state
    session_record = enforcer.register_or_update_session(eval_telemetry, risk_result)

    col_gauge, col_decision = st.columns([1, 1.4])

    with col_gauge:
        # Plotly Gauge Chart for Risk Score
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_result["risk_score"],
            title={"text": "Continuous Risk Score", "font": {"size": 22, "color": "#f8fafc"}},
            number={"suffix": "/100", "font": {"size": 36, "color": risk_result["status_color"]}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#94a3b8"},
                "bar": {"color": risk_result["status_color"], "thickness": 0.28},
                "bgcolor": "#1e293b",
                "borderwidth": 1,
                "bordercolor": "#475569",
                "steps": [
                    {"range": [0, RISK_THRESHOLD_ALLOW], "color": "rgba(16, 185, 129, 0.2)"},
                    {"range": [RISK_THRESHOLD_ALLOW, RISK_THRESHOLD_CHALLENGE], "color": "rgba(245, 158, 11, 0.25)"},
                    {"range": [RISK_THRESHOLD_CHALLENGE, 100], "color": "rgba(239, 68, 68, 0.3)"}
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
                <span style="font-family: 'JetBrains Mono'; font-size: 0.8rem; letter-spacing: 0.08em; color: #94a3b8; text-transform: uppercase;">Zero-Trust Policy Verdict</span>
                <span class="{badge_class}">{action} // {tier_title}</span>
            </div>
            <h3 style="margin: 0 0 10px 0; color: #f8fafc; font-size: 1.25rem;">{risk_result['action_description']}</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.88rem; color: #cbd5e1; margin-top: 12px; border-top: 1px solid rgba(255, 255, 255, 0.1); padding-top: 10px;">
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

    st.divider()

    # Explainable AI (XAI) Attribution Breakdown
    st.subheader("🔍 Explainable AI (XAI): Feature Attribution & Deviation from Baseline")
    st.caption("Breaks down standard deviations from administrative norm for auditor transparency.")

    explanations = pipeline.explain_deviations(eval_telemetry)
    df_exp = pd.DataFrame(explanations)

    col_xai_plot, col_xai_table = st.columns([1.2, 1])
    with col_xai_plot:
        # Bar chart of z-scores
        fig_xai = px.bar(
            df_exp,
            x="z_deviation",
            y="feature",
            orientation="h",
            color="severity",
            color_discrete_map={"NORMAL": "#10B981", "ELEVATED": "#F59E0B", "HIGH": "#F97316", "CRITICAL": "#EF4444"},
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
# TAB 2: ACTIVE SESSIONS MONITOR & INCIDENT MAP
# ==============================================================================
with tab_sessions:
    st.subheader("Administrative Session Monitor & Threat Map")

    # Interactive session reset button
    col_hdr1, col_hdr2 = st.columns([3, 1])
    with col_hdr2:
        if st.button("🔄 Reset Quarantine / Clear Locks"):
            enforcer.reset_quarantine()
            st.success("All locks and session quarantines cleared!")
            st.rerun()

    # Convert active sessions to DataFrame
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

    # Plotly Geographic Map
    fig_map = px.scatter_geo(
        df_sessions,
        lat="lat",
        lon="lon",
        hover_name="Admin User",
        hover_data=["Session ID", "Location", "Risk Score", "State"],
        color="State",
        color_discrete_map={"ACTIVE": "#10B981", "CHALLENGED": "#F59E0B", "REVOKED": "#EF4444"},
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
        landcolor="#1e293b",
        showocean=True,
        oceancolor="#0f172a"
    )
    fig_map.update_layout(height=420, margin=dict(l=0, r=0, t=40, b=0), paper_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig_map, use_container_width=True)

    # Sessions Table
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
# TAB 3: BASELINE TELEMETRY & ML DIAGNOSTICS
# ==============================================================================
with tab_model:
    st.subheader("Machine Learning Baseline & Anomaly Boundary Diagnostics")
    st.markdown("""
    The model was trained on **3,500 baseline administrative sessions** across routine public healthcare/welfare databases.
    Below is the empirical distribution of normal activity versus detected attack vectors.
    """)

    baseline_csv = DATA_DIR / "baseline_admin_logs.csv"
    if baseline_csv.exists():
        df_base = pd.read_csv(baseline_csv)

        col_m1, col_m2 = st.columns(2)
        with col_m1:
            # Hour of Day vs API Calls
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
            # Overlay current test point
            fig_scatter1.add_trace(go.Scatter(
                x=[eval_telemetry["hour_of_day"]],
                y=[eval_telemetry["data_download_mb"]],
                mode="markers",
                marker=dict(size=16, color=risk_result["status_color"], symbol="star"),
                name="Current Evaluated Session"
            ))
            fig_scatter1.update_layout(height=350, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_scatter1, use_container_width=True)

        with col_m2:
            # API Calls vs Sensitive Ratio
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
            # Overlay current test point
            fig_scatter2.add_trace(go.Scatter(
                x=[eval_telemetry["api_calls_per_min"]],
                y=[eval_telemetry["sensitive_endpoint_ratio"]],
                mode="markers",
                marker=dict(size=16, color=risk_result["status_color"], symbol="star"),
                name="Current Evaluated Session"
            ))
            fig_scatter2.update_layout(height=350, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_scatter2, use_container_width=True)

        # Baseline Statistics Table
        st.subheader("Baseline Feature Distribution Statistics (Training Set)")
        st.dataframe(df_base[pipeline.features].describe().T[["mean", "std", "min", "50%", "max"]], use_container_width=True)

# ==============================================================================
# TAB 4: SIEM AUDIT TRAIL & EVENT STREAM
# ==============================================================================
with tab_siem:
    st.subheader("Security Information and Event Management (SIEM) Stream")
    st.caption("Common Event Format (CEF) / JSON security audit log stream ready for ingestion into Splunk, Microsoft Sentinel, or Elastic SIEM.")

    if enforcer.audit_log:
        latest = enforcer.audit_log[0]
        status_col = "#34d399" if latest["action"] == "ALLOW" else ("#fbbf24" if latest["action"] == "CHALLENGE" else "#f87171")
        st.markdown(f"""
        <div style="background: rgba(2, 6, 18, 0.85); border: 1px solid rgba(56, 189, 248, 0.25); border-left: 3px solid #00f2fe; border-radius: 8px; padding: 12px 16px; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #94a3b8; line-height: 1.6; margin-bottom: 14px;">
            <div><span style="color: #38bdf8;">[{latest['timestamp']}]</span> <span style="color: {status_col}; font-weight: 700;">[{latest['action']}]</span> EVENT_ID: {latest['event_id']}</div>
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
# TAB 5: PANEL PRESENTATION & DEFENSE PITCH
# ==============================================================================
with tab_pitch:
    st.subheader("🎓 Development Pitch & Evaluation Defense Guide")
    st.markdown("""
    Use the structured talking points below when pitching and defending this project before an academic or industry evaluation panel.
    """)

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

        **Q3: How does this integrate with modern cloud infrastructure like AWS or Azure?**  
        *Answer:* "AegisTrust is designed to act as an asynchronous Policy Decision Point (PDP). Telemetry can be streamed from AWS CloudTrail, CloudFront, Azure Sentinel, or an Envoy API gateway via Kafka or Kinesis. The model evaluates sessions sub-second and can push instant revocation commands via Open Policy Agent (OPA), AWS IAM session revocation APIs, or Cloudflare Zero Trust session termination endpoints."
        """)
