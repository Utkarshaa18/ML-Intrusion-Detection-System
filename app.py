import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
import os

from src.live_monitor import analyze_live_traffic
from src.live_model import predict_live
from src.live_agent import calculate_live_risk


# ============================================================
# PAGE CONFIGURATION & METADATA
# ============================================================

st.set_page_config(
    page_title="SentinelAI - Intrusion Detection Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# MODERN CYBERSECURITY UI STYLING
# ============================================================

st.markdown("""
<style>
    /* Global Typography & Background Accents */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    code, pre, [data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container Padding */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    /* Cybersecurity Header Card */
    .cyber-header {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.90) 50%, rgba(15, 23, 42, 0.95) 100%);
        border: 1px solid rgba(56, 189, 248, 0.25);
        border-radius: 16px;
        padding: 24px 30px;
        margin-bottom: 24px;
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    }

    .cyber-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38bdf8 0%, #818cf8 50%, #34d399 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 6px;
        letter-spacing: -0.5px;
    }

    .cyber-subtitle {
        color: #94a3b8;
        font-size: 1.05rem;
        font-weight: 400;
        margin-bottom: 14px;
    }

    /* Status Pill Badges */
    .status-badge {
        display: inline-flex;
        align-items: center;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.82rem;
        font-weight: 600;
        margin-right: 8px;
        border: 1px solid transparent;
    }

    .badge-green {
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border-color: rgba(52, 211, 153, 0.3);
    }

    .badge-blue {
        background: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border-color: rgba(56, 189, 248, 0.3);
    }

    .badge-purple {
        background: rgba(168, 85, 247, 0.15);
        color: #c084fc;
        border-color: rgba(192, 132, 252, 0.3);
    }

    /* Cyber Metric Cards */
    [data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 12px;
        padding: 16px 18px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    [data-testid="stMetric"]:hover {
        border-color: rgba(56, 189, 248, 0.4);
        transform: translateY(-2px);
    }

    [data-testid="stMetricLabel"] {
        font-size: 0.85rem !important;
        color: #94a3b8 !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    [data-testid="stMetricValue"] {
        font-size: 1.8rem !important;
        font-weight: 700 !important;
    }

    /* Security Alert Boxes */
    .alert-card {
        border-radius: 12px;
        padding: 18px 24px;
        margin: 16px 0;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 16px;
    }

    .alert-low {
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.12) 0%, rgba(15, 23, 42, 0.5) 100%);
        border-left: 5px solid #10b981;
        border-top: 1px solid rgba(16, 185, 129, 0.2);
        border-right: 1px solid rgba(16, 185, 129, 0.2);
        border-bottom: 1px solid rgba(16, 185, 129, 0.2);
        color: #e2e8f0;
    }

    .alert-medium {
        background: linear-gradient(90deg, rgba(245, 158, 11, 0.12) 0%, rgba(15, 23, 42, 0.5) 100%);
        border-left: 5px solid #f59e0b;
        border-top: 1px solid rgba(245, 158, 11, 0.2);
        border-right: 1px solid rgba(245, 158, 11, 0.2);
        border-bottom: 1px solid rgba(245, 158, 11, 0.2);
        color: #e2e8f0;
    }

    .alert-high {
        background: linear-gradient(90deg, rgba(249, 115, 22, 0.12) 0%, rgba(15, 23, 42, 0.5) 100%);
        border-left: 5px solid #f97316;
        border-top: 1px solid rgba(249, 115, 22, 0.2);
        border-right: 1px solid rgba(249, 115, 22, 0.2);
        border-bottom: 1px solid rgba(249, 115, 22, 0.2);
        color: #e2e8f0;
    }

    .alert-critical {
        background: linear-gradient(90deg, rgba(239, 68, 68, 0.15) 0%, rgba(15, 23, 42, 0.6) 100%);
        border-left: 5px solid #ef4444;
        border-top: 1px solid rgba(239, 68, 68, 0.2);
        border-right: 1px solid rgba(239, 68, 68, 0.2);
        border-bottom: 1px solid rgba(239, 68, 68, 0.2);
        color: #fee2e2;
    }

    /* Reasoning List Items */
    .reason-box {
        background: rgba(30, 41, 59, 0.4);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 8px;
        padding: 10px 16px;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 12px;
        font-size: 0.95rem;
    }

    /* Buttons */
    .stButton>button {
        border-radius: 10px;
        font-weight: 600;
        padding: 10px 20px;
        transition: all 0.2s ease;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# SYSTEM STATUS CHECK
# ============================================================

model_path = "models/live_isolation_forest.joblib"
scaler_path = "models/live_scaler.joblib"
models_ready = os.path.exists(model_path) and os.path.exists(scaler_path)


# ============================================================
# HEADER SECTION
# ============================================================

st.markdown("""
<div class="cyber-header">
    <div class="cyber-title">🛡️ SentinelAI Threat Intelligence Engine</div>
    <div class="cyber-subtitle">Real-Time Network Intrusion Detection, Isolation Forest AI Anomaly Scoring & Explainable Security Agent</div>
    <div>
        <span class="status-badge badge-green">🟢 AI Engine Calibrated</span>
        <span class="status-badge badge-blue">📡 Network Sensor Active</span>
        <span class="status-badge badge-purple">⚡ Streamlit Cloud Ready</span>
    </div>
</div>
""", unsafe_allow_html=True)

if not models_ready:
    st.error("⚠️ AI Model artifacts not found. Please run `python src/train_live_model.py` to initialize models.")


# ============================================================
# PRE-CONFIGURED SCENARIOS REPOSITORY
# ============================================================

PRESET_SCENARIOS = {
    "🟢 Normal Web Browsing (HTTPS)": {
        "tag": "BENIGN",
        "description": "Standard interactive user browsing: visiting websites, reading documentation, CDN assets. Balanced client-server flow with moderate packet rates.",
        "features": {
            "duration": 5, "total_packets": 240, "total_bytes": 210000,
            "packets_per_second": 48.0, "bytes_per_second": 42000.0,
            "tcp_packets": 210, "udp_packets": 30, "incoming_packets": 180, "outgoing_packets": 60,
            "forward_packets": 60, "backward_packets": 180, "forward_bytes": 35000, "backward_bytes": 175000,
            "unique_sources": 1, "unique_destinations": 18
        }
    },
    "🟢 Idle System & Background Telemetry": {
        "tag": "BENIGN",
        "description": "Desktop in idle state: periodic DNS lookups, NTP clock synchronizations, lightweight OS telemetry, and application keep-alive beacons.",
        "features": {
            "duration": 5, "total_packets": 22, "total_bytes": 12000,
            "packets_per_second": 4.4, "bytes_per_second": 2400.0,
            "tcp_packets": 15, "udp_packets": 7, "incoming_packets": 14, "outgoing_packets": 8,
            "forward_packets": 8, "backward_packets": 14, "forward_bytes": 2500, "backward_bytes": 9500,
            "unique_sources": 1, "unique_destinations": 5
        }
    },
    "🟢 High-Definition Media Streaming": {
        "tag": "BENIGN",
        "description": "High-bandwidth entertainment stream (YouTube/Netflix): sustained inbound packet delivery, high byte throughput, low outbound request ratio.",
        "features": {
            "duration": 5, "total_packets": 920, "total_bytes": 4500000,
            "packets_per_second": 184.0, "bytes_per_second": 900000.0,
            "tcp_packets": 890, "udp_packets": 30, "incoming_packets": 780, "outgoing_packets": 140,
            "forward_packets": 140, "backward_packets": 780, "forward_bytes": 65000, "backward_bytes": 4435000,
            "unique_sources": 1, "unique_destinations": 22
        }
    },
    "🔴 SYN Flood Attack (Denial of Service)": {
        "tag": "ATTACK - DoS",
        "description": "Volumetric TCP SYN flood: rapid generation of thousands of unacknowledged SYN packets. 100% outbound traffic with zero inbound responses.",
        "features": {
            "duration": 5, "total_packets": 9800, "total_bytes": 588000,
            "packets_per_second": 1960.0, "bytes_per_second": 117600.0,
            "tcp_packets": 9800, "udp_packets": 0, "incoming_packets": 0, "outgoing_packets": 9800,
            "forward_packets": 9800, "backward_packets": 0, "forward_bytes": 588000, "backward_bytes": 0,
            "unique_sources": 1, "unique_destinations": 1
        }
    },
    "🟠 Port Scan / Network Reconnaissance": {
        "tag": "ATTACK - RECON",
        "description": "Horizontal host and port sweep: probing hundreds of remote endpoints in seconds to discover exposed services and vulnerable ports.",
        "features": {
            "duration": 5, "total_packets": 1650, "total_bytes": 99000,
            "packets_per_second": 330.0, "bytes_per_second": 19800.0,
            "tcp_packets": 1620, "udp_packets": 30, "incoming_packets": 20, "outgoing_packets": 1630,
            "forward_packets": 1630, "backward_packets": 20, "forward_bytes": 96000, "backward_bytes": 3000,
            "unique_sources": 1, "unique_destinations": 320
        }
    },
    "🟠 Data Exfiltration (Outbound Spill)": {
        "tag": "ATTACK - EXFIL",
        "description": "Sensitive data theft / C2 exfiltration: massive outbound upload volume with disproportionately low inbound traffic.",
        "features": {
            "duration": 5, "total_packets": 2200, "total_bytes": 16500000,
            "packets_per_second": 440.0, "bytes_per_second": 3300000.0,
            "tcp_packets": 2180, "udp_packets": 20, "incoming_packets": 90, "outgoing_packets": 2110,
            "forward_packets": 2110, "backward_packets": 90, "forward_bytes": 16350000, "backward_bytes": 150000,
            "unique_sources": 1, "unique_destinations": 3
        }
    }
}


# ============================================================
# INPUT MODE TABS
# ============================================================

st.markdown("### 🎛️ Traffic Assessment Console")

tab_live, tab_presets, tab_custom = st.tabs([
    "📡 Live Network Sniffer",
    "🧪 Traffic Profiles & Attack Scenarios (Dropdown)",
    "⚙️ Custom Parameter Simulator"
])

features_to_analyze = None
source_label = ""

with tab_live:
    st.write("Capture real network packets directly from your active interface and run live anomaly inference:")
    col_l1, col_l2 = st.columns([3, 1])
    with col_l1:
        duration = st.slider("Live Sniffer Duration (seconds)", min_value=3, max_value=15, value=5, step=1, key="live_dur")
    with col_l2:
        st.write("")
        st.write("")
        btn_live = st.button("🚀 Capture & Analyze Live Traffic", use_container_width=True, type="primary")

    if btn_live:
        with st.spinner(f"🔍 Monitoring network interface for {duration} seconds... Browse web or test applications."):
            try:
                features_to_analyze = analyze_live_traffic(duration)
                source_label = f"Live Interface Capture ({duration}s)"
            except Exception as e:
                st.error(f"❌ Network capture failed: {e}")

with tab_presets:
    st.write("Select a pre-configured traffic profile from the dropdown to test model predictions and agent explainability:")
    selected_scenario = st.selectbox(
        "Choose Network Profile / Scenario:",
        list(PRESET_SCENARIOS.keys()),
        key="preset_sel"
    )
    preset_data = PRESET_SCENARIOS[selected_scenario]
    
    st.info(f"**[{preset_data['tag']}]** {preset_data['description']}")
    
    col_p1, col_p2 = st.columns([3, 1])
    with col_p2:
        btn_preset = st.button("⚡ Evaluate Selected Scenario", use_container_width=True, type="primary")

    if btn_preset:
        features_to_analyze = preset_data["features"].copy()
        source_label = selected_scenario

with tab_custom:
    st.write("Construct an arbitrary traffic profile by tweaking granular parameters:")
    c1, c2, c3 = st.columns(3)
    with c1:
        cust_dur = st.number_input("Capture Duration (s)", min_value=1, max_value=30, value=5)
        cust_pkts = st.number_input("Total Packets", min_value=1, max_value=50000, value=250)
    with c2:
        cust_bytes = st.number_input("Total Bytes (B)", min_value=100, max_value=100_000_000, value=200000)
        cust_fwd_ratio = st.slider("Outbound Packet Ratio", min_value=0.0, max_value=1.0, value=0.30, step=0.05)
    with c3:
        cust_dest = st.number_input("Unique Target Hosts", min_value=1, max_value=2000, value=15)
        cust_tcp_ratio = st.slider("TCP Protocol Ratio", min_value=0.0, max_value=1.0, value=0.90, step=0.05)

    btn_custom = st.button("🔬 Analyze Custom Flow", use_container_width=True, type="primary")
    if btn_custom:
        fwd_p = int(cust_pkts * cust_fwd_ratio)
        bwd_p = max(0, cust_pkts - fwd_p)
        fwd_b = int(cust_bytes * cust_fwd_ratio)
        bwd_b = max(0, cust_bytes - fwd_b)
        tcp_p = int(cust_pkts * cust_tcp_ratio)
        udp_p = max(0, cust_pkts - tcp_p)

        features_to_analyze = {
            "duration": cust_dur,
            "total_packets": cust_pkts,
            "total_bytes": cust_bytes,
            "packets_per_second": cust_pkts / cust_dur if cust_dur > 0 else 0,
            "bytes_per_second": cust_bytes / cust_dur if cust_dur > 0 else 0,
            "tcp_packets": tcp_p,
            "udp_packets": udp_p,
            "incoming_packets": bwd_p,
            "outgoing_packets": fwd_p,
            "forward_packets": fwd_p,
            "backward_packets": bwd_p,
            "forward_bytes": fwd_b,
            "backward_bytes": bwd_b,
            "unique_sources": 1,
            "unique_destinations": cust_dest
        }
        source_label = "Custom Parameter Simulation"


# ============================================================
# PERSISTENCE & INFERENCE
# ============================================================

if features_to_analyze is not None:
    st.session_state["last_features"] = features_to_analyze
    st.session_state["source_label"] = source_label

    prediction, anomaly_score = predict_live(features_to_analyze)
    risk, level, reasons = calculate_live_risk(features_to_analyze, prediction)

    st.session_state["prediction"] = prediction
    st.session_state["anomaly_score"] = anomaly_score
    st.session_state["risk"] = risk
    st.session_state["level"] = level
    st.session_state["reasons"] = reasons


# ============================================================
# RESULTS DASHBOARD
# ============================================================

if "last_features" in st.session_state:
    feat = st.session_state["last_features"]
    prediction = st.session_state["prediction"]
    anomaly_score = st.session_state["anomaly_score"]
    risk = st.session_state["risk"]
    level = st.session_state["level"]
    reasons = st.session_state["reasons"]
    source = st.session_state.get("source_label", "Analyzed Traffic")

    st.divider()
    st.markdown(f"## 📊 Security Intelligence Dashboard: `{source}`")

    # ----------------------------------------------------
    # ROW 1: PRIMARY KPI METRICS
    # ----------------------------------------------------
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.metric("AI Anomaly Classification", prediction, delta="Normal Baseline" if prediction == "NORMAL" else "Anomaly Detected", delta_color="normal" if prediction == "NORMAL" else "inverse")
    with kpi2:
        st.metric("Risk Score", f"{risk} / 100", delta=f"{100 - risk}% Trust Score")
    with kpi3:
        st.metric("Threat Category", level)
    with kpi4:
        st.metric("Model Decision Score", f"{anomaly_score:.4f}", help="Isolation Forest decision score. Positive scores indicate typical benign clustering; negative scores indicate rare outliers.")

    # ----------------------------------------------------
    # ROW 2: SECURITY STATUS BANNER
    # ----------------------------------------------------
    alert_class = f"alert-{level.lower()}"
    alert_icon = "🟢" if level == "LOW" else ("🟡" if level == "MEDIUM" else ("🟠" if level == "HIGH" else "🔴"))
    alert_text = (
        f"**{level} RISK ({risk}/100)** — Flow telemetry closely matches standard benign desktop profile. No threat signatures observed."
        if level == "LOW" else
        f"**{level} RISK ({risk}/100)** — Elevated traffic thresholds or anomalous transmission patterns observed. Agent recommends inspection."
    )
    st.markdown(f"""
    <div class="alert-card {alert_class}">
        <span style="font-size: 1.8rem;">{alert_icon}</span>
        <div>{alert_text}</div>
    </div>
    """, unsafe_allow_html=True)

    # ----------------------------------------------------
    # ROW 3: EXPLAINABILITY & RECOMMENDED ACTION
    # ----------------------------------------------------
    col_reas, col_act = st.columns([3, 2])
    with col_reas:
        st.markdown("#### 🤖 Explainable Agent Diagnostics")
        st.caption("Heuristic reasoning behind the risk calculation:")
        for r in reasons:
            st.markdown(f"""
            <div class="reason-box">
                <span style="color: #38bdf8;">✦</span>
                <span>{r}</span>
            </div>
            """, unsafe_allow_html=True)

    with col_act:
        st.markdown("#### 🛡️ Incident Response Recommendation")
        if level == "LOW":
            st.success("✅ **Status Benign**: Network traffic is healthy. Continue continuous baseline monitoring.")
        elif level == "MEDIUM":
            st.warning("⚠️ **Review Flow**: High connection counts or active background transfers detected. Check open browser tabs or background updaters.")
        elif level == "HIGH":
            st.warning("⚠️ **Security Alert**: Potential port scan or excessive asymmetry. Inspect destination IPs and inspect network firewall rules.")
        else:
            st.error("🚨 **Critical Threat**: Volumetric attack or exfiltration signature detected. Apply automated IP throttling or rate-limiting.")

    # ----------------------------------------------------
    # ROW 4: INTERACTIVE VISUALIZATIONS
    # ----------------------------------------------------
    st.divider()
    st.markdown("#### 📈 Network Flow & Protocol Analytics")
    v1, v2 = st.columns(2)

    with v1:
        # Directional Packet Distribution
        dir_data = pd.DataFrame({
            "Direction": ["Inbound (Backward)", "Outbound (Forward)"],
            "Packets": [feat.get("backward_packets", 0), feat.get("forward_packets", 0)],
            "Color": ["#38bdf8", "#818cf8"]
        })
        chart_dir = alt.Chart(dir_data).mark_bar(cornerRadius=6).encode(
            x=alt.X("Direction:N", title="Traffic Direction", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("Packets:Q", title="Packet Count"),
            color=alt.Color("Direction:N", scale=alt.Scale(domain=["Inbound (Backward)", "Outbound (Forward)"], range=["#38bdf8", "#818cf8"]), legend=None),
            tooltip=["Direction", "Packets"]
        ).properties(title="Packet Direction Symmetry (Inbound vs Outbound)", height=220)
        st.altair_chart(chart_dir, use_container_width=True)

    with v2:
        # Protocol Distribution
        proto_data = pd.DataFrame({
            "Protocol": ["TCP Packets", "UDP Packets"],
            "Count": [feat.get("tcp_packets", 0), feat.get("udp_packets", 0)]
        })
        chart_proto = alt.Chart(proto_data).mark_bar(cornerRadius=6).encode(
            x=alt.X("Protocol:N", title="Transport Layer Protocol", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("Count:Q", title="Packet Count"),
            color=alt.Color("Protocol:N", scale=alt.Scale(domain=["TCP Packets", "UDP Packets"], range=["#34d399", "#f59e0b"]), legend=None),
            tooltip=["Protocol", "Count"]
        ).properties(title="Transport Protocol Breakdown (TCP vs UDP)", height=220)
        st.altair_chart(chart_proto, use_container_width=True)

    # ----------------------------------------------------
    # ROW 5: TELEMETRY GRID
    # ----------------------------------------------------
    t1, t2, t3, t4 = st.columns(4)
    with t1:
        st.metric("Total Transferred", f"{feat['total_bytes']:,} Bytes")
    with t2:
        st.metric("Packet Rate", f"{feat['packets_per_second']:.1f} pps")
    with t3:
        st.metric("Bandwidth Throughput", f"{feat['bytes_per_second'] / 1024:.2f} KB/s")
    with t4:
        st.metric("Remote Target Hosts", f"{feat.get('unique_destinations', 1):,}")

    # ----------------------------------------------------
    # ROW 6: INSPECTION TABLES
    # ----------------------------------------------------
    with st.expander("🔍 Detailed Flow Telemetry Table"):
        feature_table = pd.DataFrame(
            list(feat.items()),
            columns=["Flow Feature", "Observed Value"]
        )
        feature_table["Observed Value"] = feature_table["Observed Value"].astype(str)
        st.dataframe(feature_table, use_container_width=True, hide_index=True)


# ============================================================
# KNOWLEDGE HUB & THREAT DIFFERENTIATION
# ============================================================

st.divider()

with st.expander("💡 Threat Intelligence Hub: How SentinelAI Differentiates Normal vs. Malicious Traffic"):
    st.markdown("""
    ### 🟢 What defines **NORMAL** Network Traffic?
    In day-to-day computer usage (web browsing, cloud productivity, video streaming):
    1. **Bidirectional Request-Response Symmetry**:
       - When a computer visits a website or streams media, it transmits small client requests (**Forward Packets**) and receives larger, multi-packet payloads (**Backward Packets**).
       - Typical benign ratio: **20% to 40% forward**, **60% to 80% backward**.
    2. **Reasonable Transmission Rates**:
       - Everyday browsing typically produces **10 to 100 packets/sec**.
       - HD video streaming produces **100 to 300 packets/sec** with high inbound byte volume.
    3. **Controlled Remote Endpoints**:
       - Normal browsing connects to a realistic set of CDN nodes and cloud servers (**5 to 50 unique destinations**).
    - **Classification**: **`NORMAL`**, Decision Score > 0, Risk Score: **`0 - 25/100 (LOW)`**.

    ---

    ### 🔴 What defines **MALICIOUS / SUSPICIOUS** Traffic?
    Cyberattack vectors fundamentally break normal protocol dynamics:
    - **SYN Flood / Volumetric DoS (`CRITICAL RISK`)**:
      - Attacker transmits thousands of packets per second (**> 1,500 pps**).
      - **100% Outbound, 0% Inbound Responses**: The attacker floods TCP SYN requests without completing the handshake.
    - **Port Scanning & Host Reconnaissance (`HIGH RISK`)**:
      - Automated scanners (e.g. Nmap) rapidly probe hundreds or thousands of distinct IP addresses or ports in seconds.
      - **High Destination Fan-Out (> 150 - 300 targets)** with minimal payload transfer.
    - **Data Exfiltration / C2 Exfil (`HIGH RISK`)**:
      - Severe byte asymmetry where outbound uploads dramatically outweigh inbound traffic.
    """)