import streamlit as st
import pandas as pd
import os

from src.live_monitor import analyze_live_traffic
from src.live_model import predict_live
from src.live_agent import calculate_live_risk


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Intrusion Detection Engine",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Intrusion Detection Engine")
st.caption("AI-Powered Live Network Monitoring, Anomaly Detection & Risk Analysis Agent")

st.write(
    "SentinelAI analyzes network traffic dynamics in real time using an **Isolation Forest AI Anomaly Detector** "
    "combined with an **Explainable Security Agent** to differentiate benign everyday activity from malicious intrusions."
)

st.divider()


# ============================================================
# SYSTEM STATUS
# ============================================================

model_path = "models/live_isolation_forest.joblib"
scaler_path = "models/live_scaler.joblib"

if os.path.exists(model_path) and os.path.exists(scaler_path):
    st.success("🟢 Live AI Model: Calibrated & Ready")
else:
    st.error(
        "🔴 Live AI Model: Not Found\n\n"
        "Please train the live model first using `python src/train_live_model.py`."
    )

st.divider()


# ============================================================
# TRAFFIC SCENARIOS PRESETS
# ============================================================

PRESET_SCENARIOS = {
    "🟢 Normal Web Browsing (HTTPS)": {
        "description": "Typical client browsing websites, news, or articles. Modest packet rates, balanced bidirectional traffic, small request payloads, and standard response payloads.",
        "features": {
            "duration": 5, "total_packets": 240, "total_bytes": 210000,
            "packets_per_second": 48.0, "bytes_per_second": 42000.0,
            "tcp_packets": 210, "udp_packets": 30, "incoming_packets": 180, "outgoing_packets": 60,
            "forward_packets": 60, "backward_packets": 180, "forward_bytes": 35000, "backward_bytes": 175000,
            "unique_sources": 1, "unique_destinations": 18
        }
    },
    "🟢 Idle System & Background Telemetry": {
        "description": "PC in an idle state. Background OS queries, NTP time-sync, lightweight cloud sync, and periodic keep-alive beacons.",
        "features": {
            "duration": 5, "total_packets": 22, "total_bytes": 12000,
            "packets_per_second": 4.8, "bytes_per_second": 2400.0,
            "tcp_packets": 15, "udp_packets": 7, "incoming_packets": 14, "outgoing_packets": 8,
            "forward_packets": 8, "backward_packets": 15, "forward_bytes": 2500, "backward_bytes": 9500,
            "unique_sources": 1, "unique_destinations": 5
        }
    },
    "🟢 Media & Video Streaming (YouTube/Netflix)": {
        "description": "High-throughput benign entertainment stream. High incoming payload volume, stable packet rates, and low outbound request volume.",
        "features": {
            "duration": 5, "total_packets": 920, "total_bytes": 4500000,
            "packets_per_second": 184.0, "bytes_per_second": 900000.0,
            "tcp_packets": 890, "udp_packets": 30, "incoming_packets": 780, "outgoing_packets": 140,
            "forward_packets": 140, "backward_packets": 780, "forward_bytes": 65000, "backward_bytes": 4435000,
            "unique_sources": 1, "unique_destinations": 22
        }
    },
    "🔴 SYN Flood Attack (Denial of Service)": {
        "description": "Malicious volumetric DoS: Extremely high packet rate with 100% outbound TCP SYN packets and zero server responses.",
        "features": {
            "duration": 5, "total_packets": 9800, "total_bytes": 588000,
            "packets_per_second": 1960.0, "bytes_per_second": 117600.0,
            "tcp_packets": 9800, "udp_packets": 0, "incoming_packets": 0, "outgoing_packets": 9800,
            "forward_packets": 9800, "backward_packets": 0, "forward_bytes": 588000, "backward_bytes": 0,
            "unique_sources": 1, "unique_destinations": 1
        }
    },
    "🟠 Port Scan / Network Reconnaissance": {
        "description": "Malicious sweep: Rapid probing across hundreds of distinct destination IP addresses or ports within seconds.",
        "features": {
            "duration": 5, "total_packets": 1650, "total_bytes": 99000,
            "packets_per_second": 330.0, "bytes_per_second": 19800.0,
            "tcp_packets": 1620, "udp_packets": 30, "incoming_packets": 20, "outgoing_packets": 1630,
            "forward_packets": 1630, "backward_packets": 20, "forward_bytes": 96000, "backward_bytes": 3000,
            "unique_sources": 1, "unique_destinations": 320
        }
    },
    "🟠 Data Exfiltration (Outbound Spill)": {
        "description": "Malicious data breach: Disproportionate outbound byte transfer with minimal inbound responses.",
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
# INPUT MODE SELECTION
# ============================================================

st.subheader("⚙️ Traffic Input Source & Settings")

input_mode = st.radio(
    "Choose how you want to evaluate traffic:",
    [
        "📡 Live Network Capture",
        "🧪 Pre-configured Traffic Profiles (Dropdown)",
        "⚙️ Custom Traffic Parameters"
    ],
    horizontal=True
)

features_to_analyze = None
trigger_analysis = False
source_label = ""

if input_mode == "📡 Live Network Capture":
    col1, col2 = st.columns([2, 1])
    with col1:
        duration = st.slider(
            "Capture Duration (seconds)",
            min_value=3,
            max_value=15,
            value=5,
            step=1
        )
    with col2:
        st.write("")
        st.write("")
        trigger_analysis = st.button("🚀 Analyze Live Traffic", use_container_width=True)

    if trigger_analysis:
        st.info(f"📡 Capturing network traffic for {duration} seconds... Browse the web or continue normal activity.")
        with st.spinner("🔍 Sniffing network packets and computing flow features..."):
            try:
                features_to_analyze = analyze_live_traffic(duration)
                source_label = f"Live Interface Capture ({duration}s)"
            except Exception as e:
                st.error(f"❌ Live capture failed: {e}")

elif input_mode == "🧪 Pre-configured Traffic Profiles (Dropdown)":
    selected_scenario = st.selectbox(
        "Select a Traffic Profile from Dropdown:",
        list(PRESET_SCENARIOS.keys())
    )
    
    scenario_info = PRESET_SCENARIOS[selected_scenario]
    st.info(f"ℹ️ **Profile Overview:** {scenario_info['description']}")
    
    trigger_analysis = st.button("⚡ Run Scenario Analysis", use_container_width=True)
    if trigger_analysis:
        features_to_analyze = scenario_info["features"].copy()
        source_label = selected_scenario

else:  # Custom Traffic Parameters
    st.write("Tune custom flow parameters to simulate attack vectors or benign baseline variations:")
    c1, c2, c3 = st.columns(3)
    with c1:
        cust_duration = st.number_input("Duration (seconds)", min_value=1, max_value=30, value=5)
        cust_pkts = st.number_input("Total Packets", min_value=1, max_value=50000, value=250)
    with c2:
        cust_bytes = st.number_input("Total Bytes", min_value=100, max_value=100_000_000, value=200000)
        cust_fwd_ratio = st.slider("Outbound (Forward) Packet Ratio", min_value=0.0, max_value=1.0, value=0.30, step=0.05)
    with c3:
        cust_dest = st.number_input("Unique Destination Hosts", min_value=1, max_value=2000, value=15)
        cust_tcp_ratio = st.slider("TCP Ratio", min_value=0.0, max_value=1.0, value=0.90, step=0.05)

    trigger_analysis = st.button("🔬 Analyze Custom Traffic", use_container_width=True)
    if trigger_analysis:
        fwd_p = int(cust_pkts * cust_fwd_ratio)
        bwd_p = max(0, cust_pkts - fwd_p)
        fwd_b = int(cust_bytes * cust_fwd_ratio)
        bwd_b = max(0, cust_bytes - fwd_b)
        tcp_p = int(cust_pkts * cust_tcp_ratio)
        udp_p = max(0, cust_pkts - tcp_p)

        features_to_analyze = {
            "duration": cust_duration,
            "total_packets": cust_pkts,
            "total_bytes": cust_bytes,
            "packets_per_second": cust_pkts / cust_duration if cust_duration > 0 else 0,
            "bytes_per_second": cust_bytes / cust_duration if cust_duration > 0 else 0,
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
        source_label = "Custom Simulated Parameters"


# ============================================================
# PERSISTENCE & EXECUTION
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
    live_features = st.session_state["last_features"]
    prediction = st.session_state["prediction"]
    anomaly_score = st.session_state["anomaly_score"]
    risk = st.session_state["risk"]
    level = st.session_state["level"]
    reasons = st.session_state["reasons"]
    source = st.session_state.get("source_label", "Analyzed Traffic")

    st.divider()
    st.header(f"📊 Analysis Dashboard — {source}")

    # ----------------------------------------------------
    # AI DETECTION SUMMARY & ALERT
    # ----------------------------------------------------
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("AI Model Classification", prediction)
    with col2:
        st.metric("Risk Score", f"{risk} / 100")
    with col3:
        st.metric("Threat Level", level)

    st.subheader("🚨 Security Status Assessment")
    if level == "LOW":
        st.success(f"🟢 **LOW RISK — {risk}/100** | Traffic pattern matches safe benign baseline.")
    elif level == "MEDIUM":
        st.warning(f"🟡 **MEDIUM RISK — {risk}/100** | Mild anomaly or elevated traffic parameters detected.")
    elif level == "HIGH":
        st.error(f"🟠 **HIGH RISK — {risk}/100** | Suspicious network signatures and significant anomalies detected.")
    else:
        st.error(f"🔴 **CRITICAL RISK — {risk}/100** | Severe intrusion or volumetric attack patterns identified.")

    # ----------------------------------------------------
    # SECURITY AGENT REASONING
    # ----------------------------------------------------
    st.subheader("🤖 Explainable Security Agent Reasoning")
    st.write("**Why did the agent reach this conclusion?**")
    for r in reasons:
        st.markdown(f"- 🔹 {r}")

    # Recommended Action
    st.subheader("🛡️ Recommended Incident Action")
    if level == "LOW":
        st.info("✅ Traffic is benign and safe. No mitigation required; continue monitoring.")
    elif level == "MEDIUM":
        st.warning("⚠️ Investigate unusual endpoints or background applications causing elevated activity.")
    elif level == "HIGH":
        st.warning("⚠️ High alert: Inspect destination IPs, verify firewall rules, and throttle suspicious connections.")
    else:
        st.error("🚨 Critical incident response: Block offending ports/IPs and initiate network rate limiting immediately.")

    # ----------------------------------------------------
    # TRAFFIC METRICS
    # ----------------------------------------------------
    st.divider()
    st.subheader("📡 Flow & Protocol Telemetry")
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Packets", f'{live_features["total_packets"]:,}')
    with m2:
        st.metric("Total Bytes", f'{live_features["total_bytes"]:,}')
    with m3:
        st.metric("Packet Rate", f'{live_features["packets_per_second"]:.2f} pps')
    with m4:
        st.metric("Throughput", f'{live_features["bytes_per_second"]:.2f} B/s')

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("TCP Packets", f'{live_features.get("tcp_packets", 0):,}')
    with c2:
        st.metric("UDP Packets", f'{live_features.get("udp_packets", 0):,}')
    with c3:
        st.metric("Forward (Outbound)", f'{live_features.get("forward_packets", 0):,}')
    with c4:
        st.metric("Backward (Inbound)", f'{live_features.get("backward_packets", 0):,}')

    d1, d2 = st.columns(2)
    with d1:
        st.metric("Unique Sources", f'{live_features.get("unique_sources", 1):,}')
    with d2:
        st.metric("Unique Destinations", f'{live_features.get("unique_destinations", 1):,}')

    # ----------------------------------------------------
    # RAW METRICS & SUMMARY TABLE
    # ----------------------------------------------------
    st.divider()
    with st.expander("🔍 View All Live Flow Features (Raw Table)"):
        feature_table = pd.DataFrame(
            list(live_features.items()),
            columns=["Feature", "Value"]
        )
        feature_table["Value"] = feature_table["Value"].astype(str)
        st.dataframe(feature_table, use_container_width=True, hide_index=True)

    with st.expander("📋 Inspection Summary Table"):
        summary_data = {
            "Metric": [
                "Capture Duration",
                "Total Packets",
                "Total Bytes",
                "Packets / Second",
                "Bytes / Second",
                "TCP Packets",
                "UDP Packets",
                "Forward (Outbound) Packets",
                "Backward (Inbound) Packets",
                "Unique Destinations",
                "AI Prediction",
                "Anomaly Decision Score",
                "Risk Score",
                "Risk Level"
            ],
            "Value": [
                f'{live_features["duration"]} seconds',
                str(live_features["total_packets"]),
                str(live_features["total_bytes"]),
                f'{live_features["packets_per_second"]:.2f}',
                f'{live_features["bytes_per_second"]:.2f}',
                str(live_features.get("tcp_packets", 0)),
                str(live_features.get("udp_packets", 0)),
                str(live_features.get("forward_packets", 0)),
                str(live_features.get("backward_packets", 0)),
                str(live_features.get("unique_destinations", 1)),
                str(prediction),
                f"{anomaly_score:.4f}",
                f"{risk}/100",
                str(level)
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df["Value"] = summary_df["Value"].astype(str)
        st.dataframe(summary_df, use_container_width=True, hide_index=True)


# ============================================================
# EDUCATIONAL KNOWLEDGE HUB
# ============================================================

st.divider()

with st.expander("💡 Knowledge Hub: How does SentinelAI differentiate Normal vs. Malicious Traffic?"):
    st.markdown("""
    ### 🟢 What defines **NORMAL** Network Traffic?
    In regular computer operation (browsing, video streaming, office apps, gaming):
    - **Balanced Request-Response Symmetry**: When your computer requests a webpage or video, it sends a small request (forward packet) and receives multiple larger data packets (backward packets). Typical ratio: 20–40% forward, 60–80% backward.
    - **Realistic Packet Rates**: Standard web browsing produces 10–100 packets/second. High-def video streaming produces 100–300 packets/second.
    - **Controlled Destination Scope**: A PC typically communicates with a dozen or two remote CDN/cloud servers at a time.
    - **AI Result**: **`NORMAL`**, Decision Score > 0, Risk: **`LOW (0-25/100)`**.

    ---

    ### 🔴 What defines **MALICIOUS / SUSPICIOUS** Traffic?
    Attacks fundamentally violate normal network protocols and behavioral dynamics:
    1. **DoS / SYN Flood Attacks (`CRITICAL RISK`)**:
       - Massive packet rates (thousands of packets/sec).
       - **100% Outbound, 0% Responses**: Attacker floods SYN packets without completing the TCP handshake.
    2. **Port Scanning / Host Reconnaissance (`HIGH RISK`)**:
       - Attacker probes hundreds of different IP addresses or ports in seconds.
       - Huge destination fan-out (> 150–300 unique hosts) with little or no payload data.
    3. **Data Exfiltration / Botnet C2 (`HIGH RISK`)**:
       - Unusually massive outbound byte transfer compared to inbound traffic.
       - Abnormal payload sizes and sustained outbound uploads to unknown endpoints.
    """)