# ui/app.py
import streamlit as st
import pandas as pd
from streamlit_autorefresh import st_autorefresh

from ui.data_bridge import (
    start_capture,
    get_summary,
    get_risk_flows,
    get_topology
)

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Offline Network Packet Analyzer",
    layout="wide"
)

# ---------------- START CAPTURE (ONCE) ----------------
if "capture_started" not in st.session_state:
    start_capture()
    st.session_state.capture_started = True

# ---------------- LIVE REFRESH (NO BLINK) ----------------
st_autorefresh(interval=2000, key="live_refresh")

# ---------------- FORCE DARK / CYBER THEME ----------------
st.markdown("""
<style>
html, body, [class*="css"]  {
    background-color: #0B0F14 !important;
    color: #E5E7EB !important;
}

.block-container {
    padding-top: 2rem;
}

/* Cards */
.card {
    background-color: #111827;
    padding: 1.3rem;
    border-radius: 12px;
    border: 1px solid #1F2937;
    box-shadow: 0 0 0 1px rgba(34,197,94,0.08);
}

/* Metrics */
.metric {
    font-size: 30px;
    font-weight: 800;
    color: #22C55E;
}

.label {
    color: #9CA3AF;
    font-size: 14px;
}

/* Section titles */
.section-title {
    font-size: 22px;
    font-weight: 800;
    color: #22C55E;
    margin-bottom: 0.6rem;
}

/* Tables */
.stDataFrame {
    background-color: #111827;
    border-radius: 10px;
}

/* Alerts */
.stAlert {
    background-color: #0F172A !important;
    color: #93C5FD !important;
    border: 1px solid #1E3A8A;
}

footer {
    visibility: hidden;
}
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.markdown("## 🛡️ Offline Network Packet Analyzer")
st.caption("Fully local • No cloud • Live capture")

summary = get_summary()

# ---------------- METRICS ----------------
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown(f"""
    <div class="card">
        <div class="label">Packets Captured</div>
        <div class="metric">{summary["total_packets"]}</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="card">
        <div class="label">Active Flows</div>
        <div class="metric">{summary["active_flows"]}</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="card">
        <div class="label">Status</div>
        <div class="metric">LIVE</div>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# ---------------- TRAFFIC OVERVIEW ----------------
st.markdown('<div class="section-title">Traffic Overview</div>', unsafe_allow_html=True)

proto_data = summary["protocols"]
proto_df = (
    pd.DataFrame(proto_data.items(), columns=["Protocol", "Packets"])
    if proto_data else
    pd.DataFrame(columns=["Protocol", "Packets"])
)

col1, col2 = st.columns([1, 2])

with col1:
    st.dataframe(proto_df, use_container_width=True)

with col2:
    if not proto_df.empty:
        st.bar_chart(proto_df.set_index("Protocol"))

st.divider()

# ---------------- RISK FLOWS ----------------
st.markdown('<div class="section-title">Suspicious / High-Risk Flows</div>', unsafe_allow_html=True)

risk_flows = get_risk_flows()

if not risk_flows:
    st.info("No suspicious flows detected yet.")
else:
    for flow in risk_flows:
        risk_pct = int(flow["risk"] * 100)

        if flow["risk"] >= 0.7:
            confidence = "High confidence anomaly"
        elif flow["risk"] >= 0.4:
            confidence = "Moderate confidence anomaly"
        else:
            confidence = "Low confidence anomaly"

        with st.expander(f"{flow['src']} → {flow['dst']}  |  Risk {risk_pct}%"):
            col1, col2 = st.columns([1, 2])

            with col1:
                st.markdown(f"**Protocol:** {flow['protocol']}")
                st.markdown(f"**Packets:** {flow['packets']}")
                st.markdown(f"**Assessment:** {confidence}")

            with col2:
                st.progress(flow["risk"])
                st.markdown("**Why flagged:**")
                for reason in flow["reasons"].split(","):
                    st.markdown(f"- {reason.strip()}")

st.divider()

# ---------------- TOPOLOGY SUMMARY (NO BLINK) ----------------
st.markdown(
    '<div class="section-title">Network Topology (Summary)</div>',
    unsafe_allow_html=True
)

topo = get_topology()

st.markdown(f"""
<div class="card">
<b>Nodes:</b> {len(topo["nodes"])}<br>
<b>Flows:</b> {len(topo["edges"])}
</div>
""", unsafe_allow_html=True)

st.caption("Topology visualization will be enhanced in the next iteration.")
