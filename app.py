import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from datetime import datetime
import random

from detector import DeauthDetector
from packet_analyzer import PacketAnalyzer


# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------

st.set_page_config(
    page_title="Wi-Fi Security Monitor",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ---------------------------------------------------------
# CUSTOM CSS
# ---------------------------------------------------------

st.markdown(
    """
    <style>

    /* Main background */
    .stApp {
        background:
            radial-gradient(
                circle at 20% 20%,
                rgba(0, 100, 255, 0.10),
                transparent 30%
            ),
            radial-gradient(
                circle at 80% 80%,
                rgba(120, 0, 255, 0.08),
                transparent 30%
            ),
            #050b16;
        color: #e6edf7;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #07101f;
        border-right: 1px solid rgba(100, 160, 255, 0.15);
    }

    /* Metrics */
    div[data-testid="stMetric"] {
        background: rgba(10, 25, 48, 0.75);
        border: 1px solid rgba(70, 140, 255, 0.22);
        padding: 18px;
        border-radius: 14px;
        box-shadow: 0 0 25px rgba(0, 90, 255, 0.08);
    }

    /* Buttons */
    .stButton > button {
        border-radius: 10px;
        border: 1px solid rgba(70, 140, 255, 0.3);
        background: rgba(20, 45, 85, 0.8);
        color: white;
    }

    /* Tables */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------

if "packets" not in st.session_state:
    st.session_state.packets = []

if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "detector" not in st.session_state:
    st.session_state.detector = DeauthDetector()

if "monitoring" not in st.session_state:
    st.session_state.monitoring = False


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

with st.sidebar:

    st.markdown("## 🛡️ WiFiGuard")

    st.caption(
        "Deauthentication Attack Detector"
    )

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Live Packets",
            "Alerts",
            "Devices",
            "Packet Analysis"
        ]
    )

    st.divider()

    st.markdown("### ⚙️ Monitoring")

    interface = st.text_input(
        "Wireless Interface",
        value="wlan0mon"
    )

    channel = st.selectbox(
        "Channel",
        [1, 6, 11]
    )

    st.divider()

    if st.session_state.monitoring:
        st.success("● Monitoring Active")
    else:
        st.warning("● Monitoring Standby")


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

header_col1, header_col2 = st.columns([4, 1])

with header_col1:

    st.markdown(
        "# 📡 Wi-Fi Security Monitor"
    )

    st.caption(
        "Detect • Analyze • Investigate • Stay Safe"
    )

with header_col2:

    if st.session_state.monitoring:
        st.success("● LIVE")
    else:
        st.info("● READY")


# ---------------------------------------------------------
# DEMO DATA
# ---------------------------------------------------------

def generate_demo_packets():

    sources = [
        "AA:BB:CC:11:22:33",
        "66:77:88:99:AA:BB",
        "12:34:56:78:9A:BC",
        "FF:EE:DD:CC:BB:AA"
    ]

    destinations = [
        "11:22:33:44:55:66",
        "AA:BB:CC:44:55:66",
        "22:33:44:55:66:77"
    ]

    packet_types = [
        ("Management", "Beacon"),
        ("Management", "Probe Request"),
        ("Management", "Authentication"),
        ("Data", "QoS Data")
    ]

    data = []

    for _ in range(40):

        packet_type, subtype = random.choice(packet_types)

        data.append(
            {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "source": random.choice(sources),
                "destination": random.choice(destinations),
                "type": packet_type,
                "subtype": subtype
            }
        )

    return data


# ---------------------------------------------------------
# 3D NETWORK GRAPH
# ---------------------------------------------------------

def create_network_3d():

    nodes = {
        "AP": (0, 0, 0),

        "Client 1": (-3, 2, 1),
        "Client 2": (-3, -2, 0),
        "Client 3": (2, 3, -1),
        "Client 4": (3, -2, 1),

        "Suspicious": (5, 1, 2)
    }

    edges = [
        ("AP", "Client 1"),
        ("AP", "Client 2"),
        ("AP", "Client 3"),
        ("AP", "Client 4"),
        ("AP", "Suspicious")
    ]

    fig = go.Figure()

    # Connections
    for start, end in edges:

        x = [
            nodes[start][0],
            nodes[end][0]
        ]

        y = [
            nodes[start][1],
            nodes[end][1]
        ]

        z = [
            nodes[start][2],
            nodes[end][2]
        ]

        fig.add_trace(
            go.Scatter3d(
                x=x,
                y=y,
                z=z,
                mode="lines",
                line=dict(
                    width=4
                ),
                hoverinfo="none",
                showlegend=False
            )
        )

    # Normal nodes
    normal_names = [
        "Client 1",
        "Client 2",
        "Client 3",
        "Client 4"
    ]

    fig.add_trace(
        go.Scatter3d(
            x=[nodes[n][0] for n in normal_names],
            y=[nodes[n][1] for n in normal_names],
            z=[nodes[n][2] for n in normal_names],
            mode="markers+text",
            marker=dict(
                size=13
            ),
            text=normal_names,
            textposition="top center",
            name="Clients"
        )
    )

    # AP
    fig.add_trace(
        go.Scatter3d(
            x=[0],
            y=[0],
            z=[0],
            mode="markers+text",
            marker=dict(
                size=22
            ),
            text=["ACCESS POINT"],
            textposition="top center",
            name="Access Point"
        )
    )

    # Suspicious node
    suspicious = nodes["Suspicious"]

    fig.add_trace(
        go.Scatter3d(
            x=[suspicious[0]],
            y=[suspicious[1]],
            z=[suspicious[2]],
            mode="markers+text",
            marker=dict(
                size=20,
                symbol="diamond"
            ),
            text=["⚠ SUSPICIOUS"],
            textposition="top center",
            name="Suspicious"
        )
    )

    fig.update_layout(
        height=480,
        margin=dict(
            l=0,
            r=0,
            t=20,
            b=0
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        scene=dict(
            bgcolor="rgba(0,0,0,0)",
            xaxis=dict(
                showbackground=False,
                showgrid=True,
                zeroline=False
            ),
            yaxis=dict(
                showbackground=False,
                showgrid=True,
                zeroline=False
            ),
            zaxis=dict(
                showbackground=False,
                showgrid=True,
                zeroline=False
            )
        ),
        legend=dict(
            bgcolor="rgba(5,10,20,0.7)"
        )
    )

    return fig


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

if page == "Dashboard":

    # Demo data
    if not st.session_state.packets:

        st.session_state.packets = generate_demo_packets()

    packets = st.session_state.packets

    packet_count = len(packets)

    deauth_count = sum(
        1
        for p in packets
        if p.get("subtype") == "Deauthentication"
    )

    suspicious_devices = 1

    risk_score = min(
        100,
        25 + deauth_count * 5
    )

    if risk_score >= 80:
        threat = "HIGH"

    elif risk_score >= 50:
        threat = "MEDIUM"

    else:
        threat = "LOW"

    # Metrics
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "Packets Captured",
            f"{packet_count:,}",
            "+12%"
        )

    with c2:
        st.metric(
            "Deauth Events",
            deauth_count,
            "+180%"
        )

    with c3:
        st.metric(
            "Suspicious Devices",
            suspicious_devices
        )

    with c4:
        st.metric(
            "Threat Level",
            threat,
            f"Risk {risk_score}/100"
        )

    st.divider()

    # Main visualization
    left, right = st.columns([2, 1])

    with left:

        st.subheader("🌐 3D Network Visualization")

        st.plotly_chart(
            create_network_3d(),
            use_container_width=True
        )

    with right:

        st.subheader("🚨 Latest Alerts")

        if risk_score >= 80:

            st.error(
                "HIGH\n\n"
                "Possible Deauthentication Attack"
            )

            st.write(
                "Repeated management frames detected."
            )

        elif risk_score >= 50:

            st.warning(
                "MEDIUM\n\n"
                "Suspicious Wireless Activity"
            )

        else:

            st.success(
                "LOW\n\n"
                "No significant threat detected."
            )

    st.divider()

    # Lower dashboard
    left, middle, right = st.columns(3)

    with left:

        st.subheader("📊 Packet Traffic")

        traffic = pd.DataFrame(
            {
                "Time": range(30),
                "Packets": np.random.randint(
                    300,
                    1500,
                    30
                )
            }
        )

        st.line_chart(
            traffic.set_index("Time")
        )

    with middle:

        st.subheader("🔍 Detection Summary")

        st.write(
            f"**Packets:** {packet_count}"
        )

        st.write(
            f"**Deauthentication:** {deauth_count}"
        )

        st.write(
            f"**Risk Score:** {risk_score}/100"
        )

        st.progress(
            risk_score / 100
        )

    with right:

        st.subheader("🖥️ Monitoring")

        st.write(
            f"Interface: `{interface}`"
        )

        st.write(
            f"Channel: `{channel}`"
        )

        if st.button("Start Monitoring"):

            st.session_state.monitoring = True

            st.rerun()

        if st.button("Stop Monitoring"):

            st.session_state.monitoring = False

            st.rerun()


# ---------------------------------------------------------
# LIVE PACKETS
# ---------------------------------------------------------

elif page == "Live Packets":

    st.subheader("📦 Live Wireless Packets")

    if not st.session_state.packets:

        st.session_state.packets = generate_demo_packets()

    df = pd.DataFrame(
        st.session_state.packets
    )

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )


# ---------------------------------------------------------
# ALERTS
# ---------------------------------------------------------

elif page == "Alerts":

    st.subheader("🚨 Security Alerts")

    alerts = st.session_state.detector.get_alerts()

    if alerts:

        st.dataframe(
            pd.DataFrame(alerts),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No detector alerts yet."
        )


# ---------------------------------------------------------
# DEVICES
# ---------------------------------------------------------

elif page == "Devices":

    st.subheader("🖥️ Detected Devices")

    if not st.session_state.packets:

        st.session_state.packets = generate_demo_packets()

    devices = {}

    for packet in st.session_state.packets:

        source = packet["source"]

        devices[source] = (
            devices.get(source, 0) + 1
        )

    device_df = pd.DataFrame(
        [
            {
                "MAC Address": mac,
                "Packets": count,
                "Status": "Active"
            }
            for mac, count
            in devices.items()
        ]
    )

    st.dataframe(
        device_df,
        use_container_width=True,
        hide_index=True
    )


# ---------------------------------------------------------
# PACKET ANALYSIS
# ---------------------------------------------------------

elif page == "Packet Analysis":

    st.subheader("🔬 Packet Inspector")

    if not st.session_state.packets:

        st.session_state.packets = generate_demo_packets()

    df = pd.DataFrame(
        st.session_state.packets
    )

    selected_index = st.selectbox(
        "Select Packet",
        range(len(df))
    )

    packet = df.iloc[selected_index]

    st.markdown("### Packet Details")

    c1, c2 = st.columns(2)

    with c1:

        st.write(
            "**Timestamp:**",
            packet["timestamp"]
        )

        st.write(
            "**Source:**",
            packet["source"]
        )

        st.write(
            "**Destination:**",
            packet["destination"]
        )

    with c2:

        st.write(
            "**Type:**",
            packet["type"]
        )

        st.write(
            "**Subtype:**",
            packet["subtype"]
        )
