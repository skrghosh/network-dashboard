import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import *
from collections import defaultdict
import time
from datetime import datetime
import threading
import warnings
import logging
from typing import Dict, List, Optional
import socket
from streamlit_autorefresh import st_autorefresh
from scapy.all import sniff, conf, get_if_list


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PacketProcessor:
    """Process and analyze network packets"""

    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }

                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Keep only last 10000 packets to prevent memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(self.packet_data)


def create_visualizations(df: pd.DataFrame):
    """Create all dashboard visualizations"""
    if len(df) > 0:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,
            title="Packets per Second",
            labels={
                'x': 'Time (s since start)',
                'y': 'Packets per Second'
            }
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)


def start_packet_capture(iface: str):
    processor = PacketProcessor()
    def capture_packets():
        sniff(iface=iface, prn=processor.process_packet, store=False, promisc=True)
    threading.Thread(target=capture_packets, daemon=True).start()
    return processor


# helper to format bytes
def format_bytes(size: int) -> str:
    for unit in ["B","KB","MB","GB","TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def main():
    """Main function to run the dashboard"""
    # auto-refresh every 2 seconds
    st_autorefresh(interval=2_000, key="packet_refresh")

    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # 1) Auto-detect & dropdown
    default_iface = conf.route.route("8.8.8.8")[0]
    interfaces = get_if_list()
    default_index = interfaces.index(default_iface) if default_iface in interfaces else 0
    iface = st.sidebar.selectbox("📡 Capture interface", interfaces, index=default_index)

    # 2) Initialize session_state.iface
    if 'iface' not in st.session_state:
        st.session_state.iface = iface

    # 3) Detect changes
    if iface != st.session_state.iface:
        st.session_state.iface = iface
        st.session_state.processor = start_packet_capture(iface)
        st.session_state.start_time = time.time()

    # 4) Ensure processor exists
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture(st.session_state.iface)
        st.session_state.start_time = time.time()

    # 5) Show which iface is active
    st.write(f"🐾 Capturing on interface: **{st.session_state.iface}**")

    # Create dashboard layout
    col1, col2 = st.columns(2)

    # Get current data
    df = st.session_state.processor.get_dataframe()

    # ——— 5-tuple flow aggregation ———
    if not df.empty:
        # ensure timestamp is datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        flow_df = (
            df
            .groupby(
                ['source', 'destination', 'protocol', 'src_port', 'dst_port'],
                as_index=False
            )
            .agg(
                packet_count=('size', 'count'),
                total_bytes=('size', 'sum'),
                first_seen=('timestamp', 'min'),
                last_seen=('timestamp', 'max')
            )
        )

        # sort by most active flows
        flow_df = flow_df.sort_values('packet_count', ascending=False)

        # convert raw bytes into human-readable sizes
        flow_df['total_size'] = flow_df['total_bytes'].apply(format_bytes)
    else:
        flow_df = pd.DataFrame(
            columns=['source', 'destination', 'protocol', 'src_port', 'dst_port',
                     'packet_count', 'total_bytes', 'first_seen', 'last_seen']
        )

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )

    display_cols = [
        "source", "src_port", "destination", "dst_port", "protocol",
        "packet_count", "first_seen", "last_seen"
    ]
    if 'total_size' in flow_df.columns:
        display_cols.insert(6, 'total_size')
    st.subheader("Top Network Flows")
    # show only the top 10
    st.dataframe(flow_df.head(10)[display_cols], use_container_width=True)

    # Add refresh button
    if st.button('Refresh Data'):
        st.rerun()

    # Auto refresh
    # time.sleep(5)
    # st.rerun()


if __name__ == "__main__":
    main()
