# Network Traffic Dashboard



A Streamlit-based real-time network traffic analysis dashboard that captures live packets using Scapy and visualizes protocol distribution, packet rates, and top network flows.

*Initial version adapted from a [freeCodeCamp tutorial](https://www.freecodecamp.org/news/build-a-real-time-network-traffic-dashboard-with-python-and-streamlit/). Made several enhancements on top of it*

## Features

* **Live packet capture** on any network interface (auto-detected or user-selected)
* **Auto-refresh** of metrics and charts every 2 seconds
* **Protocol distribution** pie chart
* **Packets per Second** line chart with axis labels
* **Recent packets** table showing the latest 10 packets
* **Flow aggregation** by 5-tuple (src, dst, protocol, src\_port, dst\_port) with human-readable byte counts
* **Interface selector** in the sidebar with default set to the machine’s primary outbound interface

## Prerequisites

* Python 3.7+
* Streamlit
* Pandas
* Plotly
* Scapy
* streamlit-autorefresh

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/network-dashboard.git
   cd network-dashboard
   ```

2. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate    # macOS/Linux
   .venv\Scripts\activate     # Windows
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the dashboard:

   ```bash
   streamlit run dashboard.py
   ```

2. Open your browser at `http://localhost:8501`.

3. Use the **Capture interface** dropdown in the sidebar to select or change the network interface to monitor.

4. View live protocol distribution, packet rates, recent packets, and top flows.

## Configuration

* **Interface detection:** Uses your system’s default route to `8.8.8.8` to choose a default interface. You can override via the sidebar.
* **Auto-refresh interval:** Currently set to 2 seconds via the `streamlit-autorefresh` helper.

## Troubleshooting

* **Permission errors capturing packets**:

  * On Linux/macOS, grant your Python binary packet-capture capabilities:

    ```bash
    sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
    ```
  * On Windows, run your IDE/terminal as Administrator and install Npcap.

* **No traffic appears**:

  * Ensure the correct interface is selected in the sidebar.
  * Verify you have root/admin privileges or correct capabilities.

## Contributing

Feel free to open issues or submit PRs to add new visualizations, alerting, pcap export, or integrations.

## License

[MIT License](LICENSE)]\(LICENSE)
