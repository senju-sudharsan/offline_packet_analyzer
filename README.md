# Offline Network Packet Analyzer

A fully offline, local network packet analyzer built in Python that captures live traffic, tracks flows, computes basic risk scores, and presents insights through a Streamlit-based dashboard.

This project is designed as a final-year / portfolio-level system focusing on clean architecture, explainable analysis, and zero dependency on cloud services or APIs.

---

##  Features

- Live packet capture (offline, local only)
- Flow-based traffic tracking
- Protocol statistics (TCP / UDP / ICMP)
- Explainable risk scoring engine
- Suspicious flow inspection
- Network Communication Matrix (who talks to whom)
- Live Streamlit dashboard
- Fully offline (no APIs, no cloud)
- Safe, conservative detection (low false positives)

---

##  Tech Stack

- **Language:** Python 3.10+
- **Packet Capture:** Scapy
- **UI:** Streamlit
- **Data Handling:** Pandas
- **OS:** Windows (Npcap required)

---

##  System Requirements

- Windows 10 / 11
- Python 3.10 or higher
- Administrator privileges (for packet capture)
- Npcap installed (WinPcap-compatible mode)

---

##  Installation

###  Clone the repository

```bash
git clone https://github.com/senju-sudharsan/offline_packet_analyzer.git
cd offline_packet_analyzer

==================================================================================================================================
Npcap Requirement (IMPORTANT)

This project requires Npcap for packet capture on Windows.

Download from: https://nmap.org/npcap/

During installation:

✅ Check “Install Npcap in WinPcap API-compatible mode”

✅ Allow loopback traffic

Restart your system after installation

Run the application as Administrator.
==================================================================================================================================

▶️ Running the Project
Run via Streamlit (Recommended)

PowerShell
python -m streamlit run ui/app.py

VS Code Terminal
streamlit run ui/app.py

**********************************************************************************************************************************

🖥️ Dashboard Sections Explained

Metrics: Total packets, active flows, capture status

Traffic Overview: Protocol distribution

Suspicious / High-Risk Flows: Explainable risk scoring

Network Communication Matrix:
Summarizes dominant source → destination communication pairs with packet volume, duration, and risk score

**********************************************************************************************************************************

