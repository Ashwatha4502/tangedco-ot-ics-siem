# ⚡ TANGEDCO OT/ICS Threat Detection SIEM

A working Security Operations Center (SOC) lab simulating real-world cyberattacks against an Operational Technology (OT) / Industrial Control System (ICS) environment modeled after TANGEDCO — Tamil Nadu Generation and Distribution Corporation, a critical power utility infrastructure.

## 🎯 Project Overview

This project demonstrates end-to-end OT/ICS threat detection using:
- **Wazuh SIEM 4.7** for real-time log ingestion and alert generation
- **Custom detection rules** mapped to MITRE ATT&CK for ICS
- **Synthetic SCADA dataset** simulating 720 hours of power utility sensor data
- **Interactive Streamlit dashboard** for alert triage and threat visualization

## 🏗️ Architecture~SCADA Simulator (Python)
↓ UDP Syslog :514
Wazuh Manager (analysisd)
↓ Custom Rules (local_rules.xml)
Alert Engine → /var/ossec/logs/alerts/alerts.log
↓
Streamlit Dashboard (port 8501)
↓
Live Threat Visualization## 🔍 MITRE ATT&CK for ICS Coverage

| Technique | Name | Severity | Status |
|-----------|------|----------|--------|
| T0855 | Unauthorized Command Message | HIGH (Level 12) | ✅ Detected |
| T0856 | Spoof Reporting Message | HIGH (Level 14) | ✅ Detected |
| T0814 | Denial of Control | CRITICAL (Level 15) | ✅ Detected |
| T0840 | Network Connection Enumeration | MEDIUM | ⚠️ Gap |
| T0878 | Alarm Suppression | HIGH | ⚠️ Gap |

## 📊 Dataset

Synthetic SCADA dataset modeled after BATADAL (Battle of Attack Detection Algorithms) competition format:
- **720 hours** of simulated power utility sensor data
- **3 tank levels** (L_T1, L_T2, L_T3)
- **2 pump flow rates** (F_PU1, F_PU2) and pump status
- **3 junction pressures** (P_J1, P_J2, P_J3)
- **33 labeled attack events** across 3 attack scenarios

## 🚨 Attack Scenarios

### T0855 — Unauthorized Command (Hours 200–215)
Adversary sends unauthorized Modbus write commands forcing pump PU1 offline. Tank levels drop as water/power distribution is disrupted.

### T0856 — Spoof Reporting (Hours 400–410)
Adversary injects false sensor readings. All junction pressures appear abnormally stable — masking a real pressure drop event from operators.

### T0814 — Denial of Control (Hours 600–608)
All pump actuators become unresponsive. PU1 and PU2 both go offline simultaneously — critical infrastructure impact.

## 🛠️ Tech Stack

- **SIEM**: Wazuh 4.7.5
- **Detection Rules**: XML (custom, mapped to MITRE ATT&CK for ICS)
- **Ingestion**: Python 3 (UDP syslog to Wazuh)
- **Dashboard**: Streamlit + Plotly
- **OS**: Kali Linux (Debian-based)
- **Dataset**: Synthetic SCADA (BATADAL-format)

## 📁 Repository Structureot-ics-siem/
├── datasets/
│   └── ics_train.csv              # 720-hour SCADA simulation with labeled attacks
├── ingestion/
│   ├── generate_dataset.py        # Synthetic dataset generator
│   └── ingest_to_wazuh.py         # UDP syslog ingestion to Wazuh
├── detection/
│   └── rules/
│       └── local_rules.xml        # Custom Wazuh rules (MITRE ATT&CK for ICS)
├── dashboard/
│   └── app.py                     # Streamlit interactive dashboard
└── README.md## 🚀 Setup & Run

```bash
# 1. Install Wazuh
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a -i

# 2. Install Python dependencies
pip3 install pandas streamlit plotly requests

# 3. Generate dataset
cd ingestion && python3 generate_dataset.py

# 4. Deploy detection rules
sudo cp detection/rules/local_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager

# 5. Ingest attack data
python3 ingestion/ingest_to_wazuh.py

# 6. Launch dashboard
streamlit run dashboard/app.py
```

## 📸 Dashboard Preview

> Live dashboard showing 720 SCADA events, 33 attack detections across 3 MITRE ATT&CK for ICS techniques, with real-time Wazuh alert integration.

## 👤 Author

**Ashwatha Narayan**
Cybersecurity Graduate | SOC Analyst & GRC Analyst Candidate
[LinkedIn](https://linkedin.com/in/ashwatha) | [GitHub](https://github.com/Ashwatha4502)

---
*Built as part of a cybersecurity portfolio demonstrating OT/ICS security operations capabilities.*
