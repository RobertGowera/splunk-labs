# 🛡️ Splunk Detection Engineering Labs

This repository documents a growing series of hands-on SOC detection labs built using **Splunk SIEM**, Windows Security Logs, and real-world attack simulation.

Each project demonstrates:
- Detection logic using SPL
- Threat analysis & attack reconstruction
- Indicators of Compromise (IOCs)
- Incident reporting
- Visual evidence via screenshots

---

## 🔍 Detection Labs

### ✅ 1. Brute-Force Attack Detection  
📂 `brute-force-detection/`

**Scenario:**
Multiple failed authentication attempts detected against a Windows endpoint.

**Key Findings:**
- Targeted Account: `VIROTA$`
- Total Failed Attempts: **22**
- Peak Velocity: **4 attempts in one minute**
- Event ID: **4625**
- MITRE ATT&CK: **T1110 – Brute Force**

➡️ [View Full Lab](./brute-force-detection)

---

## 🧰 Tools & Technologies
- Splunk Cloud
- Windows Security Event Logs
- SPL (Search Processing Language)
- MITRE ATT&CK Framework
- GitHub Documentation

---

## 📈 Roadmap
- Privilege Escalation Detection
- Impossible Travel Detection
- Malware Execution Detection
- Malware Command & Control Detection
- Detection Dashboards

---

## 👤 Author
**Robert Gowera**  
SOC Analyst in Training | SIEM & Threat Detection

