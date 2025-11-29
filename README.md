# Enterprise SOC Simulation & Threat Detection Lab

A hands-on SOC (Security Operations Center) simulation designed to replicate real-world enterprise detection workflows using Splunk, Sysmon, Windows Event Logs, and Active Directory.  
This project focuses on generating attacker telemetry, building custom detection rules, and producing MITRE-aligned incident reports.

---

## 🔍 About This Project

This lab simulates how a SOC monitors, detects, and investigates malicious activity inside a Windows enterprise environment.  
I built an Active Directory–based network, configured centralized log forwarding into Splunk, generated real attack telemetry (brute-force + persistence), and developed custom SPL detections mapped to MITRE ATT&CK techniques.

The goal was simple:  
**Understand attacker behavior → detect it → investigate it → document it like a real SOC analyst.**

---

## 🧱 Lab Architecture

- Domain Controller (Windows Server 2019)
- Windows 10 Workstation (Attacker + Victim simulation)
- Sysmon v14+ for detailed host telemetry
- Splunk Enterprise as the SIEM for log ingestion + alerting
- Hydra for brute-force simulations
- Winlogbeat / WEF for Windows log forwarding (optional)
- MITRE ATT&CK alignment throughout the investigation

Architecture Diagram (ASCII):

[Attacker VM] → Brute-force / Persistence Attacks  
        ↓  
[Victim Windows 10] → Sysmon + Windows Logs  
        ↓  
[Splunk Server] ← Centralized Log Forwarding  
        ↓  
[Detection Engineering + IR Report]

---

## 🎯 Objectives

- Build an enterprise-style detection environment  
- Generate realistic attacker telemetry  
- Tune detection logic using SPL rules  
- Correlate Sysmon + Windows logs  
- Investigate persistence techniques  
- Create MITRE-aligned IR documentation  

---

## 🛠️ Tools Used

- Splunk Enterprise  
- Sysmon  
- Windows Event Logs  
- Active Directory (AD DS)  
- Hydra  
- Winlogbeat / WEF  
- MITRE ATT&CK Navigator  

---

## ⚡ Attack Scenarios Simulated

### 1. RDP Brute Force (Credential Access — T1110)

What I did:
- Simulated RDP brute-force attacks using Hydra  
- Generated 5,000+ failed logon events  

Key logs captured:
- Event ID 4625 — Failed logon  
- Event ID 4624 — Successful logon  
- Sysmon ProcessCreate events  

Analysis:
- Abnormal authentication patterns visualized in Splunk  
- Mapped to MITRE technique T1110 (Brute Force)

---

### 2. Registry Run Key Persistence (T1547)

What I did:
- Added unauthorized Run Key entries to simulate persistence  
- Sysmon Event 13 captured key modifications  

Analysis:
- Correlated registry events with process creation  
- Identified suspicious autorun entries  
- Mapped to MITRE T1547 (Registry Run Key / Startup Folder)

---

## 📈 Custom SPL Detection Rules

Brute Force Detection (4625):
index=wineventlog EventCode=4625  
| stats count by Account_Name, Source_Network_Address  
| where count > 20  

Registry Persistence Detection (T1547):
index=sysmon EventCode=13  
| search TargetObject="*\\Run"  
| stats values(Image) as Process, values(TargetObject) as RegistryKey by Computer  

---

## 🧪 Detection Results

- Detected RDP brute-force attempts  
- Identified unauthorized Run Key modifications  
- Reconstructed attacker timelines via Sysmon + Windows logs  
- Verified full log flow through centralized forwarding → Splunk  

---

## 📄 Incident Response Report (MITRE Mapped)

Includes:
- IOC summary  
- Attack timeline  
- Affected hosts  
- MITRE mappings:  
  - T1110 — Brute Force  
  - T1547 — Registry Run Key Persistence  
- Recommended detection improvements  
- Remediation steps  
- Reusable triage notes  

Files:
- Reports/IR_Report.pdf  
- Reports/MITRE_Mapping.json  

---
<!--
## 📁 Repository Structure

/Screenshots  
    brute-force-events.png  
    registry-persistence.png  
    splunk-dashboard.png  

/Detections  
    brute_force_rule.spl  
    persistence_T1547_rule.spl  

/Reports  
    IR_Report.pdf  
    MITRE_Mapping.json  

/Configs  
    sysmon-config.xml  
    splunk-inputs.conf  
    winlogbeat.yml  

README.md  
-->
---

## 🧠 Key Learnings

- How Windows authentication attacks appear across logs  
- How Sysmon enriches detection visibility  
- How to design SPL correlation rules  
- How to map activity to MITRE ATT&CK  
- How to write a SOC-ready incident report  
- How attackers use persistence techniques  

---

## 📬 Contact
 
LinkedIn: linkedin.com/in/anirudh-mehandru
