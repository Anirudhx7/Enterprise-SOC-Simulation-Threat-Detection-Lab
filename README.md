# 🛡️ Enterprise SOC Simulation & Threat Detection Lab  

![Splunk](https://img.shields.io/badge/Splunk-SIEM-000000?style=flat&logo=splunk&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Identity-0078D6?style=flat&logo=microsoft&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-Server-E95420?style=flat&logo=ubuntu&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK-Framework-E01F26?style=flat&logo=target&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Red%20Team-557C94?style=flat&logo=kalilinux&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-Telemetry-8148DD?style=flat&logo=windows-terminal&logoColor=white)

A hands-on SOC (Security Operations Center) simulation designed to replicate **real-world enterprise detection workflows**.  
This project demonstrates how identity attacks, persistence techniques, and suspicious command execution appear inside Windows logs and how a SOC analyst detects, investigates, and documents them.

---

# 🎯 Project Goal  
Most SOC labs only “install tools.”

This project goes deeper:

**Simulate attacks → Capture telemetry → Engineer detections → Investigate → Produce MITRE-aligned findings.**

Built to practice real SOC workflows, including:

- Active Directory monitoring  
- Centralized log ingestion  
- Sysmon-based visibility  
- Identity attack detection  
- Registry persistence triage  
- SPL correlation rule creation  
- Incident response reporting  

---

# 🧱 1. Lab Architecture

```
                 Attacks
          ┌──────────────────────┐
          │ Kali Linux(Red Team) │
          │----------------------│
          │ Hydra, PowerShell,   │
          │ Persistence, Scanning│
          └───────────┬──────────┘
                      │
      Attacks Windows │ and AD SERVER
                      ▼
      ┌───────────────────────────────────┐
      │     Windows 10 Endpoint (Victim)  │
      │-----------------------------------│
      │ Sysmon Telemetry (Process, Reg,   │
      │ Network)                          │
      └───────────────┬───────────────────┘
                      │   Forwards Logs
                      ▼
      ┌───────────────────────────────────┐
      │ Windows Server 2022 (Domain Ctrl) │
      │-----------------------------------│
      │ AD DS, DNS, Auth Logs (4624/4625) │
      └───────────────┬───────────────────┘
                      │    Forwards Logs
                      ▼
        ┌────────────────────────────┐
        │ Ubuntu Server (Splunk SIEM)│
        │----------------------------│
        │ Receives Sysmon + Windows  │
        │ Security Logs for analysis │
        └────────────────────────────┘
```


### **Tools Used**
- **Splunk Enterprise (SIEM)**
- **Sysmon v14+**
- **Windows Event Logs**
- **Hydra** (for brute-force simulation)
- **MITRE ATT&CK**
- **GPO Hardening**
<img src='https://github.com/Anirudhx7/Enterprise-SOC-Simulation-Threat-Detection-Lab/blob/1b9c6c2fae71156125031d995d692e803a70f3e3/images/architecture.png'>
---

# ⚡ 2. Attack Scenarios Simulated

## 🔸 A. RDP Brute-Force Attack  
**MITRE: T1110 — Brute Force**

What I did:
- Launched Hydra brute-force attempts against the Domain Controller  
- Generated **5,000+ failed logons (Event ID 4625)**  

What I captured:
- Repeated credential attempts  
- Abnormal authentication patterns  
- Source IP profiling  
- Account enumeration behavior  

> **Detection:** Splunk correlation rule + thresholding on failed logons

---

## 🔸 B. Registry Run Key Persistence  
**MITRE: T1547 — Registry Run Key / Startup Folder**

What I did:
- Added unauthorized persistence via registry Run Key  

What I captured:
- Sysmon Event ID **13** — Registry value set  
- Sysmon Event ID **11** — File created  
- Suspicious startup chain  

> **Detection:** Registry modification + parent/child tree analysis

---

## 🔸 C. Suspicious PowerShell Execution  
**MITRE: T1059 — Command and Scripting Interpreter**

What I did:
- Executed encoded + suspicious PowerShell commands  

What I captured:
- Sysmon Event ID **1** — Process create  
- Obfuscated commands  
- PowerShell spawned by unusual parents  

> **Detection:** Command-line + parent process heuristics

---

# 📊 3. Splunk Detection Engineering

### ✔ **Anomalous Logon Behavior (4625 spikes)**  
```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, IpAddress, Workstation_Name
| where count > 20
```

### ✔ **Registry Persistence (Run Key)**  
```spl
index=sysmon EventCode=13
| search TargetObject="*\\Run*"
| table Computer, User, Image, TargetObject
```

### ✔ **Suspicious PowerShell Execution**  
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*IEX*" OR CommandLine="*download*"
```

### ✔ **Process Tree Abnormalities**  
```spl
index=sysmon EventCode=1
| where ParentImage="*cmd.exe" AND Image="*powershell.exe"
```
<img src='https://github.com/Anirudhx7/Enterprise-SOC-Simulation-Threat-Detection-Lab/blob/e3d3e044067fe5b1578f22b6c03ebb4f967a2bf5/images/splunk_event-id.png'>
---

# 🧠 4. Key Findings

- RDP brute-force patterns create highly distinct authentication bursts  
- Sysmon’s registry and process telemetry reveals persistence clearly  
- Splunk correlation rules dramatically reduce false positives  
- MITRE alignment helps communicate attacker behavior clearly  
- Combined Sysmon + AD logs provide strong identity-attack visibility  

**MTTD (Mean Time To Detect) reduced to under 60 seconds** during simulations.

---

# 🕵️ 5. MITRE ATT&CK Mapping

| Technique | ID | Observed |
|----------|-----|---------|
| Brute Force | **T1110** | ✔ |
| Registry Run Key Persistence | **T1547** | ✔ |
| PowerShell Execution | **T1059** | ✔ |
| Remote Services (RDP) | **T1021** | ✔ |
| Credential Access (Kerberos-related noise) | **T1003** | Partial |
| Active Scanning | **T1595** | ✔ |

---

# 🧩 6. Project Files

```
/detections
    brute_force_T1110.spl
    persistence_T1547.spl
    powershell_T1059.spl

/reports
    SOC_Investigation_Report.md
    MITRE_Mapping.json

/attacks
    hydra_bruteforce_commands.txt
    registry_persistence_script.ps1

/configs
    sysmon-config.xml
    splunk-inputs.conf

/images
    setup.png
    architecture.png
    splunk_event-id.png
    hyrda.png
```

---

# 📘 7. Learning Outcomes

Through this project I gained hands-on experience in:

- Investigating Windows identity attacks  
- Designing SIEM detections using SPL  
- Using Sysmon for high-fidelity host telemetry  
- Correlating logs from multiple sources  
- Understanding attacker tradecraft  
- Creating structured SOC reports  
- Mapping behavior to MITRE ATT&CK  

This is the exact kind of workflow used in real SOC Tier 1 & Tier 2 environments.


---

# 🙌 8. About Me
**Anirudh Mehandru**  
SOC Analyst | Blue Team | Detection Engineering  
Always building labs, learning in public, and sharing my journey.
LinkedIn → https://linkedin.com/in/anirudh-mehandru
