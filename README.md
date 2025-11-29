# Enterprise SOC Simulation & Threat Detection Lab

A hands-on SOC (Security Operations Center) simulation designed to replicate real-world enterprise detection workflows using **Splunk**, **Sysmon**, **Windows Event Logs**, and **Active Directory**.  
This project focuses on generating attacker telemetry, building custom detection rules, and producing MITRE-aligned incident reports.

---

## 🔍 About This Project

This lab simulates how a SOC monitors, detects, and investigates malicious activity inside a Windows enterprise environment.  
I built an **Active Directory–based network**, configured **centralized log forwarding into Splunk**, generated real attack telemetry (brute-force + persistence), and developed **custom SPL detections** mapped to MITRE ATT&CK techniques.

The goal was simple:  
**Understand attacker behavior → detect it → investigate it → document it like a real SOC analyst.**

---

## 🧱 Lab Architecture

- **Domain Controller (Windows Server 2019)**  
- **Windows 10 Workstation (Attacker + Victim simulation)**  
- **Sysmon** (Process, Registry, Network telemetry)  
- **Splunk Enterprise** (SIEM for log ingestion + detection rules)  
- **Hydra** (Brute-force simulation)  
- **MITRE ATT&CK** alignment  


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

- **Splunk Enterprise**
- **Sysmon**
- **Windows Event Logs**
- **Active Directory (AD DS)**
- **Hydra** (for brute-force simulation)
- **Winlogbeat / WEF**
- **MITRE ATT&CK Navigator**

---

## ⚡ Attack Scenarios Simulated

### **1. RDP Brute Force (Credential Access — T1110)**

**What I did:**
- Simulated RDP brute-force attacks using Hydra  
- Generated **5,000+ failed logon events**

**Key logs captured:**
- Event ID **4625** — Failed logon  
- Event ID **4624** — Successful logon  
- Sysmon **ProcessCreate** events for attack processes  

**Analysis:**
- Abnormal authentication patterns visualized in Splunk  
- Mapped to MITRE technique **T1110 (Brute Force)**

---

### **2. Registry Run Key Persistence (T1547)**

**What I did:**
- Added unauthorized Run Key entries to simulate persistence  
- Sysmon **Event 13** captured key modifications  

**Analysis:**
- Correlated registry events with process creation  
- Identified suspicious autorun entries  
- Mapped to MITRE **T1547 – Registry Run Key / Startup Folder**

---

## 📈 Custom SPL Detection Rules

### **Brute Force Detection Rule**

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 20

