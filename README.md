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

