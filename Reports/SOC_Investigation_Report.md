# 🛡️ SOC Investigation Report  
**Enterprise SOC Simulation & Threat Detection Lab**  
**Author:** Anirudh Mehandru  
**Environment:** AD + Windows 10 + Sysmon + Splunk + Kali Linux  
**Date:** 2025-11-30

---

# 1. Executive Summary

A controlled attack simulation was performed to understand how identity attacks, persistence techniques, and suspicious command execution appear inside a monitored Windows environment.  
The goal was to detect, analyze, correlate, and document malicious activity using Sysmon and Splunk SIEM.

Three major attack paths were executed:

1. **RDP Brute-Force Attempts (T1110 – Brute Force)**  
2. **Registry Run Key Persistence (T1547 – Boot/Logon Autostart Execution)**  
3. **Suspicious PowerShell Execution (T1059 – Command & Scripting Interpreter)**

All attacks were successfully detected using custom SPL correlation rules.

---

# 2. Environment Summary

- **Windows Server 2022 (Domain Controller)**  
- **Windows 10 Endpoint** with Sysmon  
- **Ubuntu Server running Splunk Enterprise**  
- **Kali Linux Attack Machine**  
- Log Sources:  
  - Windows Security Logs (4624/4625)  
  - Sysmon (Process, Registry, Network telemetry)

---

# 3. Attack Scenario Details

## 🔥 3.1 RDP Brute-Force Attack (Hydra)  
**Purpose:** Test identity-based detection capability  
**Technique:** MITRE **T1110 – Brute Force**

### Observed Telemetry:
- Massive spike in **Event ID 4625** (Failed Logon)  
- Repeated attempts from attacker IP  
- Multiple invalid credential pairs  
- Uniform timing pattern consistent with automated brute-force tools  

### Detection:
Splunk correlation rule aggregated >20 failed logons per account/IP within a short time window.

### Outcome:
Detection successful — flagged as brute-force behavior.

---

## 🔥 3.2 Registry Run Key Persistence  
**Purpose:** Detect persistence creation via autostart mechanisms  
**Technique:** MITRE **T1547 – Registry Run Key Startup**

### Observed Telemetry:
- Sysmon Event ID **13** (Registry Value Set)  
- Sysmon Event ID **11** (File Created)  
- Suspicious path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- Parent process anomalies

### Detection:
Splunk search matched Sysmon registry modification events for Run Key paths.

### Outcome:
Persistence attempt detected successfully.

---

## 🔥 3.3 PowerShell Execution Abuse  
**Purpose:** Identify suspicious command execution  
**Technique:** MITRE **T1059 – Command & Scripting Interpreter**

### Observed Telemetry:
- Sysmon Event ID **1** (Process Create)  
- Encoded or obfuscated PowerShell commands  
- PowerShell spawned by unexpected parent (cmd.exe)  
- Non-standard command-line flags

### Detection:
Matched Sysmon process events using command-line heuristics.

### Outcome:
Execution chain identified and alerted.

---

# 4. Detection Engineering Summary

Custom Splunk detections built for:

- Failed Logon Spike Detection  
- Registry Persistence Detection  
- Suspicious PowerShell Execution  
- Parent/Child Process Anomalies  

All detections successfully triggered during simulations.

---

# 5. MITRE ATT&CK Summary

| Attack | Technique | Status |
|--------|-----------|--------|
| RDP Brute Force | **T1110** | Detected |
| Registry Run Key Persistence | **T1547** | Detected |
| PowerShell Execution | **T1059** | Detected |
| Remote Services (RDP) | **T1021** | Observed |
| Active Scanning | **T1595** | Observed |

---

# 6. Incident Timeline (Simulated)

| Timestamp | Event | Source |
|-----------|--------|---------|
| 13:04 | RDP brute-force begins | Kali Linux |
| 13:06 | 4625 spikes detected | DC Logs |
| 13:10 | Persistence modification executed | Windows 10 |
| 13:11 | Sysmon Event ID 13 logged | Sysmon |
| 13:13 | Suspicious PowerShell starts | Windows 10 |
| 13:14 | Correlation rules trigger | Splunk |

---

# 7. Conclusion

The SOC simulation successfully demonstrated how real-world Windows attacks appear in Sysmon and security logs. Correlation rules provided rapid detection (<60 seconds MTTD), and MITRE mapping helped categorize attacker behavior.

This lab replicates core Tier 1/Tier 2 SOC workflows, including investigation, triage, telemetry analysis, and detection engineering.

---

# 8. Recommendations

- Improve PowerShell ScriptBlock Logging  
- Deploy additional Sysmon rules for network telemetry  
- Add lateral movement simulation in next phase  
- Expand detections to include privilege escalation and shadow copy abuse  

---

**End of Report**

