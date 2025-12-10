# Active Defense Lab: Automated Threat Neutralization🛡️

## 🚀 Project Overview
Most SOCs rely on passive monitoring. I wanted to build a system that **fights back**.
This project integrates **Splunk (SIEM)** and **Wazuh (EDR)** into a hybrid architecture that detects ransomware-like behavior and automatically neutralizes the threat in under 1 second.

**Key Capabilities:**
* **Cloud Threat Intelligence:** Real-time hash lookups against VirusTotal's database.
* **Automated Remediation:** Zero-touch removal of malicious files using custom Python scripts.
* **FIM (File Integrity Monitoring):** Real-time detection of filesystem changes on Windows/Linux.

## 🏗️ Architecture
![Architecture](01_Network_Architecture.jpg)

## ⚡ The Kill Chain (Proof of Concept)
I simulated a malware drop to test the automated response capabilities.
1.  **Attack:** "Malware" file dropped in a monitored directory.
2.  **Detection:** Wazuh Agent (FIM) detects the new file and generates a hash.
3.  **Intelligence:** Wazuh Manager queries the **VirusTotal API**.
4.  **Decision:** If `positives > 0`, the Manager triggers an Active Response.
5.  **Action:** A compiled Python executable (`remove-threat.exe`) runs on the endpoint to delete the file.
4.  **Result:** Threat eliminated immediately.

### Watch the Automation in Action:
![Active Response](03_Active_Response_Demo.gif)

## 🛠️ Technical Implementation

### 1. Infrastructure Engineering
* **Hypervisor:** VirtualBox (Bridged Networking for Manager/Agent communication).
* **Storage:** Manually resized Linux LVM partitions to accommodate Elastic Stack indexer requirements.
* **Tuning:** Optimized JVM Heap memory for performance on resource-constrained VMs.

### 2. The Defense Logic
**Endpoint Configuration (`ossec.conf`):**
Configured real-time monitoring on critical directories to bypass standard polling intervals.

**The "Kill Script" (Batch):**
A custom script that logs the incident for audit purposes before removing the threat.
```bat
@echo off
set LOG_FILE="C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
echo %date% %time% active-response: 'delete_malware' - Threat Neutralized >> %LOG_FILE%
del /f /q "C:\Users\User\Desktop\FIM_TEST\malware.exe"
