# Active Defense Lab: Automated Threat Neutralization 🛡️

## 🚀 Project Overview
Most SOCs rely on passive monitoring. I wanted to build a system that **fights back**.
This project integrates **Splunk (SIEM)** and **Wazuh (EDR)** into a hybrid architecture that detects ransomware-like behavior and automatically neutralizes the threat in under 1 second.

**Key Capabilities:**
* **Hybrid Architecture:** Integrated Splunk Enterprise and Wazuh Manager for full-stack visibility.
* **Real-Time FIM:** Configured File Integrity Monitoring to detect unauthorized file drops (`malware.exe`).
* **Active Response:** Engineered an automated kill-chain that triggers a script to delete malicious files instantly.

## 🏗️ Architecture
![Architecture](01_Network_Architecture.jpg)

## ⚡ The Kill Chain (Proof of Concept)
I simulated a malware drop to test the automated response capabilities.
1.  **Attack:** "Malware" file dropped in a monitored directory.
2.  **Detection:** Wazuh Agent detects file creation (Rule ID 554).
3.  **Response:** Manager triggers `remove-threat.bat` on the endpoint.
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
