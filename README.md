# Active Defense Lab: Automated Threat Neutralization🛡️

## 🚀 Project Overview
Most SOCs rely on passive monitoring. I wanted to build a system that **fights back**.
This project integrates **Splunk (SIEM)** and **Wazuh (EDR)** into a hybrid architecture that detects ransomware-like behavior and automatically neutralizes the threat in under 1 second.

**Key Capabilities:**
* **Cloud Threat Intelligence:** Real-time hash lookups against VirusTotal's database.
* **Automated Remediation:** Zero-touch removal of malicious files using custom Python scripts.
* **FIM (File Integrity Monitoring):** Real-time detection of filesystem changes on Windows/Linux.

## 🏗️ Architecture
![Architecture](https://github.com/Anirudhx7/Active-Defense-Lab/blob/ca20bce519899b9d934d65d6d85d2f491ea91398/images/01_Architecture.png)

## ⚡ The Kill Chain (Proof of Concept)
I simulated a malware drop to test the automated response capabilities.
1.  **Attack:** "Malware" file dropped in a monitored directory.
2.  **Detection:** Wazuh Agent (FIM) detects the new file and generates a hash.
3.  **Intelligence:** Wazuh Manager queries the **VirusTotal API**.
4.  **Decision:** If `positives > 0`, the Manager triggers an Active Response.
5.  **Action:** A compiled Python executable (`remove-threat.exe`) runs on the endpoint to delete the file.
4.  **Result:** Threat eliminated immediately.

### Watch the Automation in Action:
![Active Response](https://github.com/Anirudhx7/Active-Defense-Lab/blob/9ee5f4cb4e658ecbed963aef5f3045b4c4e43f1d/images/03_Active_Response_Demo.gif)

## 🛠️ Technical Implementation

### 1. The Intelligence Engine (Wazuh Manager)
A. I configured the global `ossec.conf` to enable the VirusTotal integration. This allows the SIEM to enrich logs with external threat data.
```xml
<integration>
  <name>virustotal</name>
  <api_key>HIDDEN_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```
B. Append the following blocks to the Wazuh server /var/ossec/etc/ossec.conf file. This enables Active Response and trigger the remove-threat.exe executable when the VirusTotal query returns positive matches for threats:
```
<ossec_config>
  <command>
    <name>remove-threat</name>
    <executable>remove-threat.exe</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
</ossec_config>
```
C. Add the following rules to the Wazuh server /var/ossec/etc/rules/local_rules.xml file to alert about the Active Response results.
```
<group name="virustotal,">
  <rule id="100092" level="12">
      <if_sid>657</if_sid>
      <match>Successfully removed threat</match>
      <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>

  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```
### 2. The "Kill Script" (Python):
A custom script that logs the incident for audit purposes before removing the threat.
Instead of a simple batch script, I wrote a Python script to parse the JSON alert from Wazuh, extract the filename, and execute a secure deletion. This was compiled to an .exe using PyInstaller to ensure stability on the Windows Agent.
<br>
- <a href="https://github.com/Anirudhx7/Active-Defense-Lab/blob/00277f6fa75201085b4087dcbcd61bb2e9ee66e4/Scripts/remove-threat.py">`remove-threat.py`</a>
Convert the active response Python script remove-threat.py to a Windows executable application.
```
> pyinstaller -F \path_to_remove-threat.py
```
### 3. Endpoint Configuration
The Windows Agent was configured to monitor the FIM_TEST directory in real-time to catch drive-by downloads.
```xml
<syscheck>
  <directories realtime="yes">C:\Users\Windows10\FIM_TEST</directories>
</syscheck>
```

## 🚧 Challenges & Troubleshooting
JSON Parsing: The Wazuh Manager passes the alert data as a complex JSON object. Debugging the Python script to correctly extract the file path required analyzing the full alert payload.

PyInstaller Pathing: Compiling the script to .exe caused issues with relative paths. I had to ensure the executable was in the specific active-response bin folder and added to the Agent's definition.

API Latency: There is a slight delay between file creation and the API return. I tuned the response timeout to ensure the script didn't time out while waiting for the verdict.

# 🧠 Learning Outcomes
From this project I gained hands-on experience in:

- **SOAR (Security Orchestration, Automation, and Response)** implementation.
- **API Integration** (Connecting SIEM tools to external Threat Intelligence providers).
- **Python Scripting** for security automation and JSON log parsing.
- **Endpoint Security** configuration using Wazuh Agents (FIM).
- **False Positive Management** and alert tuning in a live environment.
- **Log Analysis** to troubleshoot communication between Manager and Agent.

---

# 📁 Repository Structure
```text
/scripts
    remove-threat.py       # The source Python script for remediation
    

/configs
    ossec-manager.conf     # VirusTotal integration block
    ossec-agent-win.conf   # Windows FIM configuration block

/images
    01_Architecture.png
    02_VirusTotal_Log.png
    03_Active_Response_Demo.gif
```

---

# 🏁 Final Notes
This project bridges the gap between **detection** and **remediation**. By leveraging the VirusTotal API, I turned Wazuh from a passive tool into an active defense system capable of stopping threats the moment they touch the disk, significantly reducing MTTR (Mean Time to Respond).

## 📬 Contact

LinkedIn: <a href="https://www.linkedin.com/in/anirudh-mehandru/">linkedin.com/in/anirudh-mehandru </a>
