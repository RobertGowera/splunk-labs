# Incident Report – Privilege Escalation Detection (Lab 2)

## 1. Overview
This lab investigates a simulated **privilege escalation scenario** using Windows Security Event Logs ingested into **Splunk Cloud**. The objective was to detect the assignment of elevated privileges and identify processes executed with those privileges.

Key Windows Event IDs analysed:
- **4672** – Special privileges assigned to a new logon
- **4688** – New process creation

The results confirmed **SYSTEM-level privilege usage** and the execution of both legitimate and administrative verification processes.

---

## 2. Environment

| Component | Description |
|----------|-------------|
| SIEM | Splunk Cloud |
| Log Source | Windows Security Event Logs |
| Host | Windows 10 |
| Users Observed | SYSTEM, Virota |
| Logging Policy | Advanced Security Auditing Enabled |

---

## 3. Detection Objectives

- Detect when **special privileges** are assigned to a user or process
- Identify **SYSTEM-level process execution**
- Validate whether **post-escalation verification commands** were used
- Correlate privilege escalation with process creation

---

## 4. Indicators of Compromise (IOCs)

| Type | Value |
|------|--------|
| Privileged Account | SYSTEM |
| Privilege Assignment Event ID | 4672 |
| Process Creation Event ID | 4688 |
| Verification Command | whoami.exe |

---

## 5. Attack Analysis

### 5.1 Privilege Assignment Detection – Event ID 4672

Splunk Query Used:

```
index=main "Event ID"=4672
| rex field=_raw "Account Name:\s+(?<AccountName>[^\r\n]+)"
| stats count by AccountName
```
Results:
|Account Name |	Count |
|---|---|
|SYSTEM	| 5 |

This confirms that special privileges were assigned to the SYSTEM account five times.

### 5.2 Elevated Process Execution – Event ID 4688
Splunk Query Used:

```
index=main "Event ID"=4688
| rex field=_raw "Process Name:\s+(?<ProcessName>[^\r\n]+)"
| stats count by ProcessName
| sort -count
```

Top Processes Executed with Elevated Privileges:
| Process Name |	Count |
|---|---|
| C:\Windows\System32\svchost.exe	| 6 |
| C:\Program Files (x86)\Google\GoogleUpdater\144.0.7547.0\updater.exe	| 6 |
| C:\Users\---\AppData\Local\Microsoft\OneDrive\FileCoAuth.exe	| 3 |
| C:\Program Files (x86)\Google\Chrome\Application\chrome.exe	| 2 |
| C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe | 2 |
| whoami.exe	| 1 |

### 5.3 Privilege Verification – whoami.exe
The execution of:

```
whoami.exe
```
confirms manual validation of privilege level, a common attacker or administrator verification step after successful privilege escalation.

## 6. Timeline Correlation
Splunk Correlation Query:

```
index=main ("Event ID"=4672 OR "Event ID"=4688)
| table _time "Event ID" AccountName ProcessName
| sort _time
```
Observed Sequence:
- Special privileges granted to SYSTEM

- SYSTEM-level services and update processes executed

- whoami.exe manually executed for privilege confirmation

This confirms a valid privilege escalation activity chain.

## 7. Impact Assessment
| Area	| Impact |
|---|---|
| System Integrity |	High |
| Privilege Abuse Risk |	High |
| Persistence Potential |	Medium |
| Lateral Movement | Risk	Medium |
| Data Exposure |	No direct evidence |

If this event were malicious in production, it could lead to:

- Full system takeover

- Credential theft

- Malware deployment

- Domain privilege escalation

## 8. Incident Classification
| Category |	Classification |
|---|---|
| Attack Type |	Privilege Escalation |
| MITRE ATT&CK | TA0004 – Privilege Escalation |
| Technique	| T1068 – Exploitation for Privilege Escalation |
| Severity |	High |

## 9. Recommendations
- Enable real-time alerting for Event ID 4672

- Monitor new process creation from SYSTEM context

- Alert on manual verification commands such as:

  - whoami.exe

  - net user

  - ipconfig

- Apply least privilege principles

- Ensure credential protection (LSA, Credential Guard) is enabled

## 10. Conclusion
This lab successfully demonstrated the detection of:

- SYSTEM-level privilege assignment

- Elevated process execution

- Post-escalation privilege verification

The Splunk queries provided full visibility into privilege abuse behavior and confirmed that the environment is capable of detecting high-risk escalation activity. This type of detection is critical for SOC analysts and DFIR teams when responding to advanced intrusions.

- Status: Detection Successful
- Logs Validated
- Threat Scenario Confirmed

## 11. Author
- SOC Detection Engineering Lab – Privilege Escalation
- Created using Splunk Cloud
- By: Robert Gowera
