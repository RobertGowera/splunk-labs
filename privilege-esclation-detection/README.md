# **Privilege Escalation Detection – Splunk SIEM Lab**

## Overview

This lab simulates and detects privilege escalation behaviour on a Windows endpoint using Splunk Cloud and Windows Security Event Logs. The investigation focuses on identifying special privilege assignments (Event ID 4672) and elevated process execution (Event ID 4688) to confirm whether administrative-level access was obtained and abused.

This detection is mapped to MITRE ATT&CK T1068 – Privilege Escalation.

## Objectives

- Detect special privileges assigned to an account

- Detect admin-level process execution

**Identify:**

- Who gained elevated privileges

- When it occurred

- What elevated processes were executed

- Produce a SOC-style incident report

- Add a second detection lab to my Splunk portfolio series

## Tools Used

- Splunk Cloud

- Windows Security Event Logs

- SPL (Search Processing Language)

- Event Viewer

- MITRE ATT&CK Framework

- GitHub

## Data Source

- Windows Security Log (CSV Export)

- Collection Window: Last 1 hour after admin activity

- Event IDs Analysed:

  - 4624 – Successful Logon

  - 4672 – Special Privileges Assigned

  - 4688 – New Process Created

## Detection Results Summary
**Privilege Assignment (Event ID 4672)**

- **Account Name:** SYSTEM

- **Total Privilege Assignments:** 5

This confirms repeated high-privilege access tokens were issued.

## Elevated Process Execution (Event ID 4688 – Top Processes)
| Process Name | Count |
|---|---|
| Google Updater (updater.exe) |	6 |
| svchost.exe |	6 |
| OneDrive Co-Authoring (FileCoAuth.exe) |	3 |
| Google Chrome (chrome.exe) |	2 |
| Microsoft Edge Updater (MicrosoftEdgeUpdate.exe) |	2 |
| whoami.exe |	1 |

These processes confirm SYSTEM-level process execution and administrative context validation (whoami).

## Attack Interpretation

An elevated session was established under the SYSTEM account, generating:

- Repeated special privilege assignments

- Multiple SYSTEM-level processes

- Manual confirmation of elevated context using whoami

This behaviour is consistent with a post-exploitation privilege escalation phase, where an attacker confirms elevated control and initiates system-level processes.

## Key SPL Queries Used
**Detect Special Privileges Assigned**
```
index=main "Event ID"=4672
| rex field=_raw "Account Name:\s+(?<AccountName>[^\r\n]+)"
| stats count by AccountName
```

**Detect Elevated Processes**
```
index=main "Event ID"=4688
| rex field=_raw "Process Name:\s+(?<ProcessName>[^\r\n]+)"
| stats count by ProcessName
| sort -count
```

**Full Privilege Escalation Timeline**
```
index=main ("Event ID"=4672 OR "Event ID"=4688)
| rex field=_raw "Account Name:\s+(?<AccountName>[^\r\n]+)"
| rex field=_raw "Process Name:\s+(?<ProcessName>[^\r\n]+)"
| table _time "Event ID" AccountName ProcessName
| sort _time
```

## Indicators of Compromise (IOCs)
|Indicator Type |	Value |
|---|---|
| Privileged Account |	SYSTEM |
| Privilege Assignment Event |	4672 |
| Elevated Process Execution |	4688 |
| Validation Command |	whoami |
| SYSTEM-Level Services |	svchost.exe |


## Impact Assessment

Privilege escalation to SYSTEM level represents the highest level of control on a Windows endpoint. If this activity were malicious, the attacker would be capable of:

- Installing malware

- Creating backdoor users

- Disabling security controls

- Exfiltrating sensitive data

- Deploying ransomware

## Response Actions (SOC Playbook)

- Verify legitimacy of the SYSTEM activity

- Review recent admin group changes (4728 / 4732)

- Inspect processes executed under SYSTEM

- Check for persistence mechanisms

- Reset credentials if compromise is suspected

- Enable alerting on repeated 4672 events

### MITRE ATT&CK Mapping
| Tactic |	Technique |	ID |
|---|---|---
| Privilege Escalation |	Exploitation for Privilege Escalation |	T1068 |

## Final Outcome

This lab successfully demonstrates the detection of:

- High-privilege access grants

- SYSTEM-level process execution

- Administrative validation commands

- End-to-end SOC investigation using Splunk
