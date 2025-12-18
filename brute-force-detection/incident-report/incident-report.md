**Incident Title:** Brute-Force Authentication Attempts Against Machine Account

**Incident ID:** BF-4625-001

**Date of Detection:** 02 December 2025

**Detected By:** Splunk SIEM

**Analyst:** Junior SOC Analyst

----

**1. Executive Summary**

On 02 December 2025, multiple failed authentication attempts were detected against the Windows machine account LAB-SERVICE-01$. A total of 22 failed login attempts were recorded within a short time frame, with a maximum of 4 attempts occurring within a single minute. The activity pattern was consistent with a brute-force credential attack.

No successful authentication events (Event ID 4624) were observed for the targeted account during or after the attack window, indicating that the brute-force attempt was unsuccessful and no system compromise occurred.

---

**2. Detection Method**

The activity was detected through monitoring of Windows Security Event ID 4625 using Splunk SIEM. The following detection query was used to identify the targeted account and count failed attempts:

```
index=bruteforce "Event ID"=4625
| rex "Account Name:\s+(?<AccountName>[^\s]+)"
| stats count by AccountName
| sort -count
```

To analyse the rate of attack, the following time-based query was used:

```
index=bruteforce "Event ID"=4625
| timechart span=1m count
```

This confirmed a peak rate of 4 failed authentication attempts within one minute.

---

**3. Indicators of Compromise (IOCs)**

| Indicator Type | Value |
|---|---|
| Event ID | 4625 |
| Target Account |	LAB-SERVICE-01$ |
| Total Failed Attempts |	22 |
| Peak Rate |	4 attempts per minute |
| Attack Type |	Brute-force authentication |
| Log Source | Windows Security Log |

---

**4. Affected Asset**

- **Asset Type:** Windows Machine Account

- **Account Name:** LAB-SERVICE-01$

- **Account Classification:** System / Host account

The $ suffix confirms that the attack targeted a machine account, not a standard user account. This suggests automated authentication attempts or misconfigured services rather than normal user activity.

---

**5. MITRE ATT&CK Classification**

- **Tactic:** Credential Access

- **Technique:** T1110 – Brute Force

---

**6. Attack Analysis**

The attack showed the following characteristics:

- Repeated authentication failures
- Consistent attempt rate (up to 4 per minute)
- Focus on a system-level machine account
- No evidence of valid credentials being used successfully

This behaviour is consistent with:

- Automated credential guessing
- Misconfigured scheduled tasks or services repeatedly failing authentication
- Scripted authentication abuse

Because the target was a machine account rather than a human user, this significantly increases concern, as successful compromise could enable:

- Service impersonation
- Lateral movement
- Persistence within the environment

---

**7. Impact Assessment**
| Category |	Assessment |
|---|---|
| Number of attempts |	Moderate (22) |
| Attack speed |	Low–Moderate |
| Target type |	Machine account
| Successful compromise |	None |
| Operational impact |	None observed |
| Risk if successful |	High |

**Final Severity Rating: Medium**

Although the attack was unsuccessful, the repeated targeting of a machine account presents a serious security risk if left undetected.

---

**8. Root Cause Hypothesis**

The most likely causes of this activity are:

- Automated brute-force script targeting local machine accounts
- Misconfigured service authentication loop
- Unauthorized authentication testing

At this stage, no direct evidence of malware or external attacker tooling is confirmed.

---

**9. Containment & Remediation Recommendations**

The following actions are recommended to prevent recurrence:

- Enforce account lockout thresholds for repeated failures

- Restrict machine account network authentication where possible

- Monitor all repeated Event ID 4625 failures in real-time

- Implement automated SIEM alerting for ≥4 failures per 5 minutes

- Review service account configurations
- Enable endpoint protection monitoring for abnormal authentication behaviour

---

**10. Detection Rule Implemented (Splunk)**
```
index=bruteforce "Event ID"=4625
| rex "Account Name:\s+(?<AccountName>[^\s]+)"
| bin _time span=5m
| stats count by AccountName, _time
| where count >= 4
```

This rule will generate an alert for potential brute-force behaviour in production environments.

**11. Final Verdict**

This incident was confirmed as a brute-force authentication attempt against a machine account, detected using Splunk SIEM. The attack was successfully detected, investigated, and contained, with no confirmed compromise.
