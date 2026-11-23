# Detection titles and MITRE ATT&CK notes

Use the **Detection title** as the rule name in CrowdStrike. Copy the corresponding description into its notes/description field and select the listed tactic/technique where supported by your tenant's ATT&CK catalog. Windows, thresholds, severity suggestions, and CQL files remain in the [rule guide](README.md).

Mappings were reviewed against MITRE's live Enterprise ATT&CK catalog on November 22, 2026. They describe detection hypotheses and observed behavior; a matching event does not establish malicious intent. Where the query lacks evidence for a specific technique, leave the structured mapping blank. Conditional mappings belong in analyst notes until the stated conditions are established.

MITRE's current catalog uses **T1685 — Disable or Modify Tools**, tactic **TA0112 — Defense Impairment**, for tampering with logging tools and forwarding pipelines. A Falcon tenant may expose an older ATT&CK catalog. Check its catalog version if an ID is unavailable; retain the current mapping in the notes instead of selecting an unrelated technique. These notes do not require a parser change.

## 01 — External syslog export disabled

**Detection title:** UniFi OS — External Syslog Export Disabled

**MITRE ATT&CK:** [T1685 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/); [TA0112 — Defense Impairment](https://attack.mitre.org/tactics/TA0112/).

**Description / notes:** UniFi OS reported that Syslog Settings Mode changed from `external` to `internal`, `off`, or `disabled`. This can interrupt centralized visibility and is consistent with impairing a logging/forwarding tool when unauthorized. Review the actor, source IP, affected console, approved change records, and subsequent log delivery. Authorized logging maintenance can match. Switching from `internal` to `external` and sending `Test Syslog` do not match this rule. The query does not show deletion of historical logs or modification of the Linux audit subsystem, so no narrower log-clearing/audit sub-technique is assigned.

## 02 — Repeated admin authentication failures

**Detection title:** UniFi — Repeated Admin Authentication Failures

**MITRE ATT&CK:** Candidate [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/); [TA0006 — Credential Access](https://attack.mitre.org/tactics/TA0006/).

**Description / notes:** At least 10 failed authentication events were received from one source IP for the same application and console in 10 minutes. Investigate possible automated credential attempts, checking targeted users, subsequent successful logins, shared proxies, and stale automation credentials. The query does not reveal attempted passwords or establish whether one account or many accounts were targeted; use the parent technique rather than asserting Password Guessing, Credential Stuffing, or Password Spraying.

## 03 — Possible admin password spraying

**Detection title:** UniFi — Possible Admin Password Spraying

**MITRE ATT&CK:** Candidate [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/); [TA0006 — Credential Access](https://attack.mitre.org/tactics/TA0006/).

**Description / notes:** At least 10 failed authentication events targeted at least 5 distinct usernames from one source IP against the same application and console in 10 minutes. This pattern can indicate password spraying. The logs do not expose password reuse across accounts, so this remains a hypothesis. Check shared management systems, scanners, automation, account names, and any later successful logins before classifying the activity as an attack.

## 04 — High severity Network intrusion alert

**Detection title:** UniFi Network — High Severity Intrusion Alert

**MITRE ATT&CK:** No fixed tactic or technique. Assign from the specific signature and validated activity during triage.

**Description / notes:** UniFi Network produced an intrusion alert with normalized CPS severity of at least 70. Review the original event name, signature information, source/destination, protocol, and detection-versus-blocking action. Severity and an IDS alert alone do not identify an ATT&CK technique. For example, do not label every alert as exploitation, command and control, or successful compromise. Record the appropriate technique only when the signature and supporting evidence establish that behavior.

## 05 — Repeated Network intrusion alerts

**Detection title:** UniFi Network — Repeated Intrusion Alerts From One Source

**MITRE ATT&CK:** No fixed tactic or technique. Signature-dependent mapping after investigation.

**Description / notes:** At least 5 intrusion records attributed to one source IP were received by the same console in 10 minutes. Review event/signature identities, targets, source ownership, gateway action, and duplicate delivery. Multiple records can describe one incident or routine traffic. Determine the behavior from the underlying alerts before selecting an ATT&CK technique; alert volume alone does not establish one.

## 06 — Firewall denies across multiple destinations

**Detection title:** UniFi Network — Firewall Denies Across Multiple Destinations

**MITRE ATT&CK:** Conditional [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/), [TA0007 — Discovery](https://attack.mitre.org/tactics/TA0007/), when the activity is internal service probing. For external pre-compromise reconnaissance, consider [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/) / Reconnaissance instead. Leave structured mappings blank until direction and behavior are established.

**Description / notes:** One source IP generated at least 20 firewall-denied records involving at least 10 destination IPs in 10 minutes. Investigate possible network probing. Check routing direction, NAT, destination ports, authorized scanners, discovery tools, and the firewall policy. This query counts destinations but does not prove service enumeration; do not assign internal Discovery solely because an address looks private, or assign both candidate techniques automatically.

## 07 — Firewall denies across multiple ports

**Detection title:** UniFi Network — Firewall Denies Across Multiple Ports

**MITRE ATT&CK:** Conditional [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/), [TA0007 — Discovery](https://attack.mitre.org/tactics/TA0007/), for internal port/service probing. External pre-compromise scanning may instead support [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/). Leave structured mappings blank until context is established.

**Description / notes:** One source generated at least 20 denied records to at least 10 destination ports on the same target in 10 minutes. Investigate possible port scanning, checking traffic direction, scanner authorization, protocol, and normal discovery/monitoring behavior. Firewall denials show attempted traffic rather than successful access. Confirm the scanning context before assigning the candidate ATT&CK mapping.

## 08 — Admin configuration change burst

**Detection title:** UniFi — Admin Configuration Change Burst

**MITRE ATT&CK:** No direct mapping from change volume alone.

**Description / notes:** One named admin made at least 5 configuration-change records on the same console in 10 minutes. Review the changed settings, approval, actor/source identity, and whether one UI action generated several records. Routine provisioning and upgrades can match. Do not infer Valid Accounts abuse or defense impairment solely from multiple changes. Rule 01 provides the narrower signal for disabling external logging.

## 09 — Failed login followed by successful login

**Detection title:** UniFi — Failed Login Followed by Successful Login

**MITRE ATT&CK:** No automatic mapping. Consider [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) only if additional evidence establishes unauthorized account use. Choose the tactic from the observed objective; a successful login alone does not establish Initial Access, Persistence, Privilege Escalation, or Stealth.

**Description / notes:** A failed login was followed by a successful login within 10 minutes for the same console, application, named user, and source IP. Review surrounding failures, user confirmation, source ownership, and subsequent admin activity. A password typo is sufficient to match this query. It does not establish brute force, stolen credentials, or account compromise, so the rule should not automatically claim those techniques.

## 10 — Admin login followed by syslog export disabled

**Detection title:** UniFi — Admin Login Followed by Syslog Export Disabled

**MITRE ATT&CK:** [T1685 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/); [TA0112 — Defense Impairment](https://attack.mitre.org/tactics/TA0112/). Additional T1078 is conditional on independently established account abuse.

**Description / notes:** A successful admin login was followed within 15 minutes by disabling external syslog export, with the same console, named user, and source IP. This associates an authenticated session with a reduction in centralized visibility. Check the change approval, actor, source, and subsequent delivery. Network login and OS configuration records can correlate if their identities match. Authorized maintenance can produce the same sequence; the relationship does not independently prove that the account was compromised.

## 11 — Protect camera tamper event template

**Detection title:** UniFi Protect — Camera Tamper Event (Template)

**MITRE ATT&CK:** No direct Enterprise ATT&CK mapping for a generic physical camera-tamper indication.

**Description / notes:** Protect emitted a tamper-named event, excluding several recovery or disabled-state names. Confirm the actual firmware event name, camera, location, maintenance work, and available video context. A camera being physically covered or moved does not by itself establish cyber defense impairment. Map a cyber technique only if independent evidence shows software/tool tampering. Verify actual Protect exports before enabling this template.

## 12 — Protect multiple cameras offline template

**Detection title:** UniFi Protect — Multiple Cameras Reported Offline (Template)

**MITRE ATT&CK:** No direct mapping; operational availability signal.

**Description / notes:** At least 3 distinct subject devices behind one NVR emitted offline/disconnect events in 10 minutes. Review power, PoE, switch uplinks, network maintenance, NVR health, and camera identity consistency. The query does not establish malicious service stopping or denial of service. It also cannot detect total silence when the NVR or collector cannot report events. Validate actual Protect event names and subject fields before enabling this template.

## 13 — Parser failure burst

**Detection title:** UniFi — Log Parsing Failure Burst

**MITRE ATT&CK:** No direct mapping; operational ingestion-health signal.

**Description / notes:** At least 5 unsupported or invalid records were received from one reporter with the same parser status in 15 minutes. Check firmware changes, raw versus CEF exports, transport wrapping, collector configuration, and raw records. Parsing errors do not establish indicator blocking or defense impairment. Escalate to an ATT&CK-mapped security investigation only if evidence independently shows deliberate interference with telemetry.
