// Detection title: UniFi OS — External Syslog Export Disabled
// MITRE ATT&CK: T1685 Disable or Modify Tools; TA0112 Defense Impairment.
// Mapping note: Review change approval; a logging change does not by itself prove malicious intent.
// Full description and triage notes: searches/detection-notes.md
// Candidate rule: syslog export disabled. Window 10m; run every 5m.
// Matches the UniFi OS config-change message structure; validate against your version.
#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
Parser.status=parsed Vendor.Cef.name="Admin Made Config Changes"
| Vendor.msg = /(?i) changed Syslog Settings Mode setting from "external" to "(?:internal|off|disabled)"\./
