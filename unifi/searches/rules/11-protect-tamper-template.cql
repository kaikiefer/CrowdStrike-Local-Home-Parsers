// Detection title: UniFi Protect — Camera Tamper Event (Template)
// MITRE ATT&CK: No direct Enterprise ATT&CK mapping for a generic physical tamper indication.
// Mapping note: Confirm actual firmware event names and distinguish physical from software tampering.
// Full description and triage notes: searches/detection-notes.md
// TEMPLATE: verify actual Protect event names before enabling a rule.
// Window 10m; run every 5m. Match a tamper indication, excluding recovery names.
// Raw names are used because the parser does not label motion as cyber alerts.
#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.protect
Parser.status=parsed
| Vendor.Cef.name = /(?i)\btamper\b/
| Vendor.Cef.name != /(?i)\b(?:cleared|resolved|restored|ended|disabled)\b/
