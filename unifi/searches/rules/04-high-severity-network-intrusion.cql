// Detection title: UniFi Network — High Severity Intrusion Alert
// MITRE ATT&CK: No fixed mapping; use the specific signature and validated behavior.
// Mapping note: Severity alone does not identify an ATT&CK tactic or technique.
// Full description and triage notes: searches/detection-notes.md
// Candidate event rule: one Network intrusion alert with CPS severity >=70.
// Window 10m; run every 5m. This can match both detected and blocked threats.
#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
Parser.status=parsed #event.kind=alert
event.category[0]=intrusion_detection event.severity>=70
