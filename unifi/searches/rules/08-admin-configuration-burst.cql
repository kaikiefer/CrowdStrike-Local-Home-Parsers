// Detection title: UniFi — Admin Configuration Change Burst
// MITRE ATT&CK: No direct mapping from configuration-change volume alone.
// Mapping note: Review the actual settings and approval before assigning a malicious objective.
// Full description and triage notes: searches/detection-notes.md
// Candidate threshold: >=5 configuration CHANGE events per admin/console in 10m.
// Test Syslog has type=info and is deliberately excluded.
// One UI operation may emit multiple changes: baseline before enabling.
#Vendor=ubiquiti #event.module=unifi Parser.status=parsed
event.category[0]=configuration event.type[0]=change
observer.name=* user.name=*
| groupBy([observer.name, user.name], function=[
    count(as=configurationChanges),
    min(@timestamp, as=firstSeen),
    max(@timestamp, as=lastSeen)
], limit=20000)
| configurationChanges >= 5
| @timestamp := lastSeen
