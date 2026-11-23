// Detection title: UniFi — Repeated Admin Authentication Failures
// MITRE ATT&CK: Candidate T1110 Brute Force; TA0006 Credential Access.
// Mapping note: Failure volume does not establish a particular password-attack sub-technique.
// Full description and triage notes: searches/detection-notes.md
// Candidate threshold: >=10 failures from one source/application/console in 10m.
// Window 10m; run every 5m. Require all grouping fields to avoid null groups.
#Vendor=ubiquiti #event.module=unifi Parser.status=parsed
#event.outcome=failure event.category[0]=authentication
observer.name=* source.ip=*
| groupBy([#event.dataset, observer.name, source.ip], function=[
    count(as=failures),
    min(@timestamp, as=firstSeen),
    max(@timestamp, as=lastSeen)
], limit=20000)
| failures >= 10
| @timestamp := lastSeen
