// Detection title: UniFi Network — Repeated Intrusion Alerts From One Source
// MITRE ATT&CK: No fixed mapping; signature-dependent after triage.
// Mapping note: Repeated records may describe one incident or routine traffic.
// Full description and triage notes: searches/detection-notes.md
// Candidate threshold: >=5 Network intrusion records from one source in 10m.
// These are repeated records, not necessarily five distinct attacks/signatures.
#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
Parser.status=parsed #event.kind=alert event.category[0]=intrusion_detection
observer.name=* source.ip=*
| groupBy([observer.name, source.ip], function=[
    count(as=intrusionEvents),
    min(@timestamp, as=firstSeen),
    max(@timestamp, as=lastSeen)
], limit=20000)
| intrusionEvents >= 5
| @timestamp := lastSeen
