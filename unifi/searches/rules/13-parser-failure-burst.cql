// Detection title: UniFi — Log Parsing Failure Burst
// MITRE ATT&CK: No direct mapping; operational ingestion-health signal.
// Mapping note: Parser failures alone do not establish deliberate telemetry impairment.
// Full description and triage notes: searches/detection-notes.md
// Candidate operational rule: >=5 unsupported/invalid records per reporter in 15m.
// This cannot detect complete source silence; that requires an expected-source list.
#Vendor=ubiquiti #event.module=unifi
| Parser.status = /^(?:unsupported_format|unsupported_cef|invalid_cef)$/
| coalesce([observer.name, Vendor.Syslog.hostname, "unattributed"], as=Reporter)
| groupBy([Reporter, Parser.status], function=[
    count(as=failedRecords),
    min(@ingesttimestamp, as=firstIngested),
    max(@ingesttimestamp, as=lastIngested)
], limit=20000)
| failedRecords >= 5
| @timestamp := lastIngested
