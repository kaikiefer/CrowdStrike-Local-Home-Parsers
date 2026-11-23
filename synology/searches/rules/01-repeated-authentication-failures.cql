// Synology: repeated authentication failures. Candidate ATT&CK T1110.
// Window 10m; run every 5m; candidate threshold >=10 records per NAS/source/service.
// Tune for duplicate DSM info/warning records, stale credentials and NAT.
#Vendor=synology #event.module=dsm Parser.status=parsed
#event.outcome=failure event.category[0]=authentication
observer.name=* source.ip=* service.name=*
| groupBy([observer.name, source.ip, service.name], function=[
    count(as=failures), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)
], limit=20000)
| failures >= 10
| @timestamp := lastSeen
