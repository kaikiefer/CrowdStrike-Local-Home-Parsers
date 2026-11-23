// Synology: possible password spraying. Candidate ATT&CK T1110.003.
// Window 10m; run every 5m. Password reuse is not visible in these logs.
#Vendor=synology #event.module=dsm Parser.status=parsed
#event.outcome=failure event.category[0]=authentication
observer.name=* source.ip=* service.name=* user.name=*
| groupBy([observer.name, source.ip, service.name], function=[
    count(as=failures), count(user.name, distinct=true, as=targetedUsers),
    min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)
], limit=20000)
| failures >= 10 AND targetedUsers >= 5
| @timestamp := lastSeen
