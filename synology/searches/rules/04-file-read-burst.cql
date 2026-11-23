// Synology: unusual file-read volume; investigation lead only.
// Window 10m; run every 5m. >=500 distinct paths per NAS/user/source.
// Reads can be application preloads, indexing or backups, not exfiltration.
#Vendor=synology #event.module=dsm Parser.status=parsed
#event.dataset=dsm.file event.action=read
observer.name=* source.ip=* user.name=* file.path=*
| groupBy([observer.name, source.ip, user.name], function=[
    count(as=readRecords), count(file.path, distinct=true, as=readPaths),
    min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)
], limit=20000)
| readPaths >= 500
| @timestamp := lastSeen
