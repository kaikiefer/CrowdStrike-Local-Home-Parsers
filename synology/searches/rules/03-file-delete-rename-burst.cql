// Synology: possible destructive file activity. Candidate ATT&CK T1485/T1486.
// Window 5m; run every 5m. >=100 records across >=50 paths per NAS/user/source.
// Benign cleanup/sync/retention jobs can trigger this. No encryption proof.
#Vendor=synology #event.module=dsm Parser.status=parsed
#event.dataset=dsm.file event.category[0]=file
event.action=/^(delete|rename)$/
observer.name=* source.ip=* user.name=* file.path=*
| groupBy([observer.name, source.ip, user.name], function=[
    count(as=operations), count(file.path, distinct=true, as=affectedPaths),
    min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen)
], limit=20000)
| operations >= 100 AND affectedPaths >= 50
| @timestamp := lastSeen
