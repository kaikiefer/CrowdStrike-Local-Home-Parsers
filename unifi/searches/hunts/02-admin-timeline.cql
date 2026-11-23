// Raw event timeline. Set the UI time range and add user.name/source.ip filters.
// This is an investigation view; keep presentation sorting out of rule queries.
#Vendor=ubiquiti #event.module=unifi Parser.status=parsed
| event.category[0]=authentication OR (event.category[0]=configuration AND event.type[0]=change)
| sort(@timestamp, order=asc, limit=2000)
| table([@timestamp, #event.dataset, observer.name, user.name, source.ip,
         event.action, #event.outcome, message])
