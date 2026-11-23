// Historical operational status. A past disk/pool error does not establish
// current hardware health; select the time range appropriate to the incident.
#Vendor=synology #event.module=dsm #event.dataset=dsm.storage Parser.status=parsed
| table([@timestamp, observer.name, event.action, log.level, Vendor.Storage.pool, Vendor.Storage.volume, Vendor.Storage.disk, Vendor.Storage.sector, Vendor.Storage.target, message], limit=1000)
