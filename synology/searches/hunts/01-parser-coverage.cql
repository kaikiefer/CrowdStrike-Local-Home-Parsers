// Select a time range appropriate to your NAS activity and retention.
#Vendor=synology #event.module=dsm
| groupBy([#event.dataset, Parser.status, Parser.timestamp_source], limit=20000)
