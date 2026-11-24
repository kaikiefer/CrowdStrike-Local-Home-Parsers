#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
observer.name=*
| groupBy([observer.name, #event.dataset], function=[count(as=events), max(@timestamp, as=lastSeen)], limit=1000) | sort(lastSeen, order=desc, limit=100)
