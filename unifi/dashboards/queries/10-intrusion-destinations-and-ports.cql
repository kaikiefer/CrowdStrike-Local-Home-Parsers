#Vendor=ubiquiti #event.module=unifi
#event.dataset=unifi.network #event.kind=alert destination.ip=*
| groupBy([destination.ip, destination.port, network.transport], function=count(as=events), limit=1000) | sort(events, order=desc, limit=20)
