#Vendor=ubiquiti #event.module=unifi
#event.dataset=unifi.network #event.kind=alert
| groupBy([Vendor.Cef.name, event.severity], function=count(as=events), limit=1000) | sort(events, order=desc, limit=20)
