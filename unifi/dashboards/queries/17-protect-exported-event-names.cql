#Vendor=ubiquiti #event.module=unifi
#event.dataset=unifi.protect
| groupBy([Vendor.Cef.name], function=count(as=events), limit=1000) | sort(events, order=desc, limit=30)
