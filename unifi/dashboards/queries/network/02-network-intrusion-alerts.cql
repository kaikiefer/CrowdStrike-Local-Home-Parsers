#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
#event.kind=alert
| count(as=events)
