#Vendor=ubiquiti #event.module=unifi
#event.dataset=unifi.network #event.kind=alert
| timeChart(event.severity, function=count(), limit=10)
