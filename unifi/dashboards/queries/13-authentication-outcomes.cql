#Vendor=ubiquiti #event.module=unifi
event.category[0]=authentication
| timeChart(#event.outcome, function=count(), limit=10)
