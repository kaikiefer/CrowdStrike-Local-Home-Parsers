#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
event.category[0]=authentication
| timeChart(#event.outcome, function=count(), limit=10)
