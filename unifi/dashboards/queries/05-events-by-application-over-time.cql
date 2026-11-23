#Vendor=ubiquiti #event.module=unifi
| timeChart(#event.dataset, function=count(), limit=10)
