#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
event.category[0]=authentication #event.outcome=failure
| count(as=events)
