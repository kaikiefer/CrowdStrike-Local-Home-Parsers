#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
event.category[0]=authentication #event.outcome=failure
| count(as=events)
