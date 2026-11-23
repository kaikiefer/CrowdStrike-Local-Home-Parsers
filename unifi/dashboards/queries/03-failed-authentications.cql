#Vendor=ubiquiti #event.module=unifi
event.category[0]=authentication #event.outcome=failure
| count(as=events)
