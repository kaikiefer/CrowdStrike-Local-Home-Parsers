#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
event.category[0]=configuration event.type[0]=change
| count(as=events)
