#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
event.category[0]=authentication #event.outcome=failure source.ip=*
| top([source.ip], limit=20)
