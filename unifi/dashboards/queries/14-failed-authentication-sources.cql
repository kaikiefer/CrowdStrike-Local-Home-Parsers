#Vendor=ubiquiti #event.module=unifi
event.category[0]=authentication #event.outcome=failure source.ip=*
| top([source.ip], limit=20)
