#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
#event.kind=alert source.ip=*
| top([source.ip], limit=20)
