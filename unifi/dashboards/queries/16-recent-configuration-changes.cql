#Vendor=ubiquiti #event.module=unifi
event.category[0]=configuration event.type[0]=change
| sort(@timestamp, order=desc, limit=100) | table([@timestamp, observer.name, user.name, source.ip, event.action, message], limit=100)
