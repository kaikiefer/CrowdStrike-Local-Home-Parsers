#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
| sort(@timestamp, order=desc, limit=100) | table([@timestamp, observer.name, event.code, event.action, user.name, source.ip, message], limit=100)
