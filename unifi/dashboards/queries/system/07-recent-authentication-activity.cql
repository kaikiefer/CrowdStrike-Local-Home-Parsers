#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
event.category[0]=authentication
| sort(@timestamp, order=desc, limit=100) | table([@timestamp, #event.dataset, observer.name, user.name, source.ip, event.action, #event.outcome], limit=100)
