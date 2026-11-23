#Vendor=synology #event.module=dsm Parser.status=parsed
event.category[0]=authentication
| table([@timestamp, observer.name, event.action, #event.outcome, user.name, source.ip, service.name, event.reason, message], limit=1000)
