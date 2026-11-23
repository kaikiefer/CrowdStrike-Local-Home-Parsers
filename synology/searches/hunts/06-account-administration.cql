#Vendor=synology #event.module=dsm Parser.status=parsed
event.category[0]=iam
| table([@timestamp, observer.name, event.action, user.name, user.target.name, user.changes.name, user.target.group.name, group.name, Vendor.Privilege.app, Vendor.Privilege.permission, #event.outcome, message], limit=1000)
