#Vendor=synology #event.module=dsm Parser.status=parsed
event.category[0]=file
| table([@timestamp, observer.name, user.name, source.ip, event.action, file.path, file.size, Vendor.Share.name, Vendor.File.size, message], limit=1000)
