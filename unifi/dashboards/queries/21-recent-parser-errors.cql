#Vendor=ubiquiti #event.module=unifi
#event.kind=pipeline_error
| sort(@timestamp, order=desc, limit=50) | table([@timestamp, observer.name, Parser.status, message], limit=50)
