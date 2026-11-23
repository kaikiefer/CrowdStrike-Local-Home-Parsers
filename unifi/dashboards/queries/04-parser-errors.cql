#Vendor=ubiquiti #event.module=unifi
#event.kind=pipeline_error
| count(as=events)
