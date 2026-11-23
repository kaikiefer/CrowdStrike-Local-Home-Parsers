#Vendor=ubiquiti #event.module=unifi
| groupBy([Parser.status], function=count(as=events), limit=20) | sort(events, order=desc)
