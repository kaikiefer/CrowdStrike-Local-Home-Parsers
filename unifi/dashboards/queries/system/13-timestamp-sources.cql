#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
| groupBy([Parser.timestamp_source], function=count(as=events), limit=20) | sort(events, order=desc)
