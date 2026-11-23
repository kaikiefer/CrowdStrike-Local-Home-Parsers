#Vendor=ubiquiti #event.module=unifi
observer.type=firewall event.type[0]=denied destination.ip=*
| groupBy([destination.ip, destination.port], function=count(as=events), limit=1000) | sort(events, order=desc, limit=20)
