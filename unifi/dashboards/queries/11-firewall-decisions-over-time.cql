#Vendor=ubiquiti #event.module=unifi
observer.type=firewall
| timeChart("event.type[0]", function=count(), limit=10)
