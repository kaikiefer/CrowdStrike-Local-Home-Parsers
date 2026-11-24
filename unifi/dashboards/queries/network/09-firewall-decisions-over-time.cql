#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
observer.type=firewall
| timeChart("event.type[0]", function=count(), limit=10)
