#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
observer.type=firewall event.type[0]=denied
| count(as=events)
