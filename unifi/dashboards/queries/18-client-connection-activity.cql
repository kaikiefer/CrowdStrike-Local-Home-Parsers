#Vendor=ubiquiti #event.module=unifi
#event.dataset=unifi.network Vendor.Cef.name=/(?i)(?:client connected|client disconnected|client roamed)/
| timeChart(Vendor.Cef.name, function=count(), limit=20)
