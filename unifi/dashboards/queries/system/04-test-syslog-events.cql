#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.os
Vendor.Cef.name="Test Syslog"
| count(as=events)
