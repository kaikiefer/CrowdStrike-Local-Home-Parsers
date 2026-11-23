// Inspect Protect's actual event names and subject-device keys.
// Motion/person events are useful context and are not automatically threats.
#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.protect
Parser.status=parsed
| sort(@timestamp, order=desc, limit=500)
| table([@timestamp, observer.name, event.code, Vendor.Cef.name,
         Vendor.UNIFIcategory, Vendor.UNIFIsubCategory, Vendor.UNIFIdeviceName,
         Vendor.UNIFIdeviceIp, Vendor.UNIFIdeviceMac, message])
