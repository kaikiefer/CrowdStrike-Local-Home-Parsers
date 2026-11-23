#Vendor=ubiquiti #event.module=unifi
event.category[0]=authentication Parser.status=parsed Vendor.Cef.name=/(?i)(?:login failed|failed login|failed to log in|authentication failed|admin access failed|admin accessed|logged in|login successful)/ Vendor.Cef.name!=/(?i)(?:logged out|logout)/ source.ip=* #event.outcome=failure
| ioc:lookup(field=source.ip, type="ip_address", confidenceThreshold="high", strict=true) | count(as=Failures)
