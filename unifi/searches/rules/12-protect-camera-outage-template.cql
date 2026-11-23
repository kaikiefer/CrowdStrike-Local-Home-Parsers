// Detection title: UniFi Protect — Multiple Cameras Reported Offline (Template)
// MITRE ATT&CK: No direct mapping; operational availability signal.
// Mapping note: Offline records alone do not establish service stopping or denial of service.
// Full description and triage notes: searches/detection-notes.md
// TEMPLATE: verify actual Protect offline names and camera identity fields first.
// Threshold: >=3 distinct affected devices behind one NVR in 10m.
// Count MAC, IP or name in that order. Identity changes can overcount a camera.
#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.protect
Parser.status=parsed observer.name=*
| Vendor.Cef.name = /(?i)\b(?:camera|device)\b.*\b(?:offline|disconnected)\b/
| coalesce([Vendor.UNIFIdeviceMac, Vendor.UNIFIdeviceIp, Vendor.UNIFIdeviceName], as=Camera)
| Camera=*
| lower(Camera)
| groupBy(observer.name, function=[
    count(as=offlineEvents),
    count(Camera, distinct=true, as=affectedCameras),
    min(@timestamp, as=firstSeen),
    max(@timestamp, as=lastSeen)
], limit=20000)
| affectedCameras >= 3
| @timestamp := lastSeen
