// Detection title: UniFi Network — Firewall Denies Across Multiple Destinations
// MITRE ATT&CK: Conditional T1046 / TA0007 Discovery for internal service probing.
// Mapping note: External pre-compromise scanning may support T1595 instead; verify direction first.
// Full description and triage notes: searches/detection-notes.md
// Candidate threshold: >=20 firewall denies to >=10 destination IPs in 10m.
// Possible probing; determine traffic direction before assigning intent.
// This query needs CEF firewall decision records with populated src and dst.
#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
Parser.status=parsed #observer.type=firewall event.type[0]=denied
observer.name=* source.ip=* destination.ip=*
| groupBy([observer.name, source.ip], function=[
    count(as=deniedEvents),
    count(destination.ip, distinct=true, as=destinationCount),
    min(@timestamp, as=firstSeen),
    max(@timestamp, as=lastSeen)
], limit=20000)
| deniedEvents >= 20 AND destinationCount >= 10
| @timestamp := lastSeen
