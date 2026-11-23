// Detection title: UniFi Network — Firewall Denies Across Multiple Ports
// MITRE ATT&CK: Conditional T1046 / TA0007 Discovery for internal port/service probing.
// Mapping note: External pre-compromise scanning may support T1595 instead; verify direction first.
// Full description and triage notes: searches/detection-notes.md
// Candidate threshold: >=20 denies to >=10 ports on the same target in 10m.
// Possible port probing; approved scanners and some discovery tools also match.
#Vendor=ubiquiti #event.module=unifi #event.dataset=unifi.network
Parser.status=parsed #observer.type=firewall event.type[0]=denied
observer.name=* source.ip=* destination.ip=* destination.port=*
| groupBy([observer.name, source.ip, destination.ip], function=[
    count(as=deniedEvents),
    count(destination.port, distinct=true, as=destinationPortCount),
    min(@timestamp, as=firstSeen),
    max(@timestamp, as=lastSeen)
], limit=20000)
| deniedEvents >= 20 AND destinationPortCount >= 10
| @timestamp := lastSeen
