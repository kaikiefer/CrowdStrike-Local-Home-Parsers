// Detection title: UniFi — Possible Admin Password Spraying
// MITRE ATT&CK: Candidate T1110.003 Password Spraying; TA0006 Credential Access.
// Mapping note: Multiple targeted users support a hypothesis; attempted password reuse is not visible.
// Full description and triage notes: searches/detection-notes.md
// Candidate threshold: >=10 failures against >=5 distinct users in 10m.
// A NAT/shared proxy or a broken automation can also produce this pattern.
#Vendor=ubiquiti #event.module=unifi Parser.status=parsed
#event.outcome=failure event.category[0]=authentication
observer.name=* source.ip=* user.name=*
| groupBy([#event.dataset, observer.name, source.ip], function=[
    count(as=failures),
    count(user.name, distinct=true, as=targetedUsers),
    min(@timestamp, as=firstSeen),
    max(@timestamp, as=lastSeen)
], limit=20000)
| failures >= 10 AND targetedUsers >= 5
| @timestamp := lastSeen
