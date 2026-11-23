// Detection title: UniFi — Admin Login Followed by Syslog Export Disabled
// MITRE ATT&CK: T1685 Disable or Modify Tools; TA0112 Defense Impairment.
// Mapping note: T1078 is additional context only after account abuse is independently established.
// Full description and triage notes: searches/detection-notes.md
// Candidate behavioral rule: successful admin login, then logging disabled.
// Same console, named user and source IP; within 15m.
// Application dataset is intentionally not a key: login may be in Network and
// the config change in OS. Both must report the same console/user identity.
#Vendor=ubiquiti #event.module=unifi Parser.status=parsed
observer.name=* source.ip=* user.name=*
| correlate(
    Login: {
        event.category[0]=authentication event.type[0]=start #event.outcome=success
    } include: [observer.name, #event.dataset, user.name, source.ip, message],
    LoggingDisabled: {
        #event.dataset=unifi.os Vendor.Cef.name="Admin Made Config Changes"
        | Vendor.msg = /(?i) changed Syslog Settings Mode setting from "external" to "(?:internal|off|disabled)"\./
    } include: [observer.name, #event.dataset, user.name, source.ip, message],
    globalConstraints=[observer.name, user.name, source.ip],
    sequence=true,
    within=15m
)
