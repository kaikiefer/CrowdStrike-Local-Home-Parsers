// Detection title: UniFi — Failed Login Followed by Successful Login
// MITRE ATT&CK: No automatic mapping; T1078 only if account abuse is independently established.
// Mapping note: A password typo can match; this query does not establish brute force or compromise.
// Full description and triage notes: searches/detection-notes.md
// Candidate behavioral rule: one failed login followed by one successful login.
// Same console, application, source IP and named user; within 10m.
// A single typo also matches. Start as low severity; rule 02 measures volume.
// Use Created/event time. No other aggregate functions are combined with correlate.
#Vendor=ubiquiti #event.module=unifi Parser.status=parsed
observer.name=* source.ip=* user.name=*
event.category[0]=authentication
| correlate(
    Failure: {
        #event.outcome=failure event.type[0]=start
    } include: [observer.name, #event.dataset, user.name, source.ip, event.action, message],
    Success: {
        #event.outcome=success event.type[0]=start
    } include: [observer.name, #event.dataset, user.name, source.ip, event.action, message],
    globalConstraints=[observer.name, #event.dataset, user.name, source.ip],
    sequence=true,
    within=10m
)
