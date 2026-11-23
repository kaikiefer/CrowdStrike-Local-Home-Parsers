// Filter actual DSM events. A bare data-connection ID also matches Falcon's
// connection telemetry, which naturally has no DSM message or package name.
#Vendor=synology #event.module=dsm
| table([@timestamp, #event.dataset, Parser.version, Parser.status, Vendor.Template, event.category[0], event.type[0], event.action, #event.outcome, host.name, user.name, source.ip, service.name, package.name, message, @rawstring], limit=1000)
