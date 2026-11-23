// Display actual DSM events without unrelated collector telemetry rows.
// Category and Activity are presentation fields only; original ECS fields
// and stored Parser.version/status remain unchanged.
#Vendor=synology #event.module=dsm
| Activity := "Unmapped message"
| case {
    package.name = * | Activity := package.name;
    service.name = * | Activity := service.name;
    event.action = * | Activity := event.action;
    *;
}
| Category := "Unmapped by stored parser"
| case { event.category[0] = * | Category := event.category[0]; *; }
| table([@timestamp, Parser.version, Parser.status, Category, Activity, message], limit=1000)
