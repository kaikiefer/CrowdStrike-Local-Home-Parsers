// Inventory actual exported event names before enabling matching rules.
// Suggested hunt window: 7 days; this query returns counts, not raw events.
#Vendor=ubiquiti #event.module=unifi
| coalesce([Vendor.Cef.name, "unparsed_or_unnamed"], as=ObservedEventName)
| groupBy([#event.dataset, ObservedEventName, Parser.status], function=[
    count(as=events),
    min(@timestamp, as=firstSeen),
    max(@timestamp, as=lastSeen)
], limit=20000)
| sort(events, order=desc, limit=20000)
