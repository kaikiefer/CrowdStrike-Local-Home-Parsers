# UniFi dashboards for Falcon Next-Gen SIEM / LogScale

Choose the dashboard that matches the UniFi CEF feed or overview you want. All three can be imported side by side into the Third Party view receiving parsed UniFi events. They share a 24-hour default interval.

| Dashboard | Feed | Main panels |
| --- | --- | --- |
| [UniFi System Logs](unifi-system-logs.yaml) | UniFi OS console, `#event.dataset=unifi.os` | Admin changes, authentication, login IOC matches, Test Syslog, and recent console events |
| [UniFi Network Logs](unifi-network-logs.yaml) | UniFi Network app, `#event.dataset=unifi.network` | IDS/IPS, firewall decisions, client events, authentication, and login IOC matches |
| [UniFi Security and Operations](unifi-security-operations.yaml) | Combined: OS, Network, and Protect | Cross-app overview, Protect event inventory, and parser errors even when no dataset can be determined |

The combined dashboard is unchanged. The individual dashboards exclude Protect and unclassified parser errors on purpose. They filter by the **CEF product after parsing**, not by destination port or the label of the UniFi export setting. Plain syslog and NetFlow/IPFIX are not covered.

## Import

1. Confirm `#Vendor=ubiquiti #event.module=unifi | count()` returns events in the intended repository or view.
2. Open Dashboards, select Import, and upload the YAML for each dashboard you want. Navigation depends on the tenant version. For a scoped dashboard, verify that the matching dataset from the table above returns events.
3. Run the dashboard and inspect each widget for query errors. Verify representative OS admin or Test Syslog events and Network client, firewall or IDS/IPS events as appropriate.
4. Check Parser status in the combined dashboard and Timestamp sources in any dashboard. Investigate `pipeline_error` records and unexpected collector-time fallback.

If dashboard import is unavailable in your tenant, use the standalone CQL files in `queries/system/`, `queries/network/` or the top level of `queries/` for the combined dashboard to create the equivalent widgets manually. Each filename matches its panel title. Run the offline build below to generate the import file. Verify all queries and representative results in your own tenant before operational use.

## Combined panels and interpretation

| Area | Panels |
| --- | --- |
| Overview | Received events, Network intrusion alerts, failed authentications, parser errors |
| Ingestion | Events by application, parser status, reporting consoles with last-seen time, timestamp sources, recent parser errors |
| IDS/IPS | Severity timeline, signatures, source IPs, destinations and ports |
| Firewall | Decisions over time and denied destinations |
| Identity | Authentication outcome timeline, failed source IPs, recent authentication activity |
| Administration | Recent configuration changes with actor, source and message |
| Applications | Protect exported event inventory and Network client connection activity |

All query widgets begin with the parser's tagged vendor and module fields. Metadata fields such as dataset, outcome and kind use their tagged names. Category/type filters use the first normalized array element because this parser writes the relevant value at index zero. Keep these queries aligned with parser changes.

Firewall widgets select `observer.type=firewall`. Network IDS/IPS alerts use `observer.type=ids` and are counted separately. Intrusion alert totals include informational, medium and high severity alerts; severity charts preserve the parser's numeric buckets. Protect motion and alarms are never counted as cyber intrusion alerts.

Counts describe exported events. This dashboard cannot infer bandwidth, throughput, packet totals, currently connected clients, active users, camera availability or uptime from these logs. Reporting consoles shows only sources seen within the selected time interval; silent or missing devices are not automatically identified. Collector-time fallback can be expected for bare CEF with no source timestamp.

The firewall and client event mappings have limited synthetic fixture coverage in parser version 1.0.1. Empty panels may mean events were not exported, normalized fields are absent, or no matching activity occurred. Verify representative exports before relying on them. Protect event names are an inventory, not a camera-health detection. Top/grouped tables are bounded and can truncate high-cardinality results. This dashboard creates no alerts or automated response actions.

## Development and validation

Run within the parser package directory with PyYAML installed:

```sh
python scripts/build_dashboard.py
python scripts/build_dashboard.py --check
python -m unittest discover -s tests -p 'test_dashboard.py' -v
```

Optional schema validation: install jsonschema and pass `--schema /path/to/dashboard-v0.24.0.json` to the builder. Use a local copy obtained from the official endpoint below. Offline tests do not compile or execute CQL.

References: [dashboard import](https://library.humio.com/logscale-gdo/dashboards-create.html), [widget creation](https://library.humio.com/data-analysis/widgets-create.html), [dashboard schema](https://schemas.humio.com/dashboard/v0.24.0).

## CrowdStrike IOC login matching

Three panels match completed successful and failed login records by `source.ip` using `ioc:lookup()` with a high confidence threshold and `strict=true`. Counts are login records before splitting; the details table splits the IOC array to show individual indicator matches and labels. Logout records are excluded. Matches use current CrowdStrike intelligence at search time and do not establish compromise. Private, masked or relay source addresses can prevent useful matches. Zero results can mean no login events, no matching indicators or limited intelligence coverage; it is not proof that all logins are safe. No alerts or blocking actions are installed.

Import into the Third Party view containing your UniFi connection. Each dashboard is labeled for its scope and includes a CrowdStrike IOC label. Its native table widgets use `table`, with time charts and single-value counters for their respective result shapes.
