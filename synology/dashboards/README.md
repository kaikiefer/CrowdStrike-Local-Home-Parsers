# Synology NAS Overview

Generate `synology-nas-overview.yaml` with the build command below, then import it as a native Falcon Next-Gen SIEM dashboard. It contains 24 widgets across six sections, with a shared time selector (default: last day) and a NAS hostname parameter (default: `*`).

The dashboard covers DSM event volume and category trends, devices seen, parser version/status, authentication outcomes and failed-login sources, historical storage events, operational warnings, service/package changes, network activity, account/permission changes, file activity and unmapped record review.

Open **Advanced event search → Dashboards**, choose **Create dashboard → Import dashboard**, select the YAML (use a `.yml` extension if the file picker requires it), and choose the **Third Party** repository/view containing the Synology connection. Save it as **Synology NAS Overview**. Use the shared time control to change the period; set **NAS hostname** to a syslog hostname to narrow all query widgets consistently. Last-seen timestamps include the UTC timezone. The template does not create alerts, schedules or public sharing links.

All queries select `#Vendor=synology #event.module=dsm` to exclude data-connection telemetry. Service/package activity uses one Activity column, rather than showing an inapplicable package name for every event. Other detail panels retain optional fields where their absence is meaningful.

Authentication summaries count recognized log records, not guaranteed distinct login attempts. First-factor success remains separate from completed sign-in. Authentication views use ingest mappings first and recognize exact supported historical authentication bodies for `envelope_only` records in `dsm.connection`. The builder derives these patterns from the parser source. `Auth.mapping` identifies the source; original ECS and parser fields are unchanged. Older unmapped events remain visible in the coverage counters even when recognized by the authentication view. Other semantic panels still depend on their stored parser fields. Storage panels show recorded events, not current capacity, SMART metrics, uptime or a hardware health verdict. Empty result panels indicate no matching records in the chosen period; confirm ingestion and auditing before interpreting them.

## Build and validation

From the parser package directory, install PyYAML and run:

```sh
python scripts/build_dashboard.py
python scripts/build_dashboard.py --check
```

The builder checks section membership, non-overlapping layout and consistent source/hostname filters. For optional schema validation, install jsonschema and pass `--schema /path/to/dashboard-v0.24.0.json` using a local copy of the [official dashboard schema](https://schemas.humio.com/dashboard/v0.24.0). Widget types and query options follow the [dashboard creation guide](https://library.humio.com/logscale-gdo/dashboards-create.html).


## CrowdStrike IOC matches

The IOC section checks supported completed login events against CrowdStrike IP intelligence with `ioc:lookup(field=Auth.source, type="ip_address", confidenceThreshold="high", strict=true)`. It reuses the exact historical authentication view and rejects non-IP addresses before lookup. Successful first-factor completion and logout are excluded. Counters count matching login records; the details table splits IOC results to show indicators, confidence and intelligence labels with account, client address and auth mapping.

Matches are search-time intelligence enrichment, not a compromise verdict. Missing original client IPs or limited intelligence coverage can prevent matches. This adds no alerts or response actions.
