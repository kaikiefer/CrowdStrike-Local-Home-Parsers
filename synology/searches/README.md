# Synology hunts and candidate detections

These CQL files use ingested CPS tag names and the fields produced by `synology-dsm`. They are source queries to review and test in the tenant, not an installable detection-rule package. They have not run against tenant data. No alert actions or schedules are created automatically.

## Hunts

- `hunts/01-parser-coverage.cql`: dataset, parser status and timestamp-source counts.
- `hunts/02-authentication-timeline.cql`: login/logout records, users, sources and services.
- `hunts/03-file-activity.cql`: file paths and share access.
- `hunts/04-unmapped-messages.cql`: unfamiliar records and timestamp fallback for mapping review.
- `hunts/05-storage-health.cql`: disk, pool, volume and scrub events.
- `hunts/06-account-administration.cql`: acting and affected users, group membership and app privileges.
- `hunts/07-event-details.cql`: parsed categories, actions, identities, service/package names, message and original raw record. Filters to Synology DSM events to exclude data-connection telemetry.
- `hunts/08-activity-overview.cql`: compact table with an Activity column using the package, service or action. Missing categories are explicitly labeled `Unmapped by stored parser` in a separate display column; stored ECS fields are unchanged.

Use the event-details query for exports intended to diagnose parser behavior. A table containing only timestamp, package name and message hides categories and identities; connection telemetry can also appear as timestamp-only rows when the selected columns do not apply.

## Candidate rules

| Query | Starting threshold | Window / suggested interval |
| --- | --- | --- |
| `rules/01-repeated-authentication-failures.cql` | At least 10 failure records per NAS/source/service | 10 minutes / 5 minutes |
| `rules/02-possible-password-spray.cql` | At least 10 failure records against 5 users per NAS/source/service | 10 minutes / 5 minutes |
| `rules/03-file-delete-rename-burst.cql` | At least 100 delete/rename records affecting 50 paths per NAS/user/source | 5 minutes / 5 minutes |
| `rules/04-file-read-burst.cql` | At least 500 distinct read paths per NAS/user/source | 10 minutes / 5 minutes |

Set the search lookback in the NG-SIEM rule configuration; the query files do not enforce a time window. Suppress overlapping-window repeats by the rule's grouping keys. Align scheduling and ingestion delay with the environment, and review group limits in larger fleets. These are starting points, not universal thresholds.

Every rule requires NAS identity and client IP, and requires user/service/path where it groups on those fields. Bare body records without NAS identity can be searched but do not trigger these grouped candidates. Configure forwarding to retain the original NAS hostname. IP-only hosts work as observer names; reused hostnames across sites require a stable distinct collector-provided device identity or query customization.

Authentication counters count log records, not guaranteed distinct attempts. Some DSM versions can emit multiple records for a single failure. Inspect the actual info/warning templates and use a consistent event family or a tenant-specific deduplication strategy before setting production thresholds. The parser preserves both forms; dropping either globally would lose visibility on devices emitting only one form. Tune stale automation, shared proxies/NAT and empty-user events. Password-spray logic cannot observe the attempted passwords.

Delete/rename volume is an investigation signal. Cleanup, sync and retention jobs can produce it. It does not prove file encryption or malicious intent. ATT&CK T1485/T1486 comments describe candidate investigation hypotheses, not established attack classifications.

Read volume may come from indexing, antivirus, backups or application preloading. [Synology documents extra SMB reads caused by client software](https://kb.synology.com/en-au/DSM/tutorial/Why_does_Log_Center_record_multiple_read_events_when_I_only_open_one_file_via_SMB). A read record does not prove exfiltration, and file size is not the number of bytes transferred. File-operation coverage depends on service-specific auditing enabled before the activity occurred.
