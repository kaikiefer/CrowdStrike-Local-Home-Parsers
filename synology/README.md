# Synology DSM parser for CrowdStrike Falcon Next-Gen SIEM

Parses Synology DiskStation and RackStation DSM Log Center syslog. Editable [CQL](parsers/synology-dsm.cql) and generated [YAML import](parsers/synology-dsm.yaml) target CPS 1.2.0 and ECS 9.5.0.

Supports RFC 3164/BSD, RFC 5424/IETF, ISO-style relays, and recognized bare DSM messages. Maps common English login/logout, file operation, storage, service/package, network, account and administration templates. Unknown and localized messages are preserved rather than assigned a guessed meaning. Does not ingest CSV or JSON directly, poll DSM, or provide SNMP or SMART metrics. Run your own firmware-specific checks.

1. Enable Log Sending in DSM Log Center. Configure your syslog relay/collector with a dedicated route into Falcon Next-Gen SIEM. Prefer RFC 5424 for explicit timestamps; set the actual source timezone on the collector for yearless RFC 3164.
2. Import the YAML as a custom parser; run its included cases and validate representative records in your tenant before assigning it to the route. Forward one raw syslog record per event.
3. Review the [searches](searches/README.md) and [dashboard](dashboards/README.md) before using them in production. A detection candidate is not a deployment.

## Offline checks

Run from this package directory using Python with dependencies in requirements-dev.txt:

    python scripts/build.py --check
    python -m unittest discover -s tests -v

Set SYNOLOGY_PARSER_SCHEMA to a local copy of the official https://schemas.humio.com/parser/v0.3.0 schema to run optional schema validation. Third-party schemas are not bundled.

The release fixtures contain synthetic examples only and cover a subset of supported message templates. Offline tests check import consistency and source regex behavior, not CQL or tenant execution. No additional license is granted for this package.
