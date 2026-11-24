# UniFi CEF parser for CrowdStrike Falcon Next-Gen SIEM

Independent custom parser and candidate searches for UniFi Network, Protect and OS CEF exports. Not an official CrowdStrike or Ubiquiti product. Targets CPS 1.2.0 and ECS 9.5.0.

## !!! USE AT YOUR OWN RISK !!!

## Supported UniFi apps

The parser handles **CEF SIEM exports**, either bare CEF or CEF carried inside RFC 3164, RFC 5424, or ISO-style syslog envelopes. It consumes one event per input record.

| App | Synthetic fixture coverage | Other recognition in the parser |
| --- | --- | --- |
| **UniFi Network** (`unifi.network`) | Admin access, IDS/IPS events with numeric severities, client connection, IPv6 and syslog envelopes. | Firewall allow/deny, client disconnect/roam and other recognized authentication events are mapped but are not covered by this release's fixture set. |
| **UniFi Protect** (`unifi.protect`) | Failed login. | Camera motion and alarms that arrive as CEF are kept as ordinary events, not cyber intrusion alerts. The camera tamper and offline queries are templates to validate against your deployment's event names. |
| **UniFi OS** (`unifi.os`) | Failed login, admin configuration changes with IPv4/IPv6 source addresses, Test Syslog, and a shortened OS CEF header. | Other recognized authentication and configuration names are handled best-effort. A shortened admin record without enough detail is kept as informational, not inferred as a successful login or change. |

The table describes code and synthetic examples, not compatibility verified in a live Falcon/LogScale tenant or across UniFi firmware versions. Run the included tests in your tenant and validate representative exports before production ingestion.

**Not covered:** Other UniFi app exports (such as Access, Talk, and Connect), non-CEF syslog or raw device logs, iptables logs, support bundles, Protect API JSON, and Alarm Manager webhook JSON. An unsupported or malformed record is retained and flagged as a pipeline error rather than normalized as a supported event.

## Package layout

Like the Synology package, UniFi keeps its parsers, searches, dashboards, build scripts, and tests in separate folders.

- **Parsers:** [YAML import](parsers/ubiquiti-unifi.yaml) and editable [CQL source](parsers/ubiquiti-unifi.cql).
- **Searches:** [investigation searches and candidate rules](searches/README.md), with [detection notes](searches/detection-notes.md).
- **Dashboards:** [System, Network, and combined views](dashboards/README.md). The dashboard folder also includes optional standalone widget queries for tenants without dashboard import.
- **Build and tests:** [scripts](scripts/) regenerate the imports; [fixtures](tests/fixtures.json) contain synthetic events only.

## Installation
Create a custom parser named ubiquiti-unifi in your Falcon/LogScale tenant, import the YAML and run its testCases before production ingestion. CQL compilation and tenant execution are NOT validated by the offline tests. Forward one raw CEF/syslog event per input; JSON wrappers and raw daemon logs require separate parsing.

When using script-only import, tag: Cps.version, Vendor, ecs.version, event.dataset, event.kind, event.module, event.outcome, observer.type (without a leading #).
Configure your collector separately. For yearless local timestamps provide the actual source timezone via @timezone rather than guessing.

## Validation
Python is a development dependency, not part of tenant ingestion.

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements-dev.txt
    .venv/bin/python scripts/build.py
    .venv/bin/python scripts/build.py --check
    .venv/bin/python -m unittest discover -s tests -v

For schema validation set UNIFI_PARSER_SCHEMA to a local copy of the official https://schemas.humio.com/parser/v0.3.0 schema. Without it that test explicitly skips. The schema is not bundled.

Tests check export schema (when supplied), YAML/source consistency, fixture structure and selected regex extraction only. They do not emulate parseCEF or the full CQL engine. Validate firmware-specific exports in your tenant.

## Fixtures and licensing

All example events are synthetic. No captured logs are included.
The standalone UniFi parser and searches retain the [MIT License](LICENSE). Keep the copyright and permission notices in copies or substantial portions of the software. The software is provided as is, without warranty.

## References
- https://developer.crowdstrike.com/ngsiem/cps/compliant-parsers/
- https://developer.crowdstrike.com/ngsiem/cps/parser-guidelines/
- https://schemas.humio.com/parser/v0.3.0
- https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration
