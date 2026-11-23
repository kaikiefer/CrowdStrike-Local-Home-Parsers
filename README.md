# CrowdStrike Local/Home Parsers

Independent parser packages for CrowdStrike Falcon Next-Gen SIEM. These are not official CrowdStrike, Ubiquiti or Synology products.

| Package | Log input | Included |
| --- | --- | --- |
| [UniFi](unifi/README.md) | UniFi Network, Protect and OS CEF SIEM exports | Parser, investigation queries, detection candidates and dashboard |
| [Synology](synology/README.md) | Synology DSM Log Center syslog | Parser, investigation queries, detection candidates and dashboard |

Start with the matching package's README. Use a dedicated ingestion route for each format, verify the supplied synthetic events in your own tenant and confirm the dashboard view names, available fields and permissions before enabling detections. No tenant credentials, captured logs or tenant-specific IDs are needed to use these files.

Each package describes its license separately. The standalone UniFi parser and searches retain their existing [MIT license](unifi/LICENSE). No new license is assigned to the other material by this compilation.
