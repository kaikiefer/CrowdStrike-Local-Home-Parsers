# UniFi Advanced Event Searches and candidate correlation rules

These standalone CQL files use the fields and tags emitted by this project's `ubiquiti-unifi` parser (version 1.0.1). Open a file, copy its query into CrowdStrike Advanced Event Search, and use **Test query** before creating a rule. Nothing in this folder has been deployed or executed in a CrowdStrike tenant.

Start with rules **01**, **04**, and **13**. Add authentication and firewall thresholds after checking whether those event types and required fields arrive. The Protect searches are templates because actual Protect exports have not yet been supplied.

Copy-ready detection titles, descriptions, MITRE ATT&CK tactic/technique mappings, and mapping limitations for all 13 rules are in [Detection titles and MITRE ATT&CK notes](detection-notes.md). The same titles and mapping summaries are included as comments at the top of each rule query.

## Candidate rules

Windows, thresholds, severities, and repeat-handling keys below are suggested starting settings, not CrowdStrike or Ubiquiti defaults. Run every **5 minutes** where your tenant offers that frequency; use the listed search window. Each query's final output is its trigger condition: alert when it returns at least one row/constellation.

| ID / CQL file | Signal | Window | Suggested severity | Key for repeat handling |
| --- | --- | --- | --- | --- |
| [01 — Syslog export disabled](rules/01-syslog-export-disabled.cql) | One OS config event changes export from `external` to `internal`, `off`, or `disabled` | 10m | High | Console + event ID if available |
| [02 — Repeated auth failures](rules/02-repeated-authentication-failures.cql) | At least 10 failures from one source to one console/application | 10m | Medium | Dataset + console + source IP |
| [03 — Password spray](rules/03-password-spray.cql) | At least 10 failures against at least 5 named users from one source | 10m | Medium | Dataset + console + source IP |
| [04 — High-severity intrusion](rules/04-high-severity-network-intrusion.cql) | One Network intrusion event with CPS severity at least 70 | 10m | High | Console + source event ID if available |
| [05 — Repeated intrusions](rules/05-repeated-network-intrusions.cql) | At least 5 intrusion records attributed to one source | 10m | Medium | Console + source IP |
| [06 — Denies to many destinations](rules/06-denied-multiple-destinations.cql) | At least 20 firewall denies to at least 10 IPs | 10m | Medium | Console + source IP |
| [07 — Denies to many ports](rules/07-denied-multiple-ports.cql) | At least 20 denies to at least 10 ports on one target | 10m | Medium | Console + source IP + destination IP |
| [08 — Configuration burst](rules/08-admin-configuration-burst.cql) | At least 5 configuration changes by one named admin | 10m | Low | Console + admin |
| [09 — Failure then success](rules/09-failed-login-then-success.cql) | Failed login followed by success for the same source/user/console/application | 15m; sequence within 10m | Low | Console + application + admin + source IP |
| [10 — Login then export disabled](rules/10-login-then-syslog-export-disabled.cql) | Successful login followed by export disabled for the same source/user/console | 20m; sequence within 15m | High | Console + admin + source IP |
| [11 — Protect tamper template](rules/11-protect-tamper-template.cql) | Tamper-named event, excluding several recovery/disabled names | 10m | Medium | NVR + camera identity, when available |
| [12 — Protect outage template](rules/12-protect-camera-outage-template.cql) | At least 3 distinct cameras/devices emit offline/disconnect events behind one NVR | 10m | Medium | NVR |
| [13 — Parser failures](rules/13-parser-failure-burst.cql) | At least 5 malformed/unsupported records attributed to one reporter and status | 15m | Low / operational | Reporter + parser status |

Rules 01 and 10 look for syslog export being switched off. A synthetic enabling example (`"internal"` → `"external"`) should not trigger them. `Test Syslog` should not trigger these rules or the configuration-change burst. Rules 01 and 10 overlap intentionally; start with 01 and use 10 for added login context, or route their detections together to avoid separate escalations.

Rule 09 detects **one** failed attempt followed by success. It does not establish a successful brute-force attack; a password typo is a common cause. Rule 02 provides a separate volume-based signal. Rule 10 establishes an ordered association, not proof of account compromise.

## Investigation searches

| File | Use |
| --- | --- |
| [Observed event coverage](hunts/01-event-coverage.cql) | Inventory event names, counts, datasets, and parser status over the last 7 days |
| [Admin timeline](hunts/02-admin-timeline.cql) | Review authentication and configuration-change events in time order; add exact admin/source filters |
| [Protect coverage](hunts/03-protect-coverage.cql) | Inspect actual Protect names, categories, and device identity keys before adapting rules 11–12 |

For an admin timeline limited to one person, add this before sorting, substituting the actual logged name:

```logscale
| user.name="John Doe"
```

For one source, use an exact `source.ip` filter. A source address may be IPv4 or IPv6; the queries do not assume IPv4.

## Create a rule in CrowdStrike

1. Confirm the parser's **Fields to tag** settings. The queries expect `#Vendor`, `#event.module`, `#event.dataset`, `#event.kind`, `#event.outcome`, and `#observer.type` as tags, while category/type array elements are ordinary fields.
2. Open Advanced Event Search over the repository/view containing the UniFi data. Use the event-coverage hunt to confirm which event names exist, then run the candidate query over the intended window. No results means no matching pattern in that data; it does not prove coverage is working.
3. For a threshold query, temporarily remove only the final threshold filter to inspect baseline counts, then restore it before creating the rule. Avoid using a 7-day count to choose a 10-minute threshold.
4. Use **Create Rule**, or go to **Next-Gen SIEM → Monitor and investigate → Rules → Add rule → Create new rule**. Paste the query and select **Test query**.
5. For rules 01–12, use **Created (`@timestamp`)** after confirming event timestamps are correct. In particular, the ordered rules 09–10 depend on event time. For rule 13, use **Ingested (`@ingesttimestamp`)** to monitor newly received parser failures, including old forwarded records.
6. Apply the suggested search window and cadence. The search window must be at least the cadence. If a cadence of 5 minutes is unavailable, choose a supported cadence and enlarge the window accordingly; reassess thresholds against that window. Late data outside the window will be missed.
7. Select the severity and trigger mode. **Summary** creates one detection for a run's returned results. **Verbose** creates a detection per result, up to the platform's per-execution limit. Preserve the grouping fields in threshold output so the detection identifies the relevant source/console.
8. Copy the title and description from the [detection notes](detection-notes.md). Select an ATT&CK mapping only where listed as applicable. Conditional mappings require the stated evidence; leave operational/signature-dependent rules unmapped until that evidence exists. Check the tenant's ATT&CK catalog version if a current technique is unavailable.
9. Start in your tenant's draft/test or inactive workflow. Review expected admin work, firmware updates, scanners, monitoring services, and shared-address traffic before activating notifications.

The files for rules 09–10 use `correlate()` for ordered behavior. Their nodes share the specified `globalConstraints`, use `sequence=true`, and have an explicit `within` bound. They intentionally do not combine `correlate()` with `groupBy()`, `count()`, `table()`, or other aggregate functions. The other threshold queries use `groupBy()` and counts in scheduled correlation searches. The investigation-only files contain presentation functions and are not the rule bodies.

Threshold queries preserve `firstSeen`/`lastSeen` as epoch milliseconds and set the result's `@timestamp` to the latest contributing event. The operational parser-failure query uses the latest ingestion time instead.

These are copy/paste query files with documented settings, not an API-importable rule package.

## Coverage and tuning

- **Field availability:** rules that group or link events explicitly require those identity/address fields. Authentication records without `source.ip` or `user.name` will be excluded from rules needing them. The current parser extracts message-only identity/IP values for the verified OS config-change template; it does not do that for every possible auth format. Check raw events when fields are missing.
- **Console scope:** `observer.name` comes from the console's display name or syslog hostname. It must be stable and unambiguous in the searched environment. For shared views with duplicate console names, add your tenant/site/stable console identifier to grouping fields and `globalConstraints` before enabling rules. Avoid linking unrelated consoles by username or IP alone.
- **Cross-application behavior:** rule 09 includes `#event.dataset` to keep failures/successes within one application. Rule 10 deliberately permits a Network login to correlate with an OS configuration change, but only when console, username, and source IP match exactly. Differences in how applications report those fields can prevent a match.
- **Repeated windows:** overlapping windows can return the same source event or threshold group on successive executions. Summary mode reduces output within a run; it does not prevent repeat detections across runs. Configure available suppression/deduplication controls using the listed keys, or choose a cadence/overlap and notification policy that suit your environment. `correlate()` limits also do not provide persistence across runs.
- **User identity:** the parser preserves usernames as reported. Different casing, display names versus login IDs, or missing usernames can split counts and prevent joins. Normalize only after confirming which fields identify the same person.
- **Network coverage:** firewall queries need CEF firewall decision records with source/destination information. They do not inspect unsupported raw iptables records. The high-severity rule uses the parser's normalized CPS severity, whose mapping is documented in the main README. Repeated IDS records may be duplicates or follow-up notifications of one incident.
- **Direction and NAT:** a denied source is not automatically an internal compromised endpoint. Review ingress/egress context and how the gateway reports translated addresses. A public, VPN, proxy, or NAT address can represent multiple users; an upstream router can alter which source identities are visible.
- **Protect templates:** motion/person events are excluded from tamper rules by using the event name rather than treating the `detection` category as an intrusion. Rules 11–12 still require verification of exact names and device fields in your firmware. Do not activate either based solely on the synthetic parser fixtures.
- **Outage limits:** rule 12 sees reported offline events. Complete NVR/collector failure may produce no record at all; source-silence monitoring requires a maintained expected-source inventory and a last-seen comparison, which these queries do not provide.
- **Counts and limits:** distinct counts can be estimated, and the group limit is explicit at 20,000. Review query warnings/limits before relying on high-volume results. Increase thresholds or scope the query if routine activity produces too many results; truncating the output is not a detection tuning strategy.

## Validation status

The query field references were checked against the current parser. Validate logging-change regexes with a disabled-export event, and verify that an enabling change and `Test Syslog` do not match. Protect patterns remain firmware-dependent templates. No CQL compiler, query execution, schedule, or detection output has been tested against your tenant.

## Sources

Checked November 22, 2026:

- [CrowdStrike correlation rules](https://developer.crowdstrike.com/ngsiem/correlation-rules/) — creation, event-time selection, recurring windows, trigger modes, and behavioral rules.
- [CQL correlate()](https://library.humio.com/crowdstrike-query-language/functions-correlate.html) — ordered nodes, `include`, keys and time bounds.
- [CQL groupBy()](https://library.humio.com/crowdstrike-query-language/functions-groupby.html) and [count()](https://library.humio.com/crowdstrike-query-language/functions-count.html) — grouped thresholds and distinct-count behavior.
- [UniFi SIEM export](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration) — source formats and category export selection.
