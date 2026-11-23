"""Build the UniFi dashboard and standalone widget queries; no tenant access."""
from pathlib import Path
import json
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASE = '#Vendor=ubiquiti #event.module=unifi'
AUTH = 'event.category[0]=authentication'
CHANGE = 'event.category[0]=configuration event.type[0]=change'
ALERT = '#event.dataset=unifi.network #event.kind=alert'
DENIED = 'observer.type=firewall event.type[0]=denied'

# title, filter, aggregation, visualization, x, y, width, height
PANELS = [
    ('Events received', '', 'count(as=events)', 'single-value', 0, 2, 3, 2),
    ('Network intrusion alerts', ALERT, 'count(as=events)', 'single-value', 3, 2, 3, 2),
    ('Failed authentications', AUTH + ' #event.outcome=failure', 'count(as=events)', 'single-value', 6, 2, 3, 2),
    ('Parser errors', '#event.kind=pipeline_error', 'count(as=events)', 'single-value', 9, 2, 3, 2),
    ('Events by application over time', '', 'timeChart(#event.dataset, function=count(), limit=10)', 'time-chart', 0, 4, 8, 4),
    ('Parser status', '', 'groupBy([Parser.status], function=count(as=events), limit=20) | sort(events, order=desc)', 'table', 8, 4, 4, 4),
    ('Intrusion alerts by severity', ALERT, 'timeChart(event.severity, function=count(), limit=10)', 'time-chart', 0, 8, 6, 4),
    ('Intrusion signatures', ALERT, 'groupBy([Vendor.Cef.name, event.severity], function=count(as=events), limit=1000) | sort(events, order=desc, limit=20)', 'table', 6, 8, 6, 4),
    ('Intrusion source addresses', ALERT + ' source.ip=*', 'top([source.ip], limit=20)', 'table', 0, 12, 6, 4),
    ('Intrusion destinations and ports', ALERT + ' destination.ip=*', 'groupBy([destination.ip, destination.port, network.transport], function=count(as=events), limit=1000) | sort(events, order=desc, limit=20)', 'table', 6, 12, 6, 4),
    ('Firewall decisions over time', 'observer.type=firewall', 'timeChart("event.type[0]", function=count(), limit=10)', 'time-chart', 0, 16, 6, 4),
    ('Firewall denied destinations', DENIED + ' destination.ip=*', 'groupBy([destination.ip, destination.port], function=count(as=events), limit=1000) | sort(events, order=desc, limit=20)', 'table', 6, 16, 6, 4),
    ('Authentication outcomes', AUTH, 'timeChart(#event.outcome, function=count(), limit=10)', 'time-chart', 0, 20, 6, 4),
    ('Failed authentication sources', AUTH + ' #event.outcome=failure source.ip=*', 'top([source.ip], limit=20)', 'table', 6, 20, 6, 4),
    ('Recent authentication activity', AUTH, 'sort(@timestamp, order=desc, limit=100) | table([@timestamp, #event.dataset, observer.name, user.name, source.ip, event.action, #event.outcome], limit=100)', 'table', 0, 24, 6, 5),
    ('Recent configuration changes', CHANGE, 'sort(@timestamp, order=desc, limit=100) | table([@timestamp, observer.name, user.name, source.ip, event.action, message], limit=100)', 'table', 6, 24, 6, 5),
    ('Protect exported event names', '#event.dataset=unifi.protect', 'groupBy([Vendor.Cef.name], function=count(as=events), limit=1000) | sort(events, order=desc, limit=30)', 'table', 0, 29, 6, 4),
    ('Client connection activity', '#event.dataset=unifi.network Vendor.Cef.name=/(?i)(?:client connected|client disconnected|client roamed)/', 'timeChart(Vendor.Cef.name, function=count(), limit=20)', 'time-chart', 6, 29, 6, 4),
    ('Reporting consoles', 'observer.name=*', 'groupBy([observer.name, #event.dataset], function=[count(as=events), max(@timestamp, as=lastSeen)], limit=1000) | sort(lastSeen, order=desc, limit=100)', 'table', 0, 33, 6, 4),
    ('Timestamp sources', '', 'groupBy([Parser.timestamp_source], function=count(as=events), limit=20) | sort(events, order=desc)', 'table', 6, 33, 6, 4),
    ('Recent parser errors', '#event.kind=pipeline_error', 'sort(@timestamp, order=desc, limit=50) | table([@timestamp, observer.name, Parser.status, message], limit=50)', 'table', 0, 37, 12, 5),
]


IOC = 'ioc:lookup(field=source.ip, type="ip_address", confidenceThreshold="high", strict=true)'
LOGIN = AUTH + ' Parser.status=parsed Vendor.Cef.name=/(?i)(?:login failed|failed login|failed to log in|authentication failed|admin access failed|admin accessed|logged in|login successful)/ Vendor.Cef.name!=/(?i)(?:logged out|logout)/ source.ip=*'
DETAILS = 'split(ioc) | sort(@timestamp, order=desc, limit=200) | table([@timestamp, observer.name, user.name, source.ip, #event.outcome, Vendor.Cef.name, ioc.indicator, ioc.malicious_confidence, ioc.labels], limit=200)'
PANELS.extend([
    ('Successful logins from IOC addresses', LOGIN + ' #event.outcome=success', IOC + ' | count(as=Logins)', 'single-value', 0, 42, 6, 2),
    ('Failed logins from IOC addresses', LOGIN + ' #event.outcome=failure', IOC + ' | count(as=Failures)', 'single-value', 6, 42, 6, 2),
    ('Login IOC match details', LOGIN, IOC + ' | ' + DETAILS, 'table', 0, 44, 12, 6),
])


def build():
    widgets = {'coverage-note': {
        'type': 'note', 'title': 'UniFi security and operations',
        'text': 'CEF exports from Network, Protect and OS. Counts describe received logs, not total traffic, active clients or device health. Protect motion is not a cyber intrusion alert. Empty panels can mean no matching exports. See dashboards/README.md for coverage and validation.',
        'x': 0, 'y': 0, 'width': 12, 'height': 2,
    }}
    queries = {}
    for index, (title, filt, agg, vis, x, y, width, height) in enumerate(PANELS, 1):
        query = BASE + ('\n' + filt if filt else '') + '\n| ' + agg + '\n'
        key = str(uuid.uuid5(uuid.NAMESPACE_URL, 'crowdstrike-local-home-parsers/unifi/dashboard/' + title))
        options = ({'series': {}, 'plotType': 'line', 'connect-points': False, 'imputation': 'none'} if vis == 'time-chart'
                   else {'default': {}, 'value-format': 'raw', 'decimal-places': 0} if vis == 'single-value'
                   else {'cell-overflow': 'wrap-text', 'row-numbers-enabled': False})
        widgets[key] = dict(type='query', title=title, queryString=query, visualization=vis,
                            x=x, y=y, width=width, height=height, start='1d', end='now', isLive=False, options=options)
        slug = '-'.join(title.lower().split())
        queries[f'{index:02d}-{slug}.cql'] = query
    dashboard = {'name': 'UniFi — Security and Operations',
                 'description': 'Companion dashboard for the UniFi CEF parser. Received CEF events, security activity and parser health. Validate queries in your tenant.',
                 'updateFrequency': 'never', 'timeSelector': {},
                 'sharedTimeInterval': {'enabled': True, 'isLive': False, 'start': '1d'},
                 'labels': ['UniFi', 'Network', 'Protect', 'Security', 'CrowdStrike IOC'],
                 'widgets': widgets, '$schema': 'https://schemas.humio.com/dashboard/v0.24.0'}
    return dashboard, queries


if __name__ == '__main__':
    import argparse
    import yaml
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--schema', type=Path, help='Optional local copy of the official dashboard v0.24.0 schema')
    args = parser.parse_args()
    dashboard, queries = build()
    if args.schema:
        import jsonschema
        jsonschema.validate(dashboard, json.loads(args.schema.read_text()))
    files = {ROOT / 'dashboards/unifi-security-operations.yaml': yaml.safe_dump(dashboard, sort_keys=False, allow_unicode=True)}
    files.update({ROOT / 'dashboards/queries' / name: query for name, query in queries.items()})
    for path, content in files.items():
        if args.check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit(f'Out of date: {path.relative_to(ROOT)}')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    print(f'{"Checked" if args.check else "Built"} dashboard and {len(queries)} widget queries')
