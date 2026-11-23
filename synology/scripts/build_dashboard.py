#!/usr/bin/env python3
"""Build and schema-check the native Falcon Synology dashboard template."""
import argparse
import json
import re
from pathlib import Path

import yaml

from build import Dumper

ROOT = Path(__file__).resolve().parents[1]
BASE = '#Vendor=synology #event.module=dsm\n| observer.name = ?nas\n'
widgets = {}


def authentication_view():
    """Use ingest fields first; decode exact historical auth bodies separately.

    Reuse the parser's reviewed patterns, without rewriting stored ECS fields,
    Parser.version or Parser.status. Never classify using keyword searches.
    """
    source = (ROOT / 'parsers/synology-dsm.cql').read_text()
    templates = re.findall(
        r'_body = (/[^\n]+/)\n\s*\| Vendor.Template := "(auth_[^"]+)" '
        r'\| event.action := "([^"]+)"(?: \| event.outcome := "([^"]+)")?;', source)
    assert len(templates) == 7, 'Review auth dashboard support when parser templates change'
    replacements = {'Vendor.User.name': 'Auth.user', 'Vendor.Client.address': 'Auth.source',
                    'Vendor.Service.name': 'Auth.service', 'Vendor.Auth.method': 'Auth.method',
                    'Vendor.Auth.reason': 'Auth.reason'}
    branches = []
    for pattern, template, action, outcome in templates:
        for old, new in replacements.items():
            pattern = pattern.replace(old, new)
        branches.append(f'            message = {pattern}\n'
                        f'                | Auth.action := "{action}" | Auth.outcome := "{outcome or "not-reported"}"'
                        f' | Auth.mapping := "historical exact template";')
    return ('| Auth.action := event.action\n'
            '| Auth.outcome := "not-reported"\n'
            '| case { #event.outcome=* | Auth.outcome := #event.outcome; *; }\n'
            '| Auth.user := user.name\n| Auth.source := source.address\n'
            '| Auth.service := service.name\n| Auth.method := Vendor.Auth.method\n'
            '| case {\n'
            '    Parser.status=parsed event.category[0]=authentication | Auth.mapping := "ingest";\n'
            '    Parser.status=envelope_only #event.dataset=dsm.connection\n'
            '        | case {\n' + '\n'.join(branches) + '\n            *;\n        };\n'
            '    *;\n}\n| Auth.mapping=*\n')


def widget(key, title, query, visualization, x, y, width, height, description):
    options = {}
    if visualization == 'time-chart':
        options = {'connect-points': False, 'imputation': 'none', 'yAxisScale': 'linear'}
    elif visualization == 'bar-chart':
        options = {'inputDataFormat': 'long', 'legend': False,
                   'valuesOnBars': True, 'yAxisScale': 'linear'}
    widgets[key] = dict(title=title, description=description, type='query',
                        queryString=BASE + query, visualization=visualization,
                        x=x, y=y, width=width, height=height, start='1d',
                        end='now', options=options)


def document():
    widgets.clear()
    auth = authentication_view()
    widgets['scope'] = dict(type='note', title='Reading this dashboard', x=0, y=0,
        width=12, height=2, text=(
            'DSM log activity in the selected time range. Storage events are historical; '
            'they do not establish current disk health or capacity. Authentication '
            'views also recognize exact supported historical login templates. Stored '
            'parser fields are unchanged; review **Unmapped records** for coverage gaps.'))
    widget('events', 'DSM records', '| count(as=Records)', 'single-value', 0, 2, 3, 2,
           'Number of DSM log records in the selected period, excluding connection telemetry.')
    widget('nas-count', 'NAS devices seen', '| count(observer.name, distinct=true, as=Devices)',
           'single-value', 3, 2, 3, 2, 'Distinct syslog observer names, not current availability.')
    widget('login-failures', 'Login failures', auth + '| Auth.action=login Auth.outcome=failure\n| count(as=Failures)',
           'single-value', 6, 2, 3, 2, 'Failed-login records from ingest mappings or exact supported historical templates; records may not equal distinct attempts.')
    widget('unmapped-count', 'Unmapped records', 'Parser.status!=parsed\n| count(as=Records)',
           'single-value', 9, 2, 3, 2, 'Preserved records that need additional message mappings, including older parser versions.')
    category = '| Category := "Unmapped"\n| case { event.category[0]=* | Category := event.category[0]; *; }\n'
    widget('activity-trend', 'Activity over time', category + '| timeChart(Category, function=count(), limit=20)',
           'time-chart', 0, 4, 8, 5, 'Counts by first ECS category; uncategorized records remain visible as Unmapped.')
    widget('categories', 'Activity by category', category + '| groupBy(Category, function=count(), limit=100)',
           'bar-chart', 8, 4, 4, 5, 'Each record is counted once using its first category.')
    widget('last-seen', 'NAS last seen and parser coverage',
           '| groupBy([observer.name, Parser.version, Parser.status], function=[count(as=Records), max(@timestamp, as=LastSeen)], limit=1000)\n| sort(LastSeen, order=desc, limit=1000)\n| formatTime("%Y-%m-%d %H:%M:%S %Z", field=LastSeen, as=LastSeen, timezone="UTC")',
           'table', 0, 9, 12, 4, 'Last event timestamp per NAS, parser version and status within the selected period; not an online/offline check.')
    widget('auth-success', 'Successful sign-ins', auth + '| Auth.action=login Auth.outcome=success\n| count(as=SignIns)',
           'single-value', 0, 0, 6, 2, 'Successful login records; excludes first-factor events. Includes exact historical templates.')
    widget('auth-logout', 'Recorded sign-outs', auth + '| Auth.action=logout\n| count(as=SignOuts)',
           'single-value', 6, 0, 6, 2, 'Only received, recognized logout records. Zero does not establish that no one signed out.')
    widget('auth-trend', 'Sign-in, sign-out and first-factor activity', auth +
           '| format("%s (%s)", field=[Auth.action, Auth.outcome], as=Activity)\n| timeChart(Activity, function=count(), limit=20)',
           'time-chart', 0, 2, 6, 5, 'Login, logout and first-factor records remain distinct. Logout outcome is not inferred.')
    widget('auth-sources', 'Failed-login client addresses', auth +
           '| Auth.action=login Auth.outcome=failure Auth.source=*\n| groupBy(Auth.source, function=count(), limit=100)\n| sort(_count, order=desc, limit=20)',
           'bar-chart', 6, 2, 6, 5, 'Top 20 reported client addresses by failed-login record count, not necessarily distinct attempts.')
    widget('auth-details', 'Authentication details', auth +
           '| table([@timestamp, observer.name, Auth.action, Auth.outcome, Auth.user, Auth.source, Auth.method, Auth.mapping, Parser.version, Parser.status, message], limit=200)',
           'table', 0, 7, 12, 5, 'Auth.mapping distinguishes ingest fields from exact historical templates. Stored parser version/status are retained; first-factor success is not a completed login.')
    widget('storage-events', 'Storage events', '#event.dataset=dsm.storage\n'
           '| table([@timestamp, observer.name, event.action, log.level, message], limit=200)',
           'table', 0, 0, 12, 5, 'Pool, volume, disk and scrub log events. No results means no matching records, not a healthy hardware assessment.')
    widget('operational-warnings', 'Warnings, errors and reported failures',
           '(log.level=/^(?:warning|error|critical|alert|emergency)$/ OR #event.outcome=failure)\n'
           '| table([@timestamp, observer.name, log.level, event.action, message], limit=200)',
           'table', 0, 5, 12, 5, 'Reported operational and security failures. Syslog severity is not threat severity.')
    widget('services-packages', 'Service and package activity',
           'Parser.status=parsed event.category[0]=/^(?:process|package)$/\n'
           '| Activity := event.action\n| case { package.name=* | Activity := package.name; service.name=* | Activity := service.name; *; }\n'
           '| table([@timestamp, observer.name, event.action, Activity, message], limit=200)',
           'table', 0, 10, 12, 5, 'Relevant package or service labels share an Activity column; generic update completion does not invent a package name.')
    widget('network', 'Network activity', 'Parser.status=parsed event.category[0]=network\n'
           '| table([@timestamp, observer.name, event.action, message], limit=200)',
           'table', 0, 15, 12, 5, 'DDNS, link, DHCP and CMS messages. A CMS connection switch does not prove reconnection succeeded.')
    widget('iam', 'Account and permission changes', 'Parser.status=parsed event.category[0]=iam\n'
           '| table([@timestamp, observer.name, event.action, user.name, user.target.name, message], limit=200)',
           'table', 0, 0, 12, 5, 'Acting and affected users are separate; some system/group changes legitimately omit one identity.')
    widget('files', 'File activity over time', 'Parser.status=parsed event.category[0]=file\n'
           '| timeChart(event.action, function=count(), limit=20)',
           'time-chart', 0, 5, 6, 5, 'Logged file operations and share activity only; coverage depends on DSM service auditing.')
    widget('file-details', 'File and share details', 'Parser.status=parsed event.category[0]=file\n'
           '| table([@timestamp, observer.name, event.action, user.name, source.ip, message], limit=200)',
           'table', 6, 5, 6, 5, 'Original message retains paths or share labels. Read activity does not establish exfiltration.')
    widget('unmapped', 'Unmapped record review', 'Parser.status!=parsed\n'
           '| table([@timestamp, observer.name, Parser.version, Parser.status, message, @rawstring], limit=200)',
           'table', 0, 0, 12, 5, 'Review original raw records to extend mappings. Previously stored events are not retroactively reparsed.')
    # Reuse reviewed historical authentication mappings; first-factor and logout
    # events cannot enter completed-login IOC panels. CIDR rejects non-IP clients.
    ioc = (auth + '| Auth.action=login\n'
           '| cidr(Auth.source, subnet=["0.0.0.0/0", "::/0"])\n'
           '| ioc:lookup(field=Auth.source, type="ip_address", confidenceThreshold="high", strict=true)\n')
    widget('ioc-success', 'Successful logins from IOC addresses', ioc +
           '| Auth.outcome=success\n| count(as=SignIns)', 'single-value', 0, 0, 6, 2,
           'Completed login records matching high-confidence CrowdStrike IP indicators; excludes first-factor completion and logout.')
    widget('ioc-failure', 'Failed logins from IOC addresses', ioc +
           '| Auth.outcome=failure\n| count(as=Failures)', 'single-value', 6, 0, 6, 2,
           'Failed login records matching high-confidence CrowdStrike IP indicators. Matches warrant investigation, not a compromise verdict.')
    widget('ioc-details', 'Login IOC match details', ioc +
           '| split(ioc)\n| sort(@timestamp, order=desc, limit=200)\n'
           '| table([@timestamp, observer.name, Auth.user, Auth.source, Auth.outcome, Auth.mapping, ioc.indicator, ioc.malicious_confidence, ioc.labels], limit=200)',
           'table', 0, 2, 12, 6,
           'Reported client IP, account, outcome, confidence and intelligence labels; one row per indicator match. Current intelligence applied at search time.')
    overview = ['scope' , 'events', 'nas-count', 'login-failures', 'unmapped-count',
                'activity-trend', 'categories', 'last-seen']
    section_items = [
        ('overview', 'Overview', overview),
        ('authentication', 'Authentication', ['auth-success', 'auth-logout', 'auth-trend', 'auth-sources', 'auth-details']),
        ('ioc', 'CrowdStrike IOC matches', ['ioc-success', 'ioc-failure', 'ioc-details']),
        ('operations', 'Storage and operations', ['storage-events', 'operational-warnings', 'services-packages', 'network']),
        ('administration', 'Administration and file activity', ['iam', 'files', 'file-details']),
        ('coverage', 'Parser coverage', ['unmapped']),
    ]
    return {
        '$schema': 'https://schemas.humio.com/dashboard/v0.24.0',
        'name': 'Synology NAS Overview',
        'description': 'DSM log activity, authentication, historical storage events, service/package changes and parser coverage. Requires the Synology DSM parser; does not poll hardware metrics.',
        'updateFrequency': 'never',
        'sharedTimeInterval': {'enabled': True, 'start': '1d'},
        'labels': ['Synology', 'NAS', 'DSM', 'CrowdStrike IOC'],
        'parameters': {'nas': {'type': 'text', 'label': 'NAS hostname', 'defaultValue': '*', 'order': 0, 'width': 2}},
        'widgets': widgets,
        'sections': {key: {'title': title, 'order': order, 'widgetIds': ids}
                     for order, (key, title, ids) in enumerate(section_items)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--schema', type=Path, help='Optional local copy of the official dashboard v0.24.0 schema')
    args = parser.parse_args()
    dashboard = document()
    if args.schema:
        import jsonschema
        schema = json.loads(args.schema.read_text())
        jsonschema.Draft7Validator(schema).validate(dashboard)
    # Validate layout and filter propagation beyond the public schema.
    used = [key for section in dashboard['sections'].values() for key in section['widgetIds']]
    assert len(used) == len(set(used)) == len(widgets)
    for section in dashboard['sections'].values():
        rects = []
        for key in section['widgetIds']:
            w = widgets[key]
            assert w['x'] + w['width'] <= 12
            for other in rects:
                assert not (w['x'] < other['x'] + other['width'] and other['x'] < w['x'] + w['width']
                            and w['y'] < other['y'] + other['height'] and other['y'] < w['y'] + w['height'])
            rects.append(w)
            if w['type'] == 'query':
                assert w['queryString'].startswith(BASE)
    rendered = yaml.dump(dashboard, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=120)
    path = ROOT / 'dashboards/synology-nas-overview.yaml'
    if args.check:
        assert path.read_text() == rendered, 'Dashboard YAML is stale; run scripts/build_dashboard.py'
        print(f'Dashboard schema, layout and source consistency passed ({len(widgets)} widgets).')
    else:
        path.parent.mkdir(exist_ok=True)
        path.write_text(rendered)
        print(f'Built {path.relative_to(ROOT)} ({len(widgets)} widgets).')


if __name__ == '__main__':
    main()
