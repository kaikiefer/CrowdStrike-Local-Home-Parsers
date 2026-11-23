import importlib.util
import json
import os
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_dashboard', ROOT / 'scripts/build_dashboard.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.dashboard = yaml.safe_load((ROOT / 'dashboards/unifi-security-operations.yaml').read_text())

    def test_generated_artifacts_match_and_every_query_is_scoped(self):
        expected, queries = builder.build()
        self.assertEqual(self.dashboard, expected)
        self.assertEqual(len(queries), 24)
        for name, query in queries.items():
            self.assertEqual((ROOT / 'dashboards/queries' / name).read_text(), query)
            self.assertTrue(query.startswith('#Vendor=ubiquiti #event.module=unifi\n'))

    def test_ioc_login_scope_and_count_semantics(self):
        panels = {w['title']: w for w in self.dashboard['widgets'].values()}
        for title in ['Successful logins from IOC addresses', 'Failed logins from IOC addresses', 'Login IOC match details']:
            query = panels[title]['queryString']
            self.assertIn('ioc:lookup(field=source.ip', query)
            self.assertIn('confidenceThreshold="high", strict=true', query)
            self.assertIn('Vendor.Cef.name!=/(?i)(?:logged out|logout)/', query)
            if title != 'Login IOC match details':
                self.assertNotIn('split(ioc)', query)
        self.assertIn('#event.outcome=success', panels['Successful logins from IOC addresses']['queryString'])
        self.assertIn('#event.outcome=failure', panels['Failed logins from IOC addresses']['queryString'])

    def test_widgets_fit_without_overlap(self):
        occupied = set()
        for widget in self.dashboard['widgets'].values():
            self.assertGreater(widget['width'], 0)
            self.assertGreater(widget['height'], 0)
            self.assertGreaterEqual(widget['x'], 0)
            self.assertGreaterEqual(widget['y'], 0)
            self.assertLessEqual(widget['x'] + widget['width'], 12)
            for x in range(widget['x'], widget['x'] + widget['width']):
                for y in range(widget['y'], widget['y'] + widget['height']):
                    self.assertNotIn((x, y), occupied)
                    occupied.add((x, y))

    def test_official_schema(self):
        path = os.environ.get('DASHBOARD_SCHEMA')
        if not path:
            self.skipTest('Set DASHBOARD_SCHEMA to validate against a local official v0.24.0 schema')
        import jsonschema
        schema = json.loads(Path(path).read_text())
        jsonschema.validate(self.dashboard, schema)


if __name__ == '__main__':
    unittest.main()
