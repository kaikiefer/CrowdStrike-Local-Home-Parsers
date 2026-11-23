"""Historical dashboard extraction checks; runtime CQL is checked in Falcon."""
import importlib.util
import re
import sys
import unittest

from test_artifacts import ROOT, FIXTURES, LITERALS, captures, extract

sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('build_dashboard', ROOT / 'scripts/build_dashboard.py')
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class DashboardTests(unittest.TestCase):
    def test_historical_auth_patterns_match_reviewed_fixtures_only(self):
        view = dashboard.authentication_view()
        patterns = [m['pattern'] for m in LITERALS.finditer(view) if m['field'] == 'message']
        self.assertEqual(len(patterns), 7)
        checked = 0
        for fixture in FIXTURES:
            extracted = extract(fixture['raw'])
            body = extracted['_body']
            matches = [value for pattern in patterns
                       if (value := captures(pattern, body)) is not None]
            is_auth = fixture['fields'].get('event.category[0]') == 'authentication'
            with self.subTest(fixture=fixture['id']):
                self.assertEqual(bool(matches), is_auth)
                if matches:
                    checked += 1
                    self.assertEqual(matches[0].get('Auth.user'), extracted.get('Vendor.User.name'))
                    expected = extracted.get('Vendor.Client.address')
                    if expected is not None:
                        self.assertEqual(matches[0].get('Auth.source'), expected)
        self.assertGreater(checked, 5)

    def test_ioc_panels_require_completed_login_and_ip(self):
        doc = dashboard.document()
        for key in ['ioc-success', 'ioc-failure', 'ioc-details']:
            query = doc['widgets'][key]['queryString']
            self.assertIn(dashboard.authentication_view(), query)
            self.assertIn('| Auth.action=login', query)
            self.assertIn('cidr(Auth.source', query)
            self.assertIn('ioc:lookup(field=Auth.source', query)
            self.assertIn('confidenceThreshold="high", strict=true', query)
        self.assertIn('Auth.outcome=success', doc['widgets']['ioc-success']['queryString'])
        self.assertIn('Auth.outcome=failure', doc['widgets']['ioc-failure']['queryString'])
        self.assertNotIn('split(ioc)', doc['widgets']['ioc-success']['queryString'])
        self.assertIn('split(ioc)', doc['widgets']['ioc-details']['queryString'])

    def test_auth_view_preserves_stored_fields_and_separates_first_factor(self):
        view = dashboard.authentication_view()
        assignments = re.findall(r'([\w.#\[\]]+)\s*:=', view)
        self.assertTrue(assignments)
        self.assertTrue(all(name.startswith('Auth.') for name in assignments))
        self.assertIn('Parser.status=envelope_only #event.dataset=dsm.connection', view)
        doc = dashboard.document()
        self.assertIn('Auth.action=login Auth.outcome=success', doc['widgets']['auth-success']['queryString'])
        self.assertIn('Auth.action=logout', doc['widgets']['auth-logout']['queryString'])
        self.assertIn('authentication-first-factor', doc['widgets']['auth-trend']['queryString'])
        for key in ['login-failures', 'auth-success', 'auth-logout', 'auth-trend', 'auth-sources', 'auth-details']:
            self.assertIn(view, doc['widgets'][key]['queryString'])
