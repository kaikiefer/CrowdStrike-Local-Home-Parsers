"""Offline artifact and extraction checks. This does not execute CQL."""
import importlib.util
import os
import ipaddress
import json
from pathlib import Path
import re
import unittest

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "parsers/ubiquiti-unifi.cql").read_text()
FIXTURES = json.loads((ROOT / "tests/fixtures.json").read_text())
spec = importlib.util.spec_from_file_location("build", ROOT / "scripts/build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

# Extract regex literals actually used in CQL. The Python adapter changes only
# named-group syntax; it is a syntax/fixture check, not a LogScale regex engine.
LITERALS = re.compile(r"(?P<field>[\w.@]+)\s*=\s*/(?P<pattern>(?:\\.|[^/\n])*)/")


def compile_pattern(pattern):
    names = {}

    def group(match):
        alias = f"capture_{len(names)}"
        names[alias] = match[1]
        return f"(?P<{alias}>"

    translated = re.sub(r"\(\?<([\w.@]+)>", group, pattern)
    return re.compile(translated), names


def captures(pattern, text):
    compiled, names = compile_pattern(pattern)
    match = compiled.search(text)
    if not match:
        return None
    return {names[key]: value for key, value in match.groupdict().items()
            if value is not None}


def envelope(raw):
    block = SCRIPT.split("// Strip a syslog program tag")[0]
    result = {"_payload": raw}
    for literal in LITERALS.finditer(block):
        if literal["field"] == "@rawstring":
            values = captures(literal["pattern"], raw)
            if values is not None:
                result.update(values)
                break
    strip = SCRIPT.split("// Strip a syslog program tag")[1].split("// Older OS")[0]
    for literal in LITERALS.finditer(strip):
        values = captures(literal["pattern"], result["_payload"])
        if values is not None:
            result.update(values)
            break
    return result


class ArtifactTests(unittest.TestCase):
    def test_yaml_schema(self):
        document = yaml.safe_load((ROOT / "parsers/ubiquiti-unifi.yaml").read_text())
        schema_path = os.environ.get("UNIFI_PARSER_SCHEMA")
        if not schema_path:
            self.skipTest("Supply UNIFI_PARSER_SCHEMA pointing to the official parser v0.3.0 schema")
        schema = json.loads(Path(schema_path).read_text())
        jsonschema.Draft7Validator(schema).validate(document)

    def test_generated_yaml_is_current(self):
        self.assertEqual((ROOT / "parsers/ubiquiti-unifi.yaml").read_text(), build.render())

    def test_tags_and_assertions_use_ingested_names(self):
        document = build.document()
        self.assertEqual(set(document["tagFields"]), set(build.TAGS))
        for case in document["testCases"]:
            expected = case["assertions"][0]["fieldsHaveValues"]
            for tag in build.TAGS:
                self.assertNotIn(tag, expected)
            self.assertEqual(expected["#Cps.version"], "1.2.0")

    def test_all_regex_literals_compile_with_adapter(self):
        literals = list(LITERALS.finditer(SCRIPT))
        self.assertGreater(len(literals), 25)
        for literal in literals:
            with self.subTest(pattern=literal["pattern"]):
                compile_pattern(literal["pattern"])

    def test_syslog_extraction_from_actual_source_patterns(self):
        covered = 0
        for case in FIXTURES:
            if "envelope" not in case:
                continue
            with self.subTest(fixture=case["id"]):
                actual = envelope(case["raw"])
                for field, value in case["envelope"].items():
                    self.assertEqual(actual.get(field), value, field)
            covered += 1
        self.assertGreaterEqual(covered, 10)

    def test_os_message_template_extracts_supplied_format(self):
        pattern = next(m["pattern"] for m in LITERALS.finditer(SCRIPT)
                       if "_configActor" in m["pattern"])
        for case in FIXTURES:
            if case["id"] in {"os-user-sample-sanitized", "os-config-ipv4"}:
                message = case["raw"].split("msg=", 1)[1]
                values = captures(pattern, message)
                self.assertIsNotNone(values)
                self.assertEqual(values["_configActor"], case["fields"]["user.name"])
                self.assertEqual(str(ipaddress.ip_address(values["_configSource"])),
                                 case["fields"]["source.ip"])
        self.assertIsNone(captures(pattern, "John Doe mentioned Source IP: 192.0.2.1"))

    def test_short_os_detection_does_not_swallow_full_cef(self):
        pattern = next(m["pattern"] for m in LITERALS.finditer(SCRIPT)
                       if "_osExtension" in m["pattern"])
        for case in FIXTURES:
            payload = envelope(case["raw"])["_payload"]
            result = captures(pattern, payload)
            if case["id"].startswith("os-short"):
                self.assertIsNotNone(result)
                self.assertEqual(result["_osCode"], "admins")
            elif case["fields"].get("event.dataset") == "unifi.os":
                self.assertIsNone(result)

    def test_fixture_consistency_and_security_semantics(self):
        ids = [case["id"] for case in FIXTURES]
        self.assertEqual(len(ids), len(set(ids)))
        for case in FIXTURES:
            with self.subTest(fixture=case["id"]):
                fields = case["fields"]
                self.assertFalse(set(fields) & set(case["absent"]))
                self.assertTrue(case["provenance"])
                if fields.get("event.kind") == "alert":
                    self.assertIn("event.severity", fields)
                    self.assertTrue(1 <= int(fields["event.severity"]) <= 100)
                if case["id"] in {"protect-motion", "protect-person-detected",
                                  "protect-camera-tamper-detected", "protect-alarm-triggered"}:
                    self.assertEqual(fields["event.kind"], "event")
                    self.assertIn("event.category[0]", case["absent"])


if __name__ == "__main__":
    unittest.main()
