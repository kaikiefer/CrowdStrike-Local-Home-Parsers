"""Offline import/schema and source-regex checks; these do not execute CQL."""
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
SCRIPT = (ROOT / "parsers/synology-dsm.cql").read_text()
FIXTURES = json.loads((ROOT / "tests/fixtures.json").read_text())
spec = importlib.util.spec_from_file_location("build", ROOT / "scripts/build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
LITERALS = re.compile(r"(?P<field>[\w.@]+)\s*=\s*/(?P<pattern>(?:\\.|[^/\n])*)/")


def compile_pattern(pattern):
    """Adapt captures and strict end anchors; this is not the LogScale engine."""
    names = {}

    def group(match):
        alias = f"capture_{len(names)}"
        names[alias] = match[1]
        return f"(?P<{alias}>"

    translated = re.sub(r"\(\?<([\w.@]+)>", group, pattern)
    # Unlike LogScale's unflagged $, Python's $ accepts a position before a
    # final LF. That difference hid the production UDP-terminator regression.
    translated = re.sub(r"(?<!\\)\$", lambda _: r"\Z", translated)
    return re.compile(translated), names


def captures(pattern, value):
    compiled, names = compile_pattern(pattern)
    match = compiled.search(value)
    if match is None:
        return None
    return {names[key]: value for key, value in match.groupdict().items()
            if value is not None}


def first_match(block, field, value):
    for literal in LITERALS.finditer(block):
        if literal["field"] == field:
            result = captures(literal["pattern"], value)
            if result is not None:
                return result
    return None


def extract(raw):
    """Check actual source patterns in extraction order, not CQL semantics."""
    normalized = normalize(raw)
    result = {"_payload": normalized}
    header = first_match(SCRIPT.split("// PROGRAM:")[0], "_input", normalized)
    if header is not None:
        result.update(header)
    program_block = SCRIPT.split("// PROGRAM:")[1].split("| Vendor.Message :=")[0]
    program = first_match(program_block, "_payload", result["_payload"])
    # The generic program branch applies only with a syslog envelope and no
    # RFC 5424 APP-NAME. A known DSM program can also occur in a bare record.
    if program and ("Vendor.Log.type" in program or
                    (header and "Vendor.Syslog.appname" not in result)):
        result.update(program)
    elif result.get("Vendor.Syslog.appname") in {
        "Connection", "System", "WinFileService", "MacFileService",
        "FileStation", "FTP", "WebDAV", "Backup", "StorageManager", "CMS"
    }:
        result["Vendor.Log.type"] = result["Vendor.Syslog.appname"]
    result["Vendor.Message"] = result["_payload"]
    result["_body"] = result["_payload"]
    if result.get("Vendor.Log.type") in {"Connection", "System", "Backup", "StorageManager", "CMS"}:
        actor = first_match(SCRIPT.split("// ACTOR:")[1].split("// #endregion")[0],
                            "_body", result["_body"])
        if actor is not None:
            result.update(actor)
    body_block = SCRIPT.split("// #region MESSAGE TEMPLATES")[1].split(
        "// #region SYSTEM TEMPLATES")[0]
    match_template(body_block, result)
    if "Vendor.Template" not in result and result.get("Vendor.Log.type") == "System":
        system_block = SCRIPT.split("// #region SYSTEM TEMPLATES")[1].split(
            "// #endregion SYSTEM TEMPLATES")[0]
        match_template(system_block, result)
    if "Vendor.Template" not in result and result.get("Vendor.Log.type") == "CMS":
        cms_block = SCRIPT.split("// #region CMS TEMPLATES")[1].split(
            "// #endregion CMS TEMPLATES")[0]
        match_template(cms_block, result)
    return result


def match_template(block, result):
    for literal in LITERALS.finditer(block):
        if literal["field"] != "_body":
            continue
        values = captures(literal["pattern"], result["_body"])
        if values is not None:
            result.update(values)
            tail = block[literal.end():]
            result["Vendor.Template"] = re.search(r'Vendor.Template := "([^"]+)"', tail)[1]
            break


def normalize(raw):
    """Exercise the cleanup regex/string escaping actually used in CQL."""
    literal = re.search(r'replace\(("(?:\\.|[^"\\])*")', SCRIPT)[1]
    pattern = json.loads(literal)
    compiled, _ = compile_pattern(pattern)
    return compiled.sub("", raw)


class ArtifactTests(unittest.TestCase):
    def test_import_schema_and_generated_yaml(self):
        document = yaml.safe_load((ROOT / "parsers/synology-dsm.yaml").read_text())
        self.assertEqual(document, build.document())
        self.assertEqual((ROOT / "parsers/synology-dsm.yaml").read_text(), build.render())
        self.assertEqual(document["script"], SCRIPT)

    def test_schema(self):
        schema_path = os.environ.get("SYNOLOGY_PARSER_SCHEMA")
        if not schema_path:
            self.skipTest("Set SYNOLOGY_PARSER_SCHEMA to the official parser schema")
        document = yaml.safe_load((ROOT / "parsers/synology-dsm.yaml").read_text())
        schema = json.loads(Path(schema_path).read_text())
        jsonschema.Draft7Validator(schema).validate(document)

    def test_tag_assertions_use_ingested_names(self):
        document = build.document()
        self.assertEqual(set(document["tagFields"]), set(build.TAGS))
        self.assertEqual(len(document["testCases"]), sum(
            f["fields"].get("Parser.status", "parsed") == "parsed" for f in FIXTURES))
        for case in document["testCases"]:
            values = case["assertions"][0]["fieldsHaveValues"]
            self.assertEqual(values["#Vendor"], "synology")
            self.assertEqual(values["#event.module"], "dsm")
            self.assertEqual(values["Parser.status"], "parsed")
            self.assertIn("event.category[0]", values)
            for tag in build.TAGS:
                self.assertNotIn(tag, values)

    def test_source_regex_syntax(self):
        literals = list(LITERALS.finditer(SCRIPT))
        self.assertGreater(len(literals), 20)
        for literal in literals:
            with self.subTest(pattern=literal["pattern"]):
                compile_pattern(literal["pattern"])

    def test_source_extraction_against_fixtures(self):
        checked = 0
        for fixture in FIXTURES:
            with self.subTest(fixture=fixture["id"]):
                actual = extract(fixture["raw"])
                for key, value in fixture.get("extraction", {}).items():
                    self.assertEqual(actual.get(key), value, key)
                # Verify source captures which also have tenant assertions.
                for key, value in fixture["fields"].items():
                    if key.startswith("Vendor.") or key == "message":
                        self.assertEqual(actual.get("_body" if key == "message" else key), value, key)
                if fixture["fields"].get("Parser.status") in {"envelope_only", "unsupported_format"}:
                    self.assertNotIn("Vendor.Template", actual)
                else:
                    self.assertIn("Vendor.Template", actual)
            checked += 1
        self.assertGreaterEqual(checked, 40)

    def test_invalid_and_hostname_addresses_are_not_valid_ips(self):
        for id in ("hostname-client", "invalid-ip-client"):
            fixture = next(f for f in FIXTURES if f["id"] == id)
            address = extract(fixture["raw"])["Vendor.Client.address"]
            with self.assertRaises(ValueError):
                ipaddress.ip_address(address)
            self.assertIn("source.ip", fixture["absent"])

    def test_fixture_consistency_and_semantic_guards(self):
        self.assertEqual(len({f["id"] for f in FIXTURES}), len(FIXTURES))
        for fixture in FIXTURES:
            with self.subTest(fixture=fixture["id"]):
                self.assertTrue(fixture["provenance"])
                self.assertFalse(set(fixture["fields"]) & set(fixture["absent"]))
                self.assertTrue(all(isinstance(v, str) for v in fixture["fields"].values()))
        # File operations do not prove successful completion or maliciousness.
        for fixture in FIXTURES:
            if fixture["id"].startswith("file-"):
                self.assertIn("event.outcome", fixture["absent"])
        self.assertNotIn('event.kind := "alert"', SCRIPT)
        self.assertNotIn('observer.type := "nas"', SCRIPT)
        self.assertIn('cidr(source.address', SCRIPT)
        self.assertIn('Vendor.Syslog.priority <= 191', SCRIPT)

    def test_synthetic_coverage_includes_core_workflows(self):
        observed = {extract(f["raw"]).get("Vendor.Template") for f in FIXTURES}
        self.assertGreaterEqual(len(observed - {None}), 10)

    def test_transport_cleanup_preserves_content_and_rejects_bulk_input(self):
        raw = '<14>Nov 23 00:28:22 nas-demo.example System Test message from Synology Syslog Client from (198.51.100.52)'
        for suffix in ("\n", "\r", "\r\n", "\x00", "\r\n\x00"):
            with self.subTest(suffix=repr(suffix)):
                self.assertEqual(normalize(raw + suffix), raw)
                # The original strict envelope cannot accept the LF that the
                # previous Python adapter silently allowed before its $ anchor.
                if "\n" in suffix:
                    self.assertIsNone(first_match(SCRIPT.split("// PROGRAM:")[0], "_input", raw + suffix))
                self.assertEqual(extract(raw + suffix)["Vendor.Template"], "syslog_test")
        self.assertEqual(normalize("keep trailing spaces  \n"), "keep trailing spaces  ")
        combined = raw + "\n" + raw
        self.assertEqual(normalize(combined), combined)
        self.assertNotIn("Vendor.Template", extract(combined))

    def test_case_conversion_has_explicit_output_fields(self):
        # lower() defaults to _lower, not its input field. Require explicit
        # destinations so normalized host/address values really reach CPS.
        calls = re.findall(r"\blower\(([^)]*)\)", SCRIPT)
        self.assertEqual(len(calls), 3)
        for call in calls:
            self.assertIn("as=", call)

    def test_system_templates_require_system_program_context(self):
        body = "User [demo-user] was created."
        for raw in (body, "Connection SYSTEM: " + body, "Backup SYSTEM: " + body):
            self.assertNotIn("Vendor.Template", extract(raw))
        self.assertEqual(extract("System admin: " + body)["Vendor.Template"],
                         "system_account_state")


if __name__ == "__main__":
    unittest.main()
