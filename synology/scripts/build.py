#!/usr/bin/env python3
"""Build the importable CrowdStrike parser from CQL and reviewed fixtures."""
import argparse
import json
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
TAGS = ["Cps.version", "Vendor", "ecs.version", "event.dataset", "event.kind",
        "event.module", "event.outcome", "observer.type"]


class Dumper(yaml.SafeDumper):
    pass


def string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value,
                                   style="|" if "\n" in value else None)


Dumper.add_representer(str, string)


def document():
    fixtures = json.loads((ROOT / "tests/fixtures.json").read_text())
    cases = []
    for fixture in fixtures:
        # Keep unrecognized-input cases in the offline suite rather than
        # importing deliberate missing-category failures into CPS validation.
        if fixture["fields"].get("Parser.status", "parsed") != "parsed":
            continue
        fields = {"Cps.version": "1.2.0", "ecs.version": "9.5.0",
                  "Parser.version": "1.2.0", "Vendor": "synology",
                  "event.module": "dsm", "event.kind": "event",
                  "observer.vendor": "synology", "observer.product": "DSM",
                  "@rawstring": fixture["raw"], "Parser.status": "parsed",
                  **fixture["fields"]}
        fields = {"#" + key if key in TAGS else key: value
                  for key, value in fields.items()}
        assertion = {"fieldsHaveValues": fields, "outputEventIndex": 0}
        absent = [*fixture.get("absent", []), "_input", "_payload", "_body", "_eventTime", "_lower", "@error"]
        assertion["fieldsNotPresent"] = ["#" + key if key in TAGS else key
                                         for key in dict.fromkeys(absent)]
        cases.append({"event": {"rawString": fixture["raw"]},
                      "assertions": [assertion]})
    return {
        "$schema": "https://schemas.humio.com/parser/v0.3.0",
        "name": "synology-dsm",
        "description": (
            "Synology DSM Log Center syslog. Targets CPS 1.2.0 and ECS 9.5.0. "
            "Normalizes English authentication, share-access and labeled file "
            "operation templates. Preserves unfamiliar system/storage/backup "
            "messages as envelope_only. Includes BSD/IETF wrappers and tenant "
            "test cases. Validate against actual NAS exports before production."
        ),
        "script": (ROOT / "parsers/synology-dsm.cql").read_text(),
        "tagFields": TAGS,
        "testCases": cases,
    }


def render():
    return yaml.dump(document(), Dumper=Dumper, sort_keys=False,
                     allow_unicode=True, width=120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the YAML needs rebuilding")
    args = parser.parse_args()
    destination = ROOT / "parsers/synology-dsm.yaml"
    content = render()
    if args.check:
        if not destination.exists() or destination.read_text() != content:
            sys.exit("Parser YAML is stale. Run python scripts/build.py")
        print("Parser YAML matches source and fixtures.")
    else:
        destination.write_text(content)
        print(f"Built {destination.relative_to(ROOT)} with {len(document()['testCases'])} tenant test cases.")


if __name__ == "__main__":
    main()
