"""Convert a JSON threats file into Python threat classes.

Prints a module with one ``Threat`` subclass per threat in the file, in file
order, followed by a ``THREATS`` tuple listing them::

    python docs/threats_to_python.py threats.json > my_threats.py
    python docs/threats_to_python.py threats.json INP01 CR01 > some_threats.py
    ruff format my_threats.py

Name SIDs after the file to convert only those threats. Each threat is loaded
with ``Threat`` first, so a condition pytm would reject stops the conversion.
Deprecated threats keep their ``DEPRECATED`` note as a class attribute.

To add a converted threat to the built-in library, move its class into the
matching ``pytm/threatlib`` module and list it in ``BUILTIN_THREATS``.
"""

import argparse
import ast
import json
import os
import re
import sys

import pytm
from pytm.threat import Threat

# JSON key, Threat field. "" is the field default, so empty values are left out.
FIELDS = [
    ("description", "description"),
    ("details", "details"),
    ("Likelihood Of Attack", "likelihood"),
    ("likelihood", "likelihood"),
    ("severity", "severity"),
    ("prerequisites", "prerequisites"),
    ("mitigations", "mitigations"),
    ("example", "example"),
    ("references", "references"),
]
KNOWN_KEYS = {"SID", "id", "target", "condition", "DEPRECATED"} | {
    key for key, _ in FIELDS
}
ENUMS = {"Action", "Classification", "DatastoreType", "Lifetime", "TLSVersion"}


def quote(text):
    """Return *text* as a double-quoted Python string literal."""
    text = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{text}"'


def class_name(sid):
    """Return a valid Python class name for a threat SID."""
    name = re.sub(r"\W", "_", sid)
    return f"T{name}" if name[0].isdigit() else name


def condition_names(condition):
    """Return the pytm names a condition refers to, split into enums and others."""
    allowed = Threat._allowed_global_names() - set(Threat._SAFE_BUILTINS)
    names = {
        node.id
        for node in ast.walk(ast.parse(condition, mode="eval"))
        if isinstance(node, ast.Name)
    } & allowed
    return names & ENUMS, names - ENUMS


def convert(threat):
    """Return the class source for one threat from a threats file."""
    sid = threat.get("SID", threat.get("id"))
    for key in sorted(set(threat) - KNOWN_KEYS):
        print(f"{sid}: ignoring unknown key {key!r}", file=sys.stderr)

    targets = threat.get("target", ["Element"])
    if isinstance(targets, str):
        targets = [targets]
    for name in targets:
        if not isinstance(getattr(pytm, name, None), type):
            sys.exit(f"{sid}: unknown target {name!r}")
    target = ", ".join(f"pytm.{name}" for name in targets)
    if len(targets) == 1:
        target += ","

    description = threat.get("description", "").replace("\\", "\\\\")
    description = description.replace('"""', '\\"\\"\\"')
    if description and description[-1] not in ".?!":
        description += "."

    lines = [f"class {class_name(sid)}(Threat):", f'    """{description}"""', ""]
    if "DEPRECATED" in threat:
        lines += [f"    DEPRECATED: ClassVar[str] = {quote(threat['DEPRECATED'])}", ""]
    lines.append(f"    id: str = {quote(sid)}")
    lines.append(f"    target: tuple = ({target})")
    for key, field in FIELDS:
        if threat.get(key):
            lines.append(f"    {field}: str = {quote(threat[key])}")

    condition = threat.get("condition", "").strip() or "False"
    if "\n" in condition:
        condition = f"(\n            {condition}\n        )"
    lines += [
        "",
        "    def condition_applies(self, target) -> bool:",
        f"        return {condition}",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("threats_file", help="JSON threats file to convert")
    parser.add_argument("sids", nargs="*", help="only convert these threats")
    args = parser.parse_args()

    with open(args.threats_file, encoding="utf8") as threats_file:
        threats = json.load(threats_file)
    if args.sids:
        threats = [t for t in threats if t.get("SID", t.get("id")) in args.sids]
        missing = set(args.sids) - {t.get("SID", t.get("id")) for t in threats}
        if missing:
            sys.exit(f"not in {args.threats_file}: {', '.join(sorted(missing))}")

    for threat in threats:
        try:
            Threat(**dict(threat))  # fail on anything pytm wouldn't load
        except ValueError as e:
            sid = threat.get("SID", threat.get("id"))
            sys.exit(f"{sid}: pytm can't load this threat:\n{e}")

    enums, others = set(), set()
    for threat in threats:
        threat_enums, threat_others = condition_names(threat.get("condition") or "0")
        enums |= threat_enums
        others |= threat_others

    source = os.path.basename(args.threats_file)
    header = [f'"""Threats converted from {source}."""', ""]
    header += ["from __future__ import annotations", ""]
    if any("DEPRECATED" in threat for threat in threats):
        header += ["from typing import ClassVar", ""]
    header.append("import pytm")
    if others:
        header.append(f"from pytm import {', '.join(sorted(others))}")
    if enums:
        header.append(f"from pytm.enums import {', '.join(sorted(enums))}")
    header += ["from pytm.threat import Threat", "", ""]

    classes = [convert(threat) for threat in threats]
    names = ", ".join(class_name(t.get("SID", t.get("id"))) for t in threats)
    footer = f"THREATS: tuple[type[Threat], ...] = ({names}{',' if len(threats) == 1 else ''})"
    print("\n".join(header) + "\n\n\n".join([*classes, footer]))


if __name__ == "__main__":
    main()
