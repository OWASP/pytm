"""Assumptions survive the --json output and load back with pytm.load()."""

import json
import random
import sys

import pytest

from pytm import TM, Actor, Assumption, Dataflow, Server, load


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _build_model():
    tm = TM("assumptions tm", description="assumptions round trip")
    tm.assumptions = [
        "Documented only",
        Assumption("Nobody uses SSI", exclude=["INP17"]),
    ]
    user = Actor("User")
    web = Server("Web Server")
    web.assumptions = [
        Assumption(
            "This webserver does not use PHP",
            exclude=["INP16", "DE03"],
            description="PHP is not installed",
        )
    ]
    Dataflow(user, web, "Request")
    return tm


def _write_json(tm, path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["tm.py", "--json", str(path)])
    tm.process()
    with open(path, encoding="utf8") as f:
        return json.load(f)


def _findings(tm):
    return sorted((f.threat_id, f.target) for f in tm.findings)


def _excluded(tm):
    return sorted(
        (f.threat_id, f.target, f.assumption.name) for f in tm.excluded_findings
    )


def test_json_output_keeps_assumption_exclusions(tmp_path, monkeypatch):
    output = _write_json(_build_model(), tmp_path / "tm.json", monkeypatch)

    web = next(e for e in output["elements"] if e["name"] == "Web Server")
    assert web["assumptions"] == [
        {
            "name": "This webserver does not use PHP",
            "exclude": ["DE03", "INP16"],
            "description": "PHP is not installed",
        }
    ]
    assert output["assumptions"] == [
        {"name": "Documented only", "exclude": [], "description": ""},
        {"name": "Nobody uses SSI", "exclude": ["INP17"], "description": ""},
    ]
    excluded = {f["threat_id"]: f["assumption"] for f in output["excluded_findings"]}
    assert excluded["INP16"]["exclude"] == ["DE03", "INP16"]


def test_json_output_loads_back_with_the_same_findings(tmp_path, monkeypatch):
    tm = _build_model()
    path = tmp_path / "tm.json"
    _write_json(tm, path, monkeypatch)
    findings, excluded = _findings(tm), _excluded(tm)
    assert ("INP16", "Web Server") in [e[:2] for e in excluded]

    TM.reset()
    with open(path, encoding="utf8") as f:
        loaded = load(f)
    loaded.check()
    loaded.resolve()

    web = next(e for e in TM._elements if e.name == "Web Server")
    assert web.assumptions[0].exclude == {"INP16", "DE03"}
    assert _findings(loaded) == findings
    assert _excluded(loaded) == excluded
