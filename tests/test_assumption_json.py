"""Assumptions must survive threat-model JSON export and import."""

import json

import pytest

from pytm import TM, Assumption, Server, loads
from pytm.pytm import to_serializable


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


@pytest.mark.parametrize("scope", ["model", "element"])
def test_assumption_round_trip_preserves_fields(scope):
    assumption = Assumption(
        "Reviewed input", exclude=["INP01", "INP02"], description="Validated upstream"
    )
    tm = TM("Assumptions", assumptions=[assumption] if scope == "model" else [])
    Server("API", assumptions=[assumption] if scope == "element" else [])

    output = json.dumps(tm, default=to_serializable)
    TM.reset()
    restored = loads(output)

    assumptions = (
        restored.assumptions if scope == "model" else restored._elements[0].assumptions
    )
    assert len(assumptions) == 1
    assert assumptions[0].name == "Reviewed input"
    assert assumptions[0].description == "Validated upstream"
    assert assumptions[0].exclude == {"INP01", "INP02"}


@pytest.mark.parametrize("scope", ["model", "element"])
def test_round_trip_preserves_threat_exclusion(tmp_path, scope):
    threats_file = tmp_path / "threats.json"
    threats_file.write_text(
        json.dumps(
            [
                {
                    "SID": "TEST01",
                    "target": ["Server"],
                    "description": "Always matches the server",
                    "condition": "True",
                }
            ]
        )
    )
    tm = TM("Exclusions", threatsFile=str(threats_file))
    server = Server("API")
    tm.resolve()
    assert [finding.threat_id for finding in tm.findings] == ["TEST01"]

    owner = tm if scope == "model" else server
    owner.assumptions = [Assumption("Reviewed", exclude=["TEST01"])]
    tm.resolve()
    assert tm.findings == []
    assert [finding.threat_id for finding in tm.excluded_findings] == ["TEST01"]

    output = json.dumps(tm, default=to_serializable)
    TM.reset()
    restored = loads(output)
    restored.resolve()

    assert restored.findings == []
    assert [finding.threat_id for finding in restored.excluded_findings] == ["TEST01"]
    assert restored.excluded_findings[0].assumption.exclude == {"TEST01"}
