"""Tests for the Finding accessor helpers in ReportUtils."""

from __future__ import annotations

from typing import Any

import pytest

from pytm import TM, Finding, Server
from pytm.report_util import ReportUtils


@pytest.fixture(autouse=True)
def reset_tm() -> Any:
    TM.reset()
    yield
    TM.reset()


def _finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "element": Server("Web"),
        "id": "F1",
        "threat_id": "INP01",
        "description": "Buffer overflow",
        "details": "details text",
        "severity": "High",
        "mitigations": "Validate input",
        "example": "A long string",
        "references": "CWE-120",
        "condition": "True",
    }
    values.update(overrides)
    return Finding(**values)


@pytest.mark.parametrize(
    ("helper", "expected"),
    [
        ("getThreatId", "INP01"),
        ("getFindingDescription", "Buffer overflow"),
        ("getFindingSeverity", "High"),
        ("getFindingMitigations", "Validate input"),
        ("getFindingReferences", "CWE-120"),
        ("getFindingExample", "A long string"),
    ],
)
def test_helper_returns_finding_field(helper: str, expected: str) -> None:
    assert getattr(ReportUtils, helper)(_finding()) == expected


def test_get_finding_target_returns_target_name() -> None:
    assert ReportUtils.getFindingTarget(_finding(target="Web")) == "Web"


def test_get_finding_target_defaults_to_empty_string() -> None:
    finding = _finding(element=None)

    assert ReportUtils.getFindingTarget(finding) == ""


def test_helpers_distinguish_between_findings() -> None:
    first = _finding(threat_id="A1", severity="Low")
    second = _finding(threat_id="B2", severity="Very High")

    assert ReportUtils.getThreatId(first) == "A1"
    assert ReportUtils.getThreatId(second) == "B2"
    assert ReportUtils.getFindingSeverity(first) == "Low"
    assert ReportUtils.getFindingSeverity(second) == "Very High"


@pytest.mark.parametrize(
    "helper",
    [
        "getThreatId",
        "getFindingDescription",
        "getFindingTarget",
        "getFindingSeverity",
        "getFindingMitigations",
        "getFindingReferences",
        "getFindingExample",
    ],
)
@pytest.mark.parametrize("bad", [None, "INP01", 42, object(), Server("S")])
def test_helper_returns_empty_string_for_non_finding(helper: str, bad: Any) -> None:
    assert getattr(ReportUtils, helper)(bad) == ""
