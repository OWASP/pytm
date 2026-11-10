"""The report templates under docs/ list Control objects."""

import pytest

from pytm import TM, Control, ControlCategory, ControlStatus, Dataflow, Server

TEMPLATES = ["basic_template", "advanced_template", "reveal"]


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


def make_tm() -> tuple[TM, Server]:
    tm = TM("rep", description="d", threatsFile="pytm/threatlib/threats.json")
    web, other = Server("Web"), Server("Other")
    Dataflow(web, other, "Call")
    return tm, web


@pytest.mark.parametrize("template", TEMPLATES)
def test_controls_are_rendered(template):
    tm, web = make_tm()
    Control(
        "Input filter",
        category=ControlCategory.PREVENTIVE,
        status=ControlStatus.IMPLEMENTED,
        mitigates=["INP03", "INP05"],
        appliesTo=web,
    )
    Control("Global WAF")
    tm.check()
    tm.resolve()
    report = tm.report(f"docs/{template}.md")
    assert "Input filter" in report
    assert "PREVENTIVE" in report and "IMPLEMENTED" in report
    assert "INP03<br>INP05<br>" in report
    assert "Web<br>" in report
    assert "Global WAF" in report and "whole model" in report


@pytest.mark.parametrize("template", TEMPLATES)
def test_no_controls_section_without_controls(template):
    tm, _ = make_tm()
    tm.check()
    tm.resolve()
    assert "Controls" not in tm.report(f"docs/{template}.md")
