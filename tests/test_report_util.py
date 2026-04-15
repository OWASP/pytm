import pytest

from pytm import Boundary, Finding, Server, TM
from pytm.report_util import ReportUtils


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


def test_get_parent_name_returns_parent_name():
    outer = Boundary("Outer")
    inner = Boundary("Inner", inBoundary=outer)

    assert ReportUtils.getParentName(inner) == "Outer"


def test_get_parent_name_returns_empty_string_when_no_parent():
    boundary = Boundary("Standalone")

    assert ReportUtils.getParentName(boundary) == ""


def test_get_parent_name_rejects_non_boundary():
    server = Server("App Server")

    message = ReportUtils.getParentName(server)

    assert message == "ERROR: getParentName method is not valid for Server"


def test_get_names_of_parents_returns_full_chain():
    grandparent = Boundary("Grandparent")
    parent = Boundary("Parent", inBoundary=grandparent)
    child = Boundary("Child", inBoundary=parent)

    assert ReportUtils.getNamesOfParents(child) == ["Parent", "Grandparent"]


def test_get_names_of_parents_rejects_non_boundary():
    server = Server("API")

    message = ReportUtils.getNamesOfParents(server)

    assert message == "ERROR: getNamesOfParents method is not valid for Server"


def test_get_finding_count_returns_number_as_string():
    server = Server("API")
    finding = Finding(
        element=server,
        id="F1",
        threat_id="T1",
        description="desc",
        details="details",
        severity="High",
        mitigations="mit",
        example="example",
        references="refs",
        condition="cond",
    )
    server.findings.append(finding)

    assert ReportUtils.getFindingCount(server) == "1"


def test_get_finding_count_rejects_non_element():
    message = ReportUtils.getFindingCount(object())

    assert message == "ERROR: getFindingCount method is not valid for object"


def test_get_element_type_returns_class_name():
    server = Server("Web")

    assert ReportUtils.getElementType(server) == "Server"


def test_get_element_type_rejects_non_element():
    message = ReportUtils.getElementType(object())

    assert message == "ERROR: getElementType method is not valid for object"
