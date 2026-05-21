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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(element):
    """Return a Finding attached to *element* using fixed test values."""
    return Finding(
        element=element,
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


# ---------------------------------------------------------------------------
# getInScopeFindings — non-element input
# ---------------------------------------------------------------------------

def test_get_in_scope_findings_rejects_non_element():
    assert ReportUtils.getInScopeFindings(object()) == []


# ---------------------------------------------------------------------------
# getInScopeFindings — out-of-scope element
# ---------------------------------------------------------------------------

def test_get_in_scope_findings_returns_empty_for_out_of_scope_element():
    server = Server("OutOfScope")
    server.inScope = False
    server.findings.append(_make_finding(server))

    result = ReportUtils.getInScopeFindings(server)

    assert result == []


# ---------------------------------------------------------------------------
# getInScopeFindings — in-scope element
# ---------------------------------------------------------------------------

def test_get_in_scope_findings_returns_findings_for_in_scope_element():
    """An in-scope element with findings should have those findings returned."""
    server = Server("InScope")
    finding = _make_finding(server)
    server.findings.append(finding)

    result = ReportUtils.getInScopeFindings(server)

    assert len(result) == 1
    assert result[0] is finding


def test_get_in_scope_findings_returns_all_findings_for_in_scope_element():
    server = Server("InScope2")
    f1 = _make_finding(server)
    f2 = Finding(
        element=server,
        id="F2",
        threat_id="T2",
        description="desc2",
        details="details2",
        severity="Low",
        mitigations="mit2",
        example="ex2",
        references="refs2",
        condition="cond2",
    )
    server.findings.extend([f1, f2])

    result = ReportUtils.getInScopeFindings(server)

    assert len(result) == 2


def test_get_in_scope_findings_returns_empty_when_no_findings():
    server = Server("Clean")

    result = ReportUtils.getInScopeFindings(server)

    assert result == []


# ---------------------------------------------------------------------------
# getInScopeFindings — no cross-element leakage (regression for issue #310)
# ---------------------------------------------------------------------------

def test_get_in_scope_findings_does_not_leak_findings_across_elements():
    """Findings on one element must not appear on a different element."""
    server_a = Server("ServerA")
    server_b = Server("ServerB")

    finding_a = _make_finding(server_a)
    server_a.findings.append(finding_a)

    # ServerB has no findings of its own
    result = ReportUtils.getInScopeFindings(server_b)

    assert result == []


def test_get_in_scope_findings_out_of_scope_element_is_independent_of_previous_in_scope():
    """Out-of-scope element must not inherit findings from a preceding in-scope element."""
    in_scope = Server("InScopeServer")
    out_of_scope = Server("OutOfScopeServer")
    out_of_scope.inScope = False

    in_scope.findings.append(_make_finding(in_scope))

    result = ReportUtils.getInScopeFindings(out_of_scope)

    assert result == []
