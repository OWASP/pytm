"""Regression tests for cyclic trust-boundary parent traversal."""

import pytest

from pytm import TM, Boundary, Dataflow, Server
from pytm.pytm import _get_elements_and_boundaries
from pytm.report_util import ReportUtils


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


@pytest.mark.parametrize("start", [0, 1, 2])
def test_parents_reject_cycle(start):
    outer = Boundary("Outer")
    inner = Boundary("Inner", inBoundary=outer)
    child = Boundary("Child", inBoundary=inner)
    outer.inBoundary = inner

    with pytest.raises(ValueError, match="Cyclic trust boundary hierarchy"):
        (outer, inner, child)[start].parents()


def test_report_rejects_cycle():
    outer = Boundary("Outer")
    inner = Boundary("Inner", inBoundary=outer)
    outer.inBoundary = inner

    with pytest.raises(ValueError, match="Cyclic trust boundary hierarchy"):
        ReportUtils.getNamesOfParents(inner)


def test_used_boundaries_reject_cycle():
    outer = Boundary("Outer")
    inner = Boundary("Inner", inBoundary=outer)
    source = Server("Source", inBoundary=inner)
    sink = Server("Sink")
    flow = Dataflow(source, sink, "Request")
    outer.inBoundary = inner

    with pytest.raises(ValueError, match="Cyclic trust boundary hierarchy"):
        _get_elements_and_boundaries([flow])


def test_parents_with_repeated_names_are_not_a_cycle():
    outer = Boundary("Network")
    inner = Boundary("Network", inBoundary=outer)
    child = Boundary("Network", inBoundary=inner)

    parents = child.parents()
    assert len(parents) == 2
    assert parents[0] is inner
    assert parents[1] is outer
    assert outer.parents() == []
