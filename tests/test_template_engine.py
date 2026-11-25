"""Tests for SuperFormatter and its custom format specs."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pytm import TM, Boundary, Finding, Server
from pytm.template_engine import SuperFormatter


@pytest.fixture(autouse=True)
def reset_tm() -> Any:
    TM.reset()
    SuperFormatter._resolve_report_method.cache_clear()
    yield
    TM.reset()


@pytest.fixture
def sf() -> SuperFormatter:
    return SuperFormatter()


# --- plain formatting -------------------------------------------------------


def test_plain_format_spec_delegates_to_standard_formatter(sf: SuperFormatter) -> None:
    assert sf.format("{n:05d}|{s:>4}|{x}", n=42, s="ab", x="y") == "00042|  ab|y"


def test_escaped_braces_are_literal(sf: SuperFormatter) -> None:
    assert sf.format("{{literal}} {v}", v=1) == "{literal} 1"


# --- repeat -----------------------------------------------------------------


def test_repeat_renders_template_per_item(sf: SuperFormatter) -> None:
    out = sf.format("{xs:repeat:[{{item}}]}", xs=["a", "b", "c"])

    assert out == "[a][b][c]"


def test_repeat_empty_list_renders_nothing(sf: SuperFormatter) -> None:
    assert sf.format("x{xs:repeat:[{{item}}]}y", xs=[]) == "xy"


def test_repeat_accesses_item_attributes(sf: SuperFormatter) -> None:
    objs = [SimpleNamespace(name="one"), SimpleNamespace(name="two")]

    assert sf.format("{xs:repeat:{{item.name}};}", xs=objs) == "one;two;"


def test_repeat_over_dict_yields_key_value_pairs(sf: SuperFormatter) -> None:
    out = sf.format("{d:repeat:{{item[0]}}={{item[1]}},}", d={"a": 1, "b": 2})

    assert out == "a=1,b=2,"


def test_repeat_over_generator(sf: SuperFormatter) -> None:
    out = sf.format("{g:repeat:{{item}}}", g=(i for i in range(3)))

    assert out == "012"


@pytest.mark.parametrize("value", ["text", b"bytes", 5, None, 1.5])
def test_repeat_over_non_iterable_or_string_renders_nothing(
    sf: SuperFormatter, value: Any
) -> None:
    assert sf.format("{v:repeat:[{{item}}]}", v=value) == ""


def test_repeat_keeps_colons_in_template(sf: SuperFormatter) -> None:
    assert sf.format("{xs:repeat:{{item}}: ok;}", xs=[1, 2]) == "1: ok;2: ok;"


def test_nested_repeat(sf: SuperFormatter) -> None:
    rows = [[1, 2], [3]]
    out = sf.format("{rows:repeat:<{{item:repeat:{{{{item}}}}}}>}", rows=rows)

    assert out == "<12><3>"


# --- call -------------------------------------------------------------------


def test_call_invokes_callable_value(sf: SuperFormatter) -> None:
    assert sf.format("{f:call:}", f=lambda: "result") == "result"


def test_call_callable_returning_list_is_repeated(sf: SuperFormatter) -> None:
    out = sf.format("{f:call:<{{item}}>}", f=lambda: [1, 2])

    assert out == "<1><2>"


def test_call_callable_returning_list_without_template_cannot_be_joined(
    sf: SuperFormatter,
) -> None:
    # format_field hands back the raw list, which str.join rejects.
    with pytest.raises(TypeError, match="expected str instance, list found"):
        sf.format("{f:call:}", f=lambda: [1, 2])


def test_call_callable_returning_non_list_ignores_template(sf: SuperFormatter) -> None:
    assert sf.format("{f:call:ignored}", f=lambda: "r") == "r"


def test_call_util_method_on_object(sf: SuperFormatter) -> None:
    server = Server("Web")

    assert sf.format("{e:call:getElementType}", e=server) == "Server"


def test_call_util_method_error_string_is_rendered(sf: SuperFormatter) -> None:
    out = sf.format("{e:call:getElementType}", e=object())

    assert out == "ERROR: getElementType method is not valid for object"


def test_call_util_method_returning_list_uses_template(sf: SuperFormatter) -> None:
    outer = Boundary("Outer")
    inner = Boundary("Inner", inBoundary=outer)

    out = sf.format("{b:call:getNamesOfParents:[{{item}}]}", b=inner)

    assert out == "[Outer]"


def test_call_util_method_returning_list_without_template_cannot_be_joined(
    sf: SuperFormatter,
) -> None:
    outer = Boundary("Outer")
    inner = Boundary("Inner", inBoundary=outer)

    with pytest.raises(TypeError, match="expected str instance, list found"):
        sf.format("{b:call:getNamesOfParents}", b=inner)


def test_call_finding_helper_in_repeat(sf: SuperFormatter) -> None:
    server = Server("Web")
    findings = [
        Finding(
            element=server,
            id=f"F{i}",
            threat_id=f"T{i}",
            description=f"d{i}",
            details="x",
            severity="High",
            mitigations="m",
            example="e",
            references="r",
            condition="c",
        )
        for i in (1, 2)
    ]

    out = sf.format(
        "{fs:repeat:{{item:call:getThreatId}}-{{item:call:getFindingDescription}};}",
        fs=findings,
    )

    assert out == "T1-d1;T2-d2;"


def test_call_unknown_util_method_raises(sf: SuperFormatter) -> None:
    with pytest.raises(AttributeError, match="noSuchMethod"):
        sf.format("{e:call:noSuchMethod}", e=Server("Web"))


def test_call_util_method_direct_unknown_raises(sf: SuperFormatter) -> None:
    with pytest.raises(AttributeError, match="missing"):
        sf.call_util_method("missing", 1)


def test_call_util_method_direct_passes_object(sf: SuperFormatter) -> None:
    assert sf.call_util_method("getElementType", Server("S")) == "Server"


def test_resolve_report_method_returns_report_utils_function() -> None:
    from pytm.report_util import ReportUtils

    method = SuperFormatter._resolve_report_method("getElementType")

    assert method is ReportUtils.getElementType


def test_resolve_report_method_is_cached() -> None:
    first = SuperFormatter._resolve_report_method("getParentName")
    second = SuperFormatter._resolve_report_method("getParentName")

    assert first is second
    assert SuperFormatter._resolve_report_method.cache_info().hits >= 1


# --- conditionals -----------------------------------------------------------


@pytest.mark.parametrize("value", [True, "x", 1, [0]])
def test_if_truthy_renders_template(sf: SuperFormatter, value: Any) -> None:
    assert sf.format("{v:if:shown}", v=value) == "shown"


@pytest.mark.parametrize("value", [False, "", 0, [], None])
def test_if_falsy_renders_nothing(sf: SuperFormatter, value: Any) -> None:
    assert sf.format("a{v:if:shown}b", v=value) == "ab"


@pytest.mark.parametrize("value", [False, "", 0, [], None])
def test_not_falsy_renders_template(sf: SuperFormatter, value: Any) -> None:
    assert sf.format("{v:not:empty}", v=value) == "empty"


@pytest.mark.parametrize("value", [True, "x", 1, [0]])
def test_not_truthy_renders_nothing(sf: SuperFormatter, value: Any) -> None:
    assert sf.format("a{v:not:empty}b", v=value) == "ab"


def test_if_evaluates_callable_value(sf: SuperFormatter) -> None:
    assert sf.format("{f:if:yes}", f=lambda: True) == "yes"
    assert sf.format("{f:if:yes}", f=lambda: []) == ""


def test_not_evaluates_callable_value(sf: SuperFormatter) -> None:
    assert sf.format("{f:not:no}", f=lambda: []) == "no"
    assert sf.format("{f:not:no}", f=lambda: "x") == ""


def test_conditional_template_may_contain_colons(sf: SuperFormatter) -> None:
    assert sf.format("{v:if:a: b}", v=True) == "a: b"


def test_conditional_template_is_not_re_expanded(sf: SuperFormatter) -> None:
    out = sf.format("{v:if:{{xs}}}", v=True, xs=[1, 2])

    assert out == "{xs}"


def test_conditional_on_template_attribute(sf: SuperFormatter) -> None:
    obj = SimpleNamespace(assumptions=["one"])

    assert sf.format("{o.assumptions:if:has}", o=obj) == "has"
    obj.assumptions = []
    assert sf.format("{o.assumptions:if:has}", o=obj) == ""
