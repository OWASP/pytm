"""Negative tests for threats INP01-INP20.

Each test first proves the threat applies to a model, then flips the
attribute under test and proves the threat no longer applies.
"""

import json
import os
from typing import Any

import pytest

from pytm import TM, Lambda, Process, Server, Threat

with open(
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    + "/pytm/threatlib/threats.json",
) as threat_file:
    threats = {t["SID"]: Threat(**t) for t in json.load(threat_file)}


@pytest.fixture(autouse=True)
def reset_tm() -> None:
    TM.reset()


def secure(target: Any, *names: str) -> Any:
    """Set the named controls on target to True and return it."""
    for name in names:
        setattr(target.controls, name, True)
    return target


def flip_only(sid: str, target: Any, name: str) -> None:
    """Assert threat applies, then stops applying once control `name` is set."""
    threat = threats[sid]
    assert threat.apply(target)
    setattr(target.controls, name, True)
    assert not threat.apply(target)


def flip_any(sid: str, make: Any, names: tuple[str, ...]) -> None:
    """For 'A is False or B is False': securing only one still applies."""
    threat = threats[sid]
    assert threat.apply(make())
    assert not threat.apply(secure(make(), *names))
    for name in names:
        partial = secure(make(), *[n for n in names if n != name])
        assert threat.apply(partial), f"{sid} should apply when {name} is False"


@pytest.mark.parametrize("cls", [Lambda, Process])
def test_INP01_does_not_apply_when_clause_broken(cls: Any) -> None:
    threat = threats["INP01"]

    def make() -> Any:
        t = cls("t")
        t.usesEnvironmentVariables = True
        return t

    assert threat.apply(make())

    no_env = make()
    no_env.usesEnvironmentVariables = False
    assert not threat.apply(no_env)

    assert not threat.apply(secure(make(), "sanitizesInput"))
    assert not threat.apply(secure(make(), "checksInputBounds"))


def test_INP01_does_not_apply_to_server() -> None:
    server = Server("s")
    server.usesEnvironmentVariables = True
    assert not threats["INP01"].apply(server)


def test_INP02_does_not_apply_when_bounds_checked() -> None:
    flip_only("INP02", Process("p"), "checksInputBounds")


def test_INP02_does_not_apply_to_server() -> None:
    assert not threats["INP02"].apply(Server("s"))


def test_INP03_does_not_apply_when_sanitized_and_encoded() -> None:
    flip_any("INP03", lambda: Server("s"), ("sanitizesInput", "encodesOutput"))


def test_INP03_does_not_apply_to_process() -> None:
    assert not threats["INP03"].apply(Process("p"))


def test_INP04_does_not_apply() -> None:
    threat = threats["INP04"]

    def make() -> Server:
        s = Server("s")
        s.protocol = "HTTP"
        return s

    assert threat.apply(make())
    assert not threat.apply(secure(make(), "validatesInput", "validatesHeaders"))
    assert threat.apply(secure(make(), "validatesInput"))
    assert threat.apply(secure(make(), "validatesHeaders"))

    other = make()
    other.protocol = "HTTPS"
    assert not threat.apply(other)


def test_INP05_does_not_apply_when_input_validated() -> None:
    flip_only("INP05", Server("s"), "validatesInput")


def test_INP05_does_not_apply_to_process() -> None:
    assert not threats["INP05"].apply(Process("p"))


def test_INP06_does_not_apply() -> None:
    threat = threats["INP06"]

    def make() -> Server:
        s = Server("s")
        s.protocol = "SOAP"
        return s

    assert threat.apply(make())
    assert not threat.apply(secure(make(), "sanitizesInput", "validatesInput"))
    assert threat.apply(secure(make(), "sanitizesInput"))
    assert threat.apply(secure(make(), "validatesInput"))

    other = make()
    other.protocol = "HTTP"
    assert not threat.apply(other)


def test_INP07_does_not_apply_when_secure_functions_used() -> None:
    flip_only("INP07", Process("p"), "usesSecureFunctions")


def test_INP07_does_not_apply_to_server() -> None:
    assert not threats["INP07"].apply(Server("s"))


@pytest.mark.parametrize("cls", [Process, Lambda, Server])
def test_INP08_does_not_apply_when_validated_and_sanitized(cls: Any) -> None:
    flip_any("INP08", lambda: cls("t"), ("validatesInput", "sanitizesInput"))


def test_INP09_does_not_apply_when_input_validated() -> None:
    flip_only("INP09", Server("t"), "validatesInput")


def test_INP09_does_not_apply_to_process() -> None:
    assert not threats["INP09"].apply(Process("p"))


def test_INP10_does_not_apply_when_input_validated() -> None:
    flip_only("INP10", Server("s"), "validatesInput")


def test_INP10_does_not_apply_to_process() -> None:
    assert not threats["INP10"].apply(Process("p"))


def test_INP11_does_not_apply_when_validated_and_sanitized() -> None:
    flip_any("INP11", lambda: Server("s"), ("validatesInput", "sanitizesInput"))


def test_INP11_does_not_apply_to_process() -> None:
    assert not threats["INP11"].apply(Process("p"))


@pytest.mark.parametrize("cls", [Process, Lambda])
def test_INP12_does_not_apply_when_either_control_set(cls: Any) -> None:
    threat = threats["INP12"]
    assert threat.apply(cls("t"))
    assert not threat.apply(secure(cls("t"), "checksInputBounds"))
    assert not threat.apply(secure(cls("t"), "validatesInput"))


def test_INP12_does_not_apply_to_server() -> None:
    assert not threats["INP12"].apply(Server("s"))


@pytest.mark.parametrize("cls", [Process, Lambda])
def test_INP13_does_not_apply_when_input_validated(cls: Any) -> None:
    flip_only("INP13", cls("t"), "validatesInput")


def test_INP13_does_not_apply_to_server() -> None:
    assert not threats["INP13"].apply(Server("s"))


@pytest.mark.parametrize("cls", [Process, Lambda, Server])
def test_INP14_does_not_apply_when_input_validated(cls: Any) -> None:
    flip_only("INP14", cls("t"), "validatesInput")


def test_INP15_does_not_apply() -> None:
    threat = threats["INP15"]

    def make(protocol: str) -> Server:
        s = Server("s")
        s.protocol = protocol
        return s

    for proto in ("IMAP", "SMTP"):
        assert threat.apply(make(proto))
        assert not threat.apply(secure(make(proto), "sanitizesInput"))

    assert not threat.apply(make("HTTP"))
    assert not threat.apply(make(""))


def test_INP16_does_not_apply_when_input_validated() -> None:
    flip_only("INP16", Server("s"), "validatesInput")


def test_INP16_does_not_apply_to_process() -> None:
    assert not threats["INP16"].apply(Process("p"))


def test_INP17_does_not_apply_when_content_type_validated_and_filtered() -> None:
    flip_any(
        "INP17",
        lambda: Server("s"),
        ("validatesContentType", "invokesScriptFilters"),
    )


def test_INP17_does_not_apply_to_process() -> None:
    assert not threats["INP17"].apply(Process("p"))


def test_INP18_does_not_apply_when_sanitized_and_encoded() -> None:
    flip_any("INP18", lambda: Server("s"), ("sanitizesInput", "encodesOutput"))


def test_INP18_does_not_apply_to_process() -> None:
    assert not threats["INP18"].apply(Process("p"))


def test_INP19_does_not_apply() -> None:
    threat = threats["INP19"]

    def make() -> Server:
        s = Server("s")
        s.usesXMLParser = True
        return s

    assert threat.apply(make())
    # parser in use and DTD disabled: nothing left to flag
    both = secure(make(), "disablesDTD")
    assert not threat.apply(both)


def test_INP19_applies_when_no_xml_parser_flag_even_with_dtd_disabled() -> None:
    threat = threats["INP19"]
    s = secure(Server("s"), "disablesDTD")
    s.usesXMLParser = False
    assert threat.apply(s)


def test_INP20_does_not_apply_when_iframes_disabled() -> None:
    flip_only("INP20", Process("p"), "disablesiFrames")


def test_INP20_does_not_apply_to_server() -> None:
    assert not threats["INP20"].apply(Server("s"))
