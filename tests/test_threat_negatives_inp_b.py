"""Negative tests for input-validation threats INP21 through INP41.

Each test builds a model the threat applies to, then flips exactly the
attributes under test and checks the threat stops applying.
"""

import json
import os
from typing import Any

import pytest

from pytm import TM, Datastore, Lambda, Process, Server, Threat

with open(
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    + "/pytm/threatlib/threats.json",
) as threat_file:
    threats = {t["SID"]: Threat(**t) for t in json.load(threat_file)}


@pytest.fixture(autouse=True)
def reset_tm() -> None:
    TM.reset()


def build(cls: type, settings: dict[str, Any]) -> Any:
    """Create an element; keys prefixed with 'c.' are set on its controls."""
    element = cls("target")
    for key, value in settings.items():
        if key.startswith("c."):
            setattr(element.controls, key[2:], value)
        else:
            setattr(element, key, value)
    return element


def flipped(settings: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Return settings with the given 'c.'-prefixed keys (dots as __) changed."""
    result = dict(settings)
    for key, value in changes.items():
        result[key.replace("__", ".")] = value
    return result


def unsafe_controls(*names: str) -> dict[str, Any]:
    return {f"c.{name}": False for name in names}


def safe_controls(*names: str) -> dict[str, Any]:
    return {f"c.{name}": True for name in names}


# --- OR-of-"is False" conditions -------------------------------------------

# SID -> (target classes that apply, controls that are OR-ed together)
OR_THREATS: dict[str, tuple[tuple[type, ...], tuple[str, ...]]] = {
    "INP24": ((Process, Lambda), ("checksInputBounds", "validatesInput")),
    "INP25": ((Process, Lambda), ("validatesInput", "sanitizesInput")),
    "INP26": ((Process, Lambda), ("validatesInput", "sanitizesInput")),
    "INP27": ((Process,), ("validatesInput", "sanitizesInput")),
    "INP28": (
        (Server, Process),
        ("validatesInput", "sanitizesInput", "encodesOutput"),
    ),
    "INP29": (
        (Server, Process),
        ("validatesInput", "sanitizesInput", "encodesOutput"),
    ),
    "INP30": ((Process,), ("validatesInput", "sanitizesInput")),
    "INP32": (
        (Process,),
        ("validatesInput", "sanitizesInput", "encodesOutput"),
    ),
    "INP33": ((Process,), ("validatesInput", "sanitizesInput")),
    "INP35": ((Process,), ("validatesInput", "sanitizesInput")),
    "INP41": ((Process,), ("validatesInput", "sanitizesInput")),
}

OR_CASES = [(sid, cls) for sid, (classes, _) in OR_THREATS.items() for cls in classes]


@pytest.mark.parametrize("sid,cls", OR_CASES)
def test_or_threat_does_not_apply_when_all_controls_enabled(
    sid: str, cls: type
) -> None:
    names = OR_THREATS[sid][1]
    threat = threats[sid]
    assert threat.apply(build(cls, unsafe_controls(*names)))
    assert not threat.apply(build(cls, safe_controls(*names)))


@pytest.mark.parametrize("sid,cls", OR_CASES)
def test_or_threat_applies_when_any_single_control_missing(sid: str, cls: type) -> None:
    names = OR_THREATS[sid][1]
    threat = threats[sid]
    for missing in names:
        settings = safe_controls(*names)
        settings[f"c.{missing}"] = False
        assert threat.apply(build(cls, settings)), missing


@pytest.mark.parametrize("sid", sorted(OR_THREATS))
def test_or_threat_does_not_apply_to_wrong_target_type(sid: str) -> None:
    names = OR_THREATS[sid][1]
    assert not threats[sid].apply(build(Datastore, unsafe_controls(*names)))


# --- INP21 / INP22: XML parser and DTD --------------------------------------


@pytest.mark.parametrize("sid", ["INP21", "INP22"])
def test_xml_dtd_threat_does_not_apply(sid: str) -> None:
    threat = threats[sid]
    risky = {"usesXMLParser": True, "c.disablesDTD": False}
    assert threat.apply(build(Server, risky))
    # DTD disabled and an XML parser in use: not applicable
    assert not threat.apply(build(Server, flipped(risky, c__disablesDTD=True)))
    # Applies if no XML parser is used (condition is an "or")
    assert threat.apply(build(Server, {"usesXMLParser": False, "c.disablesDTD": True}))
    assert not threat.apply(build(Datastore, risky))


# --- INP23 ------------------------------------------------------------------


def test_INP23_does_not_apply_with_access_control() -> None:
    threat = threats["INP23"]
    risky = {
        "c.hasAccessControl": False,
        "c.sanitizesInput": False,
        "c.validatesInput": False,
    }
    assert threat.apply(build(Process, risky))
    assert not threat.apply(build(Process, flipped(risky, c__hasAccessControl=True)))


def test_INP23_does_not_apply_when_input_is_sanitized_and_validated() -> None:
    threat = threats["INP23"]
    risky = {
        "c.hasAccessControl": False,
        "c.sanitizesInput": False,
        "c.validatesInput": False,
    }
    assert threat.apply(build(Process, risky))
    safe = flipped(risky, c__sanitizesInput=True, c__validatesInput=True)
    assert not threat.apply(build(Process, safe))
    # Either one missing is enough
    assert threat.apply(build(Process, flipped(risky, c__sanitizesInput=True)))
    assert threat.apply(build(Process, flipped(risky, c__validatesInput=True)))
    assert not threat.apply(build(Datastore, risky))


# --- INP31 ------------------------------------------------------------------


def test_INP31_does_not_apply_with_parameterized_input() -> None:
    threat = threats["INP31"]
    risky = unsafe_controls(
        "usesParameterizedInput", "validatesInput", "sanitizesInput"
    )
    assert threat.apply(build(Process, risky))
    assert not threat.apply(
        build(Process, flipped(risky, c__usesParameterizedInput=True))
    )


def test_INP31_does_not_apply_when_input_is_sanitized_and_validated() -> None:
    threat = threats["INP31"]
    risky = unsafe_controls(
        "usesParameterizedInput", "validatesInput", "sanitizesInput"
    )
    assert threat.apply(build(Process, risky))
    safe = flipped(risky, c__validatesInput=True, c__sanitizesInput=True)
    assert not threat.apply(build(Process, safe))
    assert threat.apply(build(Process, flipped(risky, c__validatesInput=True)))
    assert threat.apply(build(Process, flipped(risky, c__sanitizesInput=True)))
    assert not threat.apply(build(Datastore, risky))


# --- INP34 ------------------------------------------------------------------


def test_INP34_does_not_apply_when_input_bounds_checked() -> None:
    threat = threats["INP34"]
    assert threat.apply(build(Server, unsafe_controls("checksInputBounds")))
    assert not threat.apply(build(Server, safe_controls("checksInputBounds")))
    assert not threat.apply(build(Datastore, unsafe_controls("checksInputBounds")))


# --- INP36 / INP37 ----------------------------------------------------------


@pytest.mark.parametrize("sid", ["INP36", "INP37"])
def test_http_validation_threat_does_not_apply(sid: str) -> None:
    threat = threats[sid]
    risky = unsafe_controls("implementsStrictHTTPValidation", "encodesHeaders")
    assert threat.apply(build(Server, risky))
    strict = flipped(risky, c__implementsStrictHTTPValidation=True)
    assert not threat.apply(build(Server, strict))
    encoded = flipped(risky, c__encodesHeaders=True)
    assert not threat.apply(build(Server, encoded))
    assert not threat.apply(build(Datastore, risky))


# --- INP38 / INP39 / INP40: client-side scripting ---------------------------


@pytest.mark.parametrize("sid", ["INP38", "INP39", "INP40"])
def test_client_side_scripting_threat_does_not_apply(sid: str) -> None:
    threat = threats[sid]
    risky = {
        "allowsClientSideScripting": True,
        "c.sanitizesInput": False,
        "c.validatesInput": False,
    }
    assert threat.apply(build(Process, risky))
    # No client-side scripting: not applicable
    assert not threat.apply(
        build(Process, flipped(risky, allowsClientSideScripting=False))
    )
    # Scripting allowed but input is both sanitized and validated
    safe = flipped(risky, c__sanitizesInput=True, c__validatesInput=True)
    assert not threat.apply(build(Process, safe))
    assert threat.apply(build(Process, flipped(risky, c__sanitizesInput=True)))
    assert threat.apply(build(Process, flipped(risky, c__validatesInput=True)))
    assert not threat.apply(build(Datastore, {"c.sanitizesInput": False}))
