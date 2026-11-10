"""Element attributes (formerly "controls") and Control attribute references."""

import json
import warnings

import pytest
from pydantic import ValidationError

from pytm import TM, Attributes, Control, Controls, Server
from pytm.json import loads
from pytm.pytm import to_serializable


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


def make_tm() -> TM:
    return TM("t", description="d", threatsFile="pytm/threatlib/threats.json")


def test_controls_is_alias_of_attributes():
    assert Controls is Attributes


def test_element_has_attributes():
    web = Server("Web")
    web.attributes.sanitizesInput = True
    assert isinstance(web.attributes, Attributes)
    assert web.attributes.sanitizesInput is True


def test_legacy_controls_property_warns_and_shares_state():
    web = Server("Web")
    with pytest.warns(DeprecationWarning):
        web.controls.isHardened = True
    assert web.attributes.isHardened is True
    with pytest.warns(DeprecationWarning):
        web.controls = Attributes(usesMFA=True)
    assert web.attributes.usesMFA is True


def test_legacy_controls_kwarg():
    web = Server("Web", controls=Attributes(isHardened=True))
    assert web.attributes.isHardened is True


def test_legacy_json_key_is_loaded():
    doc = {
        "name": "m",
        "description": "d",
        "elements": [
            {"__class__": "Server", "name": "Web", "controls": {"isHardened": True}}
        ],
    }
    loads(json.dumps(doc))
    (web,) = [e for e in TM._elements if e.name == "Web"]
    assert web.attributes.isHardened is True


def test_serialized_key_is_attributes():
    tm = make_tm()
    Server("Web")
    out = json.loads(json.dumps(tm, default=to_serializable))
    (element,) = [e for e in out["elements"] if e["name"] == "Web"]
    assert "attributes" in element and "controls" not in element


def test_threat_condition_alias_still_evaluates():
    from pytm.threat import Threat

    web = Server("Web")
    for cond in ("target.attributes.isHardened is False",
                 "target.controls.isHardened is False"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            assert Threat(SID="X", target="Server", condition=cond).apply(web)


def test_control_attribute_refs_and_applies_to_default():
    web, db = Server("Web"), Server("Db")
    web.attributes.sanitizesInput = True
    ctl = Control("Filter", attributes=[(web, "sanitizesInput")])
    assert ctl.attributes == [(web, "sanitizesInput")]
    assert ctl.appliesTo == [web]
    assert ctl.satisfied is True
    ctl2 = Control("Both", attributes=(db, "isHardened"), appliesTo=[web, db])
    assert ctl2.appliesTo == [web, db]
    assert ctl2.satisfied is False


def test_control_without_attributes_is_not_satisfied():
    ctl = Control("Policy")
    assert ctl.satisfied is False
    assert ctl.appliesTo == []


def test_control_rejects_unknown_attribute():
    web = Server("Web")
    with pytest.raises(ValidationError):
        Control("Bad", attributes=[(web, "noSuchThing")])


def test_control_attribute_refs_round_trip_through_json():
    tm = make_tm()
    web = Server("Web")
    Control("Filter", attributes=[(web, "sanitizesInput")])
    text = json.dumps(tm, default=to_serializable)
    assert json.loads(text)["controls"][0]["attributes"] == [["Web", "sanitizesInput"]]
    TM.reset()
    loads(text)
    (ctl,) = TM._controls
    assert [(e.name, a) for e, a in ctl.attributes] == [("Web", "sanitizesInput")]


def test_legacy_controls_alias_on_flow_and_boundary():
    from pytm import Boundary, Dataflow

    web = Server("Web")
    flow = Dataflow(web, Server("Db"), "Query")
    boundary = Boundary("Zone")
    for obj in (flow, boundary):
        with pytest.warns(DeprecationWarning):
            obj.controls.isHardened = True
        assert obj.attributes.isHardened is True
    assert Dataflow(web, web, "Self", controls=Attributes(usesVPN=True)).attributes.usesVPN


def test_control_json_with_unknown_element_is_rejected():
    doc = {
        "name": "m",
        "description": "d",
        "controls": [{"name": "C", "attributes": [["Ghost", "isHardened"]]}],
    }
    with pytest.raises(ValueError, match="Ghost"):
        loads(json.dumps(doc))


def test_control_accepts_custom_attribute_names():
    web = Server("Web")
    web.attributes.customFlag = True
    ctl = Control("Custom", attributes=[(web, "customFlag")])
    assert ctl.satisfied is True
