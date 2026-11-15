import json
import os

import pytest

from pytm import LLM, TM, Agent, Data, Lambda, Server, Threat
from pytm.asset import DataSet

with open(
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    + "/pytm/threatlib/threats.json",
) as threat_file:
    threats = {t["SID"]: Threat(**t) for t in json.load(threat_file)}


@pytest.fixture(autouse=True)
def reset_tm() -> None:
    TM.reset()
    TM("test tm", description="aaa")


def make_llm(**attrs: bool) -> LLM:
    """Build an LLM with only the given attributes (and controls) overridden."""
    llm = LLM("Model")
    for key, value in attrs.items():
        if key.startswith("controls_"):
            setattr(llm.controls, key.removeprefix("controls_"), value)
        else:
            setattr(llm, key, value)
    return llm


def assert_flip(sid: str, positive: dict, flips: dict) -> None:
    """The positive model applies; flipping each attribute alone stops it."""
    threat = threats[sid]
    assert threat.apply(make_llm(**positive))
    for key, value in flips.items():
        assert not threat.apply(make_llm(**{**positive, key: value})), key


def test_LLM01_does_not_apply():
    assert_flip(
        "LLM01",
        {"processesUntrustedInput": True, "hasContentFiltering": False},
        {"processesUntrustedInput": False, "hasContentFiltering": True},
    )


def test_LLM02_does_not_apply():
    assert_flip(
        "LLM02",
        {"hasRAG": True, "hasContentFiltering": False},
        {"hasRAG": False, "hasContentFiltering": True},
    )


def test_LLM03_does_not_apply():
    assert_flip(
        "LLM03",
        {
            "isThirdParty": True,
            "processesPersonalData": True,
            "controls_providesConfidentiality": False,
        },
        {
            "isThirdParty": False,
            "processesPersonalData": False,
            "controls_providesConfidentiality": True,
        },
    )


def test_LLM04_does_not_apply():
    assert_flip(
        "LLM04",
        {"hasFineTuning": True, "controls_providesIntegrity": False},
        {"hasFineTuning": False, "controls_providesIntegrity": True},
    )


def test_LLM05_does_not_apply():
    assert_flip(
        "LLM05",
        {
            "hasAgentCapabilities": True,
            "hasAccessToSensitiveSystems": True,
            "controls_implementsPOLP": False,
        },
        {
            "hasAgentCapabilities": False,
            "hasAccessToSensitiveSystems": False,
            "controls_implementsPOLP": True,
        },
    )


def test_LLM06_does_not_apply():
    assert_flip(
        "LLM06",
        {"executesCode": True, "controls_isHardened": False},
        {"executesCode": False, "controls_isHardened": True},
    )


def test_LLM07_does_not_apply():
    assert_flip(
        "LLM07",
        {"hasContentFiltering": False, "hasSystemPrompt": True},
        {"hasContentFiltering": True, "hasSystemPrompt": False},
    )


def test_LLM08_does_not_apply():
    assert_flip(
        "LLM08",
        {"processesPersonalData": True, "controls_encodesOutput": False},
        {"processesPersonalData": False, "controls_encodesOutput": True},
    )


def test_LLM09_does_not_apply():
    threat = threats["LLM09"]
    agent = Agent("Tool Agent")
    agent.usesExternalTools = True
    agent.validatesToolLaunchConfig = False
    assert threat.apply(agent)

    agent.usesExternalTools = False
    assert not threat.apply(agent)

    agent.usesExternalTools = True
    agent.validatesToolLaunchConfig = True
    assert not threat.apply(agent)


def test_LLM09_does_not_apply_to_plain_llm():
    llm = make_llm()
    llm.usesExternalTools = True
    llm.validatesToolLaunchConfig = False
    assert not threats["LLM09"].apply(llm)


def test_LLM10_does_not_apply():
    assert_flip(
        "LLM10",
        {
            "isThirdParty": True,
            "processesPersonalData": True,
            "retainsUserData": True,
        },
        {
            "isThirdParty": False,
            "processesPersonalData": False,
            "retainsUserData": False,
        },
    )


def test_llm_threats_do_not_apply_to_other_asset_types():
    """A Server carrying the matching attribute values is still the wrong type."""
    server = Server("Web")
    for name in (
        "processesUntrustedInput",
        "hasRAG",
        "isThirdParty",
        "processesPersonalData",
        "retainsUserData",
        "hasFineTuning",
        "hasAgentCapabilities",
        "hasAccessToSensitiveSystems",
        "executesCode",
        "hasSystemPrompt",
        "usesExternalTools",
    ):
        setattr(server, name, True)
    for name in ("hasContentFiltering", "validatesToolLaunchConfig"):
        setattr(server, name, False)
    for name in (
        "providesConfidentiality",
        "providesIntegrity",
        "implementsPOLP",
        "isHardened",
        "encodesOutput",
    ):
        setattr(server.controls, name, False)
    for sid in [f"LLM{n:02d}" for n in range(1, 11)]:
        assert not threats[sid].apply(server), sid


class TestAssetDataCoercion:
    def test_none_gives_empty_dataset(self):
        fn = Lambda("fn", data=None)
        assert isinstance(fn.data, DataSet)
        assert len(fn.data) == 0

    def test_single_data_is_wrapped(self):
        d = Data("secret")
        fn = Lambda("fn", data=d)
        assert isinstance(fn.data, DataSet)
        assert list(fn.data) == [d]

    def test_iterable_skips_none_items(self):
        a, b = Data("a"), Data("b")
        fn = Lambda("fn", data=[a, None, b])
        assert len(fn.data) == 2
        assert set(fn.data) == {a, b}

    def test_existing_dataset_is_kept(self):
        ds = DataSet()
        ds.add(Data("a"))
        fn = Lambda("fn", data=ds)
        assert fn.data is ds


class TestLambdaDfd:
    def test_levels_filter_excludes_other_levels(self):
        fn = Lambda("fn", levels=1)
        assert fn.dfd(levels={0}) == ""
        assert "fn" in fn.dfd(levels={1})

    def test_colormap_uses_severity_color(self):
        fn = Lambda("fn")
        fn.severity = 5
        assert "firebrick3" in fn.dfd(colormap=True)
        assert "firebrick3" not in fn.dfd()
