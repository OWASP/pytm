"""Tests for pydantic-specific model behaviours.

These tests verify that Pydantic validation, coercion, and field logic work
correctly — coverage that generic functional tests do not exercise.
"""

import pytest

from pytm import (
    TM,
    Actor,
    Assumption,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Finding,
    Process,
    Server,
    Threat,
)
from pytm.base import Controls, DataSet


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    TM("test tm", description="test")
    yield
    TM.reset()


# ---------------------------------------------------------------------------
# DataSet
# ---------------------------------------------------------------------------


class TestDataSet:
    def test_contains_data_object(self):
        d = Data("token")
        ds = DataSet([d])
        assert d in ds

    def test_contains_by_name_string(self):
        d = Data("token")
        ds = DataSet([d])
        assert "token" in ds
        assert "other" not in ds

    def test_names_synced_on_add(self):
        ds = DataSet()
        d = Data("token")
        ds.add(d)
        assert "token" in ds._names

    def test_names_synced_on_remove(self):
        d = Data("token")
        ds = DataSet([d])
        ds.remove(d)
        assert "token" not in ds._names
        assert d not in ds

    def test_names_synced_on_discard(self):
        d = Data("token")
        ds = DataSet([d])
        ds.discard(d)
        assert "token" not in ds._names

    def test_discard_missing_element_is_noop(self):
        ds = DataSet()
        d = Data("token")
        ds.discard(d)  # should not raise

    def test_names_synced_on_clear(self):
        ds = DataSet([Data("a"), Data("b")])
        ds.clear()
        assert len(ds._names) == 0
        assert len(ds) == 0

    def test_names_synced_on_pop(self):
        d = Data("token")
        ds = DataSet([d])
        popped = ds.pop()
        assert popped is d
        assert "token" not in ds._names

    def test_update_adds_multiple(self):
        d1, d2 = Data("a"), Data("b")
        ds = DataSet()
        ds.update([d1, d2])
        assert "a" in ds._names
        assert "b" in ds._names
        assert len(ds) == 2

    def test_str_returns_sorted_names(self):
        ds = DataSet([Data("zebra"), Data("apple")])
        assert str(ds) == "apple, zebra"

    def test_eq_with_matching_string(self):
        ds = DataSet([Data("token")])
        assert ds == "token"

    def test_ne_with_non_matching_string(self):
        ds = DataSet([Data("token")])
        assert ds != "other"

    def test_eq_with_regular_set(self):
        d = Data("token")
        ds = DataSet([d])
        assert ds == {d}

    def test_init_with_none_produces_empty_dataset(self):
        ds = DataSet(None)
        assert len(ds) == 0
        assert len(ds._names) == 0


# ---------------------------------------------------------------------------
# Levels field validator
# ---------------------------------------------------------------------------


class TestLevelsValidator:
    def test_default_levels_is_zero_set(self):
        elem = Server("s")
        assert elem.levels == {0}

    def test_none_coerced_to_default(self):
        elem = Server("s", levels=None)
        assert elem.levels == {0}

    def test_single_int_wrapped_in_set(self):
        elem = Server("s", levels=1)
        assert elem.levels == {1}

    def test_list_coerced_to_set(self):
        elem = Server("s", levels=[0, 1, 2])
        assert elem.levels == {0, 1, 2}

    def test_tuple_coerced_to_set(self):
        elem = Server("s", levels=(0, 1))
        assert elem.levels == {0, 1}

    def test_frozenset_coerced_to_set(self):
        elem = Server("s", levels=frozenset([0, 1]))
        assert isinstance(elem.levels, set)
        assert elem.levels == {0, 1}

    def test_set_passed_through(self):
        elem = Server("s", levels={0, 1})
        assert elem.levels == {0, 1}

    def test_levels_validator_runs_on_assignment(self):
        elem = Server("s")
        elem.levels = [1, 2]
        assert elem.levels == {1, 2}


# ---------------------------------------------------------------------------
# Data coercion validators (dataflow, actor, asset)
# ---------------------------------------------------------------------------


class TestDataCoercion:
    def test_dataflow_accepts_single_data_object(self):
        d = Data("payload")
        flow = Dataflow(Actor("u"), Server("s"), "f", data=d)
        assert isinstance(flow.data, DataSet)
        assert d in flow.data

    def test_dataflow_accepts_list_of_data(self):
        d1, d2 = Data("a"), Data("b")
        flow = Dataflow(Actor("u"), Server("s"), "f", data=[d1, d2])
        assert isinstance(flow.data, DataSet)
        assert d1 in flow.data
        assert d2 in flow.data

    def test_dataflow_accepts_dataset_directly(self):
        d = Data("payload")
        ds = DataSet([d])
        flow = Dataflow(Actor("u"), Server("s"), "f", data=ds)
        assert isinstance(flow.data, DataSet)
        assert d in flow.data

    def test_dataflow_legacy_string_creates_unknown_classification(self):
        flow = Dataflow(Actor("u"), Server("s"), "f", data="raw string")
        assert isinstance(flow.data, DataSet)
        items = list(flow.data)
        assert len(items) == 1
        assert items[0].classification == Classification.UNKNOWN

    def test_actor_coerces_single_data_object(self):
        d = Data("token")
        actor = Actor("u", data=d)
        assert isinstance(actor.data, DataSet)
        assert d in actor.data

    def test_actor_coerces_list_of_data(self):
        d1, d2 = Data("a"), Data("b")
        actor = Actor("u", data=[d1, d2])
        assert isinstance(actor.data, DataSet)
        assert len(actor.data) == 2

    def test_asset_coerces_single_data_object(self):
        d = Data("record")
        server = Server("s", data=d)
        assert isinstance(server.data, DataSet)
        assert d in server.data

    def test_asset_none_produces_empty_dataset(self):
        server = Server("s", data=None)
        assert isinstance(server.data, DataSet)
        assert len(server.data) == 0


# ---------------------------------------------------------------------------
# Threat model_validator (legacy field mapping)
# ---------------------------------------------------------------------------


class TestThreatModelValidator:
    def test_sid_maps_to_id(self):
        t = Threat(SID="INP01", target="Server", severity="High")
        assert t.id == "INP01"

    def test_explicit_id_not_overwritten_by_sid(self):
        t = Threat(SID="INP01", id="CUSTOM", target="Server")
        assert t.id == "CUSTOM"

    def test_likelihood_of_attack_maps_to_likelihood(self):
        t = Threat(SID="T1", target="Server", **{"Likelihood Of Attack": "Medium"})
        assert t.likelihood == "Medium"

    def test_explicit_likelihood_not_overwritten(self):
        t = Threat(
            SID="T1",
            target="Server",
            likelihood="High",
            **{"Likelihood Of Attack": "Low"},
        )
        assert t.likelihood == "High"

    def test_target_string_resolved_to_class(self):
        t = Threat(SID="T1", target="Server")
        assert Server in t.target

    def test_target_list_resolved_to_classes(self):
        t = Threat(SID="T1", target=["Server", "Datastore"])
        assert Server in t.target
        assert Datastore in t.target

    def test_unknown_target_kept_as_string(self):
        t = Threat(SID="T1", target="UnknownClass")
        assert "UnknownClass" in t.target

    def test_target_already_class_preserved(self):
        t = Threat(SID="T1", target=[Server])
        assert Server in t.target


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


class TestControls:
    def test_safeset_suppresses_type_errors(self):
        c = Controls()
        c._safeset("isEncrypted", object())  # should not raise


# ---------------------------------------------------------------------------
# Assumption
# ---------------------------------------------------------------------------


class TestAssumption:
    def test_positional_name(self):
        a = Assumption("my assumption")
        assert a.name == "my assumption"

    def test_str_returns_name(self):
        a = Assumption("my assumption")
        assert str(a) == "my assumption"
