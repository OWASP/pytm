import json

from .tm import TM
from .base import DataSet
from .boundary import Boundary
from .data import Data
from .dataflow import Dataflow
from .asset import Asset, Server, ExternalEntity, Lambda, LLM
from .datastore import Datastore
from .actor import Actor
from .process import Process, SetOfProcesses
from .enums import Action, Classification, Lifetime

_ELEMENT_CLASSES = {
    "Asset": Asset,
    "Actor": Actor,
    "Server": Server,
    "ExternalEntity": ExternalEntity,
    "Lambda": Lambda,
    "LLM": LLM,
    "Datastore": Datastore,
    "Process": Process,
    "SetOfProcesses": SetOfProcesses,
}


def loads(s):
    """Load a TM object from a JSON string *s*."""
    result = json.loads(s)
    return _decode(result)


def load(fp):
    """Load a TM object from an open file containing JSON."""
    result = json.load(fp)
    return _decode(result)


def _decode(flat):
    boundaries = _decode_boundaries(flat.pop("boundaries", []))
    data = _decode_data(flat.pop("data", []))
    elements = _decode_elements(flat.pop("elements", []), boundaries)
    _decode_flows(flat.pop("flows", []), elements, data)

    if "name" not in flat:
        raise ValueError("name property missing for threat model")
    if "onDuplicates" in flat:
        flat["onDuplicates"] = Action(flat["onDuplicates"])
    return TM(flat.pop("name"), **flat)


def _decode_boundaries(flat):
    boundaries = {}
    refs = {}
    for i, e in enumerate(flat):
        name = e.pop("name", None)
        if name is None:
            raise ValueError(f"name property missing in boundary {i}")
        if "inBoundary" in e:
            refs[name] = e.pop("inBoundary")
        e = Boundary(name, **e)
        boundaries[name] = e

    # do a second pass to resolve self-references
    for b in boundaries.values():
        if b.name not in refs:
            continue
        b.inBoundary = boundaries[refs[b.name]]

    return boundaries


def _decode_data(flat):
    data = {}
    for i, e in enumerate(flat):
        name = e.pop("name", None)
        if name is None:
            raise ValueError(f"name property missing in data {i}")

        classification_name = e.pop("classification", None)
        if classification_name:
            e["classification"] = Classification[classification_name]

        lifetime_name = e.pop("lifetime", None)
        if lifetime_name:
            e["lifetime"] = Lifetime[lifetime_name]

        d = Data(name, **e)
        data[name] = d

    return data


def _decode_elements(flat, boundaries):
    elements = {}
    for i, e in enumerate(flat):
        class_name = e.pop("__class__", "Asset")
        klass = _ELEMENT_CLASSES.get(class_name)
        if klass is None:
            raise ValueError(f"Unknown element class: {class_name}")
        name = e.pop("name", None)
        if name is None:
            raise ValueError(f"name property missing in element {i}")
        if "inBoundary" in e:
            if e["inBoundary"] not in boundaries:
                raise ValueError(
                    f"element {name} references invalid boundary {e['inBoundary']}"
                )
            e["inBoundary"] = boundaries[e["inBoundary"]]
        e = klass(name, **e)
        elements[name] = e

    return elements


def _decode_flows(flat, elements, data):
    for i, e in enumerate(flat):
        name = e.pop("name", None)
        if name is None:
            raise ValueError(f"name property missing in dataflow {i}")
        if "source" not in e:
            raise ValueError(f"dataflow {name} is missing source property")
        if e["source"] not in elements:
            raise ValueError(f"dataflow {name} references invalid source {e['source']}")
        source = elements[e.pop("source")]
        if "sink" not in e:
            raise ValueError(f"dataflow {name} is missing sink property")
        if e["sink"] not in elements:
            raise ValueError(f"dataflow {name} references invalid sink {e['sink']}")
        sink = elements[e.pop("sink")]

        if "data" in e:
            dataset = DataSet()
            for data_name in e["data"]:
                if data_name not in data:
                    raise ValueError(f"dataflow {name} references invalid data {data_name}")
                dataset.add(data[data_name])
            e["data"] = dataset

        Dataflow(source, sink, name, **e)
