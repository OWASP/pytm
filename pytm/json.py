import json

from .tm import TM
from .base import DataSet
from .boundary import Boundary
from .data import Data
from .dataflow import Dataflow
from .asset import Agent, Asset, Server, ExternalEntity, Lambda, LLM
from .datastore import Datastore
from .actor import Actor
from .process import Process, SetOfProcesses
from .enums import Action, Classification, Lifetime

_ELEMENT_CLASSES = {
    "Asset": Asset,
    "Agent": Agent,
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


# Attributes that hold state derived from flows during check()/resolve(),
# or that are serialized in a lossy form (names/ids only). They cannot be
# restored directly, so they are dropped and rebuilt when the model is run.
_DERIVED_ATTRS = ("findings", "inputs", "outputs", "overrides")


def _decode(flat):
    boundaries = _decode_boundaries(flat.pop("boundaries", []))
    data = _decode_data(flat.pop("data", []))
    elements = _decode_elements(flat.pop("elements", []), boundaries, data)
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
        ref = e.pop("inBoundary", None)
        if ref is not None:
            refs[name] = ref
        for attr in _DERIVED_ATTRS:
            e.pop(attr, None)
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

        for attr in ("carriedBy", "processedBy"):
            e.pop(attr, None)

        classification_name = e.pop("classification", None)
        if classification_name:
            e["classification"] = Classification(classification_name)

        lifetime_name = e.pop("lifetime", None)
        if lifetime_name:
            e["lifetime"] = Lifetime(lifetime_name)

        d = Data(name, **e)
        data[name] = d

    return data


def _decode_elements(flat, boundaries, data):
    elements = {}
    for i, e in enumerate(flat):
        class_name = e.pop("__class__", "Asset")
        klass = _ELEMENT_CLASSES.get(class_name)
        if klass is None:
            raise ValueError(f"Unknown element class: {class_name}")
        name = e.pop("name", None)
        if name is None:
            raise ValueError(f"name property missing in element {i}")
        boundary_ref = e.pop("inBoundary", None)
        if boundary_ref is not None:
            if boundary_ref not in boundaries:
                raise ValueError(
                    f"element {name} references invalid boundary {boundary_ref}"
                )
            e["inBoundary"] = boundaries[boundary_ref]
        for attr in _DERIVED_ATTRS:
            e.pop(attr, None)
        if "data" in e:
            e["data"] = _resolve_data_refs(e["data"], data, f"element {name}")
        e = klass(name, **e)
        elements[name] = e

    return elements


def _resolve_data_refs(refs, data, context):
    dataset = DataSet()
    for ref in refs:
        if not isinstance(ref, str):
            dataset.add(ref)
            continue
        if ref not in data:
            raise ValueError(f"{context} references invalid data {ref}")
        dataset.add(data[ref])
    return dataset


def _decode_flows(flat, elements, data):
    flows = {}
    response_refs = {}
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

        for attr in _DERIVED_ATTRS:
            e.pop(attr, None)

        # Responses reference other flows by name; link them in a second
        # pass once all flows exist.
        refs = (e.pop("response", None), e.pop("responseTo", None))
        if any(ref is not None for ref in refs):
            response_refs[name] = refs

        if "data" in e:
            e["data"] = _resolve_data_refs(e["data"], data, f"dataflow {name}")

        flows[name] = Dataflow(source, sink, name, **e)

    for name, (response_ref, response_to_ref) in response_refs.items():
        for attr, ref in (("response", response_ref), ("responseTo", response_to_ref)):
            if ref is None:
                continue
            if ref not in flows:
                raise ValueError(f"dataflow {name} references invalid dataflow {ref}")
            setattr(flows[name], attr, flows[ref])
