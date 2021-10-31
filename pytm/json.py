import json
import sys

from .pytm import (
    TM,
    Boundary,
    Element,
    Dataflow,
    Server,
    ExternalEntity,
    Datastore,
    Actor,
    Process,
    SetOfProcesses,
    Action,
    Lambda,
    Controls,
)


def loads(s):
    """Load a TM object from a JSON string *s*."""
    result = json.loads(s, object_hook=decode)
    if not isinstance(result, TM):
        raise ValueError("Failed to decode JSON input as TM")
    return result


def load(fp):
    """Load a TM object from an open file containing JSON."""
    result = json.load(fp, object_hook=decode)
    if not isinstance(result, TM):
        raise ValueError("Failed to decode JSON input as TM")
    return result


def decode(data):
    if "elements" not in data and "flows" not in data and "boundaries" not in data:
        return data

    boundaries = decode_boundaries(data.pop("boundaries", []))
    elements = decode_elements(data.pop("elements", []), boundaries)
    decode_flows(data.pop("flows", []), elements)

    if "name" not in data:
        raise ValueError("name property missing for threat model")
    if "onDuplicates" in data:
        data["onDuplicates"] = Action(data["onDuplicates"])
    return TM(data.pop("name"), **data)


def decode_boundaries(flat):
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


def decode_elements(flat, boundaries):
    elements = {}
    for i, e in enumerate(flat):
        klass = getattr(sys.modules[__name__], e.pop("__class__", "Asset"))
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


def decode_flows(flat, elements):
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
        Dataflow(source, sink, name, **e)
