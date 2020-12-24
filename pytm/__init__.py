__all__ = [
    "Element",
    "Server",
    "ExternalEntity",
    "Datastore",
    "Actor",
    "Process",
    "SetOfProcesses",
    "Dataflow",
    "Boundary",
    "TM",
    "Action",
    "Lambda",
    "Lifetime",
    "Threat",
    "Classification",
    "Data",
    "load",
    "loads",
]

import sys

from .json import load, loads
from .pytm import (
    TM,
    Action,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Element,
    ExternalEntity,
    Lambda,
    Lifetime,
    Process,
    Server,
    SetOfProcesses,
    Threat,
    var,
)


def pdoc_overrides():
    result = {"pytm": False, "json": False, "template_engine": False}
    mod = sys.modules[__name__]
    for name, klass in mod.__dict__.items():
        if not isinstance(klass, type):
            continue
        for i in dir(klass):
            if i in ("check", "dfd", "seq"):
                result[f"{name}.{i}"] = False
            attr = getattr(klass, i, {})
            if isinstance(attr, var) and attr.doc != "":
                result[f"{name}.{i}"] = attr.doc
    return result


__pdoc__ = pdoc_overrides()
