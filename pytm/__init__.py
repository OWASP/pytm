__all__ = [
    "Action",
    "Actor",
    "Assumption",
    "Boundary",
    "Classification",
    "TLSVersion",
    "Data",
    "Dataflow",
    "Datastore",
    "DatastoreType",
    "Element",
    "ExternalEntity",
    "Finding",
    "Lambda",
    "Lifetime",
    "load",
    "loads",
    "Process",
    "Server",
    "SetOfProcesses",
    "Threat",
    "TM",
]

import sys
from types import ModuleType
from typing import Any, Dict


from .json import load, loads
from .pytm import (
    TM,
    Action,
    Actor,
    Assumption,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    DatastoreType,
    Element,
    ExternalEntity,
    Finding,
    Lambda,
    Lifetime,
    Process,
    Server,
    SetOfProcesses,
    Threat,
    TLSVersion,
    var,
)


def pdoc_overrides() -> Dict[str, Any]:
    result: Dict[str, Any] = {"pytm": False, "json": False, "template_engine": False}
    mod = sys.modules[__name__]
    for name, klass in mod.__dict__.items():
        if not isinstance(klass, type):
            continue
        for i in dir(klass):
            if i in ("check", "dfd", "seq"):
                result[f"{name}.{i}"] = False
            attr: Any = getattr(klass, i, {})
            if isinstance(attr, var) and attr.doc != "":
                result[f"{name}.{i}"] = attr.doc
    return result


__pdoc__ = pdoc_overrides()
