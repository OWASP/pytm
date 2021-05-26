__all__ = [
    "Action",
    "Actor",
    "Boundary",
    "Classification",
    "TLSVersion",
    "Data",
    "Dataflow",
    "Datastore",
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

from .json import load, loads
from .pytm import (
    TM,
    Threat,
    Finding,
    Action,
    Enum,
    OrderedEnum,
    Classification,
    Lifetime,
    TLSVersion,
    var,
)

from .pytm.actor import Actor
from .pytm.boundary import Boundary
from .pytm.data import Data
from .pytm.dataflow import Dataflow
from .pytm.datastore import Datastore
from .pytm.element import Element
from .pytm.externalentity import ExternalEntity
from .pytm.serverlessfunc import ServerlessFunc
from .pytm.process import Process
from .pytm.server import Server


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
