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
    "LLM",
    "Lifetime",
    "load",
    "loads",
    "Process",
    "Server",
    "SetOfProcesses",
    "Threat",
    "TM",
    "Controls",
]

import sys

from .json import load, loads
# Import from new Pydantic models
from .enums import Action, Classification, DatastoreType, Lifetime, TLSVersion
from .base import Assumption, Controls
from .element import Element
from .data import Data
from .threat import Threat
from .finding import Finding
from .asset import Asset, Lambda, LLM, Server, ExternalEntity
from .datastore import Datastore
from .actor import Actor
from .process import Process, SetOfProcesses
from .dataflow import Dataflow
from .boundary import Boundary
from .tm import TM

# Rebuild models to resolve forward references
Element.model_rebuild()
Data.model_rebuild()
Finding.model_rebuild()
Asset.model_rebuild()
Lambda.model_rebuild()
LLM.model_rebuild()
Server.model_rebuild()
ExternalEntity.model_rebuild()
Datastore.model_rebuild()
Actor.model_rebuild()
Process.model_rebuild()
SetOfProcesses.model_rebuild()
Dataflow.model_rebuild()
Boundary.model_rebuild()
TM.model_rebuild()


def pdoc_overrides():
    result = {"pytm": False, "json": False, "template_engine": False}
    mod = sys.modules[__name__]
    for name, klass in mod.__dict__.items():
        if not isinstance(klass, type):
            continue
        for i in dir(klass):
            if i in ("check", "dfd", "seq"):
                result[f"{name}.{i}"] = False
            # Since we're using Pydantic now, we don't have var descriptors
            # This function may need to be updated for Pydantic Field documentation
    return result


__pdoc__ = pdoc_overrides()
