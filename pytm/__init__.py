__all__ = [
    "Action",
    "Agent",
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
    "var",
]

import sys

from .actor import Actor
from .asset import LLM, Agent, Asset, ExternalEntity, Lambda, Server
from .base import Assumption, Controls
from .boundary import Boundary
from .data import Data
from .dataflow import Dataflow
from .datastore import Datastore
from .element import Element

# Import from new Pydantic models
from .enums import Action, Classification, DatastoreType, Lifetime, TLSVersion
from .finding import Finding
from .json import load, loads
from .process import Process, SetOfProcesses
from .pytm import var
from .threat import Threat
from .tm import TM

# Rebuild models to resolve forward references
Element.model_rebuild()
Data.model_rebuild()
Finding.model_rebuild()
Asset.model_rebuild()
Agent.model_rebuild()
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
            model_fields = getattr(klass, "model_fields", {})
            if i in model_fields:
                description = model_fields[i].description
                if description:
                    result[f"{name}.{i}"] = description
    return result


__pdoc__ = pdoc_overrides()
