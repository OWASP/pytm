"""Threat library — auto-exports all Threat subclasses from category modules.

Import threat classes directly from this package without needing to know
which file they live in::

    from pytm.threatlib import INP01, CR01, AA01
"""

import inspect
import importlib
import pkgutil

from pytm.threat import Threat

for _finder, _mod_name, _ispkg in pkgutil.iter_modules(__path__, prefix=__name__ + "."):
    _module = importlib.import_module(_mod_name)
    for _cls_name, _cls in inspect.getmembers(_module, inspect.isclass):
        if issubclass(_cls, Threat) and _cls is not Threat and _cls.__module__ == _module.__name__:
            globals()[_cls_name] = _cls
