"""Threat library — auto-exports all Threat subclasses from category modules.

Import threat classes directly from this package without needing to know
which file they live in::

    from pytm.threatlib import INP01, CR01, AA01
"""

import importlib
import inspect
import pkgutil

from pytm.threat import Threat


def collect_threat_classes(module, include_deprecated=False):
    """Return the Threat subclasses defined directly in *module*.

    The canonical scanner for threat modules — used for the built-in library
    and reusable for external threat modules. Classes with a truthy
    ``DEPRECATED`` attribute are skipped unless *include_deprecated* is set.
    """
    classes = []
    for _name, cls in inspect.getmembers(module, inspect.isclass):
        if (
            issubclass(cls, Threat)
            and cls is not Threat
            and cls.__module__ == module.__name__
            and (include_deprecated or not getattr(cls, "DEPRECATED", None))
        ):
            classes.append(cls)
    return classes


def iter_builtin_threat_classes():
    """Yield active Threat subclasses from all modules in this package."""
    for _finder, mod_name, _ispkg in pkgutil.iter_modules(
        __path__, prefix=__name__ + "."
    ):
        module = importlib.import_module(mod_name)
        yield from collect_threat_classes(module)


# Re-export every threat class (including deprecated ones) at package level.
for _finder, _mod_name, _ispkg in pkgutil.iter_modules(__path__, prefix=__name__ + "."):
    _module = importlib.import_module(_mod_name)
    for _cls in collect_threat_classes(_module, include_deprecated=True):
        globals()[_cls.__name__] = _cls
