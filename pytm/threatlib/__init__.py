"""Threat library — re-exports all Threat subclasses from category modules.

Import threat classes directly from this package without needing to know
which file they live in::

    from pytm.threatlib import INP01, CR01, AA01
"""

import importlib
import inspect
import pkgutil
from collections.abc import Iterator

from pytm.threat import Threat

from .aa import AA01, AA02, AA03, AA04
from .ac import (
    AC01,
    AC02,
    AC03,
    AC04,
    AC05,
    AC06,
    AC07,
    AC08,
    AC09,
    AC10,
    AC11,
    AC12,
    AC13,
    AC14,
    AC15,
    AC16,
    AC17,
    AC18,
    AC19,
    AC20,
    AC21,
    AC22,
    AC23,
    AC24,
)
from .api import API01, API02
from .cr import CR01, CR02, CR03, CR04, CR05, CR06, CR07, CR08
from .de import DE01, DE02, DE03, DE04
from .do import DO01, DO02, DO03, DO04, DO05
from .dr import DR01
from .ds import DS01, DS02, DS03, DS04, DS05, DS06
from .ha import HA01, HA02, HA03, HA04
from .inp import (
    INP01,
    INP02,
    INP03,
    INP04,
    INP05,
    INP06,
    INP07,
    INP08,
    INP09,
    INP10,
    INP11,
    INP12,
    INP13,
    INP14,
    INP15,
    INP16,
    INP17,
    INP18,
    INP19,
    INP20,
    INP21,
    INP22,
    INP23,
    INP24,
    INP25,
    INP26,
    INP27,
    INP28,
    INP29,
    INP30,
    INP31,
    INP32,
    INP33,
    INP34,
    INP35,
    INP36,
    INP37,
    INP38,
    INP39,
    INP40,
    INP41,
)
from .lb import LB01
from .llm import LLM01, LLM02, LLM03, LLM04, LLM05, LLM06, LLM07, LLM08, LLM09
from .sc import SC01, SC02, SC03, SC04, SC05

__all__ = [
    "AA01", "AA02", "AA03", "AA04",
    "AC01", "AC02", "AC03", "AC04", "AC05", "AC06", "AC07", "AC08",
    "AC09", "AC10", "AC11", "AC12", "AC13", "AC14", "AC15", "AC16",
    "AC17", "AC18", "AC19", "AC20", "AC21", "AC22", "AC23", "AC24",
    "API01", "API02",
    "CR01", "CR02", "CR03", "CR04", "CR05", "CR06", "CR07", "CR08",
    "DE01", "DE02", "DE03", "DE04",
    "DO01", "DO02", "DO03", "DO04", "DO05",
    "DR01",
    "DS01", "DS02", "DS03", "DS04", "DS05", "DS06",
    "HA01", "HA02", "HA03", "HA04",
    "INP01", "INP02", "INP03", "INP04", "INP05", "INP06", "INP07", "INP08",
    "INP09", "INP10", "INP11", "INP12", "INP13", "INP14", "INP15", "INP16",
    "INP17", "INP18", "INP19", "INP20", "INP21", "INP22", "INP23", "INP24",
    "INP25", "INP26", "INP27", "INP28", "INP29", "INP30", "INP31", "INP32",
    "INP33", "INP34", "INP35", "INP36", "INP37", "INP38", "INP39", "INP40",
    "INP41",
    "LB01",
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08",
    "LLM09",
    "SC01", "SC02", "SC03", "SC04", "SC05",
    "collect_threat_classes",
    "iter_builtin_threat_classes",
]


def collect_threat_classes(module, include_deprecated=False) -> list[type[Threat]]:
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


def iter_builtin_threat_classes() -> Iterator[type[Threat]]:
    """Yield active Threat subclasses from all modules in this package."""
    for _finder, mod_name, _ispkg in pkgutil.iter_modules(
        __path__, prefix=__name__ + "."
    ):
        module = importlib.import_module(mod_name)
        yield from collect_threat_classes(module)
