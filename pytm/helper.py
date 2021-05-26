from weakref import WeakKeyDictionary
from enum import Enum
from collections.abc import Iterable
from collections import defaultdict
from functools import singledispatch

import logging
import sys
import copy
import html
import argparse

from pytm.element import Element
from pytm.tm import Finding
from pytm.data import Data
from pytm.asset import Asset
from pytm.actor import Actor
from pytm.tm import TM, Threat


class Logger(logging):
    def __init__(self, name):
        super.getLogger(name)


def _get_elements_and_boundaries(flows):
    """filter out elements and boundaries not used in this TM"""
    elements = set()
    boundaries = set()
    for e in flows:
        elements.add(e)
        elements.add(e.source)
        elements.add(e.sink)
        if e.source.inBoundary is not None:
            elements.add(e.source.inBoundary)
            boundaries.add(e.source.inBoundary)
            for b in e.source.inBoundary.parents():
                elements.add(b)
                boundaries.add(b)
        if e.sink.inBoundary is not None:
            elements.add(e.sink.inBoundary)
            boundaries.add(e.sink.inBoundary)
            for b in e.sink.inBoundary.parents():
                elements.add(b)
                boundaries.add(b)
    return (list(elements), list(boundaries))


def _sort_elem(elements):
    orders = {}
    for e in elements:
        try:
            order = e.order
        except AttributeError:
            continue
        if e.source not in orders or orders[e.source] > order:
            orders[e.source] = order
    m = max(orders.values()) + 1
    return sorted(
        elements,
        key=lambda e: (
            orders.get(e, m),
            e.__class__.__name__,
            getattr(e, "order", 0),
            str(e),
        ),
    )


def _describe_classes(classes):
    for name in classes:
        klass = getattr(sys.modules[__name__], name, None)
        if klass is None:
            Logger.error("No such class to describe: %s\n", name)
            sys.exit(1)
        print("{} class attributes:".format(name))
        attrs = []
        for i in dir(klass):
            if i.startswith("_") or callable(getattr(klass, i)):
                continue
            attrs.append(i)
        longest = len(max(attrs, key=len)) + 2
        for i in attrs:
            attr = getattr(klass, i, {})
            docs = []
            if isinstance(attr, var):
                if attr.doc:
                    docs.extend(attr.doc.split("\n"))
                if attr.required:
                    docs.append("required")
                if attr.default or isinstance(attr.default, bool):
                    docs.append("default: {}".format(attr.default))
            lpadding = f'\n{" ":<{longest+2}}'
            print(f"  {i:<{longest}}{lpadding.join(docs)}")
        print()


def _apply_defaults(flows, data):
    inputs = defaultdict(list)
    outputs = defaultdict(list)
    carriers = defaultdict(set)
    processors = defaultdict(set)

    for d in data:
        for e in d.carriedBy:
            try:
                setattr(e, "data", d)
            except ValueError:
                e.data.add(d)

    for e in flows:
        if e.source.data:
            try:
                setattr(e, "data", e.source.data.copy())
            except ValueError:
                e.data.update(e.source.data)

        for d in e.data:
            carriers[d].add(e)
            processors[d].add(e.source)
            processors[d].add(e.sink)

        e._safeset("levels", e.source.levels & e.sink.levels)

        try:
            e.overrides = e.sink.overrides
            e.overrides.extend(
                f
                for f in e.source.overrides
                if f.threat_id not in (f.threat_id for f in e.overrides)
            )
        except ValueError:
            pass

        if e.isResponse:
            e._safeset("protocol", e.source.protocol)
            e._safeset("srcPort", e.source.port)
            e._safeset("isEncrypted", e.source.isEncrypted)
            continue

        e._safeset("protocol", e.sink.protocol)
        e._safeset("dstPort", e.sink.port)
        if hasattr(e.sink, "isEncrypted"):
            e._safeset("isEncrypted", e.sink.isEncrypted)
        e._safeset("authenticatesDestination", e.source.authenticatesDestination)
        e._safeset("checksDestinationRevocation", e.source.checksDestinationRevocation)

        for d in e.data:
            if d.isStored:
                if hasattr(e.sink, "isEncryptedAtRest"):
                    for d in e.data:
                        d._safeset("isDestEncryptedAtRest", e.sink.isEncryptedAtRest)
                if hasattr(e.source, "isEncryptedAtRest"):
                    for d in e.data:
                        d._safeset(
                            "isSourceEncryptedAtRest", e.source.isEncryptedAtRest
                        )
            if d.credentialsLife != Lifetime.NONE and not d.isCredentials:
                d._safeset("isCredentials", True)
            if d.isCredentials and d.credentialsLife == Lifetime.NONE:
                d._safeset("credentialsLife", Lifetime.UNKNOWN)

        outputs[e.source].append(e)
        inputs[e.sink].append(e)

    for e, flows in inputs.items():
        try:
            e.inputs = flows
        except (AttributeError, ValueError):
            pass
    for e, flows in outputs.items():
        try:
            e.outputs = flows
        except (AttributeError, ValueError):
            pass

    for d, flows in carriers.items():
        flows = sorted(flows, key=lambda f: f.name)
        try:
            setattr(d, "carriedBy", list(flows))
        except ValueError:
            for e in flows:
                if e not in d.carriedBy:
                    d.carriedBy.append(e)
    for d, elements in processors.items():
        elements = sorted(elements, key=lambda e: e.name)
        try:
            setattr(d, "processedBy", elements)
        except ValueError:
            for e in elements:
                if e not in d.processedBy:
                    d.processedBy.append(e)


def _sort(flows, addOrder=False):
    ordered = sorted(flows, key=lambda flow: flow.order)
    if not addOrder:
        return ordered
    for i, flow in enumerate(ordered):
        if flow.order != -1:
            break
        ordered[i].order = i + 1
    return ordered


def _match_responses(flows):
    """Ensure that responses are pointing to requests"""
    index = defaultdict(list)
    for e in flows:
        key = (e.source, e.sink)
        index[key].append(e)
    for e in flows:
        if e.responseTo is not None:
            if not e.isResponse:
                e.isResponse = True
            if e.responseTo.response is None:
                e.responseTo.response = e
        if e.response is not None:
            if not e.response.isResponse:
                e.response.isResponse = True
            if e.response.responseTo is None:
                e.response.responseTo = e

    for e in flows:
        if not e.isResponse or e.responseTo is not None:
            continue
        key = (e.sink, e.source)
        if len(index[key]) == 1:
            e.responseTo = index[key][0]
            index[key][0].response = e

    return flows


class var(object):
    """ A descriptor that allows setting a value only once """

    def __init__(self, default, required=False, doc="", onSet=None):
        self.default = default
        self.required = required
        self.doc = doc
        self.data = WeakKeyDictionary()
        self.onSet = onSet

    def __get__(self, instance, owner):
        # when x.d is called we get here
        # instance = x
        # owner = type(x)
        if instance is None:
            return self
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        # called when x.d = val
        # instance = x
        # value = val
        if instance in self.data:
            raise ValueError(
                "cannot overwrite {}.{} value with {}, already set to {}".format(
                    instance, self.__class__.__name__, value, self.data[instance]
                )
            )
        self.data[instance] = value
        if self.onSet is not None:
            self.onSet(instance, value)


class varString(var):
    def __set__(self, instance, value):
        if not isinstance(value, str):
            raise ValueError("expecting a String value, got a {}".format(type(value)))
        super().__set__(instance, value)


class varStrings(var):
    def __set__(self, instance, value):
        if not isinstance(value, Iterable) or isinstance(value, str):
            value = [value]
        for i, e in enumerate(value):
            if not isinstance(e, str):
                raise ValueError(
                    f"expecting a list of str, item number {i} is a {type(e)}"
                )
        super().__set__(instance, set(value))


class varBool(var):
    def __set__(self, instance, value):
        if not isinstance(value, bool):
            raise ValueError("expecting a boolean value, got a {}".format(type(value)))
        super().__set__(instance, value)


class varInt(var):
    def __set__(self, instance, value):
        if not isinstance(value, int):
            raise ValueError("expecting an integer value, got a {}".format(type(value)))
        super().__set__(instance, value)


class varInts(var):
    def __set__(self, instance, value):
        if not isinstance(value, Iterable):
            value = [value]
        for i, e in enumerate(value):
            if not isinstance(e, int):
                raise ValueError(
                    f"expecting a list of int, item number {i} is a {type(e)}"
                )
        super().__set__(instance, set(value))


class varElements(var):
    def __set__(self, instance, value):
        for i, e in enumerate(value):
            if not isinstance(e, Element):
                raise ValueError(
                    "expecting a list of Elements, item number {} is a {}".format(
                        i, type(e)
                    )
                )
        super().__set__(instance, list(value))


class varFindings(var):
    def __set__(self, instance, value):
        for i, e in enumerate(value):
            if not isinstance(e, Finding):
                raise ValueError(
                    "expecting a list of Findings, item number {} is a {}".format(
                        i, type(e)
                    )
                )
        super().__set__(instance, list(value))


class varAction(var):
    def __set__(self, instance, value):
        if not isinstance(value, Action):
            raise ValueError("expecting an Action, got a {}".format(type(value)))
        super().__set__(instance, value)


class varClassification(var):
    def __set__(self, instance, value):
        if not isinstance(value, Classification):
            raise ValueError("expecting a Classification, got a {}".format(type(value)))
        super().__set__(instance, value)


class varLifetime(var):
    def __set__(self, instance, value):
        if not isinstance(value, Lifetime):
            raise ValueError("expecting a Lifetime, got a {}".format(type(value)))
        super().__set__(instance, value)


class varTLSVersion(var):
    def __set__(self, instance, value):
        if not isinstance(value, TLSVersion):
            raise ValueError("expecting a TLSVersion, got a {}".format(type(value)))
        super().__set__(instance, value)


class varData(var):
    def __set__(self, instance, value):
        if isinstance(value, str):
            value = [
                Data(
                    name="undefined",
                    description=value,
                    classification=Classification.UNKNOWN,
                )
            ]
            sys.stderr.write(
                "FIXME: a dataflow is using a string as the Data attribute. This has been deprecated and Data objects should be created instead.\n"
            )

        if not isinstance(value, Iterable):
            value = [value]
        for i, e in enumerate(value):
            if not isinstance(e, Data):
                raise ValueError(
                    "expecting a list of pytm.Data, item number {} is a {}".format(
                        i, type(e)
                    )
                )
        super().__set__(instance, DataSet(value))


class DataSet(set):
    def __contains__(self, item):
        if isinstance(item, str):
            return item in [d.name for d in self]
        if isinstance(item, Data):
            return super().__contains__(item)
        return NotImplemented

    def __eq__(self, other):
        if isinstance(other, set):
            return super().__eq__(other)
        if isinstance(other, str):
            return other in self
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, set):
            return super().__ne__(other)
        if isinstance(other, str):
            return other not in self
        return NotImplemented

    def __str__(self):
        return ", ".join(sorted(set(d.name for d in self)))


class Action(Enum):
    """Action taken when validating a threat model."""

    NO_ACTION = "NO_ACTION"
    RESTRICT = "RESTRICT"
    IGNORE = "IGNORE"


class OrderedEnum(Enum):
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class Classification(OrderedEnum):
    UNKNOWN = 0
    PUBLIC = 1
    RESTRICTED = 2
    SENSITIVE = 3
    SECRET = 4
    TOP_SECRET = 5


class Lifetime(Enum):
    # not applicable
    NONE = "NONE"
    # unknown lifetime
    UNKNOWN = "UNKNOWN"
    # relatively short expiration date (time to live)
    SHORT = "SHORT_LIVED"
    # long or no expiration date
    LONG = "LONG_LIVED"
    # no expiration date but revoked/invalidated automatically in some conditions
    AUTO = "AUTO_REVOKABLE"
    # no expiration date but can be invalidated manually
    MANUAL = "MANUALLY_REVOKABLE"
    # cannot be invalidated at all
    HARDCODED = "HARDCODED"

    def label(self):
        return self.value.lower().replace("_", " ")


class TLSVersion(OrderedEnum):
    NONE = 0
    SSLv1 = 1
    SSLv2 = 2
    SSLv3 = 3
    TLSv10 = 4
    TLSv11 = 5
    TLSv12 = 6
    TLSv13 = 7


@singledispatch
def to_serializable(val):
    """Used by default."""
    return str(val)


@to_serializable.register(TM)
def ts_tm(obj):
    return serialize(obj, nested=True)


@to_serializable.register(Data)
@to_serializable.register(Threat)
@to_serializable.register(Element)
@to_serializable.register(Finding)
def ts_element(obj):
    return serialize(obj, nested=False)


def serialize(obj, nested=False):
    """Used if *obj* is an instance of TM, Element, Threat or Finding."""
    klass = obj.__class__
    result = {}
    if isinstance(obj, (Actor, Asset)):
        result["__class__"] = klass.__name__
    for i in dir(obj):
        if (
            i.startswith("__")
            or callable(getattr(klass, i, {}))
            or (
                isinstance(obj, TM)
                and i in ("_sf", "_duplicate_ignored_attrs", "_threats")
            )
            or (isinstance(obj, Element) and i in ("_is_drawn", "uuid"))
            or (isinstance(obj, Finding) and i == "element")
        ):
            continue
        value = getattr(obj, i)
        if isinstance(obj, TM) and i == "_elements":
            value = [e for e in value if isinstance(e, (Actor, Asset))]
        if value is not None:
            if isinstance(value, (Element, Data)):
                value = value.name
            elif isinstance(obj, Threat) and i == "target":
                value = [v.__name__ for v in value]
            elif i == "levels":
                value = list(value)
            elif (
                not nested
                and not isinstance(value, str)
                and isinstance(value, Iterable)
            ):
                value = [v.id if isinstance(v, Finding) else v.name for v in value]
        result[i.lstrip("_")] = value
    return result


def encode_threat_data(obj):
    """Used to html encode threat data from a list of threats or findings"""
    encoded_threat_data = []

    attrs = [
        "description",
        "details",
        "severity",
        "mitigations",
        "example",
        "id",
        "target",
        "references",
        "condition",
    ]

    for e in obj:
        t = copy.deepcopy(e)

        if isinstance(t, Finding):
            attrs.append("threat_id")

        for a in attrs:
            v = getattr(e, a)

            if isinstance(v, int):
                t._safeset(a, v)
            elif isinstance(v, tuple):
                t._safeset(a, v)
            else:
                t._safeset(a, html.escape(v))

        encoded_threat_data.append(t)

    return encoded_threat_data


def get_args():
    _parser = argparse.ArgumentParser()

    _parser.add_argument(
        "--sqldump",
        help="""dumps all threat model elements and findings
into the named sqlite file (erased if exists)""",
    )
    _parser.add_argument("--debug", action="store_true", help="print debug messages")
    _parser.add_argument("--dfd", action="store_true", help="output DFD")
    _parser.add_argument(
        "--report",
        help="""output report using the named template file
(sample template file is under docs/template.md)""",
    )
    _parser.add_argument("--exclude", help="specify threat IDs to be ignored")
    _parser.add_argument("--seq", action="store_true", help="output sequential diagram")
    _parser.add_argument(
        "--list", action="store_true", help="list all available threats"
    )
    _parser.add_argument(
        "--describe", help="describe the properties available for a given element"
    )
    _parser.add_argument("--json", help="output a JSON file")
    _parser.add_argument(
        "--levels",
        type=int,
        nargs="+",
        help="Select levels to be drawn in the threat model (int separated by comma).",
    )
    _parser.add_argument(
        "--stale_days",
        help="""checks if the delta between the TM script and the code described by it is bigger than the specified value in days""",
        type=int,
    )

    _args = _parser.parse_args()
    return _args
