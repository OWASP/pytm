import argparse
import errno
import inspect
import json
import logging
import os
import random
import sys
import uuid
import html
import copy

from collections import Counter, defaultdict
from collections.abc import Iterable
from enum import Enum
from functools import lru_cache, singledispatch
from hashlib import sha224
from itertools import combinations
from shutil import rmtree
from textwrap import indent, wrap
from weakref import WeakKeyDictionary
from datetime import datetime

from pydal import DAL, Field

from .template_engine import SuperFormatter

""" Helper functions """

""" The base for this (descriptors instead of properties) has been
    shamelessly lifted from
    https://nbviewer.jupyter.org/urls/gist.github.com/ChrisBeaumont/5758381/raw/descriptor_writeup.ipynb
    By Chris Beaumont
"""


logger = logging.getLogger(__name__)


class var(object):
    """A descriptor that allows setting a value only once"""

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


class varBoundary(var):
    def __set__(self, instance, value):
        if not isinstance(value, Boundary):
            raise ValueError("expecting a Boundary value, got a {}".format(type(value)))
        super().__set__(instance, value)


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


class varElement(var):
    def __set__(self, instance, value):
        if not isinstance(value, Element):
            raise ValueError(
                "expecting an Element (or inherited) "
                "value, got a {}".format(type(value))
            )
        super().__set__(instance, value)


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


class varDatastoreType(var):
    def __set__(self, instance, value):
        if not isinstance(value, DatastoreType):
            raise ValueError("expecting a DatastoreType, got a {}".format(type(value)))
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

class varControls(var):
    def __set__(self, instance, value):
        if not isinstance(value, Controls):
            raise ValueError(
                "expecting an Controls "
                "value, got a {}".format(type(value))
            )
        super().__set__(instance, value)

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


class DatastoreType(Enum):
    UNKNOWN = "UNKNOWN"
    FILE_SYSTEM = "FILE_SYSTEM"
    SQL = "SQL"
    LDAP = "LDAP"
    AWS_S3 = "AWS_S3"

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


def _sort(flows, addOrder=False):
    ordered = sorted(flows, key=lambda flow: flow.order)
    if not addOrder:
        return ordered
    for i, flow in enumerate(ordered):
        if flow.order != -1:
            break
        ordered[i].order = i + 1
    return ordered


def _sort_elem(elements):
    if len(elements) == 0:
        return elements
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
            e.controls._safeset("isEncrypted", e.source.controls.isEncrypted)
            continue

        e._safeset("protocol", e.sink.protocol)
        e._safeset("dstPort", e.sink.port)
        if hasattr(e.sink.controls, "isEncrypted"):
            e.controls._safeset("isEncrypted", e.sink.controls.isEncrypted)
        e.controls._safeset("authenticatesDestination", e.source.controls.authenticatesDestination)
        e.controls._safeset("checksDestinationRevocation", e.source.controls.checksDestinationRevocation)

        for d in e.data:
            if d.isStored:
                if hasattr(e.sink.controls, "isEncryptedAtRest"):
                    for d in e.data:
                        d._safeset("isDestEncryptedAtRest", e.sink.controls.isEncryptedAtRest)
                if hasattr(e.source, "isEncryptedAtRest"):
                    for d in e.data:
                        d._safeset(
                            "isSourceEncryptedAtRest", e.source.controls.isEncryptedAtRest
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


def _describe_classes(classes):
    for name in classes:
        klass = getattr(sys.modules[__name__], name, None)
        if klass is None:
            logger.error("No such class to describe: %s\n", name)
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


def _list_elements():
    """List all elements which can be used in a threat model with the corisponding description"""
    def all_subclasses(cls):
        """Get all sub classes of a class"""
        subclasses = set(cls.__subclasses__())
        return subclasses.union(
            (s for c in subclasses for s in all_subclasses(c)))

    def print_components(cls_list):
        elements = sorted(cls_list, key=lambda c: c.__name__)
        max_len = max((len(e.__name__) for e in elements))
        for sc in elements:
            doc = sc.__doc__ if sc.__doc__ is not None else ''
            print(f'{sc.__name__:<{max_len}} -- {doc}')
    #print all elements
    print('Elements:')
    print_components(all_subclasses(Element))

    # Print Attributes
    print('\nAtributes:')
    print_components(
            all_subclasses(OrderedEnum) | {Data, Action, Lifetime}
            )



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


""" End of help functions """


class Threat:
    """Represents a possible threat"""

    id = varString("", required=True)
    description = varString("")
    condition = varString(
        "",
        doc="""a Python expression that should evaluate
to a boolean True or False""",
    )
    details = varString("")
    severity = varString("")
    mitigations = varString("")
    example = varString("")
    references = varString("")
    target = ()

    def __init__(self, **kwargs):
        self.id = kwargs["SID"]
        self.description = kwargs.get("description", "")
        self.condition = kwargs.get("condition", "True")
        target = kwargs.get("target", "Element")
        if not isinstance(target, str) and isinstance(target, Iterable):
            target = tuple(target)
        else:
            target = (target,)
        self.target = tuple(getattr(sys.modules[__name__], x) for x in target)
        self.details = kwargs.get("details", "")
        self.severity = kwargs.get("severity", "")
        self.mitigations = kwargs.get("mitigations", "")
        self.example = kwargs.get("example", "")
        self.references = kwargs.get("references", "")

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.id, hex(id(self))
        )

    def __str__(self):
        return "{0}({1})".format(type(self).__name__, self.id)

    def apply(self, target):
        if not isinstance(target, self.target):
            return None
        return eval(self.condition)


class Finding:
    """Represents a Finding - the element in question
    and a description of the finding"""

    element = varElement(None, required=True, doc="Element this finding applies to")
    target = varString("", doc="Name of the element this finding applies to")
    description = varString("", required=True, doc="Threat description")
    details = varString("", required=True, doc="Threat details")
    severity = varString("", required=True, doc="Threat severity")
    mitigations = varString("", required=True, doc="Threat mitigations")
    example = varString("", required=True, doc="Threat example")
    id = varString("", required=True, doc="Finding ID")
    threat_id = varString("", required=True, doc="Threat ID")
    references = varString("", required=True, doc="Threat references")
    condition = varString("", required=True, doc="Threat condition")
    response = varString(
        "",
        required=False,
        doc="""Describes how this threat matching this particular asset or dataflow is being handled.
Can be one of:
* mitigated - there were changes made in the modeled system to reduce the probability of this threat ocurring or the impact when it does,
* transferred - users of the system are required to mitigate this threat,
* avoided - this asset or dataflow is removed from the system,
* accepted - no action is taken as the probability and/or impact is very low
""",
    )
    cvss = varString("", required=False, doc="The CVSS score and/or vector")

    def __init__(
        self,
        *args,
        **kwargs,
    ):
        if args:
            element = args[0]
        else:
            element = kwargs.pop("element", Element("invalid"))

        self.target = element.name
        self.element = element
        attrs = [
            "description",
            "details",
            "severity",
            "mitigations",
            "example",
            "references",
            "condition",
        ]
        threat = kwargs.pop("threat", None)
        if threat:
            kwargs["threat_id"] = getattr(threat, "id")
            for a in attrs:
                # copy threat attrs into kwargs to allow to override them in next step
                kwargs[a] = getattr(threat, a)

        threat_id = kwargs.get("threat_id", None)
        for f in element.overrides:
            if f.threat_id != threat_id:
                continue
            for i in dir(f.__class__):
                attr = getattr(f.__class__, i)
                if (
                    i in ("element", "target")
                    or i.startswith("_")
                    or callable(attr)
                    or not isinstance(attr, var)
                ):
                    continue
                if f in attr.data:
                    kwargs[i] = attr.data[f]
            break

        for k, v in kwargs.items():
            setattr(self, k, v)

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.id, hex(id(self))
        )

    def __str__(self):
        return f"'{self.target}': {self.description}\n{self.details}\n{self.severity}"


class TM:
    """Describes the threat model administratively,
    and holds all details during a run"""

    _flows = []
    _elements = []
    _actors = []
    _assets = []
    _threats = []
    _boundaries = []
    _data = []
    _threatsExcluded = []
    _sf = None
    _duplicate_ignored_attrs = "name", "note", "order", "response", "responseTo", "controls"
    name = varString("", required=True, doc="Model name")
    description = varString("", required=True, doc="Model description")
    threatsFile = varString(
        os.path.dirname(__file__) + "/threatlib/threats.json",
        onSet=lambda i, v: i._init_threats(),
        doc="JSON file with custom threats",
    )
    isOrdered = varBool(False, doc="Automatically order all Dataflows")
    mergeResponses = varBool(False, doc="Merge response edges in DFDs")
    ignoreUnused = varBool(False, doc="Ignore elements not used in any Dataflow")
    findings = varFindings([], doc="threats found for elements of this model")
    onDuplicates = varAction(
        Action.NO_ACTION,
        doc="""How to handle duplicate Dataflow
with same properties, except name and notes""",
    )
    assumptions = varStrings(
        [],
        required=False,
        doc="A list of assumptions about the design/model.",
    )

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        self._sf = SuperFormatter()
        self._add_threats()
        # make sure generated diagrams do not change, makes sense if they're commited
        random.seed(0)

    @classmethod
    def reset(cls):
        cls._flows = []
        cls._elements = []
        cls._actors = []
        cls._assets = []
        cls._threats = []
        cls._boundaries = []
        cls._data = []
        cls._threatsExcluded = []

    def _init_threats(self):
        TM._threats = []
        self._add_threats()

    def _add_threats(self):
        with open(self.threatsFile, "r", encoding="utf8") as threat_file:
            threats_json = json.load(threat_file)

        for i in threats_json:
            TM._threats.append(Threat(**i))

    def resolve(self):
        finding_count = 0
        findings = []
        elements = defaultdict(list)
        for e in TM._elements:
            if not e.inScope:
                continue

            override_ids = set(f.threat_id for f in e.overrides)
            # if element is a dataflow filter out overrides from source and sink
            # because they will be always applied there anyway
            try:
                override_ids -= set(
                    f.threat_id for f in e.source.overrides + e.sink.overrides
                )
            except AttributeError:
                pass

            for t in TM._threats:
                if not t.apply(e) and t.id not in override_ids:
                    continue

                if t.id in TM._threatsExcluded:
                    continue

                finding_count += 1
                f = Finding(e, id=str(finding_count), threat=t)
                logger.debug(f"new finding: {f}")
                findings.append(f)
                elements[e].append(f)
        self.findings = findings
        for e, findings in elements.items():
            e.findings = findings

    def check(self):
        if self.description is None:
            raise ValueError(
                """Every threat model should have at least
a brief description of the system being modeled."""
            )

        TM._flows = _match_responses(_sort(TM._flows, self.isOrdered))

        self._check_duplicates(TM._flows)

        _apply_defaults(TM._flows, TM._data)

        for e in TM._elements:
            top = Counter(f.threat_id for f in e.overrides).most_common(1)
            if not top:
                continue
            threat_id, count = top[0]
            if count != 1:
                raise ValueError(
                    f"Finding {threat_id} have more than one override in {e}"
                )

        if self.ignoreUnused:
            TM._elements, TM._boundaries = _get_elements_and_boundaries(TM._flows)

        result = True
        for e in TM._elements:
            if not e.check():
                result = False

        if self.ignoreUnused:
            # cannot rely on user defined order if assets are re-used in multiple models
            TM._elements = _sort_elem(TM._elements)

        return result

    def _check_duplicates(self, flows):
        if self.onDuplicates == Action.NO_ACTION:
            return

        index = defaultdict(list)
        for e in flows:
            key = (e.source, e.sink)
            index[key].append(e)

        for flows in index.values():
            for left, right in combinations(flows, 2):
                left_attrs = left._attr_values()
                right_attrs = right._attr_values()
                for a in self._duplicate_ignored_attrs:
                    del left_attrs[a], right_attrs[a]
                if left_attrs != right_attrs:
                    continue
                if self.onDuplicates == Action.IGNORE:
                    right._is_drawn = True
                    continue

                left_controls_attrs = left.controls._attr_values()
                right_controls_attrs = right.controls._attr_values()
                #for a in self._duplicate_ignored_attrs:
                #    del left_controls_attrs[a], right_controls_attrs[a]
                if left_controls_attrs != right_controls_attrs:
                    continue
                if self.onDuplicates == Action.IGNORE:
                    right._is_drawn = True
                    continue


                raise ValueError(
                    "Duplicate Dataflow found between {} and {}: "
                    "{} is same as {}".format(
                        left.source,
                        left.sink,
                        left,
                        right,
                    )
                )

    def _dfd_template(self):
        return """digraph tm {{
    graph [
        fontname = Arial;
        fontsize = 14;
    ]
    node [
        fontname = Arial;
        fontsize = 14;
        rankdir = lr;
    ]
    edge [
        shape = none;
        arrowtail = onormal;
        fontname = Arial;
        fontsize = 12;
    ]
    labelloc = "t";
    fontsize = 20;
    nodesep = 1;

{edges}
}}"""

    def dfd(self, **kwargs):
        if "levels" in kwargs:
            levels = kwargs["levels"]
            if not isinstance(kwargs["levels"], Iterable):
                kwargs["levels"] = [levels]
            kwargs["levels"] = set(levels)

        edges = []
        # since boundaries can be nested sort them by level and start from top
        parents = set(b.inBoundary for b in TM._boundaries if b.inBoundary)

        # TODO boundaries should not be drawn if they don't contain elements matching requested levels
        # or contain only empty boundaries
        boundary_levels = defaultdict(set)
        max_level = 0
        for b in TM._boundaries:
            if b in parents:
                continue
            boundary_levels[0].add(b)
            for i, p in enumerate(b.parents()):
                i = i + 1
                boundary_levels[i].add(p)
                if i > max_level:
                    max_level = i

        for i in range(max_level, -1, -1):
            for b in sorted(boundary_levels[i], key=lambda b: b.name):
                edges.append(b.dfd(**kwargs))

        if self.mergeResponses:
            for e in TM._flows:
                if e.response is not None:
                    e.response._is_drawn = True
        kwargs["mergeResponses"] = self.mergeResponses
        for e in TM._elements:
            if not e._is_drawn and not isinstance(e, Boundary) and e.inBoundary is None:
                edges.append(e.dfd(**kwargs))

        return self._dfd_template().format(
            edges=indent("\n".join(filter(len, edges)), "    ")
        )

    def _seq_template(self):
        return """@startuml
{participants}

{messages}
@enduml"""

    def seq(self):
        participants = []
        for e in TM._elements:
            if isinstance(e, Actor):
                participants.append(
                    'actor {0} as "{1}"'.format(e._uniq_name(), e.display_name())
                )
            elif isinstance(e, Datastore):
                participants.append(
                    'database {0} as "{1}"'.format(e._uniq_name(), e.display_name())
                )
            elif not isinstance(e, Dataflow) and not isinstance(e, Boundary):
                participants.append(
                    'entity {0} as "{1}"'.format(e._uniq_name(), e.display_name())
                )

        messages = []
        for e in TM._flows:
            message = "{0} -> {1}: {2}".format(
                e.source._uniq_name(), e.sink._uniq_name(), e.display_name()
            )
            note = ""
            if e.note != "":
                note = "\nnote left\n{}\nend note".format(e.note)
            messages.append("{}{}".format(message, note))

        return self._seq_template().format(
            participants="\n".join(participants), messages="\n".join(messages)
        )

    def report(self, template_path):
        with open(template_path) as file:
            template = file.read()

        threats = encode_threat_data(TM._threats)
        findings = encode_threat_data(self.findings)

        elements = encode_element_threat_data(TM._elements)
        assets = encode_element_threat_data(TM._assets)
        actors = encode_element_threat_data(TM._actors)
        boundaries = encode_element_threat_data(TM._boundaries)
        flows = encode_element_threat_data(TM._flows)

        data = {
            "tm": self,
            "dataflows": flows,
            "threats": threats,
            "findings": findings,
            "elements": elements,
            "assets": assets,
            "actors": actors,
            "boundaries": boundaries,
            "data": TM._data,
        }

        return self._sf.format(template, **data)

    def process(self):
        self.check()
        result = get_args()
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

        if result.debug:
            logger.setLevel(logging.DEBUG)

        if result.exclude is not None:
            TM._threatsExcluded = result.exclude.split(",")

        if result.seq is True:
            print(self.seq())

        if result.dfd is True:
            print(self.dfd(levels=(result.levels or set())))

        if (
            result.report is not None
            or result.json is not None
            or result.sqldump is not None
            or result.stale_days is not None
        ):
            self.resolve()

        if result.sqldump is not None:
            self.sqlDump(result.sqldump)

        if result.json:
            with open(result.json, "w", encoding="utf8") as f:
                json.dump(self, f, default=to_serializable)

        if result.report is not None:
            print(self.report(result.report))

        if result.describe is not None:
            _describe_classes(result.describe.split())

        if result.list_elements:
            _list_elements()

        if result.list is True:
            [print("{} - {}".format(t.id, t.description)) for t in TM._threats]

        if result.stale_days is not None:
            print(self._stale(result.stale_days))

    def _stale(self, days):
        try:
            base_path = os.path.dirname(sys.argv[0])
            tm_mtime = datetime.fromtimestamp(
                os.stat(base_path + f"/{sys.argv[0]}").st_mtime
            )
        except os.error as err:
            sys.stderr.write(f"{sys.argv[0]} - {err}\n")
            sys.stderr.flush()
            return "[ERROR]"

        print(f"Checking for code {days} days older than this model.")

        for e in TM._elements:

            for src in e.sourceFiles:
                try:
                    src_mtime = datetime.fromtimestamp(
                        os.stat(base_path + f"/{src}").st_mtime
                    )
                except os.error as err:
                    sys.stderr.write(f"{sys.argv[0]} - {err}\n")
                    sys.stderr.flush()
                    continue

                age = (src_mtime - tm_mtime).days

                # source code is older than model by more than the speficied delta
                if (age) >= days:
                    print(f"This model is {age} days older than {base_path}/{src}.")
                elif age <= -days:
                    print(
                        f"Model script {sys.argv[0]}"
                        + " is only "
                        + str(-1 * age)
                        + " days newer than source code file "
                        + f"{base_path}/{src}"
                    )

        return ""

    def sqlDump(self, filename):
        try:
            rmtree("./sqldump")
            os.mkdir("./sqldump")
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            else:
                os.mkdir("./sqldump")

        db = DAL("sqlite://" + filename, folder="sqldump")

        for klass in (
            Server,
            ExternalEntity,
            Dataflow,
            Datastore,
            Actor,
            Process,
            SetOfProcesses,
            Boundary,
            TM,
            Threat,
            Lambda,
            Data,
            Finding,
        ):
            self.get_table(db, klass)

        for e in TM._threats + TM._data + TM._elements + self.findings + [self]:
            table = self.get_table(db, e.__class__)
            row = {}
            for k, v in serialize(e).items():
                if k == "id":
                    k = "SID"
                row[k] = ", ".join(str(i) for i in v) if isinstance(v, list) else v
            db[table].bulk_insert([row])

        db.close()

    @lru_cache(maxsize=None)
    def get_table(self, db, klass):
        name = klass.__name__
        fields = [
            Field("SID" if i == "id" else i)
            for i in dir(klass)
            if not i.startswith("_") and not callable(getattr(klass, i))
        ]
        return db.define_table(name, fields)

class Controls:
    """Controls implemented by/on and Element"""

    authenticatesDestination = varBool(
        False,
        doc="""Verifies the identity of the destination,
for example by verifying the authenticity of a digital certificate.""",
    )
    authenticatesSource = varBool(False)
    authenticationScheme = varString("")
    authorizesSource = varBool(False)
    checksDestinationRevocation = varBool(
        False,
        doc="""Correctly checks the revocation status
of credentials used to authenticate the destination""",
    )
    checksInputBounds = varBool(False)
    definesConnectionTimeout = varBool(False)
    disablesDTD = varBool(False)
    disablesiFrames = varBool(False)
    encodesHeaders = varBool(False)
    encodesOutput = varBool(False)
    encryptsCookies = varBool(False)
    encryptsSessionData = varBool(False)
    handlesCrashes = varBool(False)
    handlesInterruptions = varBool(False)
    handlesResourceConsumption = varBool(False)
    hasAccessControl = varBool(False)
    implementsAuthenticationScheme = varBool(False)
    implementsCSRFToken = varBool(False)
    implementsNonce = varBool(
        False,
        doc="""Nonce is an arbitrary number
that can be used just once in a cryptographic communication.
It is often a random or pseudo-random number issued in an authentication protocol
to ensure that old communications cannot be reused in replay attacks.
They can also be useful as initialization vectors and in cryptographic
hash functions.""",
    )
    implementsPOLP = varBool(
        False,
        doc="""The principle of least privilege (PoLP),
also known as the principle of minimal privilege or the principle of least authority,
requires that in a particular abstraction layer of a computing environment,
every module (such as a process, a user, or a program, depending on the subject)
must be able to access only the information and resources
that are necessary for its legitimate purpose.""",
    )
    implementsServerSideValidation = varBool(False)
    implementsStrictHTTPValidation = varBool(False)
    invokesScriptFilters = varBool(False)
    isEncrypted = varBool(False, doc="Requires incoming data flow to be encrypted")
    isEncryptedAtRest = varBool(False, doc="Stored data is encrypted at rest")
    isHardened = varBool(False)
    isResilient = varBool(False)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    sanitizesInput = varBool(False)
    tracksExecutionFlow = varBool(False)
    usesCodeSigning = varBool(False)
    usesEncryptionAlgorithm = varString("")
    usesMFA = varBool(
        False,
        doc="""Multi-factor authentication is an authentication method
in which a computer user is granted access only after successfully presenting two
or more pieces of evidence (or factors) to an authentication mechanism: knowledge
(something the user and only the user knows), possession (something the user
and only the user has), and inherence (something the user and only the user is).""",
    )
    usesParameterizedInput = varBool(False)
    usesSecureFunctions = varBool(False)
    usesStrongSessionIdentifiers = varBool(False)
    usesVPN = varBool(False)
    validatesContentType = varBool(False)
    validatesHeaders = varBool(False)
    validatesInput = varBool(False)
    verifySessionIdentifiers = varBool(False)

    def _attr_values(self):
        klass = self.__class__
        result = {}
        for i in dir(klass):
            if i.startswith("_") or callable(getattr(klass, i)):
                continue
            attr = getattr(klass, i, {})
            if isinstance(attr, var):
                value = attr.data.get(self, attr.default)
            else:
                value = getattr(self, i)
            result[i] = value
        return result


    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass



class Element:
    """A generic element"""

    name = varString("", required=True)
    description = varString("")
    inBoundary = varBoundary(None, doc="Trust boundary this element exists in")
    inScope = varBool(True, doc="Is the element in scope of the threat model")
    maxClassification = varClassification(
        Classification.UNKNOWN,
        required=False,
        doc="Maximum data classification this element can handle.",
    )
    minTLSVersion = varTLSVersion(
        TLSVersion.NONE,
        required=False,
        doc="""Minimum TLS version required.""",
    )
    findings = varFindings([], doc="Threats that apply to this element")
    overrides = varFindings(
        [],
        doc="""Overrides to findings, allowing to set
a custom response, CVSS score or override other attributes.""",
    )
    levels = varInts({0}, doc="List of levels (0, 1, 2, ...) to be drawn in the model.")
    sourceFiles = varStrings(
        [],
        required=False,
        doc="Location of the source code that describes this element relative to the directory of the model script.",
    )
    controls = varControls(None)

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        self.controls = Controls()
        self.uuid = uuid.UUID(int=random.getrandbits(128))
        self._is_drawn = False
        TM._elements.append(self)

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.name, hex(id(self))
        )

    def __str__(self):
        return "{0}({1})".format(type(self).__name__, self.name)

    def _uniq_name(self):
        """transform name and uuid into a unique string"""
        h = sha224(str(self.uuid).encode("utf-8")).hexdigest()
        name = "".join(x for x in self.name if x.isalpha())
        return "{0}_{1}_{2}".format(type(self).__name__.lower(), name, h[:10])

    def check(self):
        return True

    def _dfd_template(self):
        return """{uniq_name} [
    shape = {shape};
    color = {color};
    fontcolor = {color};
    label = "{label}";
    margin = 0.02;
]
"""

    def dfd(self, **kwargs):
        self._is_drawn = True

        levels = kwargs.get("levels", None)
        if levels and not levels & self.levels:
            return ""

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            shape=self._shape(),
        )

    def _color(self):
        if self.inScope is True:
            return "black"
        else:
            return "grey69"

    def display_name(self):
        return self.name

    def _label(self):
        return "\\n".join(wrap(self.display_name(), 18))

    def _shape(self):
        return "square"

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass

    def oneOf(self, *elements):
        """Is self one of a list of Elements"""
        for element in elements:
            if inspect.isclass(element):
                if isinstance(self, element):
                    return True
            elif self is element:
                return True
        return False

    def crosses(self, *boundaries):
        """Does self (dataflow) cross any of the list of boundaries"""
        if self.source.inBoundary is self.sink.inBoundary:
            return False
        for boundary in boundaries:
            if inspect.isclass(boundary):
                if (
                    (
                        isinstance(self.source.inBoundary, boundary)
                        and not isinstance(self.sink.inBoundary, boundary)
                    )
                    or (
                        not isinstance(self.source.inBoundary, boundary)
                        and isinstance(self.sink.inBoundary, boundary)
                    )
                    or self.source.inBoundary is not self.sink.inBoundary
                ):
                    return True
            elif (self.source.inside(boundary) and not self.sink.inside(boundary)) or (
                not self.source.inside(boundary) and self.sink.inside(boundary)
            ):
                return True
        return False

    def enters(self, *boundaries):
        """does self (dataflow) enter into one of the list of boundaries"""
        return self.source.inBoundary is None and self.sink.inside(*boundaries)

    def exits(self, *boundaries):
        """does self (dataflow) exit one of the list of boundaries"""
        return self.source.inside(*boundaries) and self.sink.inBoundary is None

    def inside(self, *boundaries):
        """is self inside of one of the list of boundaries"""
        for boundary in boundaries:
            if inspect.isclass(boundary):
                if isinstance(self.inBoundary, boundary):
                    return True
            elif self.inBoundary is boundary:
                return True
        return False

    def _attr_values(self):
        klass = self.__class__
        result = {}
        for i in dir(klass):
            if i.startswith("_") or callable(getattr(klass, i)):
                continue
            attr = getattr(klass, i, {})
            if isinstance(attr, var):
                value = attr.data.get(self, attr.default)
            else:
                value = getattr(self, i)
            result[i] = value
        return result

    def checkTLSVersion(self, flows):
        return any(f.tlsVersion < self.minTLSVersion for f in flows)


class Data:
    """Represents a single piece of data that traverses the system"""

    name = varString("", required=True)
    description = varString("")
    format = varString("")
    classification = varClassification(
        Classification.UNKNOWN,
        required=True,
        doc="Level of classification for this piece of data",
    )
    isPII = varBool(
        False,
        doc="""Does the data contain personally identifyable information.
Should always be encrypted both in transmission and at rest.""",
    )
    isCredentials = varBool(
        False,
        doc="""Does the data contain authentication information,
like passwords or cryptographic keys, with or without expiration date.
Should always be encrypted in transmission. If stored, they should be hashed
using a cryptographic hash function.""",
    )
    credentialsLife = varLifetime(
        Lifetime.NONE,
        doc="""Credentials lifetime, describing if and how
credentials can be revoked. One of:
* NONE - not applicable
* UNKNOWN - unknown lifetime
* SHORT - relatively short expiration date, with an allowed maximum
* LONG - long or no expiration date
* AUTO - no expiration date but can be revoked/invalidated automatically
  in some conditions
* MANUAL - no expiration date but can be revoked/invalidated manually
* HARDCODED - cannot be invalidated at all""",
    )
    isStored = varBool(
        False,
        doc="""Is the data going to be stored by the target or only processed.
If only derivative data is stored (a hash) it can be set to False.""",
    )
    isDestEncryptedAtRest = varBool(False, doc="Is data encrypted at rest at dest")
    isSourceEncryptedAtRest = varBool(False, doc="Is data encrypted at rest at source")
    carriedBy = varElements([], doc="Dataflows that carries this piece of data")
    processedBy = varElements([], doc="Elements that store/process this piece of data")

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        TM._data.append(self)

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.name, hex(id(self))
        )

    def __str__(self):
        return "{0}({1})".format(type(self).__name__, self.name)

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass


class Asset(Element):
    """An asset with outgoing or incoming dataflows"""

    port = varInt(-1, doc="Default TCP port for incoming data flows")
    protocol = varString("", doc="Default network protocol for incoming data flows")
    data = varData([], doc="pytm.Data object(s) in incoming data flows")
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")
    onAWS = varBool(False)
    handlesResources = varBool(False)
    usesEnvironmentVariables = varBool(False)
    OS = varString("")

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        TM._assets.append(self)


class Lambda(Asset):
    """A lambda function running in a Function-as-a-Service (FaaS) environment"""

    onAWS = varBool(True)
    environment = varString("")
    implementsAPI = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _dfd_template(self):
        return """{uniq_name} [
    shape = {shape};

    color = {color};
    fontcolor = {color};
    label = <
        <table border="0" cellborder="0" cellpadding="2">
            <tr><td><b>{label}</b></td></tr>
        </table>
    >;
]
"""

    def dfd(self, **kwargs):
        self._is_drawn = True

        levels = kwargs.get("levels", None)
        if levels and not levels & self.levels:
            return ""

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            shape=self._shape(),
        )

    def _shape(self):
        return "rectangle; style=rounded"


class Server(Asset):
    """An entity processing data"""

    usesSessionTokens = varBool(False)
    usesCache = varBool(False)
    usesVPN = varBool(False)
    usesXMLParser = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _shape(self):
        return "circle"


class ExternalEntity(Asset):
    hasPhysicalAccess = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)


class Datastore(Asset):
    """An entity storing data"""

    onRDS = varBool(False)
    storesLogData = varBool(False)
    storesPII = varBool(
        False,
        doc="""Personally Identifiable Information
is any information relating to an identifiable person.""",
    )
    storesSensitiveData = varBool(False)
    isSQL = varBool(True)
    isShared = varBool(False)
    hasWriteAccess = varBool(False)
    type = varDatastoreType(
        DatastoreType.UNKNOWN,
        doc="""The  type of Datastore, values may be one of:
* UNKNOWN - unknown applicable
* FILE_SYSTEM - files on a file system
* SQL - A SQL Database
* LDAP - An LDAP Server
* AWS_S3 - An S3 Bucket within AWS"""
    )

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _dfd_template(self):
        return """{uniq_name} [
    shape = {shape};
    fixedsize = shape;
    image = "{image}";
    imagescale = true;
    color = {color};
    fontcolor = {color};
    xlabel = "{label}";
    label = "";
]
"""

    def _shape(self):
        return "none"

    def dfd(self, **kwargs):
        self._is_drawn = True

        levels = kwargs.get("levels", None)
        if levels and not levels & self.levels:
            return ""

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            shape=self._shape(),
            image=os.path.join(os.path.dirname(__file__), "images", "datastore.png"),
        )


class Actor(Element):
    """An entity usually initiating actions"""

    port = varInt(-1, doc="Default TCP port for outgoing data flows")
    protocol = varString("", doc="Default network protocol for outgoing data flows")
    data = varData([], doc="pytm.Data object(s) in outgoing data flows")
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")
    isAdmin = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        TM._actors.append(self)


class Process(Asset):
    """An entity processing data"""

    codeType = varString("Unmanaged")
    implementsCommunicationProtocol = varBool(False)
    tracksExecutionFlow = varBool(False)
    implementsAPI = varBool(False)
    environment = varString("")
    allowsClientSideScripting = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _shape(self):
        return "circle"


class SetOfProcesses(Process):
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _shape(self):
        return "doublecircle"


class Dataflow(Element):
    """A data flow from a source to a sink"""

    source = varElement(None, required=True)
    sink = varElement(None, required=True)
    isResponse = varBool(False, doc="Is a response to another data flow")
    response = varElement(None, doc="Another data flow that is a response to this one")
    responseTo = varElement(None, doc="Is a response to this data flow")
    srcPort = varInt(-1, doc="Source TCP port")
    dstPort = varInt(-1, doc="Destination TCP port")
    tlsVersion = varTLSVersion(
        TLSVersion.NONE,
        required=True,
        doc="TLS version used.",
    )
    protocol = varString("", doc="Protocol used in this data flow")
    data = varData([], doc="pytm.Data object(s) in incoming data flows")
    order = varInt(-1, doc="Number of this data flow in the threat model")
    implementsCommunicationProtocol = varBool(False)
    note = varString("")
    usesVPN = varBool(False)
    usesSessionTokens = varBool(False)

    def __init__(self, source, sink, name, **kwargs):
        self.source = source
        self.sink = sink
        super().__init__(name, **kwargs)
        TM._flows.append(self)

    def display_name(self):
        if self.order == -1:
            return self.name
        return "({}) {}".format(self.order, self.name)

    def _dfd_template(self):
        return """{source} -> {sink} [
    color = {color};
    fontcolor = {color};
    dir = {direction};
    label = "{label}";
]
"""

    def dfd(self, mergeResponses=False, **kwargs):
        self._is_drawn = True

        levels = kwargs.get("levels", None)
        if (
            levels
            and not levels & self.levels
            and not (levels & self.source.levels and levels & self.sink.levels)
        ):
            return ""

        direction = "forward"
        label = self._label()
        if mergeResponses and self.response is not None:
            direction = "both"
            label += "\n" + self.response._label()

        return self._dfd_template().format(
            source=self.source._uniq_name(),
            sink=self.sink._uniq_name(),
            direction=direction,
            label=label,
            color=self._color(),
        )

    def hasDataLeaks(self):
        return any(
            d.classification > self.source.maxClassification
            or d.classification > self.sink.maxClassification
            or d.classification > self.maxClassification
            for d in self.data
        )


class Boundary(Element):
    """Trust boundary groups elements and data with the same trust level."""

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        if name not in TM._boundaries:
            TM._boundaries.append(self)

    def _dfd_template(self):
        return """subgraph cluster_{uniq_name} {{
    graph [
        fontsize = 10;
        fontcolor = {color};
        style = dashed;
        color = {color};
        label = <<i>{label}</i>>;
    ]

{edges}
}}
"""

    def dfd(self, **kwargs):
        if self._is_drawn:
            return ""

        self._is_drawn = True

        logger.debug("Now drawing boundary " + self.name)
        edges = []
        for e in TM._elements:
            if e.inBoundary != self or e._is_drawn:
                continue
            # The content to draw can include Boundary objects
            logger.debug("Now drawing content {}".format(e.name))
            edges.append(e.dfd(**kwargs))
        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            edges=indent("\n".join(edges), "    "),
        )

    def _color(self):
        return "firebrick2"

    def parents(self):
        result = []
        parent = self.inBoundary
        while parent is not None:
            result.append(parent)
            parent = parent.inBoundary
        return result


@singledispatch
def to_serializable(val):
    """Used by default."""
    return str(val)


@to_serializable.register(TM)
def ts_tm(obj):
    return serialize(obj, nested=True)


@to_serializable.register(Controls)
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
            elif i == "levels" or i == "sourceFiles":
                value = list(value)
            elif (
                not nested
                and not isinstance(value, str)
                and isinstance(value, Iterable)
            ):
                value = [v.id if isinstance(v, Finding) else v.name for v in value]
        result[i.lstrip("_")] = value
    return result

def encode_element_threat_data(obj):
    """Used to html encode threat data from a list of Elements"""
    encoded_elements = []
    if (type(obj) is not list):
       raise ValueError("expecting a list value, got a {}".format(type(value)))

    for o in obj:
       c = copy.deepcopy(o)
       for a in o._attr_values():
            if (a == "findings"):
               encoded_findings = encode_threat_data(o.findings)
               c._safeset("findings", encoded_findings)
            else:
               v = getattr(o, a)
               if (type(v) is not list or (type(v) is list and len(v) != 0)):
                  c._safeset(a, v)
                 
       encoded_elements.append(c)    

    return encoded_elements

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
        "threat_id",
        "references",
        "condition",
    ]

    if type(obj) is Finding or (len(obj) != 0 and type(obj[0]) is Finding):
        attrs.append("target")

    for e in obj:
        t = copy.deepcopy(e)

        for a in attrs:
            try:
                v = getattr(e, a)
            except AttributeError:
                # ignore missing attributes, since this can be called
                # on both a Finding and a Threat
                continue
            setattr(t, a, html.escape(v))

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
    _parser.add_argument(
        "--list-elements", action="store_true", help="list all elements which can be part of a threat model"
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
