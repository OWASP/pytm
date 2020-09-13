import argparse
import inspect
import json
import logging
import os
import random
import sys
import uuid
from collections import defaultdict
from collections.abc import Iterable
from enum import Enum
from hashlib import sha224
from itertools import combinations
from textwrap import indent, wrap
from weakref import WeakKeyDictionary

from .template_engine import SuperFormatter

''' Helper functions '''

''' The base for this (descriptors instead of properties) has been
    shamelessly lifted from
    https://nbviewer.jupyter.org/urls/gist.github.com/ChrisBeaumont/5758381/raw/descriptor_writeup.ipynb
    By Chris Beaumont
'''


logger = logging.getLogger(__name__)


class var(object):
    ''' A descriptor that allows setting a value only once '''

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
                "cannot overwrite {} value with {}, already set to {}".format(
                    self.__class__.__name__, value, self.data[instance]
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
        for i, e in enumerate(value):
            if not isinstance(e, str):
                raise ValueError(
                    "expecting a list of Strings, item number {} is a {}".format(
                        i, type(value)
                    )
                )
        super().__set__(instance, list(value))


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


class varElement(var):

    def __set__(self, instance, value):
        if not isinstance(value, Element):
            raise ValueError("expecting an Element (or inherited) "
                             "value, got a {}".format(type(value)))
        super().__set__(instance, value)


class varElements(var):

    def __set__(self, instance, value):
        for i, e in enumerate(value):
            if not isinstance(e, Element):
                raise ValueError(
                    "expecting a list of Elements, item number {} is a {}".format(
                        i, type(value)
                    )
                )
        super().__set__(instance, list(value))


class varFindings(var):

    def __set__(self, instance, value):
        for i, e in enumerate(value):
            if not isinstance(e, Finding):
                raise ValueError(
                    "expecting a list of Findings, item number {} is a {}".format(
                        i, type(value)
                    )
                )
        super().__set__(instance, list(value))


class varAction(var):

    def __set__(self, instance, value):
        if not isinstance(value, Action):
            raise ValueError("expecting an Action, got a {}".format(type(value)))
        super().__set__(instance, value)


class Action(Enum):
    NO_ACTION = 'NO_ACTION'
    RESTRICT = 'RESTRICT'
    IGNORE = 'IGNORE'


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


def _apply_defaults(flows):
    inputs = defaultdict(list)
    outputs = defaultdict(list)
    for e in flows:
        e._safeset("data", e.source.data)

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
                    docs.append(attr.doc)
                if attr.required:
                    docs.append("required")
                if attr.default or isinstance(attr.default, bool):
                    docs.append("default: {}".format(attr.default))
            print("  {}{}".format(i.ljust(longest, " "), ", ".join(docs)))
        print()


def _get_elements_and_boundaries(flows):
    """filter out elements and boundaries not used in this TM"""
    elements = {}
    boundaries = {}
    for e in flows:
        elements[e] = True
        elements[e.source] = True
        elements[e.sink] = True
        if e.source.inBoundary is not None:
            boundaries[e.source.inBoundary] = True
        if e.sink.inBoundary is not None:
            boundaries[e.sink.inBoundary] = True
    return (elements.keys(), boundaries.keys())


''' End of help functions '''


class Threat():
    """Represents a possible threat"""

    id = varString("", required=True)
    description = varString("")
    condition = varString("", doc="""a Python expression that should evaluate
to a boolean True or False""")
    details = varString("")
    severity = varString("")
    mitigations = varString("")
    example = varString("")
    references = varString("")
    target = var([])
    impactedSecurityProperties  = varStrings([])

    def __init__(self, **kwargs):
        self.id = kwargs["SID"]
        self.description = kwargs.get("description", "")
        self.condition = kwargs.get("condition", "True")
        self.details = kwargs.get("details", "")
        self.severity = kwargs.get("severity", "")
        self.mitigations = kwargs.get("mitigations", "")
        self.example = kwargs.get("example", "")
        self.references = kwargs.get("references", "")

        target = kwargs.get("target", "Element")
        if isinstance(target, str) or not isinstance(target, Iterable):
            target = [target]
        self.target = tuple(getattr(sys.modules[__name__], x) for x in target)

        impactedSecurityProperties = kwargs.get("impactedSecurityProperties", [])
        if isinstance(impactedSecurityProperties, str) or not isinstance(impactedSecurityProperties, Iterable):
            self.impactedSecurityProperties = [impactedSecurityProperties]
        else:
            self.impactedSecurityProperties = list(impactedSecurityProperties)

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


class Finding():
    """Represents a Finding - the element in question
and a description of the finding"""

    element = varElement(None, required=True, doc="Element this finding applies to")
    target = varString("", doc="Name of the element this finding applies to")
    description = varString("", required=True, doc="Threat description")
    details = varString("", required=True, doc="Threat details")
    severity = varString("", required=True, doc="Threat severity")
    mitigations = varString("", required=True, doc="Threat mitigations")
    example = varString("", required=True, doc="Threat example")
    id = varString("", required=True, doc="Threat ID")
    references = varString("", required=True, doc="Threat references")

    def __init__(
        self,
        element,
        **kwargs,
    ):
        self.target = element.name
        self.element = element
        attrs = [
            "description",
            "details",
            "severity",
            "mitigations",
            "example",
            "id",
            "references",
        ]
        threat = kwargs.get("threat", None)
        if threat:
            for a in attrs:
                setattr(self, a, getattr(threat, a))
            setattr(self, "_impactedSecurityProperties", threat.impactedSecurityProperties)
            return

        for a in attrs:
            if a in kwargs:
                setattr(self, a, kwargs.get(a))
            if "impactedSecurityProperties" in kwargs:
                setattr(
                    self,
                    "_impactedSecurityProperties",
                    kwargs.get("impactedSecurityProperties"),
                )

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.id, hex(id(self))
        )

    def __str__(self):
        return "{0}({1})".format(type(self).__name__, self.id)

    @property
    def impactedSecurityProperties(self):
        return ', '.join(self._impactedSecurityProperties)


class TM():
    """Describes the threat model administratively,
and holds all details during a run"""

    _BagOfFlows = []
    _BagOfElements = []
    _BagOfThreats = []
    _BagOfBoundaries = []
    _threatsExcluded = []
    _sf = None
    _duplicate_ignored_attrs = "name", "note", "order", "response", "responseTo"
    name = varString("", required=True, doc="Model name")
    description = varString("", required=True, doc="Model description")
    threatsFile = varString(os.path.dirname(__file__) + "/threatlib/threats.json",
                            onSet=lambda i, v: i._init_threats(),
                            doc="JSON file with custom threats")
    isOrdered = varBool(False, doc="Automatically order all Dataflows")
    mergeResponses = varBool(False, doc="Merge response edges in DFDs")
    ignoreUnused = varBool(False, doc="Ignore elements not used in any Dataflow")
    findings = varFindings([], doc="threats found for elements of this model")
    onDuplicates = varAction(Action.NO_ACTION, doc="""How to handle duplicate Dataflow
with same properties, except name and notes""")

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
        cls._BagOfFlows = []
        cls._BagOfElements = []
        cls._BagOfThreats = []
        cls._BagOfBoundaries = []

    def _init_threats(self):
        TM._BagOfThreats = []
        self._add_threats()

    def _add_threats(self):
        with open(self.threatsFile, "r", encoding="utf8") as threat_file:
            threats_json = json.load(threat_file)

        for i in threats_json:
            TM._BagOfThreats.append(Threat(**i))

    def resolve(self):
        findings = []
        elements = defaultdict(list)
        for e in TM._BagOfElements:
            if not e.inScope:
                continue
            for t in TM._BagOfThreats:
                if not t.apply(e):
                    continue
                f = Finding(e, threat=t)
                findings.append(f)
                elements[e].append(f)
        self.findings = findings
        for e, findings in elements.items():
            e.findings = findings

    def check(self):
        if self.description is None:
            raise ValueError("""Every threat model should have at least
a brief description of the system being modeled.""")
        TM._BagOfFlows = _match_responses(_sort(TM._BagOfFlows, self.isOrdered))
        self._check_duplicates(TM._BagOfFlows)
        _apply_defaults(TM._BagOfFlows)
        if self.ignoreUnused:
            TM._BagOfElements, TM._BagOfBoundaries = _get_elements_and_boundaries(
                TM._BagOfFlows
            )
        result = True
        for e in (TM._BagOfElements):
            if not e.check():
                result = False
        if self.ignoreUnused:
            # cannot rely on user defined order if assets are re-used in multiple models
            TM._BagOfElements = _sort_elem(TM._BagOfElements)
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

                raise ValueError(
                    "Duplicate Dataflow found between {} and {}: "
                    "{} is same as {}".format(left.source, left.sink, left, right,)
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

    def dfd(self):
        edges = []
        for b in TM._BagOfBoundaries:
            edges.append(b.dfd())
        if self.mergeResponses:
            for e in TM._BagOfFlows:
                if e.response is not None:
                    e.response._is_drawn = True
        for e in TM._BagOfElements:
            if not e._is_drawn and not isinstance(e, Boundary) and e.inBoundary is None:
                edges.append(e.dfd(mergeResponses=self.mergeResponses))

        return self._dfd_template().format(edges=indent("\n".join(edges), "    "))

    def _seq_template(self):
        return """@startuml
{participants}

{messages}
@enduml"""

    def seq(self):
        participants = []
        for e in TM._BagOfElements:
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
        for e in TM._BagOfFlows:
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

    def report(self, *args, **kwargs):
        result = get_args()
        TM._template = result.report
        with open(self._template) as file:
            template = file.read()

        data = {
            "tm": self,
            "dataflows": TM._BagOfFlows,
            "threats": TM._BagOfThreats,
            "findings": self.findings,
            "elements": TM._BagOfElements,
            "boundaries": TM._BagOfBoundaries,
        }
        return self._sf.format(template, **data)

    def process(self):
        self.check()
        result = get_args()
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
        if result.debug:
            logger.setLevel(logging.DEBUG)
        if result.seq is True:
            print(self.seq())
        if result.dfd is True:
            print(self.dfd())
        if result.report is not None:
            self.resolve()
            print(self.report())
        if result.exclude is not None:
            TM._threatsExcluded = result.exclude.split(",")
        if result.describe is not None:
            _describe_classes(result.describe.split())
        if result.list is True:
            [print("{} - {}".format(t.id, t.description)) for t in TM._BagOfThreats]


class Element():
    """A generic element"""

    name = varString("", required=True)
    description = varString("")
    inBoundary = varBoundary(None, doc="Trust boundary this element exists in")
    inScope = varBool(True, doc="Is the element in scope of the threat model")
    onAWS = varBool(False)
    isHardened = varBool(False)
    implementsAuthenticationScheme = varBool(False)
    implementsNonce = varBool(False, doc="""Nonce is an arbitrary number
that can be used just once in a cryptographic communication.
It is often a random or pseudo-random number issued in an authentication protocol
to ensure that old communications cannot be reused in replay attacks.
They can also be useful as initialization vectors and in cryptographic
hash functions.""")
    handlesResources = varBool(False)
    definesConnectionTimeout = varBool(False)
    authenticatesDestination = varBool(False)
    OS = varString("")
    isAdmin = varBool(False)
    findings = varFindings([])

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        self.uuid = uuid.UUID(int=random.getrandbits(128))
        self._is_drawn = False
        TM._BagOfElements.append(self)

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.name, hex(id(self))
        )

    def __str__(self):
        return "{0}({1})".format(type(self).__name__, self.name)

    def _uniq_name(self):
        ''' transform name and uuid into a unique string '''
        h = sha224(str(self.uuid).encode('utf-8')).hexdigest()
        name = "".join(x for x in self.name if x.isalpha())
        return "{0}_{1}_{2}".format(type(self).__name__.lower(), name, h[:10])

    def check(self):
        return True

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
        return "<br/>".join(wrap(self.display_name(), 18))

    def _shape(self):
        return "square"

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass

    def oneOf(self, *elements):
        ''' Is self one of a list of Elements '''
        for element in elements:
            if inspect.isclass(element):
                if isinstance(self, element):
                    return True
            elif self is element:
                return True
        return False

    def crosses(self, *boundaries):
        ''' Does self (dataflow) cross any of the list of boundaries '''
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
        ''' does self (dataflow) enter into one of the list of boundaries '''
        return self.source.inBoundary is None and self.sink.inside(*boundaries)

    def exits(self, *boundaries):
        ''' does self (dataflow) exit one of the list of boundaries '''
        return self.source.inside(*boundaries) and self.sink.inBoundary is None

    def inside(self, *boundaries):
        ''' is self inside of one of the list of boundaries '''
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


class Lambda(Element):
    """A lambda function running in a Function-as-a-Service (FaaS) environment"""

    port = varInt(-1, doc="Default TCP port for outgoing data flows")
    protocol = varString("", doc="Default network protocol for outgoing data flows")
    data = varString("", doc="Default type of data in outgoing data flows")
    onAWS = varBool(True)
    authenticatesSource = varBool(False)
    hasAccessControl = varBool(False)
    sanitizesInput = varBool(False)
    encodesOutput = varBool(False)
    handlesResourceConsumption = varBool(False)
    authenticationScheme = varString("")
    usesEnvironmentVariables = varBool(False)
    validatesInput = varBool(False)
    checksInputBounds = varBool(False)
    environment = varString("")
    implementsAPI = varBool(False)
    authorizesSource = varBool(False)
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")

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
    label = <
        <table border="0" cellborder="0" cellpadding="2">
            <tr><td><b>{label}</b></td></tr>
        </table>
    >;
]
"""

    def dfd(self, **kwargs):
        self._is_drawn = True
        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            shape=self._shape(),
            image=os.path.join(os.path.dirname(__file__), "images", "lambda.png"),
        )

    def _shape(self):
        return "none"


class Server(Element):
    """An entity processing data"""

    port = varInt(-1, doc="Default TCP port for incoming data flows")
    isEncrypted = varBool(False, doc="Requires incoming data flow to be encrypted")
    protocol = varString("", doc="Default network protocol for incoming data flows")
    data = varString("", doc="Default type of data in incoming data flows")
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    sanitizesInput = varBool(False)
    encodesOutput = varBool(False)
    hasAccessControl = varBool(False)
    implementsCSRFToken = varBool(False)
    handlesResourceConsumption = varBool(False)
    isResilient = varBool(False)
    authenticationScheme = varString("")
    validatesInput = varBool(False)
    validatesHeaders = varBool(False)
    encodesHeaders = varBool(False)
    usesSessionTokens = varBool(False)
    usesEncryptionAlgorithm = varString("")
    usesCache = varBool(False)
    usesVPN = varBool(False)
    authorizesSource = varBool(False)
    usesCodeSigning = varBool(False)
    validatesContentType = varBool(False)
    invokesScriptFilters = varBool(False)
    usesStrongSessionIdentifiers = varBool(False)
    usesLatestTLSversion = varBool(False)
    implementsServerSideValidation = varBool(False)
    usesXMLParser = varBool(False)
    disablesDTD = varBool(False)
    checksInputBounds = varBool(False)
    implementsStrictHTTPValidation = varBool(False)
    implementsPOLP = varBool(False, doc="""The principle of least privilege (PoLP),
also known as the principle of minimal privilege or the principle of least authority,
requires that in a particular abstraction layer of a computing environment,
every module (such as a process, a user, or a program, depending on the subject)
must be able to access only the information and resources
that are necessary for its legitimate purpose.""")

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _shape(self):
        return "circle"


class ExternalEntity(Element):
    hasPhysicalAccess = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)


class Datastore(Element):
    """An entity storing data"""

    port = varInt(-1, doc="Default TCP port for incoming data flows")
    isEncrypted = varBool(False, doc="Requires incoming data flow to be encrypted")
    protocol = varString("", doc="Default network protocol for incoming data flows")
    data = varString("", doc="Default type of data in incoming data flows")
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")
    onRDS = varBool(False)
    storesLogData = varBool(False)
    storesPII = varBool(False, doc="""Personally Identifiable Information
is any information relating to an identifiable person.""")
    storesSensitiveData = varBool(False)
    isSQL = varBool(True)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    isShared = varBool(False)
    hasWriteAccess = varBool(False)
    handlesResourceConsumption = varBool(False)
    isResilient = varBool(False)
    handlesInterruptions = varBool(False)
    authorizesSource = varBool(False)
    hasAccessControl = varBool(False)
    authenticationScheme = varString("")
    usesEncryptionAlgorithm = varString("")
    validatesInput = varBool(False)
    implementsPOLP = varBool(False, doc="""The principle of least privilege (PoLP),
also known as the principle of minimal privilege or the principle of least authority,
requires that in a particular abstraction layer of a computing environment,
every module (such as a process, a user, or a program, depending on the subject)
must be able to access only the information and resources
that are necessary for its legitimate purpose.""")

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _dfd_template(self):
        return """{uniq_name} [
    shape = {shape};
    color = {color};
    fontcolor = {color};
    label = <
        <table sides="TB" cellborder="0" cellpadding="2">
            <tr><td><b>{label}</b></td></tr>
        </table>
    >;
]
"""

    def _shape(self):
        return "none"


class Actor(Element):
    """An entity usually initiating actions"""

    port = varInt(-1, doc="Default TCP port for outgoing data flows")
    protocol = varString("", doc="Default network protocol for outgoing data flows")
    data = varString("", doc="Default type of data in outgoing data flows")
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)


class Process(Element):
    """An entity processing data"""

    port = varInt(-1, doc="Default TCP port for incoming data flows")
    isEncrypted = varBool(False, doc="Requires incoming data flow to be encrypted")
    protocol = varString("", doc="Default network protocol for incoming data flows")
    data = varString("", doc="Default type of data in incoming data flows")
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")
    codeType = varString("Unmanaged")
    implementsCommunicationProtocol = varBool(False)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    isResilient = varBool(False)
    hasAccessControl = varBool(False)
    tracksExecutionFlow = varBool(False)
    implementsCSRFToken = varBool(False)
    handlesResourceConsumption = varBool(False)
    handlesCrashes = varBool(False)
    handlesInterruptions = varBool(False)
    authorizesSource = varBool(False)
    authenticationScheme = varString("")
    checksInputBounds = varBool(False)
    validatesInput = varBool(False)
    sanitizesInput = varBool(False)
    implementsAPI = varBool(False)
    usesSecureFunctions = varBool(False)
    environment = varString("")
    usesEnvironmentVariables = varBool(False)
    disablesiFrames = varBool(False)
    implementsPOLP = varBool(False, doc="""The principle of least privilege (PoLP),
also known as the principle of minimal privilege or the principle of least authority,
requires that in a particular abstraction layer of a computing environment,
every module (such as a process, a user, or a program, depending on the subject)
must be able to access only the information and resources
that are necessary for its legitimate purpose.""")
    encodesOutput = varBool(False)
    usesParameterizedInput = varBool(False)
    allowsClientSideScripting = varBool(False)
    usesStrongSessionIdentifiers = varBool(False)
    encryptsCookies = varBool(False)
    usesMFA = varBool(False, doc="""Multi-factor authentication is an authentication method
in which a computer user is granted access only after successfully presenting two
or more pieces of evidence (or factors) to an authentication mechanism: knowledge
(something the user and only the user knows), possession (something the user
and only the user has), and inherence (something the user and only the user is).""")
    encryptsSessionData = varBool(False)
    verifySessionIdentifiers = varBool(False)

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
    isEncrypted = varBool(False, doc="Is the data encrypted")
    protocol = varString("", doc="Protocol used in this data flow")
    data = varString("", "Type of data carried in this data flow")
    authenticatedWith = varBool(False)
    order = varInt(-1, doc="Number of this data flow in the threat model")
    implementsCommunicationProtocol = varBool(False)
    note = varString("")
    usesVPN = varBool(False)
    authorizesSource = varBool(False)
    usesSessionTokens = varBool(False)
    usesLatestTLSversion = varBool(False)

    def __init__(self, source, sink, name, **kwargs):
        self.source = source
        self.sink = sink
        super().__init__(name, **kwargs)
        TM._BagOfFlows.append(self)

    def display_name(self):
        if self.order == -1:
            return self.name
        return '({}) {}'.format(self.order, self.name)

    def _dfd_template(self):
        return """{source} -> {sink} [
    color = {color};
    fontcolor = {color};
    dir = {direction};
    label = <
        <table border="0" cellborder="0" cellpadding="2">
            <tr><td><font color="{color}"><b>{label}</b></font></td></tr>
        </table>
    >;
]
"""

    def dfd(self, mergeResponses=False, **kwargs):
        self._is_drawn = True
        direction = "forward"
        label = self._label()
        if mergeResponses and self.response is not None:
            direction = "both"
            label += "<br/>" + self.response._label()

        return self._dfd_template().format(
            source=self.source._uniq_name(),
            sink=self.sink._uniq_name(),
            direction=direction,
            label=label,
            color=self._color(),
        )


class Boundary(Element):
    """Trust boundary"""

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        if name not in TM._BagOfBoundaries:
            TM._BagOfBoundaries.append(self)

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

    def dfd(self):
        if self._is_drawn:
            return

        self._is_drawn = True
        logger.debug("Now drawing boundary " + self.name)
        edges = []
        for e in TM._BagOfElements:
            if e.inBoundary != self or e._is_drawn:
                continue
            # The content to draw can include Boundary objects
            logger.debug("Now drawing content {}".format(e.name))
            edges.append(e.dfd())
        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            edges=indent("\n".join(edges), "    "),
        )

    def _color(self):
        return "firebrick2"


def get_args():
    _parser = argparse.ArgumentParser()
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

    _args = _parser.parse_args()
    return _args
