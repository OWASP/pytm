import argparse
import inspect
import json
import logging
import random
import sys
import uuid
import sys
from collections import defaultdict
from collections.abc import Iterable
from hashlib import sha224
from os.path import dirname
from textwrap import wrap
from weakref import WeakKeyDictionary

from .template_engine import SuperFormatter

''' Helper functions '''

''' The base for this (descriptors instead of properties) has been shamelessly lifted from https://nbviewer.jupyter.org/urls/gist.github.com/ChrisBeaumont/5758381/raw/descriptor_writeup.ipynb
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


def _setColor(element):
    if element.inScope is True:
        return "black"
    else:
        return "grey69"


def _setLabel(element):
    return "<br/>".join(wrap(element.name, 14))


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
    for e in flows:
        e._safeset("data", e.source.data)
        if e.isResponse:
            e._safeset("protocol", e.source.protocol)
            e._safeset("srcPort", e.source.port)
            e._safeset("isEncrypted", e.source.isEncrypted)
        else:
            e._safeset("protocol", e.sink.protocol)
            e._safeset("dstPort", e.sink.port)
            if hasattr(e.sink, "isEncrypted"):
                e._safeset("isEncrypted", e.sink.isEncrypted)


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
    condition = varString("", doc="a Python expression that should evaluate to a boolean True or False")
    details = varString("")
    severity = varString("")
    mitigations = varString("")
    example = varString("")
    references = varString("")
    target = ()

    def __init__(self, **kwargs):
        self.id = kwargs['SID']
        self.description = kwargs.get('description', '')
        self.condition = kwargs.get('condition', 'True')
        target = kwargs.get('target', 'Element')
        if not isinstance(target, str) and isinstance(target, Iterable):
            target = tuple(target)
        else:
            target = (target,)
        self.target = tuple(getattr(sys.modules[__name__], x) for x in target)
        self.details = kwargs.get('details', '')
        self.severity = kwargs.get('severity', '')
        self.mitigations = kwargs.get('mitigations', '')
        self.example = kwargs.get('example', '')
        self.references = kwargs.get('references', '')

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
    """Represents a Finding - the element in question and a description of the finding """

    element = varElement(None, required=True, doc="Element this finding applies to")
    target = varString("", doc="Name of the element this finding applies to")
    description = varString("", required=True, doc="Threat description")
    details = varString("", required=True, doc="Threat details")
    severity = varString("", required=True, doc="Threat severity")
    mitigations = varString("", required=True, doc="Threat mitigations")
    example = varString("", required=True, doc="Threat example")
    id = varString("", required=True, doc="Threat ID")
    references = varString("", required=True, doc="Threat references")

    def __init__(self, element, description, details, severity, mitigations, example, id, references):
        self.target = element.name
        self.element = element
        self.description = description
        self.details = details
        self.severity = severity
        self.mitigations = mitigations
        self.example = example
        self.id = id
        self.references = references


class TM():
    """Describes the threat model administratively, and holds all details during a run"""

    _BagOfFlows = []
    _BagOfElements = []
    _BagOfThreats = []
    _BagOfBoundaries = []
    _threatsExcluded = []
    _sf = None
    name = varString("", required=True, doc="Model name")
    description = varString("", required=True, doc="Model description")
    threatsFile = varString(dirname(__file__) + "/threatlib/threats.json",
                            onSet=lambda i, v: i._init_threats(),
                            doc="JSON file with custom threats")
    isOrdered = varBool(False, doc="Automatically order all Dataflows")
    mergeResponses = varBool(False, doc="Merge response edges in DFDs")
    ignoreUnused = varBool(False, doc="Ignore elements not used in any Dataflow")
    findings = varFindings([], doc="threats found for elements of this model")

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        self._sf = SuperFormatter()
        self._add_threats()

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
                f = Finding(e, t.description, t.details, t.severity, t.mitigations, t.example, t.id, t.references)
                findings.append(f)
                elements[e].append(f)
        self.findings = findings
        for e, findings in elements.items():
            e.findings = findings

    def check(self):
        if self.description is None:
            raise ValueError("Every threat model should have at least a brief description of the system being modeled.")
        TM._BagOfFlows = _match_responses(_sort(TM._BagOfFlows, self.isOrdered))
        _apply_defaults(TM._BagOfFlows)
        if self.ignoreUnused:
            TM._BagOfElements, TM._BagOfBoundaries = _get_elements_and_boundaries(TM._BagOfFlows)
        for e in (TM._BagOfElements):
            e.check()
        if self.ignoreUnused:
            # cannot rely on user defined order if assets are re-used in multiple models
            TM._BagOfElements = _sort_elem(TM._BagOfElements)

    def dfd(self):
        print("digraph tm {\n\tgraph [\n\tfontname = Arial;\n\tfontsize = 14;\n\t]")
        print("\tnode [\n\tfontname = Arial;\n\tfontsize = 14;\n\trankdir = lr;\n\t]")
        print("\tedge [\n\tshape = none;\n\tarrowtail = onormal;\n\tfontname = Arial;\n\tfontsize = 12;\n\t]")
        print('\tlabelloc = "t";\n\tfontsize = 20;\n\tnodesep = 1;\n')
        for b in TM._BagOfBoundaries:
            b.dfd()

        if self.mergeResponses:
            for e in TM._BagOfFlows:
                if e.response is not None:
                    e.response._is_drawn = True
        for e in TM._BagOfElements:
            #  Boundaries draw themselves
            if not e._is_drawn and not isinstance(e, Boundary) and e.inBoundary is None:
                e.dfd(mergeResponses=self.mergeResponses)
        print("}")

    def seq(self):
        print("@startuml")
        for e in TM._BagOfElements:
            if isinstance(e, Actor):
                print("actor {0} as \"{1}\"".format(e._uniq_name(), e.name))
            elif isinstance(e, Datastore):
                print("database {0} as \"{1}\"".format(e._uniq_name(), e.name))
            elif not isinstance(e, Dataflow) and not isinstance(e, Boundary):
                print("entity {0} as \"{1}\"".format(e._uniq_name(), e.name))

        for e in TM._BagOfFlows:
            print("{0} -> {1}: {2}".format(e.source._uniq_name(), e.sink._uniq_name(), e.name))
            if e.note != "":
                print("note left\n{}\nend note".format(e.note))
        print("@enduml")

    def report(self, *args, **kwargs):
        result = get_args()
        TM._template = result.report
        with open(self._template) as file:
            template = file.read()

        print(self._sf.format(template, tm=self, dataflows=self._BagOfFlows, threats=self._BagOfThreats, findings=self.findings, elements=self._BagOfElements, boundaries=self._BagOfBoundaries))

    def process(self):
        self.check()
        result = get_args()
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
        if result.debug:
            logger.setLevel(logging.DEBUG)
        if result.seq is True:
            self.seq()
        if result.dfd is True:
            self.dfd()
        if result.report is not None:
            self.resolve()
            self.report()
        if result.exclude is not None:
            TM._threatsExcluded = result.exclude.split(",")
        if result.describe is not None:
            _describe_classes(result.describe.split())
        if result.list is True:
            [print("{} - {}".format(t.id, t.description)) for t in TM._BagOfThreats]
            sys.exit(0)


class Element():
    """A generic element"""

    name = varString("", required=True)
    description = varString("")
    inBoundary = varBoundary(None, doc="Trust boundary this element exists in")
    inScope = varBool(True, doc="Is the element in scope of the threat model")
    onAWS = varBool(False)
    isHardened = varBool(False)
    implementsAuthenticationScheme = varBool(False)
    implementsNonce = varBool(False)
    handlesResources = varBool(False)
    definesConnectionTimeout = varBool(False)
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
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        if self.description == "" or self.name == "":
            raise ValueError("Element {} need a description and a name.".format(self.name))

    def dfd(self, **kwargs):
        self._is_drawn = True
        label = _setLabel(self)
        print("%s [\n\tshape = square;" % self._uniq_name())
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{0}</b></td></tr></table>>;'.format(label))
        print("]")

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass

    def oneOf(self, *elements):
        for element in elements:
            if inspect.isclass(element):
                if isinstance(self, element):
                    return True
            elif self is element:
                return True
        return False

    def crosses(self, *boundaries):
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
        return self.source.inBoundary is None and self.sink.inside(*boundaries)

    def exits(self, *boundaries):
        return self.source.inside(*boundaries) and self.sink.inBoundary is None

    def inside(self, *boundaries):
        for boundary in boundaries:
            if inspect.isclass(boundary):
                if isinstance(self.inBoundary, boundary):
                    return True
            elif self.inBoundary is boundary:
                return True
        return False


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

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def dfd(self, **kwargs):
        self._is_drawn = True
        color = _setColor(self)
        pngpath = dirname(__file__) + "/images/lambda.png"
        label = _setLabel(self)
        print('{0} [\n\tshape = none\n\tfixedsize=shape\n\timage="{2}"\n\timagescale=true\n\tcolor = {1}'.format(self._uniq_name(), color, pngpath))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(label))
        print("]")


class Server(Element):
    """An entity processing data"""

    port = varInt(-1, doc="Default TCP port for incoming data flows")
    isEncrypted = varBool(False, doc="Requires incoming data flow to be encrypted")
    protocol = varString("", doc="Default network protocol for incoming data flows")
    data = varString("", doc="Default type of data in incoming data flows")
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    authenticatesDestination = varBool(False)
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

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def dfd(self, **kwargs):
        self._is_drawn = True
        color = _setColor(self)
        label = _setLabel(self)
        print("{0} [\n\tshape = circle\n\tcolor = {1}".format(self._uniq_name(), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(label))
        print("]")


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
    onRDS = varBool(False)
    storesLogData = varBool(False)
    storesPII = varBool(False)
    storesSensitiveData = varBool(False)
    isSQL = varBool(True)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    authenticatesDestination = varBool(False)
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
    implementsPOLP = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def dfd(self, **kwargs):
        self._is_drawn = True
        color = _setColor(self)
        label = _setLabel(self)
        print("{0} [\n\tshape = none;\n\tcolor = {1};".format(self._uniq_name(), color))
        print('\tlabel = <<table sides="TB" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(label, color))
        print("]")


class Actor(Element):
    """An entity usually initiating actions"""

    port = varInt(-1, doc="Default TCP port for outgoing data flows")
    protocol = varString("", doc="Default network protocol for outgoing data flows")
    data = varString("", doc="Default type of data in outgoing data flows")

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def dfd(self, **kwargs):
        self._is_drawn = True
        label = _setLabel(self)
        print("%s [\n\tshape = square;" % self._uniq_name())
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{0}</b></td></tr></table>>;'.format(label))
        print("]")


class Process(Element):
    """An entity processing data"""

    port = varInt(-1, doc="Default TCP port for incoming data flows")
    isEncrypted = varBool(False, doc="Requires incoming data flow to be encrypted")
    protocol = varString("", doc="Default network protocol for incoming data flows")
    data = varString("", doc="Default type of data in incoming data flows")
    codeType = varString("Unmanaged")
    implementsCommunicationProtocol = varBool(False)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    authenticatesDestination = varBool(False)
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
    implementsPOLP = varBool(False)
    encodesOutput = varBool(False)
    usesParameterizedInput = varBool(False)
    allowsClientSideScripting = varBool(False)
    usesStrongSessionIdentifiers = varBool(False)
    encryptsCookies = varBool(False)
    usesMFA = varBool(False)
    encryptsSessionData = varBool(False)
    verifySessionIdentifiers = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def dfd(self, **kwargs):
        self._is_drawn = True
        color = _setColor(self)
        label = _setLabel(self)
        print("{0} [\n\tshape = circle;\n\tcolor = {1};\n".format(self._uniq_name(), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(label, color))
        print("]")


class SetOfProcesses(Process):

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def dfd(self, **kwargs):
        self._is_drawn = True
        color = _setColor(self)
        label = _setLabel(self)
        print("{0} [\n\tshape = doublecircle;\n\tcolor = {1};\n".format(self._uniq_name(), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(label, color))
        print("]")


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

    def __set__(self, instance, value):
        print("Should not have gotten here.")

    def check(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to _BagOfFlows
        pass

    def dfd(self, mergeResponses=False, **kwargs):
        self._is_drawn = True
        color = _setColor(self)
        label = _setLabel(self)
        if self.order >= 0:
            label = '({0}) {1}'.format(self.order, label)
        direction = "forward"
        if mergeResponses and self.response is not None:
            direction = "both"
            resp_label = _setLabel(self.response)
            if self.response.order >= 0:
                resp_label = "({0}) {1}".format(self.response.order, resp_label)
            label += "<br/>" + resp_label
        print("\t{0} -> {1} [\n\t\tcolor = {2};\n\t\tdir = {3};\n".format(
            self.source._uniq_name(),
            self.sink._uniq_name(),
            color,
            direction,
        ))
        print('\t\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(label, color))
        print("\t]")


class Boundary(Element):
    """Trust boundary"""

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        if name not in TM._BagOfBoundaries:
            TM._BagOfBoundaries.append(self)

    def dfd(self):
        if self._is_drawn:
            return

        self._is_drawn = True
        logger.debug("Now drawing boundary " + self.name)
        label = self.name
        print("subgraph cluster_{0} {{\n\tgraph [\n\t\tfontsize = 10;\n\t\tfontcolor = firebrick2;\n\t\tstyle = dashed;\n\t\tcolor = firebrick2;\n\t\tlabel = <<i>{1}</i>>;\n\t]\n".format(self._uniq_name(), label))
        for e in TM._BagOfElements:
            if e.inBoundary == self and not e._is_drawn:
                # The content to draw can include Boundary objects
                logger.debug("Now drawing content {}".format(e.name))
                e.dfd()
        print("\n}\n")


def get_args():
    _parser = argparse.ArgumentParser()
    _parser.add_argument('--debug', action='store_true', help='print debug messages')
    _parser.add_argument('--dfd', action='store_true', help='output DFD')
    _parser.add_argument('--report', help='output report using the named template file (sample template file is under docs/template.md)')
    _parser.add_argument('--exclude', help='specify threat IDs to be ignored')
    _parser.add_argument('--seq', action='store_true', help='output sequential diagram')
    _parser.add_argument('--list', action='store_true', help='list all available threats')
    _parser.add_argument('--describe', help='describe the properties available for a given element')

    _args = _parser.parse_args()
    return _args
