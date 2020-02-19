import argparse
import json
import uuid
from hashlib import sha224
from os.path import dirname
from re import match, sub
from sys import exit, stderr
from textwrap import wrap
from weakref import WeakKeyDictionary

from .template_engine import SuperFormatter

""" Helper functions """

"""
The base for this (descriptors instead of properties) has been shamelessly lifted from
https://nbviewer.jupyter.org/urls/gist.github.com/ChrisBeaumont/5758381/raw/descriptor_writeup.ipynb
By Chris Beaumont
"""


class var(object):
    """ A descriptor that allows setting a value only once """

    def __init__(self, default, onSet=None):
        self.default = default
        self.data = WeakKeyDictionary()
        self.onSet = onSet

    def __get__(self, instance, owner):
        # when x.d is called we get here
        # instance = x
        # owner = type(x)
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
            raise ValueError(
                "expecting an Element (or inherited) "
                "value, got a {}".format(type(value))
            )
        super().__set__(instance, value)


def _setColor(element):
    if element.inScope is True:
        return "black"
    else:
        return "grey69"


def _setLabel(element):
    return "<br/>".join(wrap(element.name, 14))


def _debug(_args, msg):
    if _args.debug is True:
        stderr.write("DEBUG: {}\n".format(msg))


def _uniq_name(obj_name, obj_uuid):
    """ transform name and uuid into a unique string """
    hash_input = "{}{}".format(obj_name, str(obj_uuid))
    h = sha224(hash_input.encode("utf-8")).hexdigest()
    hash_without_numbers = sub(r"[0-9]", "", h)
    return hash_without_numbers


def _sort(elements, addOrder=False):
    ordered = sorted(elements, key=lambda flow: flow.order)
    if not addOrder:
        return ordered
    for i, flow in enumerate(ordered):
        if flow.order != -1:
            break
        ordered[i].order = i + 1
    return ordered


""" End of help functions """


class Threat:
    id = varString("")
    description = varString("")
    condition = varString("")
    details = varString("")
    severity = varString("")
    mitigations = varString("")
    example = varString("")
    references = varString("")
    target = ()

    """ Represents a possible threat """

    def __init__(self, json_read):
        self.id = json_read["SID"]
        self.description = json_read["description"]
        self.condition = json_read["condition"]
        self.target = json_read["target"]
        self.details = json_read["details"]
        self.severity = json_read["severity"]
        self.mitigations = json_read["mitigations"]
        self.example = json_read["example"]
        self.references = json_read["references"]

    def apply(self, target):
        if type(self.target) is list:
            if target.__class__.__name__ not in self.target:
                return None
        else:
            if target.__class__.__name__ is not self.target:
                return None
        return eval(self.condition)


class Finding:
    """ This class represents a Finding - the element in question
    and a description of the finding """

    def __init__(
        self,
        element,
        description,
        details,
        severity,
        mitigations,
        example,
        id,
        references,
    ):
        self.target = element
        self.description = description
        self.details = details
        self.severity = severity
        self.mitigations = mitigations
        self.example = example
        self.id = id
        self.references = references


class TM:
    """ Describes the threat model administratively, and holds
    all details during a run """

    _BagOfFlows = []
    _BagOfElements = []
    _BagOfThreats = []
    _BagOfFindings = []
    _BagOfBoundaries = []
    _threatsExcluded = []
    _sf = None
    description = varString("")
    threatsFile = varString(
        dirname(__file__) + "/threatlib/threats.json",
        onSet=lambda i, v: i._init_threats(),
    )
    isOrdered = varBool(False)

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        self._sf = SuperFormatter()
        self._add_threats()

    def _init_threats(self):
        TM._BagOfThreats = []
        self._add_threats()

    def _add_threats(self):
        with open(self.threatsFile, "r", encoding="utf8") as threat_file:
            threats_json = json.load(threat_file)

        for i in threats_json:
            TM._BagOfThreats.append(Threat(i))

    def resolve(self):
        for e in TM._BagOfElements:
            if e.inScope is True:
                for t in TM._BagOfThreats:
                    if t.apply(e) is True:
                        TM._BagOfFindings.append(
                            Finding(
                                e.name,
                                t.description,
                                t.details,
                                t.severity,
                                t.mitigations,
                                t.example,
                                t.id,
                                t.references,
                            )
                        )

    def check(self):
        if self.description is None:
            raise ValueError(
                "Every threat model should have at least a brief description "
                "of the system being modeled."
            )
        for e in TM._BagOfElements + TM._BagOfFlows:
            e.check()
        TM._BagOfFlows = _sort(TM._BagOfFlows, self.isOrdered)

    def dfd(self):
        print("digraph tm {\n\tgraph [\n\tfontname = Arial;\n\tfontsize = 14;\n\t]")
        print("\tnode [\n\tfontname = Arial;\n\tfontsize = 14;\n\trankdir = lr;\n\t]")
        print("\tedge [\n\tshape = none;\n\tfontname = Arial;\n\tfontsize = 12;\n\t]")
        print('\tlabelloc = "t";\n\tfontsize = 20;\n\tnodesep = 1;\n')
        for b in TM._BagOfBoundaries:
            b.dfd()
        for e in TM._BagOfElements:
            #  Boundaries draw themselves
            if not isinstance(e, Boundary) and e.inBoundary is None:
                e.dfd()
        print("}")

    def seq(self):
        print("@startuml")
        for e in TM._BagOfElements:
            if isinstance(e, Actor):
                print('actor {0} as "{1}"'.format(_uniq_name(e.name, e.uuid), e.name))
            elif isinstance(e, Datastore):
                print(
                    'database {0} as "{1}"'.format(_uniq_name(e.name, e.uuid), e.name)
                )
            elif not isinstance(e, Dataflow) and isinstance(e, Boundary):
                print('entity {0} as "{1}"'.format(_uniq_name(e.name, e.uuid), e.name))

        ordered = sorted(TM._BagOfFlows, key=lambda flow: flow.order)
        for e in ordered:
            print(
                "{0} -> {1}: {2}".format(
                    _uniq_name(e.source.name, e.source.uuid),
                    _uniq_name(e.sink.name, e.sink.uuid),
                    e.name,
                )
            )
            if e.note != "":
                print("note left\n{}\nend note".format(e.note))
        print("@enduml")

    def report(self, *args, **kwargs):
        result = get_args()
        TM._template = result.report
        with open(self._template) as file:
            template = file.read()

        print(
            self._sf.format(
                template,
                tm=self,
                dataflows=self._BagOfFlows,
                threats=self._BagOfThreats,
                findings=self._BagOfFindings,
                elements=self._BagOfElements,
                boundaries=self._BagOfBoundaries,
            )
        )

    def process(self):
        self.check()
        result = get_args()
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
            try:
                one_word = result.describe.split()[0]
                c = eval(one_word)
            except Exception:
                stderr.write("No such class to describe: {}\n".format(result.describe))
                exit(-1)
            print("The following properties are available for " + result.describe)
            [
                print("\t{}".format(i))
                for i in dir(c)
                if not callable(i) and match("__", i) is None
            ]
        if result.list is True:
            [print("{} - {}".format(t.id, t.description)) for t in TM._BagOfThreats]
            exit(0)


class Element:
    name = varString("")
    description = varString("")
    inBoundary = varBoundary(None)
    onAWS = varBool(False)
    isHardened = varBool(False)
    inScope = varBool(True)
    implementsAuthenticationScheme = varBool(False)
    implementsNonce = varBool(False)
    handlesResources = varBool(False)
    definesConnectionTimeout = varBool(False)
    OS = varString("")
    isAdmin = varBool(False)

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        self.uuid = uuid.uuid4()
        self._is_drawn = False
        TM._BagOfElements.append(self)

    def check(self):
        return True
        """ makes sure it is good to go """
        # all minimum annotations are in place
        if self.description == "" or self.name == "":
            raise ValueError(
                "Element {} need a description and a name.".format(self.name)
            )

    def dfd(self):
        self._is_drawn = True
        name = _uniq_name(self.name, self.uuid)
        label = _setLabel(self)
        print("%s [\n\tshape = square;" % name)
        print(
            '\tlabel = <<table border="0" cellborder="0" cellpadding="2">'
            "<tr><td><b>{0}</b></td></tr></table>>;".format(label)
        )
        print("]")


class Lambda(Element):
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

    def dfd(self):
        self._is_drawn = True
        name = _uniq_name(self.name, self.uuid)
        color = _setColor(self)
        pngpath = dirname(__file__) + "/images/lambda.png"
        label = _setLabel(self)
        print(
            '{0} [\n\tshape = none\n\tfixedsize=shape\n\timage="{2}"\n\t'
            "imagescale=true\n\tcolor = {1}".format(name, color, pngpath)
        )
        print(
            '\tlabel = <<table border="0" cellborder="0" cellpadding="2">'
            "<tr><td><b>{}</b></td></tr></table>>;".format(label)
        )
        print("]")


class Server(Element):
    isHardened = varBool(False)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    authenticatesDestination = varBool(False)
    sanitizesInput = varBool(False)
    encodesOutput = varBool(False)
    implementsAuthenticationScheme = varBool(False)
    hasAccessControl = varBool(False)
    implementsCSRFToken = varBool(False)
    handlesResourceConsumption = varBool(False)
    authenticationScheme = varString("")
    validatesInput = varBool(False)
    validatesHeaders = varBool(False)
    encodesHeaders = varBool(False)
    usesSessionTokens = varBool(False)
    implementsNonce = varBool(False)
    usesEncryptionAlgorithm = varString("")
    usesCache = varBool(False)
    protocol = varString("")
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

    def dfd(self):
        self._is_drawn = True
        name = _uniq_name(self.name, self.uuid)
        color = _setColor(self)
        label = _setLabel(self)
        print("{0} [\n\tshape = circle\n\tcolor = {1}".format(name, color))
        print(
            '\tlabel = <<table border="0" cellborder="0" cellpadding="2">'
            "<tr><td><b>{}</b></td></tr></table>>;".format(label)
        )
        print("]")


class ExternalEntity(Element):
    implementsAuthenticationScheme = varBool(False)
    implementsNonce = varBool(False)
    handlesResources = varBool(False)
    definesConnectionTimeout = varBool(False)
    hasPhysicalAccess = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)


class Datastore(Element):
    onRDS = varBool(False)
    storesLogData = varBool(False)
    storesPII = varBool(False)
    storesSensitiveData = varBool(False)
    isEncrypted = varBool(False)
    isSQL = varBool(True)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    authenticatesDestination = varBool(False)
    isShared = varBool(False)
    hasWriteAccess = varBool(False)
    handlesResourceConsumption = varBool(False)
    definesConnectionTimeout = varBool(False)
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

    def dfd(self):
        self._is_drawn = True
        name = _uniq_name(self.name, self.uuid)
        color = _setColor(self)
        label = _setLabel(self)
        print("{0} [\n\tshape = none;\n\tcolor = {1};".format(name, color))
        print(
            '\tlabel = <<table sides="TB" cellborder="0" cellpadding="2">'
            '<tr><td><font color="{1}"><b>{0}</b></font></td></tr>'
            "</table>>;".format(label, color)
        )
        print("]")


class Actor(Element):
    isAdmin = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def dfd(self):
        self._is_drawn = True
        name = _uniq_name(self.name, self.uuid)
        label = _setLabel(self)
        print("%s [\n\tshape = square;" % name)
        print(
            '\tlabel = <<table border="0" cellborder="0" cellpadding="2">'
            "<tr><td><b>{0}</b></td></tr></table>>;".format(label)
        )
        print("]")


class Process(Element):
    codeType = varString("Unmanaged")
    implementsCommunicationProtocol = varBool(False)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    authenticatesDestination = varBool(False)
    data = varString("")
    name = varString("")
    implementsAuthenticationScheme = varBool(False)
    implementsNonce = varBool(False)
    definesConnectionTimeout = varBool(False)
    isResilient = varBool(False)
    HandlesResources = varBool(False)
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

    def dfd(self):
        self._is_drawn = True
        name = _uniq_name(self.name, self.uuid)
        color = _setColor(self)
        label = _setLabel(self)
        print("{0} [\n\tshape = circle;\n\tcolor = {1};\n".format(name, color))
        print(
            '\tlabel = <<table border="0" cellborder="0" cellpadding="2">'
            '<tr><td><font color="{1}"><b>{0}</b></font></td></tr>'
            "</table>>;".format(label, color)
        )
        print("]")


class SetOfProcesses(Process):
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def dfd(self):
        self._is_drawn = True
        name = _uniq_name(self.name, self.uuid)
        color = _setColor(self)
        label = _setLabel(self)
        print("{0} [\n\tshape = doublecircle;\n\tcolor = {1};\n".format(name, color))
        print(
            '\tlabel = <<table border="0" cellborder="0" cellpadding="2">'
            '<tr><td><font color="{1}"><b>{0}</b></font></td></tr>'
            "</table>>;".format(label, color)
        )
        print("]")


class Dataflow(Element):
    source = varElement(None)
    sink = varElement(None)
    data = varString("")
    protocol = varString("")
    dstPort = varInt(10000)
    authenticatedWith = varBool(False)
    order = varInt(-1)
    implementsCommunicationProtocol = varBool(False)
    implementsNonce = varBool(False)
    name = varString("")
    isEncrypted = varBool(False)
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
        """ makes sure it is good to go """
        # all minimum annotations are in place
        # then add itself to _BagOfFlows
        pass

    def dfd(self):
        self._is_drawn = True
        color = _setColor(self)
        label = _setLabel(self)
        if self.order >= 0:
            label = "({0}) {1}".format(self.order, label)
        print(
            "\t{0} -> {1} [\n\t\tcolor = {2};\n".format(
                _uniq_name(self.source.name, self.source.uuid),
                _uniq_name(self.sink.name, self.sink.uuid),
                color,
            )
        )
        print(
            '\t\tlabel = <<table border="0" cellborder="0" cellpadding="2">'
            '<tr><td><font color="{1}"><b>{0}</b></font></td></tr>'
            "</table>>;".format(label, color)
        )
        print("\t]")


class Boundary(Element):
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        if name not in TM._BagOfBoundaries:
            TM._BagOfBoundaries.append(self)

    def dfd(self):
        if self._is_drawn:
            return

        result = get_args()
        self._is_drawn = True
        _debug(result, "Now drawing boundary " + self.name)
        name = _uniq_name(self.name, self.uuid)
        label = self.name
        print(
            "subgraph cluster_{0} {{\n\tgraph [\n"
            "\t\tfontsize = 10;\n\t\tfontcolor = firebrick2;\n"
            "\t\tstyle = dashed;\n\t\tcolor = firebrick2;\n"
            "\t\tlabel = <<i>{1}</i>>;\n\t]\n".format(name, label)
        )
        for e in TM._BagOfElements:
            if e.inBoundary == self and not e._is_drawn:
                # The content to draw can include Boundary objects
                _debug(result, "Now drawing content {}".format(e.name))
                e.dfd()
        print("\n}\n")


def get_args():
    _parser = argparse.ArgumentParser()
    _parser.add_argument("--debug", action="store_true", help="print debug messages")
    _parser.add_argument("--dfd", action="store_true", help="output DFD (default)")
    _parser.add_argument(
        "--report",
        help="output report using the named template file "
        "(sample template file is under docs/template.md)",
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
