import argparse
from hashlib import sha224
from re import sub, match
from .template_engine import SuperFormatter
from weakref import WeakKeyDictionary
from sys import stderr, exit

''' Helper functions '''

''' The base for this (descriptors instead of properties) has been shamelessly lifted from    https://nbviewer.jupyter.org/urls/gist.github.com/ChrisBeaumont/5758381/raw/descriptor_writeup.ipynb
    By Chris Beaumont
'''

class varString(object):
    ''' A descriptor that returns strings but won't allow writing '''
    def __init__(self, default):
        self.default = default
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        # when x.d is called we get here
        # instance = x
        # owner = type(x)
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        # called when x.d = val
        # instance = x
        # value = val
        if not isinstance(value, str):
            raise ValueError("expecting a String value, got a {}".format(type(value)))
        try:
            self.data[instance]
        except (NameError, KeyError):
            self.data[instance] = value

class varBoundary(object):
    def __init__(self, default):
        self.default = default
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if not isinstance(value, Boundary):
            raise ValueError("expecting a Boundary value, got a {}".format(type(value)))
        try:
            self.data[instance]
        except (NameError, KeyError):
            self.data[instance] = value

class varBool(object):
    def __init__(self, default):
        self.default = default
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if not isinstance(value, bool):
            raise ValueError("expecting a boolean value, got a {}".format(type(value)))
        try:
            self.data[instance]
        except (NameError, KeyError):
            self.data[instance] = value


class varInt(object):
    def __init__(self, default):
        self.default = default
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if not isinstance(value, int):
            raise ValueError("expecting an integer value, got a {}".format(type(value)))
        try:
            self.data[instance]
        except (NameError, KeyError):
            self.data[instance] = value


class varElement(object):
    def __init__(self, default):
        self.default = default
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if not isinstance(value, Element):
            raise ValueError("expecting an Element (or inherited) value, got a {}".format(type(value)))
        try:
            self.data[instance]
        except (NameError, KeyError):
            self.data[instance] = value


def _setColor(element):
    if element.inScope is True:
        return "black"
    else:
        return "grey69"


def _debug(_args, msg):
    if _args.debug is True:
        stderr.write("DEBUG: {}\n".format(msg))


def _uniq_name(s):
    ''' transform name in a unique(?) string '''
    h = sha224(s.encode('utf-8')).hexdigest()
    return sub(r'[0-9]', '', h)

''' End of help functions '''

class Threat():
    id = varString("")
    description = varString("")
    condition = varString("")
    target = ()

    ''' Represents a possible threat '''
    def __init__(self, id, description, condition, target):
        self.id = id
        self.description = description
        self.condition = condition
        self.target = target

    @classmethod
    def load(self):
        for t in Threats.keys():
            if t not in TM._threatsExcluded:
                tt = Threat(t, Threats[t]["description"], Threats[t]["condition"], Threats[t]["target"])
                TM._BagOfThreats.append(tt)
        _debug(_args, "{} threat(s) loaded\n".format(len(TM._BagOfThreats)))

    def apply(self, target):
        if type(self.target) is tuple:
            if type(target) not in self.target:
                return None
        else:
            if type(target) is not self.target:
                return None
        return eval(self.condition)


class Finding():
    ''' This class represents a Finding - the element in question and a description of the finding '''
    def __init__(self, element, description):
        self.target = element
        self.description = description


class TM():
    ''' Describes the threat model administratively, and holds all details during a run '''
    _BagOfFlows = []
    _BagOfElements = []
    _BagOfThreats = []
    _BagOfFindings = []
    _BagOfBoundaries = []
    _threatsExcluded = []
    _sf = None
    description = varString("")

    def __init__(self, name):
        self.name = name
        self._sf = SuperFormatter()
        Threat.load()

    def resolve(self):
        for e in (TM._BagOfElements):
            if e.inScope is True:
                for t in TM._BagOfThreats:
                    if t.apply(e) is True:
                        TM._BagOfFindings.append(Finding(e.name, t.description))

    def check(self):
        if self.description is None:
            raise ValueError("Every threat model should have at least a brief description of the system being modeled.")
        for e in (TM._BagOfElements + TM._BagOfFlows):
            e.check()

    def dfd(self):
        print("digraph tm {\n\tgraph [\n\tfontname = Arial;\n\tfontsize = 14;\n\t]")
        print("\tnode [\n\tfontname = Arial;\n\tfontsize = 14;\n\trankdir = lr;\n\t]")
        print("\tedge [\n\tshape = none;\n\tfontname = Arial;\n\tfontsize = 12;\n\t]")
        print('\tlabelloc = "t";\n\tfontsize = 20;\n\tnodesep = 1;\n')
        for b in TM._BagOfBoundaries:
            b.dfd()
        for e in TM._BagOfElements:
            e.dfd()
        print("}")

    def seq(self):
        print("@startuml")
        for e in TM._BagOfElements:
            if type(e) is Actor:
                print("actor {0} as \"{1}\"".format(_uniq_name(e.name), e.name))
            elif type(e) is Datastore:
                print("database {0} as \"{1}\"".format(_uniq_name(e.name), e.name))
            elif type(e) is not Dataflow and type(e) is not Boundary:
                print("entity {0} as \"{1}\"".format(_uniq_name(e.name), e.name))

        ordered = sorted(TM._BagOfFlows, key=lambda flow: flow.order)
        for e in ordered:
            print("{0} -> {1}: {2}".format(_uniq_name(e.source.name), _uniq_name(e.sink.name), e.name))
            if e.note != "":
                print("note left\n{}\nend note".format(e.note))
        print("@enduml")

    def report(self, *args, **kwargs):
        with open(self._template) as file:
            template = file.read()

        print(self._sf.format(template, tm=self, dataflows=self._BagOfFlows, threats=self._BagOfThreats, findings=self._BagOfFindings, elements=self._BagOfElements, boundaries=self._BagOfBoundaries))

    def process(self):
        self.check()
        if _args.seq is True:
            self.seq()
        if _args.dfd is True:
            self.dfd()
        if _args.report is not None:
            self.resolve()
            self.report()


class Element():
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

    def __init__(self, name):
        self.name = name
        TM._BagOfElements.append(self)

    def check(self):
        return True
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        if self.description == "" or self.name == "":
            raise ValueError("Element {} need a description and a name.".format(self.name))

    def dfd(self):
        print("%s [\n\tshape = square;" % _uniq_name(self.name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{0}</b></td></tr></table>>;'.format(self.name))
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

    def __init__(self, name):
        super().__init__(name)

    def dfd(self):
        color = _setColor(self)
        print("{0} [\n\tshape = circle\n\tcolor = {1}".format(_uniq_name(self.name), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.name))
        print("]")


class ExternalEntity(Element):
    implementsAuthenticationScheme = varBool(False)
    implementsNonce = varBool(False)
    handlesResources = varBool(False)
    definesConnectionTimeout = varBool(False)

    def __init__(self, name):
        super().__init__(name)


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
    _authenticatesDestination = varBool(False)
    isShared = varBool(False)
    hasWriteAccess = varBool(False)
    handlesResources = varBool(False)
    definesConnectionTimeout = varBool(False)
    isResilient = varBool(False)
    handlesInterruptions = varBool(False)
    authorizesSource = varBool(False)
    hasAccessControl = varBool(False)
    authenticationScheme = varString("")

    def __init__(self, name):
        super().__init__(name)

    def dfd(self):
        color = _setColor(self)
        print("{0} [\n\tshape = none;\n\tcolor = {1};".format(_uniq_name(self.name), color))
        print('\tlabel = <<table sides="TB" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.name, color))
        print("]")


class Actor(Element):
    isAdmin = varBool(False)

    def __init__(self, name):
        super().__init__(name)

    def dfd(self):
        print("%s [\n\tshape = square;" % _uniq_name(self.name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{0}</b></td></tr></table>>;'.format(self.name))
        print("]")


class Process(Element):
    codeType = varString("Unmanaged")
    implementsCommunicationProtocol = varBool(False)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    authenticatesSource = varBool(False)
    authenticatesDestination = varBool(False)
    dataType = varString("")
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

    def __init__(self, name):
        super().__init__(name)

    def dfd(self):
        color = _setColor(self)
        print("{0} [\n\tshape = circle;\n\tcolor = {1};\n".format(_uniq_name(self.name), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.name, color))
        print("]")


class SetOfProcesses(Process):
    def __init__(self, name):
        super().__init__(name)

    def dfd(self):
        color = _setColor(self)
        print("{0} [\n\tshape = doublecircle;\n\tcolor = {1};\n".format(_uniq_name(self.name), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.name, color))
        print("]")


class Dataflow(Element):
    source = varElement(None)
    sink = varElement(None)
    data = varString("")
    protocol = varString("")
    dstPort = varInt(0)
    authenticatedWith = varBool(False)
    order = varInt(-1)
    implementsCommunicationProtocol = varBool(False)
    implementsNonce = varBool(False)
    name = varString("")
    isEncrypted = varBool(False)
    note = varString("")

    def __init__(self, source, sink, name):
        self.source = source
        self.sink = sink
        self.name = name
        super().__init__(name)
        TM._BagOfFlows.append(self)

    def __set__(self, instance, value):
        print("Should not have gotten here.")

    def check(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to _BagOfFlows
        pass

    def dfd(self):
        print("\t{0} -> {1} [".format(_uniq_name(self.source.name),
                                      _uniq_name(self.sink.name)))
        color = _setColor(self)
        if self.order >= 0:
            print('\t\tcolor = {2};\n\t\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{2}"><b>({0}) {1}</b></font></td></tr></table>>;'.format(self.order, self.name, color))
        else:
            print('\t\tcolor = {1};\n\t\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color ="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.name, color))
        print("\t]")


class Boundary(Element):
    def __init__(self, name):
        super().__init__(name)
        if name not in TM._BagOfBoundaries:
            TM._BagOfBoundaries.append(self)

    def dfd(self):
        print("subgraph cluster_{0} {{\n\tgraph [\n\t\tfontsize = 10;\n\t\tfontcolor = firebrick2;\n\t\tstyle = dashed;\n\t\tcolor = firebrick2;\n\t\tlabel = <<i>{1}</i>>;\n\t]\n".format(_uniq_name(self.name), self.name))

        for e in TM._BagOfElements:
            if type(e) == Boundary:
                continue  # Boundaries are not in boundaries
            #  import pdb; pdb.set_trace()
            if e.inBoundary == self:
                e.dfd()
        print("\n}\n")


_parser = argparse.ArgumentParser()
_parser.add_argument('--debug', action='store_true', help='print debug messages')
_parser.add_argument('--dfd', action='store_true', help='output DFD (default)')
_parser.add_argument('--report', help='output report using the named template file')
_parser.add_argument('--exclude', help='specify threat IDs to be ignored')
_parser.add_argument('--seq', action='store_true', help='output sequential diagram')
_parser.add_argument('--list', action='store_true', help='list known threats')
_parser.add_argument('--describe', help='describe the contents of a given class')

_args = _parser.parse_args()
if _args.dfd is True and _args.seq is True:
    stderr.write("Cannot produce DFD and sequential diagrams in the same run.\n")
    exit(0)
if _args.report is not None:
    TM._template = _args.report
if _args.exclude is not None:
    TM._threatsExcluded = _args.exclude.split(",")
if _args.describe is not None:
    try:
        c = eval(_args.describe)
    except Exception:
        stderr.write("No such class to describe: {}\n".format(_args.describe))
        exit(-1)
    print(_args.describe)
    [print("\t{}".format(i)) for i in dir(c) if not callable(i) and match("__",i)==None]


from pytm.threats import Threats

if _args.list is True:
    tm = TM("dummy")
    [print("{} - {}".format(t.id, t.description)) for t in TM._BagOfThreats]
    exit(0)
