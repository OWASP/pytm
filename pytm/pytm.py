from sys import stderr
import argparse
from hashlib import sha224
from re import sub
from .template_engine import SuperFormatter


def _setColor(element):
    if element.inScope is True:
        return "black"
    else:
        return "grey69"


def _debug(msg):
    if _args.debug is True:
        stderr.write("DEBUG: {}\n".format(msg))


def _uniq_name(s):
    ''' transform name in a unique(?) string '''
    h = sha224(s.encode('utf-8')).hexdigest()
    return sub(r'[0-9]', '', h)


class Threat():
    _BagOfThreats = []

    ''' Represents a possible threat '''
    def __init__(self, id, description, condition, target):
        self._id = id
        self._description = description
        self._condition = condition
        self._target = target

    @classmethod
    def load(self):
        for t in Threats.keys():
            if t not in TM._threatsExcluded:
                tt = Threat(t, Threats[t]["description"], Threats[t]["condition"], Threats[t]["target"])
                TM._BagOfThreats.append(tt)
        _debug("{} threat(s) loaded\n".format(len(TM._BagOfThreats)))

    def apply(self, target):
        _debug("{} - {}".format(self._id, target.name))
        if type(self._target) is tuple:
            if type(target) not in self._target:
                return None
        else:
            if type(target) is not self._target:
                return None
        return eval(self._condition)

    @property
    def id(self):
        return self._id

    @property
    def description(self):
        return self._description
        

class Finding():

    def __init__(self, element, description):
        self.target = element
        self.description = description


class Mitigation():

    def __init__(self, mitigatesWhat, mitigatesWhere, description):
        self.mitigatesWhat = mitigatesWhat
        self.mitigatesWhere = mitigatesWhere
        self.description = description


class TM():
    
    ''' Describes the threat model '''
    _BagOfFlows = []
    _BagOfElements = []
    _BagOfThreats = []
    _BagOfFindings = []
    _BagOfBoundaries = []
    _threatsExcluded = []
    _sf = None

    def __init__(self, name, descr=""):
        self.name = name
        self.description = descr
        self._sf = SuperFormatter()
        Threat.load()

    def resolve(self):
        for e in (TM._BagOfElements):
            if e.inScope is True:
                for t in TM._BagOfThreats:
                    if t.apply(e) is True:
                        TM._BagOfFindings.append(Finding(e._name, t._description))
                        
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
    def __init__(self, name, descr=None, inBoundary=None):
        self._name = name
        self._descr = descr
        self._inBoundary = inBoundary
        self._onAWS = False
        self._isHardened = False
        self._inScope = True
        TM._BagOfElements.append(self)

    def check(self):
        return True
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        if self._descr == "" or self._name == "":
            raise ValueError("Element {} need a description and a name.".format(self._name))

    def __repr__(self):
        return "Element\nName: {0}\nTrust Boundary: {1}\nDescription: {2}\n".format(self._name, self._inBoundary.name, self._descr)
 
    def dfd(self):
        print("{} [".format(_uniq_name(self._name)))
        print('\tshape = circle;\n\tstyle = bold;\n\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;\n\t]'.format(_uniq_name(self._name)))

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, val):
        self._name = str(val)

    @property
    def description(self):
        return self._descr

    @description.setter
    def description(self, val):
        self._descr = str(val)

    @property 
    def inAWS(self):
        return self._inAWS

    @inAWS.setter
    def inAWS(self, val):
        if val not in (True, False):
            raise ValueError("inAWS can only be True or False")
        self._inAWS = val

    @property
    def isHardened(self):
        return self._isHardened

    @isHardened.setter
    def isHardened(self, val):
        if val not in (True, False):
            raise ValueError("isHardened can only be True or False")
        self._isHardened = val

    @property
    def inBoundary(self):
        return self._inBoundary

    @inBoundary.setter
    def inBoundary(self, val):
        if type(val) != Boundary:
            raise ValueError("inBoundary can only be a Boundary object")
        self._inBoundary = val

    @property
    def inScope(self):
        return self._inScope
    
    @inScope.setter
    def inScope(self, val):
        if val not in (True, False):
            raise ValueError("inScope can only be True or False")
        self._inScope = val


class Server(Element):
    def __init__(self, name):
        self._OS = ""
        super().__init__(name)

    def __str__(self):
        print("Server")
        print("Name: {}\nDescription: {}\nOS: {}".format(self._name, self._descr, self._OS))
    
    @property
    def OS(self):
        return self._OS

    @OS.setter
    def OS(self, val):
        self._OS = str(val)

    def dfd(self):
        color = _setColor(self)
        print("{0} [\n\tshape = circle\n\tcolor = {1}".format(_uniq_name(self.name), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.name))
        print("]")


class Datastore(Element):
    def __init__(self, name):
        self._onRDS = False
        self._storesLogData = False
        self._storesPII = False
        self._storesSensitiveData = False
        self._isEncrypted = False
        self._isSQL = True
        self._providesConfidentiality = False
        self._providesIntegrity = False
        self._authenticatesSource = False 
        self._authenticatesDestination = False
        super().__init__(name)
    
    def __str__(self):
        print("Datastore")
        print("Name: {}\nDescription: {}\nIs on RDS: {}".format(self._name, self._descr, self._onRDS))
    
    def dfd(self):
        color = _setColor(self)
        print("{0} [\n\tshape = none;\n\tcolor = {1};".format(_uniq_name(self.name), color))
        print('\tlabel = <<table sides="TB" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.name, color))
        print("]")
    
    @property
    def storesPII(self):
        return self._storesPII
    
    @storesPII.setter
    def storesPII(self, val):
        if val not in (True, False):
            raise ValueError("storesPII can only be True or False on {}".format(self._name))
        self._storesPII = val

    @property
    def storesLogData(self):
        return self._storesLogData
    
    @storesLogData.setter
    def storesLogData(self, val):
        if val not in (True, False):
            raise ValueError("storesLogData can only be True or False on {}".format(self._name))
        self._storesLogData = val

    @property
    def onRDS(self):
        return self._onRDS

    @onRDS.setter
    def onRDS(self, val):
        if val not in (True, False):
            raise ValueError("onRDS can only be True or False on {}".format(self._name))
        self._onRDS = val

    @property
    def isEncrypted(self):
        return self._isEncrypted
    
    @isEncrypted.setter
    def isEncrypted(self, val):
        if val not in (True, False):
            raise ValueError("isEncrypted can only be True or False on {}".format(self._name))
        self._isEncrypted = val
        self._providesConfidentiality = True

    @property
    def providesConfidentiality(self):
        return self._providesConfidentiality
    
    @providesConfidentiality.setter
    def providesConfidentiality(self, val):
        if val not in (True, False):
            raise ValueError("providesConfidentiality can only be True or False on {}".format(self._name))
        self._providesConfidentiality = val
        # encrypted -> providesConfidentiality, but the inverse may not be true 

    @property
    def providesIntegrity(self):
        return self._providesIntegrity
    
    @providesIntegrity.setter
    def providesIntegrity(self, val):
        if val not in (True, False):
            raise ValueError("providesIntegrity can only be True or False on {}".format(self._name))
        self._providesIntegrity = val

    @property
    def authenticatesSource(self):
        return self._authenticatesSource
    
    @authenticatesSource.setter
    def authenticatesSource(self, val):
        if val not in (True, False):
            raise ValueError("authenticatesSource can only be True or False on {}".format(self._name))
        self._authenticateSource = val

    @property
    def authenticatesDestination(self):
        return self._authenticatesDestination
    
    @authenticatesDestination.setter
    def authenticatesDestination(self, val):
        if val not in (True, False):
            raise ValueError("authenticatesDestination can only be True or False on {}".format(self._name))
        self._authenticatesDestination = val


class Actor(Element):
    def __init__(self, name):
        self._isAdmin = False
        super().__init__(name)

    def __str__(self):
        print("Actor")
        print("Name: {}\nAdmin: {}\nDescription: {}\n".format(self._name, self._isAdmin, self._descr))

    def dfd(self):
        print("%s [\n\tshape = square;" % _uniq_name(self._name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{0}</b></td></tr></table>>;'.format(self._name))
        print("]")
    
    @property
    def isAdmin(self):
        return self._isAdmin

    @isAdmin.setter
    def isAdmin(self, val):
        if val is not True and val is not False:
            raise ValueError("isAdmin can only be true or false on {}".format(self._name))
        self._isAdmin = val


class Process(Element):
    
    def __init__(self, name):
        self._codeType = "Unmanaged"
        super().__init__(name)

    def dfd(self):
        print("%s [\n\tshape = circle\n" % _uniq_name(self._name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self._name))
        print("]")

    @property
    def codeType(self):
        return self._codeType
    
    @codeType.setter
    def codeType(self, val):
        val = val.tolower()
        if val not in ["unamanaged", "managed"]:
            raise ValueError("codeType is either managed or unmanaged in {}".format(self.name))
        self._codeType = val


class SetOfProcesses(Process):
    def __init__(self, name):
        super().__init__(name)

    def dfd(self):
        print("%s [\n\tshape = doublecircle\n" % _uniq_name(self.name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.name))
        print("]")


class Dataflow(Element):
    def __init__(self, source, sink, name):
        self._source = source
        self._sink = sink
        self._data = ""
        self._protocol = ""
        self._dstPort = None
        self._authenticatedWith = False
        self._order = -1
        self._implementsCommunicationProtocol = False
        self._implementsNonce = False
        self._name = name
        super().__init__(name)
        TM._BagOfFlows.append(self)

    @property
    def implementsCommunicationProtocol(self):
        return self._implementsCommunicationProtocol
    
    @implementsCommunicationProtocol.setter
    def implementsCommunicationProtocol(self, val):
        if val not in (True, False):
            raise ValueError("implementsCommunicationProtocol can only be True or False on {}".format(self._name))
        self._implementsCommunicationProtocol = val
   
    @property
    def implementsNonce(self):
        return self._implementsNonce
    
    @implementsNonce.setter
    def implementsNonce(self, val):
        if val not in (True, False):
            raise ValueError("implementsNonce can only be True or False on {}".format(self._name))
        self._implementsNonce = val

    @property
    def order(self):
        return self._order

    @order.setter
    def order(self, val):
        if not isinstance(val, int):
            raise ValueError("Order must be a positive integer on {}".format(self._name))
        self._order = val

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, val):
        if type(val) != Element:
            raise ValueError("Source must be an element in {}".format(self._name))
        self.source = val

    @property
    def sink(self):
        return self._sink

    @sink.setter
    def sink(self, val):
        if type(val) != Element:
            raise ValueError("Sink must be an element in {}".format(self._name))
        self._sink = val

    @property
    def dstPort(self):
        return self._dstPort

    @dstPort.setter
    def dstPort(self, val):
        if val < 0 or val > 65535:
            raise ValueError("Destination port must be between 0 and 65535 in {}".format(self._name))
        self._dstPort = val

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, val):
        if type(val) != str:
            raise ValueError("Protocol must be a string in {}".format(self._name))
        self._protocol = val

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, val):
        if type(val) != str:
            raise ValueError("Data must be a string in {}".format(self._name))
        self._data = val

    @property
    def authenticatedWith(self):
        return self._authenticatedWith
    
    @authenticatedWith.setter
    def authenticatedWith(self, val):
        if type(val) != str:
            raise ValueError("authenticatedWith can only be a string in {}".format(self._name))
        self._authenticatedWith = val

    def check(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to _BagOfFlows
        pass

    def dfd(self):
        print("\t{0} -> {1} [".format(_uniq_name(self._source.name),
                                      _uniq_name(self._sink._name)))
        color = _setColor(self)
        if self._order >= 0:
            print('\t\tcolor = {2};\n\t\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{2}"><b>({0}) {1}</b></font></td></tr></table>>;'.format(self._order, self._name, color))
        else:
            print('\t\tcolor = {1};\n\t\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color ="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self._name, color))
        print("\t]")         


class Boundary(Element):
    def __init__(self, name):
        super().__init__(name)
        if name not in TM._BagOfBoundaries:
            TM._BagOfBoundaries.append(self)

    def dfd(self):
        print("subgraph cluster_{0} {{\n\tgraph [\n\t\tfontsize = 10;\n\t\tfontcolor = firebrick2;\n\t\tstyle = dashed;\n\t\tcolor = firebrick2;\n\t\tlabel = <<i>{1}</i>>;\n\t]\n".format(_uniq_name(self._name), self._name))
        
        for e in TM._BagOfElements:
            _debug("{0}".format(e.name))
            if type(e) == Boundary:
                continue  # Boundaries are not in boundaries
            #  import pdb; pdb.set_trace()
            if e.inBoundary == self:
                _debug("{0} contains {1}".format(e.inBoundary.name, self._name))
                e.dfd()
        print("\n}\n")
        

_parser = argparse.ArgumentParser()
_parser.add_argument('--debug', action='store_true', help='print debug messages')
_parser.add_argument('--dfd', action='store_true', help='output DFD (default)')
_parser.add_argument('--report',  help='output report using the named template file')
_parser.add_argument('--exclude', help='specify threat IDs to be ignored')
_parser.add_argument('--seq', action='store_true', help='output sequential diagram')
_args = _parser.parse_args()
if _args.dfd is True and _args.seq is True:
    print("Cannot produce DFD and sequential diagrams in the same run.")
    exit(0)
if _args.report is not None:
    TM._template = _args.report
if _args.exclude is not None:
    TM._threatsExcluded = _args.exclude.split(",")
    _debug("Excluding threats: {}".format(TM._threatsExcluded))
    

from pytm.threats import Threats