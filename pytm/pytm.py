from sys import stderr
import argparse
from hashlib import sha224
from re import sub



def debug(msg):
    if _args.debug is True:
        stderr.write("DEBUG: {}\n".format(msg))

parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true', help='print debug messages')
parser.add_argument('--resolve', action='store_true', help='identify threats')
parser.add_argument('--dfd', action='store_true', help='output DFD')
parser.add_argument('--report', action='store_true', help='output report')
parser.add_argument('--all', action='store_true', help='output everything')
parser.add_argument('--exclude', help='specify threat IDs to be ignored')
_args = parser.parse_args()
if _args.dfd is False and _args.report is False and _args.resolve is False:
    _args.all = True
if _args.exclude is not None:
    TM._threatsExcluded = _args.exclude.split(",")
    debug("Excluding threats: {}".format(TM._threatsExcluded))
    
def uniq_name(s):
    ''' transform name in a unique(?) string '''
    h = sha224(s.encode('utf-8')).hexdigest()
    return sub(r'[0-9]', '', h)


class Threat():
    _BagOfThreats = []

    ''' Represents a possible threat '''
    def __init__(self, id, description, cvss, condition, target):
        self._id = id
        self._description = description
        self._cvss = cvss
        self._condition = condition
        self._target = target

    @classmethod
    def load(self):
        for t in Threats.keys():
            if t not in TM._threatsExcluded:
                tt = Threat(t, Threats[t]["description"], Threats[t]["cvss"],
                            Threats[t]["condition"], Threats[t]["target"])
                TM._BagOfThreats.append(tt)
        debug("{} threat(s) loaded\n".format(len(TM._BagOfThreats)))

    def apply(self, target):
        if type(target) != self._target:
            return None
        return eval(self._condition)
        

class Finding():

    def __init__(self, element, description, cvss):
        self.target = element
        self.description = description
        self.cvss = cvss


class Boundary:
    def __init__(self, name):
        self._name = name
        if name not in TM._BagOfBoundaries:
            TM._BagOfBoundaries.append(self)


    def dfd(self):
        print("subgraph cluster_{0} {{\n\tgraph [\n\t\tfontsize = 10;\n\t\tfontcolor = firebrick2;\n\t\tstyle = dashed;\n\t\tcolor = firebrick2;\n\t\tlabel = <<i>{1}</i>>;\n\t]\n".format(uniq_name(self._name), self._name))
        
        for e in TM._BagOfElements:
            debug("{0} xxx {1}".format(e._inBoundary, self._name))
            if e._inBoundary == self._name:
                e.dfd()
        print("\n}\n")
        

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

    def __init__(self, name, descr=""):
        self.name = name
        self.description = descr
        Threat.load()

    def resolve(self):
        for e in (TM._BagOfElements + TM._BagOfFlows):
            for t in TM._BagOfThreats:
                if t.apply(e) is True:
                    TM._BagOfFindings.append(Finding(e._name, t._description, t._cvss))

    def check(self):
        if self.description is None:
            raise ValueError("Every threat model should have at least a brief description of the system being modeled.")
        for e in (TM._BagOfElements + TM._BagOfFlows):
            e.check()

    def dfd(self):
        print("digraph tm {\n\tgraph [\n\tfontname = Arial;\n\tfontsize = 14;\n]")
        print("\tnode [\n\tfontname = Arial;\n\tfontsize = 14;\n\t]")
        print("\tedge [\n\tshape = none;\n\tfontname = Arial;\n\tfontsize = 12;\n\t]")
        print('\tlabelloc = "t";\n\tfontsize = 20;\n\tnodesep = 1;\n\trankdir = lr;\n')
        for b in TM._BagOfBoundaries:
            b.dfd() 
        for e in TM._BagOfElements:
            if e._inBoundary is None:
                e._inBoundary = "\"\""
                e.dfd()
        for f in TM._BagOfFlows:
            f.dfd()
        print("}")

    def report(self, *args, **kwargs):
        print("/* threats = ")
        for f in TM._BagOfFindings:
            print("Finding: {} on {} with score {}".format(f.description, f.target, f.cvss))
        print("*/")

    def process(self):
        self.check()
        if _args.all is True:
            _args.report = True
            _args.dfd = True
            _args.resolve = True
        if _args.dfd is True:
            self.dfd()
        if _args.resolve is True:
            self.resolve()
        if _args.report is True:
            self.report()
        

class Element():
    _onAWS = False
    _inBoundary = None
    _isHardened = False
    _descr = ""
    _name = ""

    def __init__(self, name, descr=None, inBoundary=None):
        self._name = name
        self._descr = descr
        self._inBoundary = None
        TM._BagOfElements.append(self)

    def check(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        if self._descr == "" or self._name == "":
            raise ValueError("All elements need a description and a name.")

    def __str__(self):
        print("Element")
        print("Name: {}\nTrust Boundary: {}\nDescription: {}\n".format(self._name, self._inBoundary, self._descr))
 
    def dfd(self):
        print("{} [".format(uniq_name(self._name)))
        print('\tshape = circle;\n\tstyle = bold;\n\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;\n\t]'.format(uniq_name(self._name)))

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
        self._inBoundary = str(val)


class Server(Element):
    _OS = ""

    def __init__(self, name):
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
        print("%s [\n\tshape = circle\n" % uniq_name(self.name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.name))
        print("]")


class Database(Element):
    _onRDS = False
    
    def __init__(self, name):
        super().__init__(name)
    
    def __str__(self):
        print("Database")
        print("Name: {}\nDescription: {}\nIs on RDS: {}".format(self._name, self._descr, self._onRDS))
    
    def dfd(self):
        print("{} [\n\tshape = none\n".format(uniq_name(self.name)))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.name))
        print("]")
    
    @property
    def onRDS(self):
        return self._onRDS

    @onRDS.setter
    def onRDS(self, val):
        if val not in (True, False):
            raise ValueError("onRDS can only be True or False on {}".format(self._name))
        self._onRDS = val


class Actor(Element):
    _isAdmin = False

    def __str__(self):
        print("Actor")
        print("Name: {}\nAdmin: {}\nDescription: {}\n".format(self._name, self._isAdmin, self._descr))

    def dfd(self):
        print("%s [\n\tshape = square\n" % uniq_name(self.name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.name))
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
        super().__init__(name)

    def dfd(self):
        print("%s [\n\tshape = circle\n" % uniq_name(self.name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.name))
        print("]")


class SetOfProcesses(Element):
    def __init__(self, name):
        super().__init__(name)

    def dfd(self):
        print("%s [\n\tshape = doublecircle\n" % uniq_name(self.name))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.name))
        print("]")

class Dataflow():

    def __init__(self, source, sink, name):
        self._source = source
        self._sink = sink
        self._name = name
        self._data = ""
        self._protocol = ""
        self._dstPort = None
        self._authenticatedWith = False
        TM._BagOfFlows.append(self)

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, val):
        if type(val) != Element:
            raise ValueError("Source must be an element.")
        self.source = val

    @property
    def sink(self):
        return self._sink

    @sink.setter
    def sink(self, val):
        if type(val) != Element:
            raise ValueError("Sink must be an element.")
        self._sink = val

    @property
    def dstPort(self):
        return self._dstPort

    @dstPort.setter
    def dstPort(self, val):
        if val < 0 or val > 65535:
            raise ValueError("Destination port must be between 0 and 65535")
        self._dstPort = val

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, val):
        if type(val) != str:
            raise ValueError("Protocol must be a string")
        self._protocol = val

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, val):
        if type(val) != str:
            raise ValueError("Data must be a string")
        self._data = val

    def check(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to _BagOfFlows
        pass

    def dfd(self):
        print("\t{0} -> {1} [".format(uniq_name(self._source.name),
                                         uniq_name(self._sink._name)))
        print('\t\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="#3184e4"><b>(1) </b></font><b>{0}</b></td></tr></table>>;'.format(self._name))
        print("\t]")        
   
    
from pytm.threats import Threats