from sys import stderr
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true', help='print debug messages')
parser.add_argument('--resolve', action='store_true', help='identify threats')
parser.add_argument('--dfd', action='store_true', help='output DFD')
parser.add_argument('--report', action='store_true', help='output report')
parser.add_argument('--all', action='store_true', help='output everything')
_args = parser.parse_args()
if _args.dfd is False and _args.report is False and _args.resolve is False:
    _args.all = True


def debug(msg):
    if _args.debug is True:
        stderr.write(msg)

        
def uniq_name(s):
    ''' transform name in a unique(?) string '''
    return s.replace(' ', '_')


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
            tt = Threat(t, Threats[t]["description"], Threats[t]["cvss"],
                        Threats[t]["condition"], Threats[t]["target"])
            TM._BagOfThreats.append(tt)

    def apply(self, target):
        if type(target) != self._target:
            return None
        return eval(self._condition)
        

class Finding():
    _BagOfFindings = []

    def __init__(self, element, description, cvss):
        self.target = element
        self.description = description
        self.cvss = cvss


class Boundary:
    def __init__(self, inBoundary):
        self.name = inBoundary
        if inBoundary not in TM._BagOfBoundaries:
            TM._BagOfBoundaries.append(inBoundary)

    def add(self, element):
        element.inBoundary = self.name
        

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

    def __init__(self, name, descr=""):
        self.name = name
        self.description = descr
        Threat.load()
        debug("{} threats loaded\n".format(len(TM._BagOfThreats)))

    def resolve(self):
        for e in (TM._BagOfElements + TM._BagOfFlows):
            for t in TM._BagOfThreats:
                if t.apply(e):
                    TM._BagOfFindings.append(Finding(e._name, t._description, t._cvss))

    def check(self):
        if self.description is None:
            raise ValueError("Every threat model should have at least a brief description of the system being modeled.")
        for e in (TM._BagOfElements + TM._BagOfFlows):
            e.check()

    def dfd(self):
        print("diagram {")
        for b in TM._BagOfBoundaries:
            print("boundary {} {{".format(uniq_name(b)))
            print("    title = \"{}\"".format(b))
            for e in TM._BagOfElements:
                if e.inBoundary == b:
                    e.dfd() 
            print("}")
        for e in TM._BagOfElements:
                if e.inBoundary is None:
                    e.inBoundary = "\"\""
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
        if _args.report is True:
            self.report()
        if _args.dfd is True:
            self.dfd()
        if _args.resolve is True:
            self.resolve()


class Element():
    _onAWS = False
    _inBoundary = None
    _isHardened = False

    def __init__(self, name, descr=None, inBoundary=None):
        self._name = name
        self._descr = descr
        self._inBoundary = None
        TM._BagOfElements.append(self)

    def check(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to _BagOfElements
        pass

    def __str__(self):
        print("Element")
        print("Name: {}\nTrust Boundary: {}\nDescription: {}\n".format(self._name, self._inBoundary, self._descr))
 
    def dfd(self):
        print("    function %s {" % uniq_name(self._name))
        print("        title = \"{0}\"".format(self._name))
        print("    }")

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


class Server(Element):
    _OS = ""

    def __init__(self, name):
        super().__init__(name)

    def __str__(self):
        print("Server")
        print("Name: {}\nDescription: {}\nOS: {}".format(self._name, self._descr))
    
    @property
    def OS(self):
        return self._OS

    @OS.setter
    def OS(self, val):
        self._OS = str(val)


class Database(Element):
    _onRDS = False
    
    def __init__(self, name):
        super().__init__(name)
    
    def __str__(self):
        print("Database")
        print("Name: {}\nDescription: {}\nIs on RDS: {}".format(self._name, self._descr, self._onRDS))
    
    def dfd(self):
        print("    database %s {" % uniq_name(self.name))
        print("        title = \"{0}\"".format(self.name))
        print("    }")
    
    @property
    def onRDS(self):
        return self._onRDS

    @onRDS.setter
    def onRDS(self, val):
        if val not in (True, False):
            raise ValueError("onRDS can only be True or False")
        self._onRDS = val


class Actor(Element):
    isAdmin = False

    def print(self):
        print("Actor")
        print("Name: {}\nDescription: \n".format(self.name, self.descr))

    def dfd(self):
        print("    io %s {" % uniq_name(self.name))
        print("        title = \"{0}\"".format(self.name))
        print("    }")


class Process(Element):
    def __init__(self, name):
        super().__init__(name)


class SetOfProcesses(Element):
    def __init__(self, name):
        super().__init__(name)


class Dataflow():

    def __init__(self, source, sink, name):
        self._source = source
        self._sink = sink
        self._name = name
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

    def check(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to _BagOfFlows
        pass

    def dfd(self):
        print("    {0} -> {1} {{".format(uniq_name(self._source.name),
                                         uniq_name(self._sink._name)))
        print("         operation = \"{0}\"".format(self._name))
        print("         data = \"{0}\"".format(self._protocol))
        print("    }")        
   
    
from pytm.threats import Threats