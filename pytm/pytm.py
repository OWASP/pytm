from sys import argv

def debug(msg):
    if debug is True:
        print(msg)

        
def uniq_name(s):
    ''' transform name in a unique(?) string '''
    return s.replace(' ', '_')


class Threat():
    BagOfThreats = []

    ''' Represents a possible threat '''
    def __init__(self, id, description, cvss, condition, target):
        self.id = id
        self.description = description
        self.cvss = cvss
        self.condition = condition
        self.target = target

    @classmethod
    def load(self):
        for t in Threats.keys():
            tt = Threat(t, Threats[t]["description"], Threats[t]["cvss"],
                        Threats[t]["condition"], Threats[t]["target"])
            TM.BagOfThreats.append(tt)

    def apply(self, target):
        if type(target) != self.target:
            return None
        return eval(self.condition)
        

class Finding():
    BagOfFindings = []

    def __init__(self, element, description, cvss):
        self.target = element
        self.description = description
        self.cvss = cvss


class Mitigation():

    def __init__(self, mitigatesWhat, mitigatesWhere, description):
        self.mitigatesWhat = mitigatesWhat
        self.mitigatesWhere = mitigatesWhere
        self.description = description


class TM():
    
    ''' Describes the threat model '''
    BagOfFlows = []
    BagOfElements = []
    BagOfThreats = []
    BagOfFindings = []

    def __init__(self, name, descr=""):
        self.name = name
        self.description = descr
        Threat.load()
        print("{} threats loaded".format(len(TM.BagOfThreats)))

    def resolve(self):
        for e in (TM.BagOfElements + TM.BagOfFlows):
            for t in TM.BagOfThreats:
                if t.apply(e):
                    TM.BagOfFindings.append(Finding(e.name, t.description, t.cvss))

    def check(self):
        if self.description == None:
            print("Every threat model should have at least a brief description of the system being modeled.")
        for e in (TM.BagOfElements + TM.BagOfFlows):
            e.check()

    def dfd(self):
        ''' not taking boundaries into account yet '''
        print("diagram {")
        for e in TM.BagOfElements + TM.BagOfFlows:
            e.dfd()
        print("}")

    def report(self, *args, **kwargs):
        for f in TM.BagOfFindings:
            print("Finding: {} on {} with score {}".format(f.description, f.target, f.cvss))


class Element():
    counter = 0

    def __init__(self, name, descr = None):
        Element.counter += 1
        self.name = name
        self.descr = descr
        TM.BagOfElements.append(self)

    def check(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to BagOfElements
        pass

    def __str__(self):
        print("Element")
        print("Name: {}\nDescription: {}\n".format(self.name, self.descr))
 
    def dfd(self):
        print("    function %s {" % uniq_name(self.name))
        print("        title = \"{0}\"".format(self.name))
        print("    }")


class Server(Element):
    OS = ""
    isHardened = False
    onAWS = False

    def __init__(self, name):
        super().__init__(name)


class Database(Element):
    onRDS = False
    
    def __init__(self, name):
        super().__init__(name)
    
    def __str__(self):
        print("Database")
        print("Name: {}\nDescription: {}\n".format(self.name, self.descr))
    
    def dfd(self):
        print("    database %s {" % uniq_name(self.name))
        print("        title = \"{0}\"".format(self.name))
        print("    }")
    

class Actor(Element):
    def __init__(self, name):
        super().__init__(name)
    
    def __str__(self):
        print("Actor")
        print("Name: {}\nDescription: {}\n".format(self.name, self.descr))
    
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
    counter = 0

    def __init__(self, source, sink, name):
        Dataflow.counter += 1
        self.source = source
        self.sink = sink
        self.name = name
        self.protocol = ""
        self.dstPort = None
        self.authenticatedWith = False
        TM.BagOfFlows.append(self)

    def set_source(self, source):
        self.source = source

    def set_sink(self, sink, dstPort=None):
        self.sink = sink
        self.dstPort = dstPort

    def verify(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to BagOfFlows
        pass

    def dfd(self):
        print("    {0} -> {1} {{".format(uniq_name(self.source.name),
                              uniq_name(self.sink.name)))
        print("         operation = \"{0}\"".format(self.name))
        print("         data = \"{0}\"".format(self.protocol))
        print("    }")        
    

''' Add threats here '''

Threats = {
    "DF1": {
        "description": "Dataflow not authenticated",
        "cvss": 8.6,
        "target": Dataflow,
        "condition": "target.authenticatedWith is False"
    },
    "SR1": {
        "description": "Server not hardened",
        "cvss": 9.0,
        "target": Server,
        "condition": "target.isHardened is False"
    }
}