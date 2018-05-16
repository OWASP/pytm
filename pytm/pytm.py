from .threat import Threat


class TM():
    
    ''' Describes the threat model and contains the bag of flows 
    and of elements '''

    BagOfFlows = []
    BagOfElements = []
    BagOfThreats = Threat.BagOfThreats
    BagOfFindings = []

    def __init__(self, name, descr=""):
        self.name = name
        self.description = descr

    def set_description(self, descr):
        self.description = descr

    def verify(self):
        pass

    def resolve(self):
        for e in TM.BagOfElements:
            for t in TM.BagOfThreats:
                if t.verify(e):
                    TM.BagOfFindings.append((e.name, t.name))

    def dataflow(self):
        pass

    def report(self, *args, **kwargs):
        pass


class Element():
    counter = 0

    def __init__(self, name):
        Element.counter += 1
        self.name = name
        TM.BagOfElements.append(self)

    def set_description(self, descr):
        self.descr = descr

    def verify(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to BagOfElements
        pass


class Server(Element):
    OS = ""
    hardened = False
    onAWS = False

    def __init__(self, name):
        super().__init__(name)
    pass


class Database(Element):
    pass


class Actor(Element):
    pass


class Process(Element):
    pass


class SetOfProcesses(Element):
    pass


class Dataflow():
    counter = 0

    def __init__(self, source, sink, name):
        Dataflow.counter += 1
        self.source = source
        self.sink = sink
        self.name = name
        self.protocol = ""
        self.authenticatedWith = None
        TM.BagOfFlows.append(self)

    def set_source(self, source):
        self.source = source

    def set_sink(self, sink):
        self.sink = sink

    def verify(self):
        ''' makes sure it is good to go '''
        
        # all minimum annotations are in place
        # then add itself to BagOfFlows
        pass
            
    @classmethod
    def count(cls):
        return len(TM.BagOfFlows)



